//! Manages a ring-buffer of 16-byte-aligned memory stubs, each encoded with runtime encryption

use std::mem::MaybeUninit;
use std::ptr::write_bytes;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use windows::Win32::System::Memory::{
    VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE, PAGE_NOACCESS,
};

use crate::internal::crypto::lea::{lea_decrypt_block, lea_encrypt_block};
use crate::internal::diagnostics::*;
use crate::internal::stub_template::write_syscall_stub;
use crate::AbOut;
pub use crate::internal::stub_template::STUB_SIZE;

use once_cell::sync::Lazy;

/// Number of encrypted stubs to maintain in the ring pool.
const NUM_STUBS: usize = 32;

/// A single encrypted syscall trampoline block.
///
/// This structure wraps a pointer to the memory holding the stub, and a flag indicating
/// whether the block is currently encrypted.
#[derive(Debug)]
#[repr(C)]
pub struct StubSlot {
    /// Aligned memory block holding the encrypted syscall stub.
    pub addr: *mut u8,

    /// Flag indicating whether this stub is currently encrypted at rest.
    pub encrypted: AtomicBool,
}

unsafe impl Send for StubSlot {}
unsafe impl Sync for StubSlot {}

/// A ring-based encrypted stub allocator used by ActiveBreach.
///
/// Provides per-thread stealth trampolines by rotating through a ring of encrypted
/// syscall stubs. Decryption is performed lazily on acquire, and encryption is restored
/// on release.
pub struct AbRingAllocator {
    slots: [StubSlot; NUM_STUBS],
    index: AtomicUsize,
}

unsafe impl Send for AbRingAllocator {}
unsafe impl Sync for AbRingAllocator {}

pub static G_STUB_POOL: Lazy<AbRingAllocator> = Lazy::new(AbRingAllocator::init);

#[inline(always)]
pub fn mark_dispatcher_thread() {
}


impl AbRingAllocator {
    /// Initializes the stub ring, preallocating and encrypting each RWX stub.
    ///
    /// This is invoked once during dispatcher bootstrap. Each stub is encrypted immediately
    /// after its template is written, and protected with `PAGE_NOACCESS` until acquired.
    pub fn init() -> Self {
        AbOut!("stub pool init: slots={}, stub_size=0x{:X}", NUM_STUBS, STUB_SIZE);
        let mut slots: [MaybeUninit<StubSlot>; NUM_STUBS] =
            std::array::from_fn(|_| MaybeUninit::uninit());

        let mut min_addr: usize = usize::MAX;
        let mut max_addr: usize = 0;

        for i in 0..NUM_STUBS {
            let stub = Self::alloc_stub().unwrap();
            let stub_addr = stub as usize;
            if stub_addr < min_addr {
                min_addr = stub_addr;
            }
            if stub_addr > max_addr {
                max_addr = stub_addr;
            }
            unsafe {
                Self::write_template(stub);
                lea_encrypt_block(stub, STUB_SIZE);

                let mut old = PAGE_EXECUTE_READ;
                #[cfg(feature = "secure")]
                {
                    let ok = VirtualProtect(stub as _, STUB_SIZE, PAGE_NOACCESS, &mut old).is_ok();
                    debug_assert!(ok);
                }
            }

            slots[i] = MaybeUninit::new(StubSlot {
                addr: stub,
                encrypted: AtomicBool::new(true),
            });
        }

        let slots = unsafe { std::mem::transmute::<_, [StubSlot; NUM_STUBS]>(slots) };

        if min_addr != usize::MAX {
            let range_end = max_addr.saturating_add(STUB_SIZE.saturating_sub(1));
            AbOut!(
                "stub pool range: 0x{:X}-0x{:X} ({} stubs)",
                min_addr,
                range_end,
                NUM_STUBS
            );
        }

        AbOut!("stub pool ready");
        Self {
            slots,
            index: AtomicUsize::new(0),
        }
    }

    /// Allocates RWX memory for a new syscall stub, with 16-byte alignment.
    ///
    /// Panics if the allocation fails.
    #[inline(always)]
    fn alloc_stub() -> Result<*mut u8, u32> {
        let raw = unsafe {
            VirtualAlloc(
                None,
                STUB_SIZE + 16,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        } as usize;

        if raw == 0 {
            return Err(ABErr(ABError::StubAllocFail));
        }

        let aligned = (raw + 15) & !15;
        Ok(aligned as *mut u8)
    }

    /// Writes the syscall stub template to a newly allocated buffer.
    ///
    /// The stub template is encrypted at build-time and decrypted only when writing.
    #[inline(always)]
    unsafe fn write_template(stub: *mut u8) {
        write_syscall_stub(stub, 0);
    }

    /// Acquires a decrypted syscall stub from the ring.
    ///
    /// If available, decrypts the stub in-place, sets `PAGE_EXECUTE_READ`, and returns it.
    /// Returns `None` if no slots are available.
    ///
    /// # Returns
    /// `Some(*mut u8)` to a decrypted trampoline or `None` if exhausted.
    pub fn acquire(&self) -> Option<*mut u8> {
        let start =
            self.index.fetch_add(1, Ordering::Relaxed) % NUM_STUBS;

        for offset in 0..NUM_STUBS {
            let i = (start + offset) % NUM_STUBS;
            let slot = &self.slots[i];

            unsafe {
                #[cfg(feature = "secure")]
                {
                    let mut old = PAGE_EXECUTE_READ;
                    VirtualProtect(slot.addr as _, STUB_SIZE, PAGE_EXECUTE_READWRITE, &mut old);
                }

                if slot.encrypted.swap(false, Ordering::SeqCst) {
                    lea_decrypt_block(slot.addr, STUB_SIZE);
                }

                #[cfg(feature = "secure")]
                {
                    let mut old = PAGE_EXECUTE_READWRITE;
                    VirtualProtect(
                        slot.addr as _,
                        STUB_SIZE,
                        PAGE_EXECUTE_READ,
                        &mut old,
                    );
                }
            }

            return Some(slot.addr);
        }

        None
    }

    /// Releases a stub after use, wiping and re-encrypting the region in-place.
    ///
    /// This restores the stub to `PAGE_NOACCESS`, zeroes its memory, rewrites the template,
    /// and re-encrypts with LEA. It’s safe to call this multiple times.
    ///
    /// # Arguments
    /// - `addr`: Pointer to the stub to return
    pub fn release(&self, addr: *mut u8) {
        for slot in &self.slots {
            if slot.addr == addr {
                unsafe {
                    #[cfg(feature = "secure")]
                    {
                        let mut old = PAGE_EXECUTE_READ;
                        VirtualProtect(addr as _, STUB_SIZE, PAGE_EXECUTE_READWRITE, &mut old);
                    }

                    write_bytes(addr, 0, STUB_SIZE);
                    Self::write_template(addr);
                    lea_encrypt_block(addr, STUB_SIZE);

                    #[cfg(feature = "secure")]
                    {
                        let mut old = PAGE_EXECUTE_READWRITE;
                        VirtualProtect(
                            addr as _,
                            STUB_SIZE,
                            PAGE_NOACCESS,
                            &mut old,
                        );
                    }
                }

                slot.encrypted.store(true, Ordering::SeqCst);
                break;
            }
        }
    }
}