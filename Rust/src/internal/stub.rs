//! Manages a ring-buffer of 16-byte-aligned memory stubs, each encoded with runtime encryption

use std::ptr::{null_mut, write_bytes};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::mem::MaybeUninit;

use winapi::um::memoryapi::{VirtualAlloc, VirtualProtect};
use winapi::um::winnt::{
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_NOACCESS,
};

use crate::internal::crypto::lea::{lea_encrypt_block, lea_decrypt_block};
use crate::internal::diagnostics::*;

use lazy_static::lazy_static;

/// Size of a syscall stub in bytes.
pub const STUB_SIZE: usize = 32;

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

lazy_static! {
    /// Global stub allocator used by the dispatcher thread.
    pub static ref G_STUB_POOL: AbRingAllocator = AbRingAllocator::init();
}

impl AbRingAllocator {
    /// Initializes the stub ring, preallocating and encrypting each RWX stub.
    ///
    /// This is invoked once during dispatcher bootstrap. Each stub is encrypted immediately
    /// after its template is written, and protected with `PAGE_NOACCESS` until acquired.
    pub fn init() -> Self {
        let mut slots: [MaybeUninit<StubSlot>; NUM_STUBS] =
            std::array::from_fn(|_| MaybeUninit::uninit());
    
        for i in 0..NUM_STUBS {
            let stub = Self::alloc_stub().unwrap(); // or bubble result if you want
            unsafe {
                Self::write_template(stub);
                lea_encrypt_block(stub, STUB_SIZE); // assume no fail
    
                let mut old = 0;
                let ok = VirtualProtect(stub as _, STUB_SIZE, PAGE_NOACCESS, &mut old);
                debug_assert!(ok != 0);
            }
    
            slots[i] = MaybeUninit::new(StubSlot {
                addr: stub,
                encrypted: AtomicBool::new(true),
            });
        }
    
        let slots = unsafe { std::mem::transmute::<_, [StubSlot; NUM_STUBS]>(slots) };
    
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
            VirtualAlloc(null_mut(), STUB_SIZE + 16, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
        } as usize;
    
        if raw == 0 {
            return Err(AB_STUB_ALLOC_FAIL);
        }
    
        let aligned = (raw + 15) & !15;
        Ok(aligned as *mut u8)
    }

    /// Writes the syscall stub template to a newly allocated buffer.
    ///
    /// The stub includes `mov r10, rcx; mov eax, <ssn>; syscall; ret`, followed by padding.
    #[inline(always)]
    unsafe fn write_template(stub: *mut u8) {
        const TEMPLATE: [u8; 11] = [
            0x4C, 0x8B, 0xD1,             // mov r10, rcx
            0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, <ssn>
            0x0F, 0x05,                   // syscall
            0xC3,                         // ret
        ];

        std::ptr::copy_nonoverlapping(TEMPLATE.as_ptr(), stub, TEMPLATE.len());
        std::ptr::write_bytes(stub.add(TEMPLATE.len()), 0xCC, STUB_SIZE - TEMPLATE.len());
    }

    /// Acquires a decrypted syscall stub from the ring.
    ///
    /// If available, decrypts the stub in-place, sets `PAGE_EXECUTE_READ`, and returns it.
    /// Returns `None` if no slots are available.
    ///
    /// # Returns
    /// `Some(*mut u8)` to a decrypted trampoline or `None` if exhausted.
    pub fn acquire(&self) -> Option<*mut u8> {
        let start = self.index.fetch_add(1, Ordering::Relaxed) % NUM_STUBS;

        for offset in 0..NUM_STUBS {
            let i = (start + offset) % NUM_STUBS;
            let slot = &self.slots[i];

            unsafe {
                let mut old = 0;
                VirtualProtect(slot.addr as _, STUB_SIZE, PAGE_EXECUTE_READWRITE, &mut old);

                if slot.encrypted.swap(false, Ordering::SeqCst) {
                    lea_decrypt_block(slot.addr, STUB_SIZE);
                }

                VirtualProtect(slot.addr as _, STUB_SIZE, PAGE_EXECUTE_READ, &mut old);
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
                    let mut old = 0;
                    VirtualProtect(addr as _, STUB_SIZE, PAGE_EXECUTE_READWRITE, &mut old);

                    write_bytes(addr, 0, STUB_SIZE);
                    Self::write_template(addr);
                    lea_encrypt_block(addr, STUB_SIZE);

                    VirtualProtect(addr as _, STUB_SIZE, PAGE_NOACCESS, &mut old);
                }

                slot.encrypted.store(true, Ordering::SeqCst);
                break;
            }
        }
    }
}