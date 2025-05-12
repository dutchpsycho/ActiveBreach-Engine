//! ActiveBreach - Stub Manager (AbRingAllocator)
//!
//! Handles allocation, encryption, and lifecycle of syscall stub gadgets.
//! Implements a ring-buffer allocator with auto-recycling, aligned for high-performance stealth use.

use std::ptr::{null_mut, write_bytes};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::mem::MaybeUninit;

use winapi::um::memoryapi::{VirtualAlloc, VirtualProtect};
use winapi::um::winnt::{
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_NOACCESS,
};

use crate::internal::crypto::lea::{lea_encrypt_block, lea_decrypt_block};
use lazy_static::lazy_static;

pub const STUB_SIZE: usize = 32;
const NUM_STUBS: usize = 32;

/// Represents a single encrypted syscall stub slot.
#[derive(Debug)]
#[repr(C)]
pub struct StubSlot {
    pub addr: *mut u8,
    pub encrypted: AtomicBool,
}

unsafe impl Send for StubSlot {}
unsafe impl Sync for StubSlot {}

/// Ring-based stub allocator used by ActiveBreach syscall proxy.
pub struct AbRingAllocator {
    slots: [StubSlot; NUM_STUBS],
    index: AtomicUsize,
}

unsafe impl Send for AbRingAllocator {}
unsafe impl Sync for AbRingAllocator {}

lazy_static! {
    /// Global stub pool allocator used by the dispatcher.
    pub static ref G_STUB_POOL: AbRingAllocator = AbRingAllocator::init();
}

impl AbRingAllocator {
    /// Initializes the stub pool, encrypting all syscall templates.
    pub fn init() -> Self {
        let mut slots: [MaybeUninit<StubSlot>; NUM_STUBS] =
        std::array::from_fn(|_| MaybeUninit::uninit());

        for i in 0..NUM_STUBS {
            let stub = Self::alloc_stub();
            unsafe {
                Self::write_template(stub);
                lea_encrypt_block(stub, STUB_SIZE);

                let mut old = 0;
                VirtualProtect(stub as _, STUB_SIZE, PAGE_NOACCESS, &mut old);
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

    /// Allocates RWX memory for a single stub.
    #[inline(always)]
    fn alloc_stub() -> *mut u8 {
        let raw = unsafe {
            VirtualAlloc(null_mut(), STUB_SIZE + 16, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
        } as usize;
    
        if raw == 0 {
            panic!("AbRingAllocator: stub allocation failed");
        }
    
        let aligned = (raw + 15) & !15;
        aligned as *mut u8
    }    

    /// Writes the syscall stub template to a newly allocated buffer.
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

    /// Returns a decrypted syscall stub for use. Automatically rotates via ring.
    ///
    /// Caller must release it via `release()` once the call is complete.
    pub fn acquire(&self) -> Option<*mut u8> {
        let start = self.index.fetch_add(1, Ordering::Relaxed) % NUM_STUBS;

        for offset in 0..NUM_STUBS {
            let i = (start + offset) % NUM_STUBS;
            let slot = &self.slots[i];

            let stub = slot.addr;
            if stub.is_null() {
                continue;
            }

            unsafe {
                // double check alignment (must be 16-byte for syscall tramp)
                debug_assert_eq!(stub as usize % 16, 0, "[AB] stub not 16-byte aligned");

                // make it writable to decrypt
                let mut old = 0;
                if VirtualProtect(stub as _, STUB_SIZE, PAGE_EXECUTE_READWRITE, &mut old) == 0 {
                    eprintln!("[AB] failed to make stub RWX at index {}", i);
                    continue;
                }

                // decrypt if necessary
                if slot.encrypted.swap(false, Ordering::SeqCst) {
                    lea_decrypt_block(stub, STUB_SIZE);
                }

                // set back to RX (just in case anything tries to scan memory perms)
                if VirtualProtect(stub as _, STUB_SIZE, PAGE_EXECUTE_READ, &mut old) == 0 {
                    eprintln!("[AB] failed to set stub to RX at index {}", i);
                    continue;
                }
            }

            return Some(stub);
        }

        eprintln!("[AB] all stubs busy, no available slot");
        None
    }

    /// Releases a stub back to the pool after use.
    /// Re-encrypts the memory and restores protection to PAGE_NOACCESS.
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