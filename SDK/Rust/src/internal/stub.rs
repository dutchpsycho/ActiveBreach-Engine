//! Manages a ring-buffer of 16-byte-aligned memory stubs, each encoded with runtime encryption

use std::ptr::write_bytes;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use windows::Win32::System::Memory::{
    MEM_RELEASE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_NOACCESS,
};

use crate::internal::crypto::aes_ctr::{AbAesCtrDecryptBlock, AbAesCtrEncryptBlock};
use crate::internal::diagnostics::*;
use crate::internal::entropy::AbStrongRangeU8Inclusive;
use crate::internal::antibreach;
use crate::internal::vm;
#[cfg(not(feature = "ntdll_backend"))]
use crate::internal::stub_template::write_syscall_stub;
#[cfg(feature = "ntdll_backend")]
use crate::internal::stub_template::write_jmp64_stub;
pub use crate::internal::stub_template::STUB_SIZE;
use crate::AbOut;

/// Opaque handle to a stub slot in the ring allocator.
///
/// This prevents non-dispatcher code paths from ever receiving the real stub pointer.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub(in crate::internal) struct StubHandle(u8);

/// State for a single encrypted syscall trampoline block.
///
/// This intentionally does not store a pointer; addresses are derived from the base
/// allocation and a per-allocator stride.
#[derive(Debug)]
#[repr(C)]
pub struct StubSlotState {
    /// Flag indicating whether this stub is currently encrypted at rest.
    encrypted: AtomicBool,

    /// Flag indicating whether this slot is currently checked out.
    in_use: AtomicBool,
}

unsafe impl Send for StubSlotState {}
unsafe impl Sync for StubSlotState {}

/// A ring-based encrypted stub allocator used by ActiveBreach.
///
/// Provides per-thread stealth trampolines by rotating through a ring of encrypted
/// syscall stubs. Decryption is performed lazily on acquire, and encryption is restored
/// on release.
pub struct AbRingAllocator {
    base: *mut u8,
    count: usize,
    stub_stride: usize,
    slots: Vec<StubSlotState>,
    index: AtomicUsize,
}

unsafe impl Send for AbRingAllocator {}
unsafe impl Sync for AbRingAllocator {}

#[inline(always)]
pub fn AbMarkDispatcherThread() {}

impl AbRingAllocator {
    /// Initializes the stub ring, preallocating and encrypting each RWX stub.
    ///
    /// This is invoked once during dispatcher bootstrap. Each stub is encrypted immediately
    /// after its template is written, and protected with `PAGE_NOACCESS` until acquired.
    pub fn init() -> Self {
        let count = AbStrongRangeU8Inclusive(24, 38) as usize;
        let stride_pages = AbStrongRangeU8Inclusive(1, 8) as usize;
        let stub_stride = STUB_PAGE_SIZE * stride_pages;
        AbOut!(
            "stub pool init: slots={}, stub_size=0x{:X}, stride=0x{:X}",
            count,
            STUB_SIZE,
            stub_stride
        );
        let base = Self::alloc_region(count, stub_stride).unwrap();
        let mut slots: Vec<StubSlotState> = Vec::with_capacity(count);

        for i in 0..count {
            let stub = unsafe { base.add(i * stub_stride) };
            unsafe {
                Self::write_template(stub);
                AbAesCtrEncryptBlock(stub, STUB_SIZE);

                #[cfg(feature = "secure")]
                {
                    let mut old: u32 = PAGE_EXECUTE_READ.0;
                    let ok = vm::AbVirtualProtect(stub, STUB_SIZE, PAGE_NOACCESS.0, &mut old);
                    debug_assert!(ok);
                }
            }

            slots.push(StubSlotState {
                encrypted: AtomicBool::new(true),
                in_use: AtomicBool::new(false),
            });
        }

        #[cfg(debug_assertions)]
        {
            let min_addr = base as usize;
            let max_addr = base as usize + ((count - 1) * stub_stride);
            let range_end = max_addr.saturating_add(STUB_SIZE.saturating_sub(1));
            AbOut!(
                "stub pool range: 0x{:X}-0x{:X} ({} stubs)",
                min_addr,
                range_end,
                count
            );
        }

        AbOut!("stub pool ready");
        Self {
            base,
            count,
            stub_stride,
            slots,
            index: AtomicUsize::new(0),
        }
    }

    /// Allocates a single RWX region to hold all stubs.
    ///
    /// Panics if the allocation fails.
    #[inline(always)]
    fn alloc_region(count: usize, stride: usize) -> Result<*mut u8, u32> {
        let size = count.saturating_mul(stride);
        let raw = unsafe { vm::AbVirtualAlloc(size, PAGE_EXECUTE_READWRITE.0) } as *mut u8;

        if raw.is_null() {
            return Err(AbErr(ABError::StubAllocFail));
        }

        Ok(raw)
    }

    /// Writes the syscall stub template to a newly allocated buffer.
    ///
    /// The stub template is encrypted at build-time and decrypted only when writing.
    #[inline(always)]
    unsafe fn write_template(stub: *mut u8) {
        #[cfg(not(feature = "ntdll_backend"))]
        {
            write_syscall_stub(stub, 0);
        }
        #[cfg(feature = "ntdll_backend")]
        {
            // Default to null target; dispatcher patches a real prologue target per call.
            write_jmp64_stub(stub, 0);
        }
    }

    /// Acquires a decrypted syscall stub from the ring.
    ///
    /// If available, decrypts the stub in-place, sets `PAGE_EXECUTE_READ`, and returns it.
    /// Returns `None` if no slots are available.
    ///
    /// # Returns
    /// `Some(StubHandle)` for a decrypted trampoline or `None` if exhausted.
    pub(in crate::internal) fn acquire(&self) -> Option<StubHandle> {
        let n = self.count;
        if n == 0 {
            return None;
        }
        let start = self.index.fetch_add(1, Ordering::Relaxed) % n;

        for offset in 0..n {
            let i = (start + offset) % n;
            let slot = &self.slots[i];

            if slot
                .in_use
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                continue;
            }

            let addr = self.stub_ptr(i);

            antibreach::AbCheckHWBP();

            #[cfg(feature = "secure")]
            {
                let mut old: u32 = PAGE_EXECUTE_READ.0;
                let _ =
                    unsafe { vm::AbVirtualProtect(addr, STUB_SIZE, PAGE_EXECUTE_READWRITE.0, &mut old) };
            }

            if slot.encrypted.swap(false, Ordering::SeqCst) {
                AbAesCtrDecryptBlock(addr, STUB_SIZE);
            }

            #[cfg(feature = "secure")]
            {
                let mut old: u32 = PAGE_EXECUTE_READWRITE.0;
                let _ =
                    unsafe { vm::AbVirtualProtect(addr, STUB_SIZE, PAGE_EXECUTE_READ.0, &mut old) };
            }

            return Some(StubHandle(i as u8));
        }

        None
    }

    /// Resolves an opaque handle to the underlying stub pointer.
    ///
    /// This is intentionally restricted to the dispatcher module.
    #[inline(always)]
    pub(in crate::internal) unsafe fn resolve_ptr(&self, h: StubHandle) -> *mut u8 {
        let i = h.0 as usize;
        debug_assert!(i < self.count);
        self.stub_ptr(i)
    }

    /// Releases a stub after use, wiping and re-encrypting the region in-place.
    ///
    /// This restores the stub to `PAGE_NOACCESS`, zeroes its memory, rewrites the template,
    /// and re-encrypts with LEA. It’s safe to call this multiple times.
    ///
    /// # Arguments
    /// - `h`: Handle to the stub to return
    pub(in crate::internal) fn release(&self, h: StubHandle) {
        let i = h.0 as usize;
        debug_assert!(i < self.count);
        let slot = &self.slots[i];
        let addr = self.stub_ptr(i);

        unsafe {
            antibreach::AbCheckHWBP();

            #[cfg(feature = "secure")]
            {
                let mut old: u32 = PAGE_EXECUTE_READ.0;
                let _ = vm::AbVirtualProtect(addr, STUB_SIZE, PAGE_EXECUTE_READWRITE.0, &mut old);
            }

            write_bytes(addr, 0, STUB_SIZE);
            Self::write_template(addr);
            AbAesCtrEncryptBlock(addr, STUB_SIZE);

            #[cfg(feature = "secure")]
            {
                let mut old: u32 = PAGE_EXECUTE_READWRITE.0;
                let _ = vm::AbVirtualProtect(addr, STUB_SIZE, PAGE_NOACCESS.0, &mut old);
            }
        }

        slot.encrypted.store(true, Ordering::SeqCst);
        slot.in_use.store(false, Ordering::Release);
    }

    #[inline(always)]
    fn stub_ptr(&self, i: usize) -> *mut u8 {
        unsafe { self.base.add(i * self.stub_stride) }
    }
}

impl Drop for AbRingAllocator {
    fn drop(&mut self) {
        for i in 0..self.count {
            let addr = self.stub_ptr(i);
            unsafe {
                // Best-effort wipe before freeing. Ignore protection errors.
                let mut old: u32 = PAGE_EXECUTE_READ.0;
                let _ = vm::AbVirtualProtect(addr, STUB_SIZE, PAGE_EXECUTE_READWRITE.0, &mut old);
                write_bytes(addr, 0, STUB_SIZE);
            }
        }

        unsafe {
            // Free the original allocation base.
            let _ = MEM_RELEASE;
            let _ = vm::AbVirtualFree(self.base);
        }
    }
}

const STUB_PAGE_SIZE: usize = 0x1000;
