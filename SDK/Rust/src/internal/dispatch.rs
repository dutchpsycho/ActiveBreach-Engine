//! This module implements the **syscall dispatcher thread** that processes requests from
//! [`ab_call`](crate::ab_call), prepares a syscall stub, patches in the system service number (SSN),
//! executes the syscall, and captures the return value.
//!
//! ## How it works
//! - A single-threaded loop polls a global shared [`ABOpFrame`].
//! - When the `status` field flips to `1`, it attempts to acquire an encrypted stub.
//! - The stub is decrypted, the SSN is written into it at offset `+4`, and it's immediately invoked
//!   with all 16 possible argument registers.
//! - After execution, the stub is re-encrypted and returned to the pool.
//!
//! ## Notes
//! - Syscall stub encryption at rest is enforced using LEA-based symmetric encryption.
//! - This loop does **not** use any OS synchronization primitives — only atomics and spin/yielding.
//!
//! ## Safety
//! All memory and thread control logic assumes tight control of environment (e.g. AV evasion).
//! The system assumes this thread is spawned **once** and remains alive for the duration of use.

use core::cell::UnsafeCell;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use windows::Win32::System::Memory::{PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE};
use windows::Win32::System::Threading::{WaitOnAddress, WakeByAddressSingle, INFINITE};

use crate::internal::antibreach;
use crate::internal::diagnostics::{AbErr, ABError};
use crate::internal::exports;
#[cfg(feature = "ntdll_backend")]
use crate::internal::mapper;
use crate::internal::vm;
#[cfg(not(feature = "ntdll_backend"))]
use crate::internal::stack::AbResolveNtdllStub;
#[cfg(all(debug_assertions, not(feature = "ntdll_backend")))]
use crate::internal::stack::{AbDebugFakeStackBounds, AbDebugNtdllImageRange};
#[cfg(not(feature = "ntdll_backend"))]
use crate::internal::stack::{AbSidewinderInit, AbStackWinder};
use crate::internal::stub::{AbRingAllocator, STUB_SIZE};
#[cfg(feature = "ntdll_backend")]
use crate::internal::stub_template::{write_jmp64_stub, write_syscall_stub};
use crate::AbOut;
/// Operation frame shared between the caller and dispatcher thread.
///
/// This structure contains the syscall name (SSN), arguments, and return value.
///
/// ## States
/// - `status = 0`: Free, ready to accept request
/// - `status = 1`: Request pending
/// - `status = 2`: Syscall completed
#[repr(C)]
pub struct ABOpFrame {
    /// Frame status: 0 = free, 1 = pending, 2 = complete
    pub status: AtomicU32,
    /// Syscall name length in bytes (max 63).
    pub name_len: u32,
    /// Syscall name bytes (ASCII/UTF-8), not null-terminated.
    pub name: [u8; 64],
    /// Resolved syscall service number (SSN) used by the dispatcher.
    pub syscall_id: u32,
    /// NTDLL export stub address used for stack spoofing
    pub spoof_ret: usize,
    /// Number of arguments to pass (max: 16)
    pub arg_count: usize,
    /// Argument buffer (max 16 registers)
    pub args: [usize; 16],
    /// Return value from the syscall
    pub ret: usize,
}

impl Default for ABOpFrame {
    fn default() -> Self {
        Self {
            status: AtomicU32::new(0),
            name_len: 0,
            name: [0u8; 64],
            syscall_id: 0,
            spoof_ret: 0,
            arg_count: 0,
            args: [0; 16],
            ret: 0,
        }
    }
}

/// Function pointer representing a dynamically generated syscall stub.
///
/// This is always cast from a `*mut u8` after patching the SSN.
///
/// # Safety
/// - Must point to valid executable code
/// - Must follow Windows syscall calling convention
pub type ABStubFn = unsafe extern "system" fn(
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
) -> usize;

struct OpFrameGlobal {
    slot: UnsafeCell<MaybeUninit<ABOpFrame>>,
}

// Safe because all access is synchronized externally via `status` atomics and the
// dispatcher is launched exactly once.
unsafe impl Sync for OpFrameGlobal {}

impl OpFrameGlobal {
    const fn new() -> Self {
        Self {
            slot: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    /// # Safety
    /// Must only be called once (by the dispatcher thread) before any readers.
    #[inline(always)]
    unsafe fn init(&self) -> *mut ABOpFrame {
        (*self.slot.get()).write(ABOpFrame::default());
        (*self.slot.get()).as_mut_ptr()
    }

    /// # Safety
    /// Caller must ensure the dispatcher has initialized the frame.
    #[inline(always)]
    unsafe fn ptr(&self) -> *mut ABOpFrame {
        (*self.slot.get()).as_mut_ptr()
    }
}

/// Shared global operation frame, uninitialized until dispatcher starts.
static G_OPFRAME: OpFrameGlobal = OpFrameGlobal::new();
pub static G_READY: AtomicBool = AtomicBool::new(false);

#[cfg(feature = "long_sleep")]
static G_LONG_SLEEP_IDLE_MS: AtomicU64 = AtomicU64::new(30_000);

#[cfg(feature = "long_sleep")]
pub fn AbSetLongSleepIdleMs(ms: u64) {
    // Keep this sane; too low tends to thrash alloc/free and increases risk of races.
    let ms = ms.clamp(1_000, 24 * 60 * 60 * 1000);
    G_LONG_SLEEP_IDLE_MS.store(ms, Ordering::Relaxed);
}

#[cfg(all(debug_assertions, not(feature = "ntdll_backend")))]
static G_SPOOF_DUMPED: AtomicBool = AtomicBool::new(false);

#[inline(always)]
fn cpu_pause() {
    unsafe {
        core::arch::asm!("pause", options(nomem, nostack));
    }
}

#[inline(always)]
fn current_tid() -> u32 {
    #[cfg(target_arch = "x86_64")]
    {
        let tid: usize;
        unsafe {
            // TEB.ClientId.UniqueThread (no Kernel32 import).
            core::arch::asm!("mov {0}, gs:[0x48]", out(reg) tid);
        }
        return tid as u32;
    }

    #[cfg(target_arch = "x86")]
    {
        let tid: u32;
        unsafe {
            core::arch::asm!("mov {0:e}, fs:[0x24]", out(reg) tid);
        }
        return tid;
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
    {
        0
    }
}

#[inline(never)]
fn terminate_hard() -> ! {
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    unsafe {
        core::arch::asm!("ud2", options(noreturn));
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
    unsafe {
        core::intrinsics::abort();
    }
}

/// Syscall dispatcher thread entrypoint.
///
/// This function spins indefinitely, polling `G_OPFRAME` and processing
/// syscall requests by acquiring, decrypting, patching, and invoking a stub.
///
/// # Safety
/// This function must only be launched **once**.
/// It assumes `G_OPFRAME` is uninitialized and will remain in memory.
///
pub unsafe extern "system" fn thread_proc(_: *mut core::ffi::c_void) -> u32 {
    crate::internal::stub::AbMarkDispatcherThread();
    AbOut!(
        "dispatcher thread started @ {:p} (TID={})",
        thread_proc as *const (),
        current_tid()
    );
    let frame = &mut *G_OPFRAME.init();
    G_READY.store(true, Ordering::Release);
    // Ensure any callers waiting via WaitOnAddress get released promptly.
    WakeByAddressSingle(&G_READY as *const AtomicBool as *const core::ffi::c_void);
    AbOut!("opframe initialized, ready flag set");

        #[cfg(not(feature = "ntdll_backend"))]
        {
        let _ = AbSidewinderInit();
        }

    let mut spin = 0;

    let mut stub_pool: Option<AbRingAllocator> = None;
    #[cfg(feature = "long_sleep")]
    let mut last_activity = Instant::now();

    loop {
        while frame.status.load(Ordering::Acquire) != 1 {
            #[cfg(feature = "long_sleep")]
            {
                let idle_ms = G_LONG_SLEEP_IDLE_MS.load(Ordering::Relaxed);
                let idle = Duration::from_millis(idle_ms);
                if Instant::now().duration_since(last_activity) >= idle {
                    if stub_pool.is_some() || exports::AbSyscallTableIsInit() {
                        AbOut!("long_sleep idle: tearing down resources");
                        stub_pool = None; // drops + VirtualFree
                        exports::AbDeinitSyscallTable();
                    }

                    // Alertable-ish: park until the caller flips status away from 0.
                    let expected: u32 = 0;
                    let _ = WaitOnAddress(
                        &frame.status as *const AtomicU32 as *const core::ffi::c_void,
                        &expected as *const u32 as *const core::ffi::c_void,
                        core::mem::size_of::<u32>(),
                        Some(INFINITE),
                    );
                    continue;
                }
            }

            spin += 1;
            match spin {
                0..=64 => cpu_pause(),
                65..=256 => std::thread::yield_now(),
                _ => std::thread::sleep(std::time::Duration::from_micros(50)),
            }
        }
        spin = 0;
        #[cfg(feature = "long_sleep")]
        {
            last_activity = Instant::now();
        }

        // Ensure syscall table exists before resolving the SSN.
        if exports::AbEnsureSyscallTableInit().is_err() {
            AbOut!("syscall table init failed");
            frame.ret = AbErr(ABError::DispatchTableMissing) as usize;
            frame.status.store(2, Ordering::Release);
            continue;
        }
        if !exports::AbVerifySyscallTableHash() {
            AbOut!("syscall table hash mismatch");
            terminate_hard();
        }

        let name_len = frame.name_len as usize;
        if name_len == 0 || name_len >= frame.name.len() {
            frame.ret = AbErr(ABError::DispatchNameTooLong) as usize;
            frame.status.store(2, Ordering::Release);
            continue;
        }
        let name_bytes = &frame.name[..name_len];
        let name = match core::str::from_utf8(name_bytes) {
            Ok(s) => s,
            Err(_) => {
                frame.ret = AbErr(ABError::DispatchNameTooLong) as usize;
                frame.status.store(2, Ordering::Release);
                continue;
            }
        };

        #[cfg(feature = "ntdll_backend")]
        let ssn: u32 = match exports::AbLookupSsn(name) {
            Some(n) => n,
            None => {
                frame.ret = AbErr(ABError::DispatchSyscallMissing) as usize;
                frame.status.store(2, Ordering::Release);
                continue;
            }
        };

        #[cfg(not(feature = "ntdll_backend"))]
        {
            let ssn = match exports::AbLookupSsn(name) {
                Some(n) => n,
                None => {
                    frame.ret = AbErr(ABError::DispatchSyscallMissing) as usize;

                    frame.status.store(2, Ordering::Release);
                    continue;
                }
            };
            frame.syscall_id = ssn;
        }

        #[cfg(feature = "ntdll_backend")]
        {
            // Keep syscall_id meaningful for diagnostics. Also used if we fall back to
            // the direct-syscall stub when NTDLL's export stub is hooked.
            frame.syscall_id = ssn;
        }

        let pool = stub_pool.get_or_insert_with(AbRingAllocator::init);

        let h = match pool.acquire() {
            Some(h) => h,
            None => {
                AbOut!("stub pool empty");
                continue;
            }
        };

        let stub = unsafe { pool.resolve_ptr(h) };

        if stub as usize & 15 != 0 {
            AbOut!("stub misaligned");
            pool.release(h);
            continue;
        }

        #[cfg(not(feature = "ntdll_backend"))]
        let ssn_ptr = stub.add(4) as *mut u32;

        #[cfg(feature = "secure")]
        {
            let mut old: u32 = PAGE_EXECUTE_READ.0;
            if !vm::AbVirtualProtect(stub, STUB_SIZE, PAGE_EXECUTE_READWRITE.0, &mut old) {
                AbOut!("RWX fail");
                pool.release(h);
                continue;
            }
        }

        #[cfg(not(feature = "ntdll_backend"))]
        ssn_ptr.write_volatile(frame.syscall_id);

        #[cfg(feature = "ntdll_backend")]
        {
            // Prefer jumping into a cached loaded-NTDLL syscall prologue pointer.
            // If no intact prologue exists (inline hook overwrote the stub), fall back to a
            // direct-syscall stub. Never jump to export entry bytes.
            if let Some(target) = exports::AbLookupNtdllProloguePtr(name) {
                // Re-validate the cached prologue pointer is still inside NTDLL .text.
                // Hooks can be installed after init; if anything looks off, fall back to direct stub.
                let mut ok = false;
                unsafe {
                    if let Some((tbase, tlen)) = mapper::loaded_ntdll_text_range() {
                        let start = tbase as usize;
                        if let Some(end) = start.checked_add(tlen) {
                            let p = target as usize;
                            // Require a little headroom for reading the minimal prologue window.
                            if p >= start && p.checked_add(32).is_some_and(|p_end| p_end <= end) {
                                ok = true;
                            }
                        }
                    }
                }

                if ok {
                    unsafe { write_jmp64_stub(stub, target as u64) };
                } else {
                    unsafe { write_syscall_stub(stub, ssn) };
                }
            } else {
                unsafe { write_syscall_stub(stub, ssn) };
            }
        }

        #[cfg(feature = "secure")]
        {
            let mut old: u32 = PAGE_EXECUTE_READWRITE.0;
            vm::AbVirtualProtect(stub, STUB_SIZE, PAGE_EXECUTE_READ.0, &mut old);
        }

        let fn_ptr: ABStubFn = std::mem::transmute(stub);

        let mut regs = [0usize; 16];
        regs[..frame.arg_count].copy_from_slice(&frame.args[..frame.arg_count]);

        antibreach::AbEvaluate();

        #[cfg(not(feature = "ntdll_backend"))]
        let mut orig_rsp: usize = 0;
        #[cfg(not(feature = "ntdll_backend"))]
        let mut spoofed = false;

        // Stack spoofing is only used by the direct-syscall backend.
        #[cfg(not(feature = "ntdll_backend"))]
        if frame.spoof_ret != 0 {
            if let Some(fake_rsp) = AbStackWinder(frame.spoof_ret as u64) {
                #[cfg(debug_assertions)]
                if !G_SPOOF_DUMPED.swap(true, Ordering::SeqCst) {
                    if let Some((base, end)) = AbDebugFakeStackBounds() {
                        if fake_rsp < base || fake_rsp >= end {
                            AbOut!(
                                "spoof stack OOB: rsp=0x{:X} page=0x{:X}-0x{:X}",
                                fake_rsp,
                                base,
                                end
                            );
                        } else {
                            AbOut!(
                                "spoof stack in-bounds: rsp=0x{:X} page=0x{:X}-0x{:X}",
                                fake_rsp,
                                base,
                                end
                            );
                        }
                    }

                    if let Some((base, end)) = AbDebugNtdllImageRange() {
                        let ret = frame.spoof_ret as usize;
                        if ret < base || ret >= end {
                            AbOut!(
                                "spoof ret outside ntdll: 0x{:X} not in 0x{:X}-0x{:X}",
                                ret,
                                base,
                                end
                            );
                        } else {
                            AbOut!(
                                "spoof ret inside ntdll: 0x{:X} in 0x{:X}-0x{:X}",
                                ret,
                                base,
                                end
                            );
                        }
                    }

                    let spoof_slot = unsafe { (fake_rsp as *const u64).offset(-4) };
                    let slot_val = unsafe { *spoof_slot };
                    AbOut!(
                        "spoof stack: rsp=0x{:X} slot[rsp-0x20]=0x{:X} expected=0x{:X}",
                        fake_rsp,
                        slot_val,
                        frame.spoof_ret
                    );
                    for i in -6isize..=6isize {
                        let addr = unsafe { (fake_rsp as *const u64).offset(i) };
                        let val = unsafe { *addr };
                        AbOut!("  [rsp{:+#x}] = 0x{:X}", i * 8, val);
                    }
                }

                core::arch::asm!("mov {}, rsp", out(reg) orig_rsp);
                core::arch::asm!("mov rsp, {}", in(reg) fake_rsp);
                spoofed = true;
            }
        }

        let ret = fn_ptr(
            regs[0], regs[1], regs[2], regs[3], regs[4], regs[5], regs[6], regs[7], regs[8],
            regs[9], regs[10], regs[11], regs[12], regs[13], regs[14], regs[15],
        );

        #[cfg(not(feature = "ntdll_backend"))]
        if spoofed {
            core::arch::asm!("mov rsp, {}", in(reg) orig_rsp);
        }

        std::sync::atomic::fence(Ordering::SeqCst);
        frame.ret = ret;
        frame.status.store(2, Ordering::Release);
        WakeByAddressSingle(&frame.status as *const AtomicU32 as *const core::ffi::c_void);

        pool.release(h);
    }
}

#[inline(always)]
pub unsafe fn AbFire(name: &str, args: &[usize]) -> usize {
    #[inline(always)]
    fn wait_status_eq(status: &AtomicU32, want: u32, iters_limit: u32) -> bool {
        let mut spin: u32 = 0;
        while status.load(Ordering::Acquire) != want {
            if spin >= iters_limit {
                return false;
            }

            match spin {
                0..=64 => cpu_pause(),
                65..=256 => std::thread::yield_now(),
                257..=2048 => std::hint::spin_loop(),
                _ => {
                    // Use a short timed wait to avoid burning CPU without relying on external wakes.
                    let expected: u32 = status.load(Ordering::Relaxed);
                    unsafe {
                        let _ = WaitOnAddress(
                            status as *const AtomicU32 as *const core::ffi::c_void,
                            &expected as *const u32 as *const core::ffi::c_void,
                            core::mem::size_of::<u32>(),
                            Some(1), // ms
                        );
                    }
                }
            }

            spin = spin.wrapping_add(1);
        }
        true
    }

    let frame = &mut *G_OPFRAME.ptr();

    if !wait_status_eq(&frame.status, 0, 0x200_0000) {
        return AbErr(ABError::DispatchFrameTimeout) as usize;
    }

    // `spoof_ret` is used by the direct-syscall backend to build a synthetic stack that returns
    // into an NTDLL export stub. With `ntdll_backend`, we explicitly do not spoof the stack: we
    // JMP into the loaded NTDLL syscall prologue and let it `ret` back naturally.
    #[cfg(not(feature = "ntdll_backend"))]
    {
        frame.spoof_ret = AbResolveNtdllStub(name).unwrap_or(0) as usize;

    }
    #[cfg(feature = "ntdll_backend")]
    {
        frame.spoof_ret = 0;
    }

    // Copy syscall name into the shared frame for dispatcher-side lookup.
    // `ab_call()` already enforces name.len() < 64.
    frame.name.fill(0);
    frame.name[..name.len()].copy_from_slice(name.as_bytes());
    frame.name_len = name.len() as u32;

    frame.arg_count = args.len();
    frame.args[..args.len()].copy_from_slice(args);

    frame.status.store(1, Ordering::Release);
    WakeByAddressSingle(&frame.status as *const AtomicU32 as *const core::ffi::c_void);

    if !wait_status_eq(&frame.status, 2, 0x200_0000) {
        return AbErr(ABError::DispatchFrameTimeout) as usize;
    }

    let ret = frame.ret;
    frame.status.store(0, Ordering::Release);
    WakeByAddressSingle(&frame.status as *const AtomicU32 as *const core::ffi::c_void);

    ret
}
