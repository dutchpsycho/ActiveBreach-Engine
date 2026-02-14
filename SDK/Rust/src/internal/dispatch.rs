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

use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use windows::Win32::System::Memory::{VirtualProtect, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE};
use windows::Win32::System::Threading::{WaitOnAddress, WakeByAddressSingle, INFINITE};

use crate::internal::antibreach;
use crate::internal::diagnostics::{ABErr, ABError};
use crate::internal::exports;
#[cfg(debug_assertions)]
use crate::internal::stack::{debug_fake_stack_bounds, debug_ntdll_image_range};
use crate::internal::stack::{resolve_ntdll_stub, AbStackWinder, SidewinderInit};
use crate::internal::stub::{AbRingAllocator, STUB_SIZE};
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

/// Shared global operation frame, uninitialized until dispatcher starts.
pub static mut G_OPFRAME: MaybeUninit<ABOpFrame> = MaybeUninit::uninit();
pub static G_READY: AtomicBool = AtomicBool::new(false);

#[cfg(feature = "long_sleep")]
static G_LONG_SLEEP_IDLE_MS: AtomicU64 = AtomicU64::new(30_000);

#[cfg(feature = "long_sleep")]
pub fn ab_set_long_sleep_idle_ms(ms: u64) {
    // Keep this sane; too low tends to thrash alloc/free and increases risk of races.
    let ms = ms.clamp(1_000, 24 * 60 * 60 * 1000);
    G_LONG_SLEEP_IDLE_MS.store(ms, Ordering::Relaxed);
}

#[cfg(debug_assertions)]
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
    crate::internal::stub::mark_dispatcher_thread();
    AbOut!(
        "dispatcher thread started @ {:p} (TID={})",
        thread_proc as *const (),
        current_tid()
    );
    G_OPFRAME.write(ABOpFrame::default());
    G_READY.store(true, Ordering::Release);
    // Ensure any callers waiting via WaitOnAddress get released promptly.
    WakeByAddressSingle(&G_READY as *const AtomicBool as *const core::ffi::c_void);
    AbOut!("opframe initialized, ready flag set");

    let _ = SidewinderInit();

    let frame = &mut *G_OPFRAME.as_mut_ptr();
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
                    if stub_pool.is_some() || exports::syscall_table_is_init() {
                        AbOut!("long_sleep idle: tearing down resources");
                        stub_pool = None; // drops + VirtualFree
                        exports::deinit_syscall_table();
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
        if exports::ensure_syscall_table_init().is_err() {
            AbOut!("syscall table init failed");
            frame.ret = ABErr(ABError::DispatchTableMissing) as usize;
            frame.status.store(2, Ordering::Release);
            continue;
        }
        if !exports::verify_syscall_table_hash() {
            AbOut!("syscall table hash mismatch");
            terminate_hard();
        }

        let name_len = frame.name_len as usize;
        if name_len == 0 || name_len >= frame.name.len() {
            frame.ret = ABErr(ABError::DispatchNameTooLong) as usize;
            frame.status.store(2, Ordering::Release);
            continue;
        }
        let name_bytes = &frame.name[..name_len];
        let name = match core::str::from_utf8(name_bytes) {
            Ok(s) => s,
            Err(_) => {
                frame.ret = ABErr(ABError::DispatchNameTooLong) as usize;
                frame.status.store(2, Ordering::Release);
                continue;
            }
        };

        let ssn = match exports::lookup_ssn(name) {
            Some(n) => n,
            None => {
                frame.ret = ABErr(ABError::DispatchSyscallMissing) as usize;
                frame.status.store(2, Ordering::Release);
                continue;
            }
        };
        frame.syscall_id = ssn;

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

        let ssn_ptr = stub.add(4) as *mut u32;

        #[cfg(feature = "secure")]
        {
            let mut old = PAGE_EXECUTE_READ;
            if !VirtualProtect(stub as _, STUB_SIZE, PAGE_EXECUTE_READWRITE, &mut old).is_ok() {
                AbOut!("RWX fail");
                pool.release(h);
                continue;
            }
        }

        ssn_ptr.write_volatile(ssn);

        #[cfg(feature = "secure")]
        {
            let mut old = PAGE_EXECUTE_READWRITE;
            VirtualProtect(stub as _, STUB_SIZE, PAGE_EXECUTE_READ, &mut old).ok();
        }

        let fn_ptr: ABStubFn = std::mem::transmute(stub);

        let mut regs = [0usize; 16];
        regs[..frame.arg_count].copy_from_slice(&frame.args[..frame.arg_count]);

        antibreach::evaluate();

        let mut orig_rsp: usize = 0;
        let mut spoofed = false;

        if frame.spoof_ret != 0 {
            if let Some(fake_rsp) = AbStackWinder(frame.spoof_ret as u64) {
                #[cfg(debug_assertions)]
                if !G_SPOOF_DUMPED.swap(true, Ordering::SeqCst) {
                    if let Some((base, end)) = debug_fake_stack_bounds() {
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

                    if let Some((base, end)) = debug_ntdll_image_range() {
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
pub unsafe fn __ActiveBreachFire(name: &str, args: &[usize]) -> usize {
    let frame = &mut *G_OPFRAME.as_mut_ptr();

    let mut spin = 0;
    while frame.status.load(Ordering::Acquire) != 0 {
        if spin >= 0x200_0000 {
            return ABErr(ABError::DispatchFrameTimeout) as usize;
        }
        std::hint::spin_loop();
        spin += 1;
    }

    frame.spoof_ret = resolve_ntdll_stub(name).unwrap_or(0) as usize;

    // Copy syscall name into the shared frame for dispatcher-side lookup.
    // `ab_call()` already enforces name.len() < 64.
    frame.name.fill(0);
    frame.name[..name.len()].copy_from_slice(name.as_bytes());
    frame.name_len = name.len() as u32;

    frame.arg_count = args.len();
    frame.args[..args.len()].copy_from_slice(args);

    frame.status.store(1, Ordering::Release);
    WakeByAddressSingle(&frame.status as *const AtomicU32 as *const core::ffi::c_void);

    let mut spin2 = 0;
    while frame.status.load(Ordering::Acquire) != 2 {
        if spin2 >= 0x200_0000 {
            return ABErr(ABError::DispatchFrameTimeout) as usize;
        }
        std::hint::spin_loop();
        spin2 += 1;
    }

    let ret = frame.ret;
    frame.status.store(0, Ordering::Release);

    ret
}
