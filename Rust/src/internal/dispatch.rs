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
use std::sync::atomic::{AtomicU32, Ordering, AtomicBool};

use winapi::um::memoryapi::VirtualProtect;
use winapi::um::winnt::{PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_READ};

use crate::internal::stub::{G_STUB_POOL, STUB_SIZE};
use crate::printdev;

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
    /// Syscall service number (SSN)
    pub syscall_id: u32,
    /// Number of arguments to pass (max: 16)
    pub arg_count: usize,
    /// Argument buffer (max 16 registers)
    pub args: [usize; 16],
    /// Return value from the syscall
    pub ret: usize,
}
impl Default for ABOpFrame {
    fn default() -> Self {
        Self { status: AtomicU32::new(0), syscall_id: 0, arg_count: 0, args: [0; 16], ret: 0 }
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
    usize, usize, usize, usize, usize, usize, usize, usize,
    usize, usize, usize, usize, usize, usize, usize, usize,
) -> usize;

/// Shared global operation frame, uninitialized until dispatcher starts.
pub static mut G_OPFRAME: MaybeUninit<ABOpFrame> = MaybeUninit::uninit();
pub static        G_READY:  AtomicBool          = AtomicBool::new(false);

#[inline(always)] fn cpu_pause() { unsafe { core::arch::asm!("pause", options(nomem, nostack)); } }

/// Syscall dispatcher thread entrypoint.
///
/// This function spins indefinitely, polling `G_OPFRAME` and processing
/// syscall requests by acquiring, decrypting, patching, and invoking a stub.
///
/// # Safety
/// This function must only be launched **once**.
/// It assumes `G_OPFRAME` is uninitialized and will remain in memory.
///
pub unsafe extern "system" fn thread_proc(_: *mut winapi::ctypes::c_void) -> u32 {
    G_OPFRAME.write(ABOpFrame::default());
    G_READY.store(true, Ordering::Release);
    printdev!("opframe initialized, ready flag set");

    let frame = &mut *G_OPFRAME.as_mut_ptr();
    let mut spin = 0;

    loop {
        while frame.status.load(Ordering::Acquire) != 1 {
            spin += 1;
            match spin {
                0..=64   => cpu_pause(),                // fast wait
                65..=256 => std::thread::yield_now(),   // let scheduler breathe
                _        => std::thread::sleep(std::time::Duration::from_micros(50)),
            }
        }
        spin = 0;

        let stub = match G_STUB_POOL.acquire() {
            Some(p) if !p.is_null() => p,
            _ => { printdev!("stub pool empty"); continue; }
        };
        if stub as usize & 15 != 0 { printdev!("stub misaligned"); G_STUB_POOL.release(stub); continue; }

        let ssn_ptr = stub.add(4) as *mut u32;
        let mut old = 0;
        if VirtualProtect(stub as _, STUB_SIZE, PAGE_EXECUTE_READWRITE, &mut old) == 0 {
            printdev!("RWX fail"); G_STUB_POOL.release(stub); continue;
        }
        ssn_ptr.write_volatile(frame.syscall_id);
        VirtualProtect(stub as _, STUB_SIZE, PAGE_EXECUTE_READ, &mut old);

        let fn_ptr: ABStubFn = std::mem::transmute(stub);
        let mut regs = [0usize; 16];
        regs[..frame.arg_count].copy_from_slice(&frame.args[..frame.arg_count]);

        let ret = fn_ptr(
            regs[0], regs[1], regs[2], regs[3], regs[4], regs[5], regs[6], regs[7], regs[8], regs[9], regs[10], regs[11], regs[12], regs[13], regs[14], regs[15],
        );

        std::sync::atomic::fence(Ordering::SeqCst);   // ensure `ret` is visible first
        frame.ret = ret;
        frame.status.store(2, Ordering::Release);

        G_STUB_POOL.release(stub);
    }
}