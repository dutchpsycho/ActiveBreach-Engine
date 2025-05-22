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

use crate::internal::stub::G_STUB_POOL;
use crate::internal::stub::STUB_SIZE;
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
        Self {
            status: AtomicU32::new(0),
            syscall_id: 0,
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
    usize, usize, usize, usize, usize, usize, usize, usize,
    usize, usize, usize, usize, usize, usize, usize, usize,
) -> usize;

/// Shared global operation frame, uninitialized until dispatcher starts.
pub static mut G_OPFRAME: MaybeUninit<ABOpFrame> = MaybeUninit::uninit();

/// Whether the dispatcher thread has been started and is ready.
pub static G_READY: AtomicBool = AtomicBool::new(false);

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

    loop {
        if frame.status.load(Ordering::Acquire) != 1 {
            std::thread::yield_now();
            continue;
        }

        let stub = match G_STUB_POOL.acquire() {
            Some(ptr) if !ptr.is_null() => ptr,
            _ => {
                printdev!("failed to acquire stub — skipping frame");
                continue;
            }
        };

        if stub as usize % 16 != 0 {
            printdev!("stub alignment fail: {:p}", stub);
            G_STUB_POOL.release(stub);
            continue;
        }

        let ssn_ptr = stub.add(4) as *mut u32;
        if ssn_ptr.is_null() {
            printdev!("invalid SSN ptr (null)");
            G_STUB_POOL.release(stub);
            continue;
        }

        let mut old = 0;
        if VirtualProtect(stub as _, STUB_SIZE, PAGE_EXECUTE_READWRITE, &mut old) == 0 {
            printdev!("failed to set stub RWX before SSN write");
            G_STUB_POOL.release(stub);
            continue;
        }

        // printdev!("stub RWX set — writing syscall ID: {}", frame.syscall_id);

        ssn_ptr.write_volatile(frame.syscall_id);

        if VirtualProtect(stub as _, STUB_SIZE, PAGE_EXECUTE_READ, &mut old) == 0 {
            printdev!("failed to restore stub RX after SSN write");
        }

        let fn_ptr: ABStubFn = std::mem::transmute(stub);

        let mut padded = [0usize; 16];
        padded[..frame.arg_count].copy_from_slice(&frame.args[..frame.arg_count]);

        // printdev!("executing syscall stub with {} args", frame.arg_count);

        let ret = fn_ptr(
            padded[0], padded[1], padded[2], padded[3],
            padded[4], padded[5], padded[6], padded[7],
            padded[8], padded[9], padded[10], padded[11],
            padded[12], padded[13], padded[14], padded[15],
        );

        // printdev!("syscall returned: 0x{:X}", ret);

        frame.ret = ret;
        frame.status.store(2, Ordering::Release);

        G_STUB_POOL.release(stub);
    }
}