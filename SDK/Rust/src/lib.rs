/*!
 * ==================================================================================
 *  Repository:   https://github.com/8damon/ActiveBreach-Engine
 *  Project:      ActiveBreach (ABE)
 *  File:         lib.rs
 *  Author:       8damon
 *  Organization: TITAN Softwork Solutions
 *
 *  License:      “Commons Clause” License Condition v1.0 Apache License
 *  Copyright:    (C) 2026 TITAN Softwork Solutions. All rights reserved.
 *
 *  Licensing Terms:
 *  ----------------------------------------------------------------------------------
 *   - You are free to use, modify, and share this software.
 *   - Commercial use is strictly prohibited.
 *   - Proper credit must be given to TITAN Softwork Solutions.
 *   - Modifications must be clearly documented.
 *   - This software is provided "as-is" without warranties of any kind.
 *
 *  Full License: <https://creativecommons.org/licenses/by-nc/4.0/>
 * ==================================================================================
 */

#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(static_mut_refs)]
#![allow(non_upper_case_globals)]

pub mod internal;

pub use internal::antibreach::{ViolationHandler, ViolationType};

use crate::internal::diagnostics::*;
use crate::internal::dispatch::{AbFire, G_READY};
use core::ffi::c_void;

use windows::Win32::System::Threading::{WaitOnAddress, WakeByAddressSingle, INFINITE};

type BOOL = i32;

use std::ptr;

/// Returns the number of AntiBreach-style violations detected by the Rust dispatcher.
pub fn ab_violation_count() -> u32 {
    internal::antibreach::AbViolationCount()
}

/// Registers a global violation handler that will be invoked on each violation.
pub fn ab_set_violation_handler(handler: ViolationHandler) {
    internal::antibreach::AbRegisterViolationHandler(handler);
}

/// Clears the currently registered violation handler.
pub fn ab_clear_violation_handler() {
    internal::antibreach::AbClearViolationHandler();
}

/// Sets the long-sleep idle timeout in milliseconds (default: 30_000ms).
///
/// Only has effect when built with `--features long_sleep`.
#[cfg(feature = "long_sleep")]
pub fn ab_set_long_sleep_idle_ms(ms: u64) {
    internal::dispatch::AbSetLongSleepIdleMs(ms);
}

/// Launches the ActiveBreach syscall dispatcher thread and loads the syscall table.
///
/// This function performs the following:
/// - Maps a clean copy of `ntdll.dll` from `System32`
/// - Extracts syscall service numbers (SSNs) for `Nt*` exports
/// - Spawns a syscall dispatcher thread that listens for `ab_call()` invocations
/// - Ensures proper cleanup of temporary file resources
///
/// # Returns
/// - `Ok(())` if everything initializes successfully
/// - `Err(&str)` if mapping or thread creation fails
///
/// # Safety
/// This function performs raw memory access, Windows API interaction, and spawns unmanaged threads.
/// Caller must ensure the environment is suitable (e.g., not already launched).
///
/// # Example
/// ```ignore
/// unsafe {
///     activebreach_launch().expect("failed to init");
/// }
/// ```
pub unsafe fn activebreach_launch() -> Result<(), u32> {
    internal::thread::AbSpawnActiveBreachThread()
}

/// Issues a native system call via ActiveBreach by syscall name and arguments.
///
/// This queues a call into the global `ABOpFrame` and blocks until completion.
/// The actual syscall is issued via a custom RWX trampoline stub in memory,
/// with runtime encryption/decryption of stub memory for stealth.
///
/// # Arguments
/// - `name`: Name of the NT syscall, e.g. `"NtOpenProcess"`
/// - `args`: Slice of up to 16 `usize` arguments
///
/// # Returns
/// - `usize`: Result of the syscall (typically NTSTATUS or handle)
///
/// # Panics
/// - If the syscall name is longer than 64 bytes
/// - If more than 16 arguments are passed
/// - If the syscall dispatcher has not been launched
/// - If the syscall name is not found in the runtime table
///
/// # Safety
/// This function performs low-level system call execution. Callers are responsible for
/// providing correct arguments and ensuring system stability.
///
/// # Example
/// ```ignore
/// unsafe {
///     let h = ab_call("NtGetCurrentProcessorNumber", &[]);
///     println!("CPU: {h}");
/// }
/// ```
pub unsafe fn ab_call(name: &str, args: &[usize]) -> usize {
    if name.len() >= 64 {
        return AbErr(ABError::DispatchNameTooLong) as usize;
    }

    if args.len() > 16 {
        return AbErr(ABError::DispatchArgTooMany) as usize;
    }

    while !G_READY.load(std::sync::atomic::Ordering::Acquire) {
        let zero: u8 = 0;

        let ready_ptr: *const std::sync::atomic::AtomicBool =
            &G_READY as *const std::sync::atomic::AtomicBool;
        let zero_ptr: *const u8 = &zero as *const u8;

        let _ = WaitOnAddress(
            ready_ptr as *const c_void,
            zero_ptr as *const c_void,
            std::mem::size_of::<u8>(),
            Some(INFINITE),
        );
    }

    AbFire(name, args)
}
