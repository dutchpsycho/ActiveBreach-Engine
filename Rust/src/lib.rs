/*!
 * ==================================================================================
 *  Repository:   Syscall Proxy
 *  Project:      ActiveBreach
 *  File:         lib.rs
 *  Author:       CrisisEvasion
 *  Organization: TITAN Softwork Solutions
 *  Inspired by:  MDSEC Research
 *
 *  Description:
 *      ActiveBreach is a high-performance syscall proxy framework that enables
 *      indirect invocation of native NT system calls from usermode. It uses a
 *      ring-buffer of preallocated encrypted syscall stubs, dispatched through
 *      a usermode-only shared memory control block (`ABOpFrame`), avoiding all
 *      kernel object synchronization and WinAPI usage.
 *      System service numbers (SSNs) are dynamically extracted from a memory-mapped
 *      copy of `ntdll.dll`, and used to patch per-call trampolines in memory.
 *      Each stub is encrypted at rest using a hardware-derived, runtime-only
 *      LEA cipher variant, obfuscating opcodes and evading static memory scans
 *      (YARA/SIGMA). During execution, stubs are decrypted, the SSN is written,
 *      and the syscall is issued via a minimal inline stub.
 *      The result is a highly stealthy syscall abstraction layer optimized for
 *      evasion, speed, and dynamic reuse without persistent footprint.
 *
 *  License:      Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)
 *  Copyright:    (C) 2025 TITAN Softwork Solutions. All rights reserved.
 *
 *  Licensing Terms:
 *  ----------------------------------------------------------------------------------
 *   - You are free to use, modify, and share this software.
 *   - Commercial use is strictly prohibited.
 *   - Proper credit must be given to TITAN Softwork Solutions.
 *   - Modifications must be clearly documented.
 *   - This software is provided "as-is" without warranties of any kind.
 *
 *  Full License: https://creativecommons.org/licenses/by-nc/4.0/
 * ==================================================================================
 */

#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(static_mut_refs)]
#![allow(non_upper_case_globals)]
 
pub mod internal;

use crate::internal::diagnostics::*;

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
    internal::thread::spawn_ab_thread()
}

/// Issues a native system call via ActiveBreach by syscall name and arguments.
///
/// This queues a call into the global [`ABOpFrame`] and blocks until completion.
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
        return AB_DISPATCH_NAME_TOO_LONG as usize;
    }
    if args.len() > 16 {
        return AB_DISPATCH_ARG_TOO_MANY as usize;
    }

    // Wait until dispatcher thread signals readiness
    while !internal::dispatch::G_READY.load(std::sync::atomic::Ordering::Acquire) {
        std::thread::yield_now();
    }

    let tbl = match internal::exports::SYSCALL_TABLE.get() {
        Some(t) => t,
        None => return AB_DISPATCH_TABLE_MISSING as usize,
    };

    let ssn = match tbl.get(name) {
        Some(n) => *n,
        None => return AB_DISPATCH_SYSCALL_MISSING as usize,
    };

    let op = internal::dispatch::G_OPFRAME.as_mut_ptr();
    let frame = &mut *op;

    // Wait until the frame is free (status == 0)
    while frame.status.load(std::sync::atomic::Ordering::Acquire) != 0 {
        std::thread::yield_now();
    }

    frame.syscall_id = ssn;
    frame.arg_count = args.len();
    frame.args[..args.len()].copy_from_slice(args);
    frame.status.store(1, std::sync::atomic::Ordering::Release);

    // Wait for dispatcher to process the syscall (status == 2)
    while frame.status.load(std::sync::atomic::Ordering::Acquire) != 2 {
        std::thread::yield_now();
    }

    let ret = frame.ret;
    frame.status.store(0, std::sync::atomic::Ordering::Release);

    ret
}