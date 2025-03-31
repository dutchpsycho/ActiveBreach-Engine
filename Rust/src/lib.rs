/*
* ==================================================================================
*  Repository:   Syscall Proxy
*  Project:      ActiveBreach
*  File:         lib.rs
*  Author:       CrisisEvasion
*  Organization: TITAN Softwork Solutions
*  Inspired by:  MDSEC Research
*
*  Description:
*      ActiveBreach is a syscall abstraction layer that dynamically proxies syscalls
*      by extracting system service numbers (SSNs) from ntdll.dll and locating valid
*      syscall prologue gadgets from within the hooked ntdll. When a ab_call is made via
*      the dispatcher, the ab_call is ROP-chained through the located gadget, so that
*      the syscall appears to originate from ntdll.
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
#![allow(non_camel_case_types)]

mod internal;

use std::ffi::CString;
use std::ptr::{null, null_mut};

use winapi::um::handleapi::CloseHandle;
use winapi::um::synchapi::{WaitForSingleObject, CreateEventA, SetEvent};
use winapi::um::winbase::INFINITE;
use winapi::um::processthreadsapi::CreateThread;

/// Launch the ActiveBreach subsystem — loads NTDLL, extracts syscalls, spins dispatcher.
pub fn activebreach_launch() {
    unsafe {
        let mut ab_handle_size: usize = 0;

        let mapped_base = internal::file_buffer::buffer(&mut ab_handle_size);
        internal::exports::extract_syscalls(mapped_base as *const u8, ab_handle_size);

        let hThread = CreateThread(
            null_mut(),
            0,
            Some(internal::dispatch::thread_proc),
            null_mut(),
            0,
            null_mut(),
        );

        if hThread.is_null() {
            internal::err::fatal_err("failed to create dispatcher thread");
        }

        internal::file_buffer::zero_and_free(mapped_base as *mut _, ab_handle_size);
        CloseHandle(hThread);
    }
}

/// Perform a syscall by name + argument list
///
/// Example:
/// ```rust
/// let ret = activebreach::ab_call("NtProtectVirtualMemory", &[arg1, arg2, arg3]);
/// ```
pub fn ab_call(syscall_name: &str, args: &[usize]) -> usize {
    if args.len() > 16 {
        panic!("too many syscall arguments");
    }

    let found = internal::exports::SYSCALL_TABLE
        .get()
        .map_or(false, |tbl| tbl.contains_key(syscall_name));

    if !found {
        panic!("ab_call: syscall '{}' not found", syscall_name);
    }

    let mut syscall_name_buf = [0u8; 64];
    let name_bytes = syscall_name.as_bytes();

    if name_bytes.len() >= 64 {
        panic!("ab_call: syscall name too long");
    }

    syscall_name_buf[..name_bytes.len()].copy_from_slice(name_bytes);

    let mut req = internal::dispatch::ABCallRequest {
        syscall_name: syscall_name_buf,
        arg_count: args.len(),
        args: [0; 16],
        ret: 0,
        complete: unsafe {
            CreateEventA(null_mut(), 1, 0, null())
        },
    };

    req.args[..args.len()].copy_from_slice(args);

    {
        let mut guard = internal::dispatch::G_AB_CALL_REQUEST.lock().unwrap();
        *guard = req.clone();
    }

    unsafe {
        SetEvent(internal::dispatch::G_AB_CALL_EVENT);
        WaitForSingleObject(req.complete, INFINITE);
        CloseHandle(req.complete);
    }

    let guard = internal::dispatch::G_AB_CALL_REQUEST.lock().unwrap();
    guard.ret
}