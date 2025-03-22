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
*      syscall prologue gadgets from within the hooked ntdll. When a call is made via
*      the dispatcher, the call is ROP-chained through the located gadget, so that
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

use std::ptr::{null, null_mut};
use std::ffi::{c_void, CStr};
use std::os::raw::c_char;

use winapi::um::handleapi::CloseHandle;
use winapi::um::synchapi::{WaitForSingleObject, CreateEventA, SetEvent};
use winapi::um::winbase::INFINITE;
use winapi::um::processthreadsapi::CreateThread;

#[link_section = ".CRT$XLU"]
#[used]
static TLS_CALLBACK: extern "system" fn(*mut c_void, u32, *mut c_void) = tls_callback;

extern "system" fn tls_callback(_hModule: *mut c_void, reason: u32, _reserved: *mut c_void) {
    if reason == winapi::um::winnt::DLL_PROCESS_ATTACH {
        unsafe {
            CreateThread(
                null_mut(),
                0,
                Some(tls_launch_shim),
                null_mut(),
                0,
                null_mut(),
            );
        }
    }
}

unsafe extern "system" fn tls_launch_shim(_: *mut winapi::ctypes::c_void) -> u32 {
    ActiveBreach_launch();
    0
}

#[no_mangle]
pub unsafe extern "C" fn ActiveBreach_launch() {
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

#[no_mangle]
pub unsafe extern "C" fn ab_call(syscall_name: *const u8, args: *const usize, arg_count: usize) -> usize {
    if syscall_name.is_null() {
        panic!("ab_call: syscall name is null");
    }

    if arg_count > 8 {
        panic!("ab_call: too many arguments");
    }

    if args.is_null() {
        panic!("ab_call: args is null");
    }

    let name = match CStr::from_ptr(syscall_name as *const c_char).to_str() {
        Ok(s) => s,
        Err(_) => panic!("ab_call: invalid syscall name"),
    };

    let found = internal::exports::SYSCALL_TABLE
        .get()
        .map_or(false, |tbl| tbl.contains_key(name));

    if !found {
        panic!("ab_call: syscall '{}' not found", name);
    }

    let args_slice = std::slice::from_raw_parts(args, arg_count);

    let mut syscall_name_buf = [0u8; 64];
    let name_bytes = name.as_bytes();

    if name_bytes.len() >= 64 {
        panic!("ab_call: syscall name too long");
    }

    syscall_name_buf[..name_bytes.len()].copy_from_slice(name_bytes);

    let mut req = internal::dispatch::ABCallRequest {
        syscall_name: syscall_name_buf,
        arg_count,
        args: [0; 8],
        ret: 0,
        complete: CreateEventA(null_mut(), 1, 0, null()),
    };

    req.args[..arg_count].copy_from_slice(args_slice);

    {
        let mut guard = internal::dispatch::G_AB_CALL_REQUEST.lock().unwrap();
        *guard = req.clone();
    }

    SetEvent(internal::dispatch::G_AB_CALL_EVENT);

    WaitForSingleObject(req.complete, INFINITE);
    CloseHandle(req.complete);

    let guard = internal::dispatch::G_AB_CALL_REQUEST.lock().unwrap();

    guard.ret
}