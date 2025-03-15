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
use std::ffi::c_void;
use winapi::um::handleapi::CloseHandle;
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winbase::INFINITE;
use winapi::um::processthreadsapi::CreateThread;

#[link_section = ".CRT$XLU"]
#[used]
static TLS_CALLBACK: extern "system" fn(*mut c_void, u32, *mut c_void) = tls_callback;

extern "system" fn tls_callback(_hModule: *mut c_void, reason: u32, _reserved: *mut c_void) {
    if reason == winapi::um::winnt::DLL_PROCESS_ATTACH {
        unsafe {
            ActiveBreach_launch();
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn ActiveBreach_launch() {
    let mut ab_handle_size: usize = 0;
    let mapped_base = internal::file_buffer::buffer(&mut ab_handle_size);
    let syscall_table = internal::exports::extract_ssn(mapped_base);

    internal::file_buffer::zero_and_free(mapped_base, ab_handle_size);

    let mut ab_internal = internal::gadget::ActiveBreachInternal::new();
    ab_internal.build_gadgets(&syscall_table);

    internal::dispatcher::G_AB_INITIALIZED_EVENT = winapi::um::synchapi::CreateEventA(null_mut(), true as i32, false as i32, null());
    if internal::dispatcher::G_AB_INITIALIZED_EVENT.is_null() {
        internal::error::fatal_err("Failed to create initialization event");
    }
    let hThread = CreateThread(
        null_mut(),
        0,
        Some(internal::dispatcher::thread_proc),
        null_mut(),
        0,
        null_mut(),
    );
    if hThread.is_null() {
        internal::error::fatal_err("Failed to create ActiveBreach dispatcher thread");
    }
    WaitForSingleObject(internal::dispatcher::G_AB_INITIALIZED_EVENT, INFINITE);
    CloseHandle(internal::dispatcher::G_AB_INITIALIZED_EVENT);
    internal::dispatcher::G_AB_INITIALIZED_EVENT = null_mut();
    CloseHandle(hThread);
}

#[no_mangle]
pub unsafe extern "C" fn ab_call(gadget: *mut c_void, args: *const usize, arg_count: usize) -> usize {
    if gadget.is_null() {
        panic!("ab_call: gadget is NULL");
    }
    if arg_count > 8 {
        panic!("ab_call: Too many arguments (max 8)");
    }
    if args.is_null() {
        panic!("ab_call: args is NULL");
    }

    let args_slice = std::slice::from_raw_parts(args, arg_count);

    let mut req = internal::dispatcher::ABCallRequest {
        stub: gadget,
        arg_count,
        args: [0; 8],
        ret: 0,
        complete: winapi::um::synchapi::CreateEventA(null_mut(), true as i32, false as i32, null()),
    };
    req.args[..arg_count].copy_from_slice(args_slice);

    {
        let mut guard = internal::dispatcher::G_AB_CALL_REQUEST.lock().unwrap();
        *guard = req.clone();
    }
    winapi::um::synchapi::SetEvent(internal::dispatcher::G_AB_CALL_EVENT);

    let complete_handle = req.complete;
    WaitForSingleObject(complete_handle, INFINITE);
    CloseHandle(complete_handle);

    let ret_val = {
        let guard = internal::dispatcher::G_AB_CALL_REQUEST.lock().unwrap();
        guard.ret
    };
    ret_val
}