/*
* ==================================================================================
*  Repository:   Syscall Proxy
*  Project:      ActiveBreach
*  File:         dispatcher.rs
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

use std::ptr::{null_mut, null};
use std::sync::Mutex;
use std::ffi::c_void;

use winapi::um::winbase::INFINITE;
use winapi::um::handleapi::CloseHandle;
use winapi::um::synchapi::{CreateEventA, SetEvent, WaitForSingleObject};
use winapi::shared::minwindef::{DWORD, FALSE};
use winapi::um::processthreadsapi::CreateThread;

use std::mem::transmute;
use lazy_static::lazy_static;

use crate::internal::error::fatal_err;

#[derive(Clone)]
#[repr(C)]
pub struct ABCallRequest {
    pub stub: *mut c_void,
    pub arg_count: usize,
    pub args: [usize; 8],
    pub ret: usize,
    pub complete: winapi::shared::ntdef::HANDLE,
}

impl Default for ABCallRequest {
    fn default() -> Self {
        Self {
            stub: null_mut(),
            arg_count: 0,
            args: [0; 8],
            ret: 0,
            complete: null_mut(),
        }
    }
}

unsafe impl Send for ABCallRequest {}

lazy_static! {
    pub static ref G_AB_CALL_REQUEST: Mutex<ABCallRequest> = Mutex::new(ABCallRequest::default());
}

pub static mut G_AB_CALL_EVENT: winapi::shared::ntdef::HANDLE = null_mut();
pub static mut G_AB_INITIALIZED_EVENT: winapi::shared::ntdef::HANDLE = null_mut();

pub type ABStubFn = unsafe extern "system" fn(
    usize, usize, usize, usize, usize, usize, usize, usize
) -> usize;

pub unsafe extern "system" fn dispatcher(_lpParameter: *mut c_void) -> DWORD {
    if G_AB_CALL_EVENT.is_null() {
        fatal_err("Dispatcher event not created");
    }
    loop {
        WaitForSingleObject(G_AB_CALL_EVENT, INFINITE);
        let req = {
            let guard = G_AB_CALL_REQUEST.lock().unwrap();
            guard.clone()
        };
        let fn_ptr: ABStubFn = transmute(req.stub);
        let ret = match req.arg_count {
            0 => fn_ptr(0, 0, 0, 0, 0, 0, 0, 0),
            1 => fn_ptr(req.args[0], 0, 0, 0, 0, 0, 0, 0),
            2 => fn_ptr(req.args[0], req.args[1], 0, 0, 0, 0, 0, 0),
            3 => fn_ptr(req.args[0], req.args[1], req.args[2], 0, 0, 0, 0, 0),
            4 => fn_ptr(req.args[0], req.args[1], req.args[2], req.args[3], 0, 0, 0, 0),
            5 => fn_ptr(req.args[0], req.args[1], req.args[2], req.args[3], req.args[4], 0, 0, 0),
            6 => fn_ptr(req.args[0], req.args[1], req.args[2], req.args[3], req.args[4], req.args[5], 0, 0),
            7 => fn_ptr(req.args[0], req.args[1], req.args[2], req.args[3], req.args[4], req.args[5], req.args[6], 0),
            8 => fn_ptr(req.args[0], req.args[1], req.args[2], req.args[3], req.args[4], req.args[5], req.args[6], req.args[7]),
            _ => fatal_err("Invalid argument count in call dispatcher"),
        };
        {
            let mut guard = G_AB_CALL_REQUEST.lock().unwrap();
            guard.ret = ret;
        }
        SetEvent(req.complete);
    }
}

pub unsafe extern "system" fn thread_proc(_lp_param: *mut winapi::ctypes::c_void) -> u32 {
    G_AB_CALL_EVENT = CreateEventA(null_mut(), FALSE, false as i32, null());
    if G_AB_CALL_EVENT.is_null() {
        fatal_err("Failed to create dispatcher event");
    }
    if !G_AB_INITIALIZED_EVENT.is_null() {
        SetEvent(G_AB_INITIALIZED_EVENT);
    }
    dispatcher(null_mut())
}