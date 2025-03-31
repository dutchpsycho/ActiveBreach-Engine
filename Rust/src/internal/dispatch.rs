use std::ptr::{null_mut, null};
use std::mem::transmute;
use std::sync::Mutex;
use std::ffi::c_void;
use std::sync::Arc;

use winapi::um::winbase::INFINITE;
use winapi::um::synchapi::{CreateEventA, SetEvent, WaitForSingleObject};
use winapi::shared::minwindef::{DWORD, FALSE};
use winapi::um::winnt::PAGE_EXECUTE_READWRITE;

use lazy_static::lazy_static;

use crate::internal::err::fatal_err;
use crate::internal::stub::{G_STUB_POOL, StubPool};

#[derive(Clone)]
#[repr(C)]
pub struct ABCallRequest {
    pub syscall_name: [u8; 64],
    pub arg_count: usize,
    pub args: [usize; 16], // updated from 8 to 16
    pub ret: usize,
    pub complete: winapi::shared::ntdef::HANDLE,
}

impl Default for ABCallRequest {
    fn default() -> Self {
        Self {
            syscall_name: [0u8; 64],
            arg_count: 0,
            args: [0; 16], // updated from 8 to 16
            ret: 0,
            complete: null_mut(),
        }
    }
}

unsafe impl Send for ABCallRequest {}

lazy_static! {
    pub static ref G_AB_CALL_REQUEST: Mutex<ABCallRequest> = Mutex::new(ABCallRequest::default());
}

use std::sync::atomic::{AtomicBool, Ordering};

pub static G_AB_READY: AtomicBool = AtomicBool::new(false);

pub static mut G_AB_CALL_EVENT: winapi::shared::ntdef::HANDLE = null_mut();
pub static mut G_AB_INITIALIZED_EVENT: winapi::shared::ntdef::HANDLE = null_mut();

// updated function pointer type to support 16 parameters
pub type ABStubFn = unsafe extern "system" fn(
    usize, usize, usize, usize, usize, usize, usize, usize,
    usize, usize, usize, usize, usize, usize, usize, usize
) -> usize;

pub unsafe extern "system" fn dispatcher(_lp: *mut c_void) -> DWORD {
    if G_AB_CALL_EVENT.is_null() {
        fatal_err("dispatcher event not created");
    }

    loop {
        if WaitForSingleObject(G_AB_CALL_EVENT, INFINITE) != 0 {
            fatal_err("dispatcher: wait failed");
        }

        let req = {
            let guard = G_AB_CALL_REQUEST.lock().unwrap();
            guard.clone()
        };

        let syscall_name = match std::str::from_utf8(&req.syscall_name) {
            Ok(s) => s.trim_end_matches('\0'),
            Err(_) => fatal_err("dispatcher: invalid UTF-8 in syscall name"),
        };

        let ssn = match crate::internal::exports::SYSCALL_TABLE.get() {
            Some(tbl) => match tbl.get(syscall_name) {
                Some(ssn) => *ssn,
                None => fatal_err("dispatcher: syscall not found"),
            },
            None => fatal_err("dispatcher: syscall table uninitialized"),
        };

        let stub = {
            let mut pool = G_STUB_POOL.lock().unwrap();
            let stub = pool.acquire().unwrap_or_else(|| fatal_err("dispatcher: no available stub"));

            if stub.is_null() {
                fatal_err("dispatcher: acquired null stub pointer");
            }

            let mut old_protect = 0;
            if winapi::um::memoryapi::VirtualProtect(
                stub as _,
                32,
                PAGE_EXECUTE_READWRITE,
                &mut old_protect,
            ) == 0 {
                fatal_err("dispatcher: failed to make stub RWX");
            }

            stub
        };

        let ssn_ptr = stub.add(4) as *mut u32;
        if ssn_ptr.is_null() {
            fatal_err("dispatcher: invalid SSN injection address");
        }
        ssn_ptr.write_volatile(ssn);

        let fn_ptr: ABStubFn = match std::panic::catch_unwind(|| transmute::<*mut u8, ABStubFn>(stub)) {
            Ok(f) => f,
            Err(_) => fatal_err("dispatcher: failed to cast stub to function"),
        };

        let ret = match req.arg_count {
            0 => fn_ptr(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
            1 => fn_ptr(req.args[0], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
            2 => fn_ptr(req.args[0], req.args[1], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
            3 => fn_ptr(req.args[0], req.args[1], req.args[2], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
            4 => fn_ptr(req.args[0], req.args[1], req.args[2], req.args[3], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
            5 => fn_ptr(req.args[0], req.args[1], req.args[2], req.args[3], req.args[4], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
            6 => fn_ptr(req.args[0], req.args[1], req.args[2], req.args[3], req.args[4], req.args[5], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
            7 => fn_ptr(req.args[0], req.args[1], req.args[2], req.args[3], req.args[4], req.args[5], req.args[6], 0, 0, 0, 0, 0, 0, 0, 0, 0),
            8 => fn_ptr(req.args[0], req.args[1], req.args[2], req.args[3], req.args[4], req.args[5], req.args[6], req.args[7],
                      0, 0, 0, 0, 0, 0, 0, 0),
            9 => fn_ptr(req.args[0], req.args[1], req.args[2], req.args[3], req.args[4], req.args[5], req.args[6], req.args[7],
                      req.args[8], 0, 0, 0, 0, 0, 0, 0),
            10 => fn_ptr(req.args[0], req.args[1], req.args[2], req.args[3], req.args[4], req.args[5], req.args[6], req.args[7],
                       req.args[8], req.args[9], 0, 0, 0, 0, 0, 0),
            11 => fn_ptr(req.args[0], req.args[1], req.args[2], req.args[3], req.args[4], req.args[5], req.args[6], req.args[7],
                       req.args[8], req.args[9], req.args[10], 0, 0, 0, 0, 0),
            12 => fn_ptr(req.args[0], req.args[1], req.args[2], req.args[3], req.args[4], req.args[5], req.args[6], req.args[7],
                       req.args[8], req.args[9], req.args[10], req.args[11], 0, 0, 0, 0),
            13 => fn_ptr(req.args[0], req.args[1], req.args[2], req.args[3], req.args[4], req.args[5], req.args[6], req.args[7],
                       req.args[8], req.args[9], req.args[10], req.args[11], req.args[12], 0, 0, 0),
            14 => fn_ptr(req.args[0], req.args[1], req.args[2], req.args[3], req.args[4], req.args[5], req.args[6], req.args[7],
                       req.args[8], req.args[9], req.args[10], req.args[11], req.args[12], req.args[13], 0, 0),
            15 => fn_ptr(req.args[0], req.args[1], req.args[2], req.args[3], req.args[4], req.args[5], req.args[6], req.args[7],
                       req.args[8], req.args[9], req.args[10], req.args[11], req.args[12], req.args[13], req.args[14], 0),
            16 => fn_ptr(req.args[0], req.args[1], req.args[2], req.args[3], req.args[4], req.args[5], req.args[6], req.args[7],
                       req.args[8], req.args[9], req.args[10], req.args[11], req.args[12], req.args[13], req.args[14], req.args[15]),
            _ => fatal_err("dispatcher: invalid argument count"),
        };

        {
            let mut guard = G_AB_CALL_REQUEST.lock().unwrap();
            guard.ret = ret;
        }

        {
            let mut pool = G_STUB_POOL.lock().unwrap();
            pool.release(stub);
        }

        SetEvent(req.complete);
    }
}

pub unsafe extern "system" fn thread_proc(_: *mut winapi::ctypes::c_void) -> u32 {
    G_AB_CALL_EVENT = CreateEventA(null_mut(), FALSE, false as i32, null());
    if G_AB_CALL_EVENT.is_null() {
        fatal_err("failed to create dispatcher event");
    }

    G_AB_READY.store(true, Ordering::Release);

    dispatcher(null_mut())
}