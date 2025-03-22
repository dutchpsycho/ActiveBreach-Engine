#![cfg(windows)]
#![allow(non_snake_case)]

use std::ffi::CString;
use std::ptr::null_mut;
use std::thread::sleep;
use std::time::Duration;

use winapi::shared::minwindef::{ULONG, FARPROC};
use winapi::um::libloaderapi::{LoadLibraryA, GetProcAddress};

type AbCallFn = unsafe extern "C" fn(*const u8, *const usize, usize) -> usize;

const SYSTEM_PROCESS_INFORMATION: u32 = 5;

fn main() {
    unsafe {
        let ab_dll = LoadLibraryA(b"ActiveBreach.dll\0".as_ptr() as *const i8);
        if ab_dll.is_null() {
            println!("Failed to load ActiveBreach.dll (Is it compiled?)");
            return;
        }

        // re-added delay to let ActiveBreach system spin up
        sleep(Duration::from_millis(250));

        let ab_call_ptr = GetProcAddress(ab_dll, b"ab_call\0".as_ptr() as *const i8);
        if ab_call_ptr.is_null() {
            println!("Failed to resolve ab_call export");
            return;
        }

        let ab_call: AbCallFn = std::mem::transmute::<FARPROC, AbCallFn>(ab_call_ptr);

        let syscall_name = CString::new("NtQuerySystemInformation").unwrap();

        let mut return_len: ULONG = 0;
        let args_probe: [usize; 4] = [
            SYSTEM_PROCESS_INFORMATION as usize,
            null_mut::<u8>() as usize,
            0,
            &mut return_len as *mut _ as usize,
        ];

        let probe_status = ab_call(syscall_name.as_ptr() as *const u8, args_probe.as_ptr(), args_probe.len());

        if probe_status != 0xC0000004 {
            println!("Probe call failed -> 0x{:X}", probe_status);
            return;
        }

        let mut buffer = vec![0u8; return_len as usize];
        let args: [usize; 4] = [
            SYSTEM_PROCESS_INFORMATION as usize,
            buffer.as_mut_ptr() as usize,
            buffer.len(),
            &mut return_len as *mut _ as usize,
        ];

        let status = ab_call(syscall_name.as_ptr() as *const u8, args.as_ptr(), args.len());

        if status == 0 {
            println!("Syscall succeeded");
            println!("Return len: {}", return_len);
        } else {
            println!("Syscall failed -> 0x{:X}", status);
        }
    }
}