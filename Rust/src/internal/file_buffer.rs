use std::ffi::{OsString, OsStr};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::ptr::{null, null_mut};
use winapi::um::fileapi::{CreateFileW, GetFileSize, ReadFile, OPEN_EXISTING};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::memoryapi::{VirtualAlloc, VirtualFree};
use winapi::shared::minwindef::{DWORD, UINT, MAX_PATH};
use winapi::um::winnt::{FILE_ATTRIBUTE_NORMAL, GENERIC_READ, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, MEM_RELEASE};
use winapi::um::sysinfoapi::GetSystemDirectoryW;
use crate::internal::encryption;
use crate::internal::error::fatal_err;

pub unsafe fn buffer(out_size: &mut usize) -> *mut winapi::ctypes::c_void {
    let mut system_dir: [u16; MAX_PATH] = [0; MAX_PATH];

    if GetSystemDirectoryW(system_dir.as_mut_ptr(), MAX_PATH as UINT) == 0 {
        fatal_err("Failed to retrieve the system directory");
    }

    let decoded = encryption::decode();
    
    let system_dir_str = OsString::from_wide(
        &system_dir[..system_dir.iter().position(|&c| c == 0).unwrap_or(system_dir.len())],
    );
    let decoded_str = OsString::from_wide(
        &decoded[..decoded.iter().position(|&c| c == 0).unwrap_or(decoded.len())],
    );

    let path = format!("{}\\{}", system_dir_str.to_string_lossy(), decoded_str.to_string_lossy());
    let path_w: Vec<u16> = OsString::from(&path).as_os_str().encode_wide().chain(Some(0)).collect();

    let file = CreateFileW(
        path_w.as_ptr(),
        GENERIC_READ,
        winapi::um::winnt::FILE_SHARE_READ,
        null_mut(),
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        null_mut(),
    );

    if file == INVALID_HANDLE_VALUE {
        fatal_err("Failed to open file");
    }

    let file_size = GetFileSize(file, null_mut());
    if file_size == winapi::um::fileapi::INVALID_FILE_SIZE {
        fatal_err("Failed to get file size");
    }

    let buffer = VirtualAlloc(
        null_mut(),
        file_size as usize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    ) as *mut winapi::ctypes::c_void;

    if buffer.is_null() {
        fatal_err("Failed to allocate memory for file");
    }

    let mut bytes_read: DWORD = 0;
    if ReadFile(file, buffer as *mut _, file_size, &mut bytes_read, null_mut()) == 0 || bytes_read != file_size {
        fatal_err("Failed to read file");
    }
    CloseHandle(file);

    *out_size = file_size as usize;
    buffer
}

pub unsafe fn zero_and_free(buffer: *mut winapi::ctypes::c_void, size: usize) {
    if !buffer.is_null() {
        let buffer_u8 = buffer as *mut u8;
        for i in 0..size {
            std::ptr::write_volatile(buffer_u8.add(i), 0);
        }
    }
    VirtualFree(buffer as *mut _, 0, MEM_RELEASE);
}