//! Provides safe(ish) helpers to map a clean `ntdll.dll` copy from disk into memory, ensuring
//! no tampered bytes from userland injection affect syscall discovery logic.
//! The `ntdll.dll` image is mapped as read-only, never loaded via `LoadLibrary`, and is pulled
//! directly from `C:\Windows\System32\ntdll.dll` using low-level file I/O APIs.

use std::ptr::{null, null_mut};
use winapi::shared::minwindef::{DWORD, FALSE};
use winapi::shared::ntdef::NULL;
use winapi::um::fileapi::CreateFileW;
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::memoryapi::{CreateFileMappingW, MapViewOfFile, UnmapViewOfFile};
use winapi::um::winnt::{
    FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, GENERIC_READ, PAGE_READONLY,
};

use winapi::um::fileapi::OPEN_EXISTING;
use winapi::um::memoryapi::FILE_MAP_READ;

/// UTF-16 encoded `C:\Windows\System32\ntdll.dll` static path.
///
/// This avoids any reliance on `GetSystemDirectory` or `GetModuleFileName` APIs,
/// ensuring fully predictable resolution even in sandboxed or suspended states.
const SYSTEM32_NTDLL: &[u16] = &[
    b'C' as u16, b':' as u16, b'\\' as u16,
    b'W' as u16, b'i' as u16, b'n' as u16, b'd' as u16, b'o' as u16, b'w' as u16, b's' as u16,
    b'\\' as u16,
    b'S' as u16, b'y' as u16, b's' as u16, b't' as u16, b'e' as u16, b'm' as u16,
    b'3' as u16, b'2' as u16, b'\\' as u16,
    b'n' as u16, b't' as u16, b'd' as u16, b'l' as u16, b'l' as u16, b'.' as u16,
    b'd' as u16, b'l' as u16, b'l' as u16,
    0
];

/// Maps a fresh copy of `ntdll.dll` into memory directly from disk as read-only.
///
/// This is used during syscall table extraction to avoid contaminated or hooked in-memory versions.
///
/// # Returns
/// A tuple containing:
/// - `*const u8`: Pointer to the start of the mapped memory view
/// - `HANDLE`: Handle to the memory map (must be passed to [`unmap_and_close()`])
///
/// # Arguments
/// * `size_out` - Optional output for estimated size. Defaults to 2MB upper-bound.
///
/// # Safety
/// - Caller **must** invoke [`unmap_and_close()`] with both values returned from this function.
/// - This function performs raw memory mapping and direct file handle manipulation.
///
pub unsafe fn buffer(size_out: &mut usize) -> Option<(*const u8, winapi::shared::ntdef::HANDLE)> {
    let h_file = CreateFileW(
        SYSTEM32_NTDLL.as_ptr(),
        GENERIC_READ,
        FILE_SHARE_READ,
        null_mut(),
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        null_mut(),
    );

    if h_file == INVALID_HANDLE_VALUE {
        return None;
    }

    let h_map = CreateFileMappingW(h_file, null_mut(), PAGE_READONLY, 0, 0, null());
    if h_map.is_null() {
        CloseHandle(h_file);
        return None;
    }

    let mapped = MapViewOfFile(h_map, FILE_MAP_READ, 0, 0, 0);
    if mapped.is_null() {
        CloseHandle(h_map);
        CloseHandle(h_file);
        return None;
    }

    // We assume a 2MB upper bound, since the ntdll image size is well under this.
    *size_out = 2 * 1024 * 1024;

    Some((mapped as *const u8, h_map))
}

/// Unmaps and closes a handle returned by [`buffer()`].
///
/// This should be called exactly once per successful call to `buffer()` to avoid memory leaks.
///
/// # Safety
/// - The `mapped` pointer must be one returned by [`buffer()`].
/// - The `handle` must be the file mapping handle returned from the same call.
pub unsafe fn unmap_and_close(mapped: *const u8, handle: winapi::shared::ntdef::HANDLE) {
    if !mapped.is_null() {
        UnmapViewOfFile(mapped as _);
    }

    if handle != NULL {
        CloseHandle(handle);
    }
}