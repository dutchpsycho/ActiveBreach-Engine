use std::fs::File;
use std::io::Read;
use std::ptr::null_mut;

use winapi::um::handleapi::CloseHandle;
use winapi::um::memoryapi::{VirtualAlloc, VirtualFree};
use winapi::um::winnt::{MEM_RESERVE, MEM_COMMIT, MEM_RELEASE};
use winapi::shared::ntdef::NULL;

use crate::internal::crypto::lea::lea_decrypt_bytes;
use crate::internal::crypto::encrypted::*;
use crate::printdev;

/// Builds a decrypted UTF-16 path to `ntdll.dll` from an encrypted blob.
///
/// This avoids static plaintext strings for file access,
/// and performs on-the-fly conversion to Windows-compatible path format.
///
/// # Returns
/// A null-terminated UTF-16 buffer representing the full path.
fn build_path() -> [u16; 64] {
    let mut utf16_buf = [0u16; 64];
    let mut cursor = 0;

    // Heap-allocated decrypted string.
    let mut full = lea_decrypt_bytes(
        ENCRYPTED_C__WINDOWS_SYSTEM32_NTDLL_DLL,
        &ENCRYPTION_KEY,
    );
    printdev!("decrypted blob: {:?}", full);

    // Normalize slashes and copy into UTF-16 buffer.
    for b in full.bytes() {
        let c = if b == b'/' { b'\\' } else { b };

        if cursor >= utf16_buf.len() - 1 {
            printdev!("warning: path truncated (full path)");
            break;
        }

        utf16_buf[cursor] = c as u16;
        cursor += 1;
    }

    utf16_buf[cursor] = 0;

    let final_path = String::from_utf16_lossy(&utf16_buf[..cursor]);
    printdev!("built UTF-16 path: {}", final_path);

    // Zero the heap-allocated decrypted copy.
    unsafe {
        std::ptr::write_bytes(full.as_mut_ptr(), 0, full.len());
    }

    utf16_buf
}

/// Maps a clean copy of `ntdll.dll` from disk into memory using encrypted path construction.
///
/// The DLL is loaded using raw file I/O, never via `LoadLibrary`, and is mapped with RWX permissions
/// for maximum flexibility in manual-mapping / syscall extraction scenarios.
///
/// # Returns
/// A tuple containing:
/// - `*const u8`: Pointer to the allocated memory region containing the DLL image
/// - `HANDLE`: Always NULL (included for API compatibility)
///
/// # Arguments
/// * `size_out` - Output value receiving the size of the mapped region.
///
/// # Safety
/// - Returned pointer must be freed using [`unmap_and_close()`]
/// - Memory is RWX, use responsibly.
pub unsafe fn buffer(size_out: &mut usize) -> Option<(*const u8, winapi::shared::ntdef::HANDLE)> {
    let path = build_path();

    let null_pos = match path.iter().position(|&c| c == 0) {
        Some(pos) => pos,
        None => return None,
    };

    let path_str = String::from_utf16_lossy(&path[..null_pos]);

    let mut file = File::open(&path_str).ok()?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).ok()?;

    let alloc: *mut u8 = VirtualAlloc(
        null_mut(),
        buf.len(),
        MEM_COMMIT | MEM_RESERVE,
        winapi::um::winnt::PAGE_EXECUTE_READWRITE,
    ) as *mut u8;

    if alloc.is_null() {
        return None;
    }

    std::ptr::copy_nonoverlapping(buf.as_ptr(), alloc, buf.len());
    *size_out = buf.len();

    MAPPED_NTDLL_PTR.store(alloc, Ordering::SeqCst);
    MAPPED_NTDLL_SIZE.store(buf.len(), Ordering::SeqCst);
    
    Some((alloc as *const u8, NULL))
}

use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

static MAPPED_NTDLL_PTR: AtomicPtr<u8> = AtomicPtr::new(null_mut());
static MAPPED_NTDLL_SIZE: AtomicUsize = AtomicUsize::new(0);

/// Frees the memory-mapped copy of `ntdll.dll` previously returned by [`buffer()`].
///
/// This should be called after syscall extraction is complete,
/// unless you intend to keep the mapped region for inline stub execution.
///
/// # Safety
/// - Must only be called if [`buffer()`] was successfully used.
/// - Calling this twice without re-calling [`buffer()`] is undefined.
pub unsafe fn drop_ntdll() {
    let ptr = MAPPED_NTDLL_PTR.swap(null_mut(), Ordering::SeqCst);
    let size = MAPPED_NTDLL_SIZE.swap(0, Ordering::SeqCst);

    if !ptr.is_null() {
        // zero out RWX region before free (stealth++
        std::ptr::write_bytes(ptr, 0, size);

        printdev!("unmapping ntdll image @ {:p} ({} bytes)", ptr, size);
        VirtualFree(ptr as *mut _, 0, MEM_RELEASE);
    } else {
        printdev!("drop_ntdll called, but no mapping present");
    }
}