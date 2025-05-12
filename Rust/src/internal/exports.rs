//! Parses a clean memory-mapped copy of `ntdll.dll` and extracts system service numbers (SSNs)
//! from valid NT syscalls in the export table. This avoids relying on any user-mode API or
//! potentially hooked function tables.
//!
//! The extracted map is cached in `SYSCALL_TABLE` for global access via [`get_syscall_table()`].
//!
//! ## Safety
//! The functions in this module are **unsafe** because they perform unchecked pointer arithmetic
//! and assume valid, properly aligned memory mapped from `ntdll.dll`.

use rustc_hash::FxHashMap;
use std::ffi::CStr;
use std::os::raw::c_char;
use std::ptr::{null, null_mut};
use std::slice;

use winapi::um::winnt::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, IMAGE_EXPORT_DIRECTORY};

use once_cell::sync::OnceCell;

/// Global static syscall table, initialized by [`extract_syscalls()`].
#[link_section = ".rdata$ab"]
pub static SYSCALL_TABLE: OnceCell<FxHashMap<String, u32>> = OnceCell::new();

/// Validates that a memory offset falls within mapped image bounds.
///
/// # Safety
/// - Caller must ensure `base` is a valid pointer.
/// - `offset` must not cause integer overflow.
#[inline(always)]
unsafe fn valid_offset(base: *const u8, offset: usize, size: usize) -> bool {
    offset < size && base.add(offset) >= base
}

/// Reads an unaligned `u32` value from a raw pointer.
///
/// # Safety
/// - Pointer must be valid and point to at least 4 bytes.
#[inline(always)]
unsafe fn read_u32(ptr: *const u32) -> u32 {
    std::ptr::read_unaligned(ptr)
}

/// Reads an unaligned `u16` value from a raw pointer.
///
/// # Safety
/// - Pointer must be valid and point to at least 2 bytes.
#[inline(always)]
unsafe fn read_u16(ptr: *const u16) -> u16 {
    std::ptr::read_unaligned(ptr)
}

/// Extracts syscall numbers from a mapped `ntdll.dll` image.
///
/// This performs full PE parsing and filters for valid NT syscall prologues.
///
/// # Arguments
/// - `ntdll`: Pointer to memory-mapped ntdll.dll image (must be clean, unhooked)
/// - `size`: Size in bytes of the mapped image
///
/// # Safety
/// - Caller must guarantee that `ntdll` is valid, readable, and represents a PE image.
/// - Assumes the image is from System32, not a loaded module (e.g. via `LoadLibrary`).
///
/// # Implementation Notes
/// - Valid NT syscall signatures are matched on prologues:
///   - `mov r10, rcx; mov eax, imm32; syscall; ret`
///   - `mov eax, imm32; syscall; ret`
///   - `mov r10, rcx` (64-bit variant for Wow64 passthrough)
pub unsafe fn extract_syscalls(ntdll: *const u8, size: usize) {
    if ntdll.is_null() || size == 0 || SYSCALL_TABLE.get().is_some() {
        return;
    }

    if !valid_offset(ntdll, 0, size) {
        return;
    }

    let dos = &*(ntdll as *const IMAGE_DOS_HEADER);
    if dos.e_magic != 0x5A4D {
        return;
    }

    let nt_offset = dos.e_lfanew as usize;
    if !valid_offset(ntdll, nt_offset + std::mem::size_of::<IMAGE_NT_HEADERS>(), size) {
        return;
    }

    let nt = &*(ntdll.add(nt_offset) as *const IMAGE_NT_HEADERS);
    if nt.Signature != 0x00004550 {
        return;
    }

    let export_va = nt.OptionalHeader.DataDirectory[0].VirtualAddress as usize;
    if export_va == 0 || !valid_offset(ntdll, export_va, size) {
        return;
    }

    let export = &*(ntdll.add(export_va) as *const IMAGE_EXPORT_DIRECTORY);

    let names = ntdll.add(export.AddressOfNames as usize) as *const u32;
    let ords  = ntdll.add(export.AddressOfNameOrdinals as usize) as *const u16;
    let funcs = ntdll.add(export.AddressOfFunctions as usize) as *const u32;

    let name_count = export.NumberOfNames as usize;
    let func_count = export.NumberOfFunctions as usize;

    let mut map = FxHashMap::with_capacity_and_hasher(name_count, Default::default());

    for i in 0..name_count {
        let name_rva = read_u32(names.add(i)) as usize;
        if name_rva >= size { continue; }

        let name_ptr = ntdll.add(name_rva) as *const c_char;
        let name_bytes = CStr::from_ptr(name_ptr).to_bytes();

        // Only extract syscalls that begin with "Nt"
        if name_bytes.len() < 3 || name_bytes[0] != b'N' || name_bytes[1] != b't' {
            continue;
        }

        let ordinal = read_u16(ords.add(i)) as usize;
        if ordinal >= func_count { continue; }

        let func_rva = read_u32(funcs.add(ordinal)) as usize;
        if func_rva + 8 >= size { continue; }

        let sig = slice::from_raw_parts(ntdll.add(func_rva), 8);

        let is_valid = match sig {
            [0x4C, 0x8B, 0xD1, 0xB8, ..] |
            [0xB8, ..] |
            [0x4D, 0x8B, 0xD1, 0xB8, ..] => true,
            _ => false,
        };

        if !is_valid { continue; }

        let ssn = u32::from_le_bytes([sig[4], sig[5], sig[6], sig[7]]);
        let key = String::from_utf8_unchecked(name_bytes.to_vec());

        map.insert(key, ssn);
    }

    let _ = SYSCALL_TABLE.set(map);
}

/// Returns a reference to the global syscall table, if initialized.
///
/// # Returns
/// - `Some(&FxHashMap<String, u32>)` if the table is ready
/// - `None` otherwise
pub fn get_syscall_table() -> Option<&'static FxHashMap<String, u32>> {
    SYSCALL_TABLE.get()
}