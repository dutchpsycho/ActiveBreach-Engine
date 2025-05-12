use std::collections::BTreeMap;
use std::ffi::CStr;
use std::os::raw::c_char;
use std::ptr::{null, null_mut};
use std::slice;

use winapi::um::winnt::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, IMAGE_EXPORT_DIRECTORY};

use once_cell::sync::OnceCell;

/// Global syscall lookup table containing NT syscall names and their corresponding SSNs (Syscall Service Numbers).
///
/// This is populated once via [`extract_syscalls`] and cached statically.
#[link_section = ".rdata$ab"]
pub static SYSCALL_TABLE: OnceCell<BTreeMap<String, u32>> = OnceCell::new();

/// Validates that a given offset falls within the mapped binary bounds.
#[inline(always)]
unsafe fn validate_offset(base: *const u8, offset: usize, size: usize) -> bool {
    offset < size && base.add(offset) >= base
}

/// Performs an unaligned pointer read if the pointer is valid.
///
/// Returns `None` if the pointer is null.
#[inline(always)]
unsafe fn safe_read<T>(ptr: *const T) -> Option<T> {
    if ptr.is_null() {
        None
    } else {
        Some(std::ptr::read_unaligned(ptr))
    }
}

/// Extracts NT syscalls from a memory-mapped ntdll.dll image and populates the global [`SYSCALL_TABLE`].
///
/// This function parses the PE headers, locates the export table, filters out exported functions
/// starting with `"Nt"`, checks for syscall-compatible prologues, and extracts their SSNs.
///
/// # Arguments
/// - `ntdll_base`: pointer to base of mapped ntdll memory
/// - `ntdll_size`: size of mapped region
///
/// # Safety
/// - Assumes `ntdll_base` is a valid PE image in memory.
/// - Performs unchecked pointer arithmetic and casting.
/// - Multiple calls are silently ignored if the table is already initialized.
///
/// # Notes
/// Returns early and silently on any structural validation failure.
pub unsafe fn extract_syscalls(ntdll_base: *const u8, ntdll_size: usize) {
    if ntdll_base.is_null() || ntdll_size == 0 || SYSCALL_TABLE.get().is_some() {
        return;
    }

    if !validate_offset(ntdll_base, 0, ntdll_size) {
        return;
    }

    let dos = &*(ntdll_base as *const IMAGE_DOS_HEADER);
    if dos.e_magic != 0x5A4D {
        return;
    }

    let nt_offset = dos.e_lfanew as usize;
    if !validate_offset(ntdll_base, nt_offset + std::mem::size_of::<IMAGE_NT_HEADERS>(), ntdll_size) {
        return;
    }

    let nt = &*(ntdll_base.add(nt_offset) as *const IMAGE_NT_HEADERS);
    if nt.Signature != 0x00004550 {
        return;
    }

    let export_va = nt.OptionalHeader.DataDirectory[0].VirtualAddress as usize;
    if export_va == 0 || export_va >= ntdll_size {
        return;
    }

    if !validate_offset(ntdll_base, export_va + std::mem::size_of::<IMAGE_EXPORT_DIRECTORY>(), ntdll_size) {
        return;
    }

    let export = &*(ntdll_base.add(export_va) as *const IMAGE_EXPORT_DIRECTORY);
    let name_count = export.NumberOfNames as usize;
    let func_count = export.NumberOfFunctions as usize;

    let names_offset = export.AddressOfNames as usize;
    let ords_offset = export.AddressOfNameOrdinals as usize;
    let funcs_offset = export.AddressOfFunctions as usize;

    if !validate_offset(ntdll_base, names_offset + name_count * 4, ntdll_size)
        || !validate_offset(ntdll_base, ords_offset + name_count * 2, ntdll_size)
        || !validate_offset(ntdll_base, funcs_offset + func_count * 4, ntdll_size)
    {
        return;
    }

    let names_ptr = ntdll_base.add(names_offset) as *const u32;
    let ords_ptr = ntdll_base.add(ords_offset) as *const u16;
    let funcs_ptr = ntdll_base.add(funcs_offset) as *const u32;

    let mut map = BTreeMap::new();

    for i in 0..name_count {
        let name_rva = match safe_read(names_ptr.add(i)) {
            Some(v) => v as usize,
            None => continue,
        };

        if !validate_offset(ntdll_base, name_rva, ntdll_size) {
            continue;
        }

        let name_ptr = ntdll_base.add(name_rva) as *const c_char;
        let Ok(name_str) = CStr::from_ptr(name_ptr).to_str() else { continue };
        if !name_str.starts_with("Nt") {
            continue;
        }

        let ordinal = match safe_read(ords_ptr.add(i)) {
            Some(v) => v as usize,
            None => continue,
        };

        if ordinal >= func_count {
            continue;
        }

        let func_rva = match safe_read(funcs_ptr.add(ordinal)) {
            Some(v) => v as usize,
            None => continue,
        };

        if !validate_offset(ntdll_base, func_rva + 8, ntdll_size) {
            continue;
        }

        let func_ptr = ntdll_base.add(func_rva);

        let sig = slice::from_raw_parts(func_ptr, 8);

        let is_valid = match sig {
            [0x4C, 0x8B, 0xD1, 0xB8, ..] => true,
            [0xB8, ..] => true,
            [0x4D, 0x8B, 0xD1, 0xB8, ..] => true,
            _ => false,
        };
        
        if !is_valid {
            continue;
        }        

        let syscall_num = u32::from_le_bytes([sig[4], sig[5], sig[6], sig[7]]);
        map.insert(name_str.to_string(), syscall_num);
    }

    let _ = SYSCALL_TABLE.set(map);
}

/// Retrieves a reference to the global syscall table, if initialized.
///
/// # Returns
/// `Some(&BTreeMap)` if initialized, `None` otherwise.
pub fn get_syscall_table() -> Option<&'static BTreeMap<String, u32>> {
    SYSCALL_TABLE.get()
}