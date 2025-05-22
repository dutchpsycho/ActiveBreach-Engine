//! Parses a clean memory-mapped copy of `ntdll.dll` and extracts system service numbers (SSNs)
//! from valid NT syscalls in the export table. This avoids relying on any user-mode API or
//! potentially hooked function tables.
//!
//! The extracted map is cached in `SYSCALL_TABLE` for global access via [`get_syscall_table()`].
//!
//! ## Safety
//! The functions in this module are **unsafe** because they perform unchecked pointer arithmetic
//! and assume valid, properly aligned memory mapped from `ntdll.dll`.
//!
//! Any failure at a critical step will immediately raise a non-continuable exception with a
//! unique code to pinpoint the exact fault.

use rustc_hash::FxHashMap;
use std::{ffi::CStr, os::raw::c_char, slice};
use winapi::{
    shared::minwindef::ULONG,
    um::{
        errhandlingapi::RaiseException,
        winnt::{
            IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, IMAGE_EXPORT_DIRECTORY, IMAGE_SECTION_HEADER,
        },
    },
};
use once_cell::sync::OnceCell;

use crate::internal::mapper::drop_ntdll;
use crate::internal::diagnostics::*;
use crate::printdev;

#[link_section = ".rdata$ab"]
/// Global static syscall table, initialized by [`extract_syscalls()`].
pub static SYSCALL_TABLE: OnceCell<FxHashMap<String, u32>> = OnceCell::new();

/// Translates an RVA into a usable pointer inside a mapped PE image, or faults if invalid.
/// 
/// # Arguments
/// - `base`: Pointer to base of image (raw file or memory-mapped module)
/// - `rva`: RVA offset to resolve
/// - `size`: Full size of the mapped image in bytes
/// - `sections`: Slice of section headers from the image
/// - `fault_code`: base exception code to raise on failure
///
/// # Safety
/// - Caller must guarantee `base` and `sections` accurately describe a valid PE image.
///
unsafe fn rva_to_ptr_or_fault(
    base: *const u8,
    rva: usize,
    size: usize,
    sections: &[IMAGE_SECTION_HEADER],
    fault_code: u32,
) -> Result<*const u8, u32> {
    if base.is_null() {
        printdev!("base is null");
        return Err(fault_code);
    }
    if rva >= size {
        printdev!("rva {:X} out of bounds", rva);
        return Err(fault_code + 1);
    }

    for sec in sections {
        let virt_start = sec.VirtualAddress as usize;
        let virt_size = *sec.Misc.VirtualSize() as usize;
        if rva >= virt_start && rva < virt_start + virt_size {
            let file_offset = sec.PointerToRawData as usize + (rva - virt_start);
            if file_offset < size {
                return Ok(base.add(file_offset));
            }
        }
    }

    printdev!("rva not covered by any section");
    Err(fault_code + 2)
}

/// Extracts syscall numbers from a mapped `ntdll.dll` image.
/// 
/// This performs full PE parsing and filters for valid NT syscall prologues:
/// - `mov r10, rcx; mov eax, imm32; syscall; ret`
/// - `mov eax, imm32; syscall; ret`
/// - `mov r10, rcx; ...` (Wow64 shim variant)
///
/// Any unexpected condition (invalid headers, out-of-bounds RVAs, failed init)
/// raises a non-continuable exception with a unique code.
///
/// # Arguments
/// - `ntdll`: Pointer to memory-mapped ntdll.dll image (must be clean, unhooked)
/// - `size`: Size in bytes of the mapped image
///
/// # Safety
/// - Caller must guarantee that `ntdll` is valid, readable, and represents a System32 PE.
/// - Must be called at most once per process lifetime.
pub unsafe fn extract_syscalls(ntdll: *const u8, size: usize) -> Result<(), u32> {
    if ntdll.is_null() {
        printdev!("ntdll ptr is null");
        return Err(AB_NOT_INIT);
    }
    if size == 0 {
        printdev!("image size is zero");
        return Err(AB_NULL);
    }
    if SYSCALL_TABLE.get().is_some() {
        printdev!("syscall table already initialized");
        return Err(AB_ALREADY_INIT);
    }

    let dos = &*(ntdll as *const IMAGE_DOS_HEADER);
    if dos.e_magic != 0x5A4D {
        printdev!("invalid DOS header");
        return Err(AB_INVALID_IMAGE);
    }

    let nt_offset = dos.e_lfanew as usize;
    let nt = &*(ntdll.add(nt_offset) as *const IMAGE_NT_HEADERS);
    if nt.Signature != 0x0000_4550 {
        printdev!("invalid NT signature");
        return Err(AB_INVALID_IMAGE);
    }

    let num_secs = nt.FileHeader.NumberOfSections as usize;
    let secs_ptr = ntdll
        .add(nt_offset + std::mem::size_of::<IMAGE_NT_HEADERS>())
        as *const IMAGE_SECTION_HEADER;
    let sections = slice::from_raw_parts(secs_ptr, num_secs);

    let export_va = nt.OptionalHeader.DataDirectory[0].VirtualAddress as usize;
    let export_ptr = rva_to_ptr_or_fault(ntdll, export_va, size, sections, AB_EXPORT_FAIL)?
        as *const IMAGE_EXPORT_DIRECTORY;
    let export = &*export_ptr;

    let name_count = export.NumberOfNames as usize;
    let func_count = export.NumberOfFunctions as usize;

    let names = rva_to_ptr_or_fault(ntdll, export.AddressOfNames as usize, size, sections, AB_EXPORT_FAIL + 1)?
        as *const u32;
    let ords = rva_to_ptr_or_fault(ntdll, export.AddressOfNameOrdinals as usize, size, sections, AB_EXPORT_FAIL + 2)?
        as *const u16;
    let funcs = rva_to_ptr_or_fault(ntdll, export.AddressOfFunctions as usize, size, sections, AB_EXPORT_FAIL + 3)?
        as *const u32;

    let mut map = FxHashMap::with_capacity_and_hasher(name_count, Default::default());
    for i in 0..name_count {
        let name_rva = std::ptr::read_unaligned(names.add(i)) as usize;
        let name_ptr = rva_to_ptr_or_fault(ntdll, name_rva, size, sections, AB_BAD_SYSCALL)?
            as *const c_char;
        let name_bytes = CStr::from_ptr(name_ptr).to_bytes();
        if name_bytes.len() < 3 || &name_bytes[..2] != b"Nt" {
            continue;
        }

        let ord = std::ptr::read_unaligned(ords.add(i)) as usize;
        if ord >= func_count {
            printdev!("ordinal {} out of bounds", ord);
            return Err(AB_BAD_SYSCALL + 1);
        }

        let func_rva = std::ptr::read_unaligned(funcs.add(ord)) as usize;
        let sig_ptr = rva_to_ptr_or_fault(ntdll, func_rva, size, sections, AB_BAD_SYSCALL + 2)?;
        let sig = slice::from_raw_parts(sig_ptr, 8);

        let valid = matches!(
            sig,
            [0x4C, 0x8B, 0xD1, 0xB8, ..] |
            [0xB8, ..] |
            [0x4D, 0x8B, 0xD1, 0xB8, ..]
        );
        if !valid {
            continue;
        }

        let ssn = u32::from_le_bytes([sig[4], sig[5], sig[6], sig[7]]);
        let key = String::from_utf8_unchecked(name_bytes.to_vec());
        map.insert(key, ssn);
    }

    if SYSCALL_TABLE.set(map).is_err() {
        printdev!("syscall table already set again?");
        return Err(AB_ALREADY_INIT);
    }

    drop_ntdll();

    Ok(())  
}

/// Returns a reference to the global syscall table, if initialized.
pub fn get_syscall_table() -> Option<&'static FxHashMap<String, u32>> {
    SYSCALL_TABLE.get()
}