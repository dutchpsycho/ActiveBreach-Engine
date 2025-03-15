use std::ptr::{null_mut, null};
use std::ffi::CStr;
use winapi::um::winnt::{
    IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_HEADERS, IMAGE_NT_SIGNATURE,
    IMAGE_DATA_DIRECTORY, IMAGE_EXPORT_DIRECTORY,
};
use winapi::shared::minwindef::{DWORD, WORD};
use std::os::raw::c_char;
use std::collections::HashMap;
use crate::internal::error::fatal_err;
use winapi::ctypes::c_void;

pub unsafe fn get_export_address(moduleBase: *mut c_void, functionName: &str) -> *mut u8 {
    if moduleBase.is_null() {
        return null_mut();
    }
    let dos_header = moduleBase as *const IMAGE_DOS_HEADER;
    if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
        return null_mut();
    }
    let nt_headers = (moduleBase as *const u8)
        .add((*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS;
    let export_dir: IMAGE_DATA_DIRECTORY = (*nt_headers).OptionalHeader.DataDirectory[0];
    if export_dir.VirtualAddress == 0 {
        return null_mut();
    }
    let export_table = (moduleBase as *const u8)
        .add(export_dir.VirtualAddress as usize) as *const IMAGE_EXPORT_DIRECTORY;
    let name_table = (moduleBase as *const u8)
        .add((*export_table).AddressOfNames as usize) as *const DWORD;
    let ordinal_table = (moduleBase as *const u8)
        .add((*export_table).AddressOfNameOrdinals as usize) as *const WORD;
    let function_table = (moduleBase as *const u8)
        .add((*export_table).AddressOfFunctions as usize) as *const DWORD;

    for i in 0..(*export_table).NumberOfNames {
        let name_ptr = (moduleBase as *const u8)
            .add(*name_table.offset(i as isize) as usize) as *const c_char;
        if let Ok(name) = CStr::from_ptr(name_ptr).to_str() {
            if name.eq_ignore_ascii_case(functionName) {
                let ordinal = *ordinal_table.offset(i as isize) as isize;
                let func_rva = *function_table.offset(ordinal) as usize;
                return (moduleBase as *const u8).add(func_rva) as *mut u8;
            }
        }
    }
    null_mut()
}

pub unsafe fn extract_ssn(mapped_base: *mut c_void) -> HashMap<String, u32> {
    use winapi::um::winnt::{IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE, IMAGE_DOS_HEADER, IMAGE_NT_HEADERS};
    let mut syscall_table = HashMap::new();

    let dos_header = mapped_base as *const IMAGE_DOS_HEADER;
    if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
        fatal_err("Invalid DOS header signature");
    }
    let nt_headers = (mapped_base as *const u8)
        .add((*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS;
    if (*nt_headers).Signature != IMAGE_NT_SIGNATURE {
        fatal_err("Invalid NT header signature");
    }
    let export_data = (*nt_headers).OptionalHeader.DataDirectory[0];
    if export_data.VirtualAddress == 0 {
        fatal_err("No export directory found");
    }
    let export_dir = (mapped_base as *const u8)
        .add(export_data.VirtualAddress as usize) as *const IMAGE_EXPORT_DIRECTORY;
    let names = (mapped_base as *const u8)
        .add((*export_dir).AddressOfNames as usize) as *const DWORD;
    let functions = (mapped_base as *const u8)
        .add((*export_dir).AddressOfFunctions as usize) as *const DWORD;
    let ordinals = (mapped_base as *const u8)
        .add((*export_dir).AddressOfNameOrdinals as usize) as *const WORD;

    for i in 0..(*export_dir).NumberOfNames {
        let name_ptr = (mapped_base as *const u8)
            .add(*names.offset(i as isize) as usize) as *const c_char;
        let func_name = match CStr::from_ptr(name_ptr).to_str() {
            Ok(s) => s.to_string(),
            Err(_) => continue,
        };
        if func_name.starts_with("Nt") {
            let ordinal = *ordinals.offset(i as isize) as isize;
            let func_rva = *functions.offset(ordinal) as usize;
            let ssn_ptr = (mapped_base as *const u8).add(func_rva + 4) as *const u32;
            let ssn = *ssn_ptr;
            syscall_table.insert(func_name, ssn);
        }
    }
    syscall_table
}