use std::collections::HashMap;
use std::ptr::null_mut;
use winapi::ctypes::c_void;
use crate::internal::exports::get_export_address;
use crate::internal::error::fatal_err;
use crate::internal::syscalls::get_ntdll_base;

pub unsafe fn locate_gadget(name: &str, ssn: u32) -> *mut c_void {
    let ntdll_base = get_ntdll_base();
    if ntdll_base.is_null() {
        fatal_err("Failed to locate file base address via GetModuleHandle");
    }

    let func_addr = get_export_address(ntdll_base as *mut c_void, name);
    if func_addr.is_null() {
        fatal_err(&format!("Failed to locate function in file: {}", name));
    }

    let mut expected_pattern: [u8; 11] = [
        0x4C, 0x8B, 0xD1, // mov r10, rcx
        0xB8, 0, 0, 0, 0, // mov eax, <SSN>
        0x0F, 0x05,       // syscall
        0xC3,             // ret
    ];
    *(expected_pattern[4..8].as_mut_ptr() as *mut u32) = ssn;

    if func_addr.read() == 0xE9 || func_addr.read() == 0xE8 {
        const SCAN_LIMIT: usize = 32;
        for i in 0..SCAN_LIMIT {
            let candidate = func_addr.add(i);
            if std::slice::from_raw_parts(candidate, 3) == &expected_pattern[0..3]
                && candidate.add(8).read() == 0x0F
                && candidate.add(9).read() == 0x05
                && candidate.add(10).read() == 0xC3
            {
                let candidate_ssn = *(candidate.add(4) as *const u32);
                if candidate_ssn != ssn {
                    panic!("ACTIVEBREACH_NTDLL_STUB_PROLOGUE_HOOKED");
                }
                return candidate as *mut c_void;
            }
        }
        panic!("ACTIVEBREACH_NTDLL_STUB_HOOKED");
    } else {
        if std::slice::from_raw_parts(func_addr, 11) != expected_pattern {
            panic!("ACTIVEBREACH_NTDLL_STUB_PROLOGUE_HOOKED");
        }
        func_addr as *mut c_void
    }
}

pub struct ActiveBreachInternal {
    pub gadgets: HashMap<String, *mut c_void>,
}

impl ActiveBreachInternal {
    pub fn new() -> Self {
        Self {
            gadgets: HashMap::new(),
        }
    }

    pub unsafe fn build_gadgets(&mut self, syscall_table: &HashMap<String, u32>) {
        for (name, ssn) in syscall_table.iter() {
            let gadget = locate_gadget(name, *ssn);
            self.gadgets.insert(name.clone(), gadget);
        }
    }

    pub fn get_gadget(&self, name: &str) -> *mut c_void {
        *self.gadgets.get(name).unwrap_or(&null_mut())
    }
}