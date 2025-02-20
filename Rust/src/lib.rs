/*
* ==================================================================================
*  Repository:   Syscall Proxy
*  Project:      ActiveBreach
*  File:         lib.rs
*  Author:       CrisisEvasion
*  Organization: TITAN Softwork Solutions
*  Inspired by:  MDSEC Research
*
*  Description:
*      ActiveBreach is a syscall abstraction layer that dynamically proxies syscalls
*      by extracting system service numbers (SSNs) from ntdll.dll and locating valid
*      syscall prologue gadgets from within the hooked ntdll. When a call is made via
*      the dispatcher, the call is ROP-chained through the located gadget, so that
*      the syscall appears to originate from ntdll.
*
*  License:      Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)
*  Copyright:    (C) 2025 TITAN Softwork Solutions. All rights reserved.
*
*  Licensing Terms:
*  ----------------------------------------------------------------------------------
*   - You are free to use, modify, and share this software.
*   - Commercial use is strictly prohibited.
*   - Proper credit must be given to TITAN Softwork Solutions.
*   - Modifications must be clearly documented.
*   - This software is provided "as-is" without warranties of any kind.
*
*  Full License: https://creativecommons.org/licenses/by-nc/4.0/
* ==================================================================================
*/

#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(non_camel_case_types)]

use std::ptr;
use std::io::Write;
use std::os::raw::c_char;
use std::collections::HashMap;
use std::ffi::{CStr, OsString};
use std::ptr::{null, null_mut};
use std::mem::{transmute, zeroed};
use std::os::windows::ffi::{OsStringExt, OsStrExt};

use winapi::shared::ntdef::HANDLE;
use winapi::shared::minwindef::{TRUE, FALSE, DWORD, WORD, LPVOID, UINT};
use winapi::um::winnt::LIST_ENTRY;

use winapi::ctypes::c_void;
use winapi::um::winbase::INFINITE;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::libloaderapi::GetModuleHandleW;
use winapi::um::fileapi::{ReadFile, OPEN_EXISTING};
use winapi::um::memoryapi::{VirtualAlloc, VirtualFree};
use winapi::um::minwinbase::{LPTHREAD_START_ROUTINE, CRITICAL_SECTION};
use winapi::um::processthreadsapi::CreateThread;
use winapi::um::synchapi::{CreateEventA, CreateEventW, SetEvent, WaitForSingleObject};
use winapi::um::winnt::{FILE_SHARE_READ, FILE_ATTRIBUTE_NORMAL, GENERIC_READ, IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_EXPORT_DIRECTORY, IMAGE_NT_HEADERS, IMAGE_NT_SIGNATURE, IMAGE_DATA_DIRECTORY, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, DLL_PROCESS_ATTACH};

#[repr(C)]
struct PEB {
    reserved1: [u8; 2],
    being_debugged: u8,
    reserved2: [u8; 1],
    reserved3: [*mut c_void; 2],
    ldr: *mut PEB_LDR_DATA,
}

#[repr(C)]
struct PEB_LDR_DATA {
    reserved1: [u8; 8],
    in_memory_order_module_list: LIST_ENTRY,
}

#[repr(C)]
struct LDR_DATA_TABLE_ENTRY {
    reserved1: [u8; 16],
    in_memory_order_links: LIST_ENTRY,
    reserved2: [u8; 16],
    dll_base: *mut c_void,
}

#[repr(C)]
struct LdrDataTableEntry {
    reserved1: [u8; 16],
    in_memory_order_links: LIST_ENTRY,
    reserved2: [u8; 16],
    dll_base: *mut c_void,
}

#[link_section = ".CRT$XLU"]
#[used]
static TLS_CALLBACK: extern "system" fn(*mut c_void, u32, *mut c_void) = tls_callback;

extern "system" fn tls_callback(_hModule: *mut c_void, reason: u32, _reserved: *mut c_void) {
    if reason == DLL_PROCESS_ATTACH {
        unsafe {
            ActiveBreach_launch();
        }
    }
}


// ===================== // 
// ActiveBreach internal
// ===================== //
mod internal {
    use super::*;
    use core::arch::asm;
    use std::sync::Mutex;
    use lazy_static::lazy_static;

    const XOR_KEY: u16 = 0x5A;
    static ENC: [u16; 9] = [
        0x0036, 0x0036, 0x003E, 0x0074, 0x0036, 0x0036, 0x003E, 0x002E, 0x0034,
    ];

    pub(super) fn fatal_err(msg: &str) -> ! {
        let _ = writeln!(std::io::stderr(), "{}", msg);
        std::process::exit(1);
    }

    pub(super) unsafe fn zero_and_free(buffer: *mut c_void, size: usize) {
        if !buffer.is_null() {
            let buffer_u8 = buffer as *mut u8;
            for i in 0..size {
                ptr::write_volatile(buffer_u8.add(i), 0);
            }
        }
        VirtualFree(buffer as *mut _, 0, MEM_RELEASE);
    }

    pub(super) fn decode() -> Vec<u16> {
        let size = ENC.len() - 1;
        let mut decoded = vec![0u16; size + 1];
        for i in 0..size {
            decoded[i] = ENC[size - i - 1] ^ XOR_KEY;
        }
        decoded[size] = 0;
        decoded
    }

    pub(super) fn wide_null(s: &str) -> Vec<u16> {
        OsString::from(s).encode_wide().chain(Some(0)).collect()
    }

    pub(super) unsafe fn buffer(out_size: &mut usize) -> *mut c_void {
        let mut system_dir: [u16; winapi::shared::minwindef::MAX_PATH] = [0; winapi::shared::minwindef::MAX_PATH];
        if winapi::um::sysinfoapi::GetSystemDirectoryW(
            system_dir.as_mut_ptr(),
            winapi::shared::minwindef::MAX_PATH as UINT,
        ) == 0
        {
            fatal_err("Failed to retrieve the system directory");
        }

        let decoded = decode();
        let system_dir_str = OsString::from_wide(
            &system_dir[..system_dir.iter().position(|&c| c == 0).unwrap_or(system_dir.len())],
        );
        let decoded_str = OsString::from_wide(
            &decoded[..decoded.iter().position(|&c| c == 0).unwrap_or(decoded.len())],
        );
        let path = format!(
            "{}\\{}",
            system_dir_str.to_string_lossy(),
            decoded_str.to_string_lossy()
        );
        let path_w: Vec<u16> = OsString::from(&path).encode_wide().chain(Some(0)).collect();

        let file = winapi::um::fileapi::CreateFileW(
            path_w.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ,
            null_mut(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            null_mut(),
        );
        if file == INVALID_HANDLE_VALUE {
            fatal_err("Failed to open file");
        }

        let file_size = winapi::um::fileapi::GetFileSize(file, null_mut());
        if file_size == winapi::um::fileapi::INVALID_FILE_SIZE {
            fatal_err("Failed to get file size");
        }

        let buffer = VirtualAlloc(
            null_mut(),
            file_size as usize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if buffer.is_null() {
            fatal_err("Failed to allocate memory for file");
        }

        let mut bytes_read: DWORD = 0;
        if ReadFile(file, buffer, file_size, &mut bytes_read, null_mut()) == 0 || bytes_read != file_size {
            fatal_err("Failed to read file");
        }
        CloseHandle(file);

        *out_size = file_size as usize;
        buffer
    }

    pub(super) unsafe fn get_export_address(moduleBase: *mut c_void, functionName: &str) -> *mut u8 {
        if moduleBase.is_null() {
            return null_mut();
        }
        let dos_header = moduleBase as *const IMAGE_DOS_HEADER;
        if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
            return null_mut();
        }
        let nt_headers = (moduleBase as *const u8).add((*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS;
        let export_dir: IMAGE_DATA_DIRECTORY = (*nt_headers).OptionalHeader.DataDirectory[0];
        if export_dir.VirtualAddress == 0 {
            return null_mut();
        }
        let export_table = (moduleBase as *const u8).add(export_dir.VirtualAddress as usize) as *const IMAGE_EXPORT_DIRECTORY;
        let name_table = (moduleBase as *const u8).add((*export_table).AddressOfNames as usize) as *const DWORD;
        let ordinal_table = (moduleBase as *const u8).add((*export_table).AddressOfNameOrdinals as usize) as *const WORD;
        let function_table = (moduleBase as *const u8).add((*export_table).AddressOfFunctions as usize) as *const DWORD;

        for i in 0..(*export_table).NumberOfNames {
            let name_ptr = (moduleBase as *const u8).add(*name_table.offset(i as isize) as usize) as *const c_char;
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

    #[repr(C)]
    struct PebLdrData {
        reserved1: [u8; 8],
        in_memory_order_module_list: LIST_ENTRY,
    }

    pub(super) unsafe fn get_ntdll_base() -> *mut c_void {
        let peb: *mut PEB;
        
        asm!(
            "mov {}, gs:[0x60]", 
            out(reg) peb
        );
    
        let ldr = (*peb).ldr as *mut PEB_LDR_DATA;
        let mut module_list = (*ldr).in_memory_order_module_list.Flink;
    
        module_list = (*module_list).Flink;
        let ntdll_entry = module_list as *mut LDR_DATA_TABLE_ENTRY;
    
        (*ntdll_entry).dll_base
    }

    pub(super) unsafe fn extract_ssn(mapped_base: *mut c_void) -> HashMap<String, u32> {
        let mut syscall_table = HashMap::new();

        let dos_header = mapped_base as *const IMAGE_DOS_HEADER;
        if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
            fatal_err("Invalid DOS header signature");
        }

        let nt_headers = (mapped_base as *const u8).add((*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS;
        if (*nt_headers).Signature != IMAGE_NT_SIGNATURE {
            fatal_err("Invalid NT header signature");
        }

        let export_data = (*nt_headers).OptionalHeader.DataDirectory[0];
        if export_data.VirtualAddress == 0 {
            fatal_err("No export directory found");
        }

        let export_dir = (mapped_base as *const u8).add(export_data.VirtualAddress as usize) as *const IMAGE_EXPORT_DIRECTORY;
        let names = (mapped_base as *const u8).add((*export_dir).AddressOfNames as usize) as *const DWORD;
        let functions = (mapped_base as *const u8).add((*export_dir).AddressOfFunctions as usize) as *const DWORD;
        let ordinals = (mapped_base as *const u8).add((*export_dir).AddressOfNameOrdinals as usize) as *const WORD;

        for i in 0..(*export_dir).NumberOfNames {
            let name_ptr = (mapped_base as *const u8).add(*names.offset(i as isize) as usize) as *const c_char;
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

    pub(super) unsafe fn locate_gadget(name: &str, ssn: u32) -> *mut c_void {
        let ntdll_base = get_ntdll_base();
        if ntdll_base.is_null() {
            fatal_err("Failed to locate file base address via GetModuleHandle");
        }
        let func_addr = get_export_address(ntdll_base, name);
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

    pub(super) struct ActiveBreachInternal {
        gadgets: HashMap<String, *mut c_void>,
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

    pub(super) static mut INTERNAL: Option<ActiveBreachInternal> = None;

    #[derive(Clone)]
    #[repr(C)]
    pub(super) struct ABCallRequest {
        pub stub: *mut c_void,
        pub arg_count: usize,
        pub args: [usize; 8],
        pub ret: usize,
        pub complete: HANDLE,
    }

    impl Default for ABCallRequest {
        fn default() -> Self {
            Self {
                stub: null_mut(),
                arg_count: 0,
                args: [0; 8],
                ret: 0,
                complete: null_mut(),
            }
        }
    }

    // Since raw pointers like `*mut c_void` are not Send by default,
    // we assert that our FFI values are safe to send.
    unsafe impl Send for ABCallRequest {}

    // Replace the unsafe mutable static with a lazily-initialized Mutex.
    lazy_static! {
        pub(super) static ref G_AB_CALL_REQUEST: Mutex<ABCallRequest> = Mutex::new(ABCallRequest::default());
    }

    // Make the events public within the module so they can be used from outside.
    pub(super) static mut G_AB_CALL_EVENT: HANDLE = null_mut();
    pub(super) static mut G_AB_INITIALIZED_EVENT: HANDLE = null_mut();

    pub(super) type ABStubFn = unsafe extern "system" fn(
        usize,
        usize,
        usize,
        usize,
        usize,
        usize,
        usize,
        usize,
    ) -> usize;

    pub(super) unsafe extern "system" fn dispatcher(_lpParameter: LPVOID) -> DWORD {
        if G_AB_CALL_EVENT.is_null() {
            fatal_err("Dispatcher event not created");
        }
        loop {
            WaitForSingleObject(G_AB_CALL_EVENT, INFINITE);

            // Lock and clone the current request.
            let req = {
                let guard = G_AB_CALL_REQUEST.lock().unwrap();
                guard.clone()
            };

            let fn_ptr: ABStubFn = transmute(req.stub);
            let ret = match req.arg_count {
                0 => fn_ptr(0, 0, 0, 0, 0, 0, 0, 0),
                1 => fn_ptr(req.args[0], 0, 0, 0, 0, 0, 0, 0),
                2 => fn_ptr(req.args[0], req.args[1], 0, 0, 0, 0, 0, 0),
                3 => fn_ptr(req.args[0], req.args[1], req.args[2], 0, 0, 0, 0, 0),
                4 => fn_ptr(req.args[0], req.args[1], req.args[2], req.args[3], 0, 0, 0, 0),
                5 => fn_ptr(req.args[0], req.args[1], req.args[2], req.args[3], req.args[4], 0, 0, 0),
                6 => fn_ptr(req.args[0], req.args[1], req.args[2], req.args[3], req.args[4], req.args[5], 0, 0),
                7 => fn_ptr(req.args[0], req.args[1], req.args[2], req.args[3], req.args[4], req.args[5], req.args[6], 0),
                8 => fn_ptr(req.args[0], req.args[1], req.args[2], req.args[3], req.args[4], req.args[5], req.args[6], req.args[7]),
                _ => fatal_err("Invalid argument count in call dispatcher"),
            };

            {
                // Update the request with the result.
                let mut guard = G_AB_CALL_REQUEST.lock().unwrap();
                guard.ret = ret;
            }

            SetEvent(req.complete);
        }
    }

    pub(super) unsafe extern "system" fn thread_proc(_lpParameter: LPVOID) -> DWORD {
        // Create the dispatcher event.
        G_AB_CALL_EVENT = CreateEventA(null_mut(), FALSE, FALSE, null());
        if G_AB_CALL_EVENT.is_null() {
            fatal_err("Failed to create dispatcher event");
        }
        if !G_AB_INITIALIZED_EVENT.is_null() {
            SetEvent(G_AB_INITIALIZED_EVENT);
        }
        dispatcher(null_mut())
    }

    #[repr(C)]
    pub(super) struct SyscallState {
        pub start_time: u64,
        pub stack_ptr: usize,
        pub ret_addr: usize,
    }

    pub(super) unsafe fn sp() -> usize {
        let sp: usize;
        asm!("mov {}, rsp", out(reg) sp);
        sp
    }

    pub(super) unsafe fn ret_addr() -> usize {
        let ret: usize;
        asm!("mov {}, [rsp]", out(reg) ret);
        ret
    }

    pub(super) unsafe fn get_rdtsc() -> u64 {
        #[cfg(target_arch = "x86_64")]
        {
            core::arch::x86_64::_rdtsc()
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            0
        }
    }

    pub(super) unsafe fn activebreach_callback(state: &SyscallState) {
        let end_time = get_rdtsc();
        let elapsed = end_time - state.start_time;
        let current_stack_ptr = sp();
        let current_ret_addr = ret_addr();

        if current_stack_ptr != state.stack_ptr {
            panic!("ACTIVEBREACH_SYSCALL_STACKPTRMODIFIED");
        }
        if current_ret_addr != state.ret_addr {
            panic!("ACTIVEBREACH_SYSCALL_RETURNMODIFIED");
        }

        const SYSCALL_TIME_THRESHOLD: u64 = 100000;
        if elapsed > SYSCALL_TIME_THRESHOLD {
            panic!("ACTIVEBREACH_SYSCALL_LONGSYSCALL");
        }
    }
}

// ==================== //
// ActiveBreach Exports
// ==================== //
#[no_mangle]
pub unsafe extern "C" fn ActiveBreach_launch() {
    let mut ab_handle_size: usize = 0;
    let mapped_base = internal::buffer(&mut ab_handle_size);
    let syscall_table = internal::extract_ssn(mapped_base);

    internal::zero_and_free(mapped_base, ab_handle_size);
    internal::INTERNAL = Some(internal::ActiveBreachInternal::new());
    if let Some(ref mut internal_ref) = internal::INTERNAL {
        internal_ref.build_gadgets(&syscall_table);
    }

    // Use the public events from internal.
    internal::G_AB_INITIALIZED_EVENT = CreateEventA(null_mut(), TRUE, FALSE, null());
    if internal::G_AB_INITIALIZED_EVENT.is_null() {
        internal::fatal_err("Failed to create initialization event");
    }

    let hThread = CreateThread(
        null_mut(),
        0,
        Some(internal::thread_proc),
        null_mut(),
        0,
        null_mut(),
    );
    if hThread.is_null() {
        internal::fatal_err("Failed to create ActiveBreach dispatcher thread");
    }

    WaitForSingleObject(internal::G_AB_INITIALIZED_EVENT, INFINITE);
    CloseHandle(internal::G_AB_INITIALIZED_EVENT);
    internal::G_AB_INITIALIZED_EVENT = null_mut();
    CloseHandle(hThread);
}

#[no_mangle]
pub unsafe extern "C" fn ab_call(gadget: *mut c_void, args: *const usize, arg_count: usize) -> usize {
    if gadget.is_null() {
        panic!("ab_call: gadget is NULL");
    }
    if arg_count > 8 {
        panic!("ab_call: Too many arguments (max 8)");
    }
    if args.is_null() {
        panic!("ab_call: args is NULL");
    }

    let args_slice = core::slice::from_raw_parts(args, arg_count);

    let mut req = internal::ABCallRequest {
        stub: gadget,
        arg_count,
        args: [0; 8],
        ret: 0,
        complete: CreateEventA(null_mut(), TRUE, FALSE, null()),
    };

    req.args[..arg_count].copy_from_slice(args_slice);

    {
        let mut guard = internal::G_AB_CALL_REQUEST.lock().unwrap();
        *guard = req.clone();
    }
    SetEvent(internal::G_AB_CALL_EVENT);

    let complete_handle = req.complete;
    WaitForSingleObject(complete_handle, INFINITE);
    CloseHandle(complete_handle);

    let ret_val = {
        let guard = internal::G_AB_CALL_REQUEST.lock().unwrap();
        guard.ret
    };

    ret_val
}