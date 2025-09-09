use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::Read;
use std::mem;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::ptr::{self, null_mut};
use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

use winapi::shared::minwindef::HMODULE;
use winapi::shared::ntdef::{HANDLE, NT_SUCCESS, NULL, PVOID, ULONG, UNICODE_STRING};
use winapi::um::fileapi::QueryDosDeviceW;
use winapi::um::libloaderapi::{GetModuleFileNameW, GetModuleHandleW};
use winapi::um::memoryapi::{VirtualAlloc, VirtualFree};
use winapi::um::processthreadsapi::GetCurrentProcess;
use winapi::um::winnt::{MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE};

use crate::AbOut;

#[link(name = "ntdll")]
extern "system" {
    fn NtQueryVirtualMemory(
        ProcessHandle: HANDLE,
        BaseAddress: PVOID,
        MemoryInformationClass: ULONG,
        MemoryInformation: PVOID,
        MemoryInformationLength: usize,
        ReturnLength: *mut usize,
    ) -> i32;
}

// ---- restore the globals your code uses ----
static MAPPED_NTDLL_PTR: AtomicPtr<u8> = AtomicPtr::new(null_mut());
static MAPPED_NTDLL_SIZE: AtomicUsize = AtomicUsize::new(0);

// ---- minimal FFI types/constants ----
#[repr(C)]
struct MEMORY_BASIC_INFORMATION64 {
    BaseAddress: PVOID,
    AllocationBase: PVOID,
    AllocationProtect: u32,
    __alignment1: u32,
    RegionSize: usize,
    State: u32,
    Protect: u32,
    Type: u32,
}

#[repr(C)]
struct MEMORY_SECTION_NAME {
    SectionFileName: UNICODE_STRING,
}

const MemoryBasicInformation: ULONG = 0; // class 0
const MemorySectionName: ULONG = 2; // class 2

unsafe fn nt_device_path_to_dos_path(nt_path: &str) -> Option<String> {
    // Iterate A:Z, map each to its target device path(s), and compare prefixes.
    for letter in b'A'..=b'Z' {
        let drive_spec = format!("{}:", letter as char);

        // QueryDosDeviceW takes "C:" and returns MULTI_SZ of device targets.
        let mut drive_w: Vec<u16> = OsStr::new(&drive_spec)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let mut buf = vec![0u16; 1024];
        let got = QueryDosDeviceW(drive_w.as_mut_ptr(), buf.as_mut_ptr(), buf.len() as u32);
        if got == 0 {
            continue;
        }

        // MULTI_SZ walk
        let mut i = 0usize;
        while i < got as usize && buf[i] != 0 {
            let start = i;
            while i < got as usize && buf[i] != 0 {
                i += 1;
            }
            let target = OsString::from_wide(&buf[start..i])
                .to_string_lossy()
                .to_string();

            // Match with and without trailing slash
            if nt_path.starts_with(&target) {
                let tail = &nt_path[target.len()..];
                let tail = if tail.is_empty() || !tail.starts_with('\\') {
                    format!(r"\{}", tail)
                } else {
                    tail.to_string()
                };
                return Some(format!("{}{}", drive_spec, tail));
            }
            let with_slash = format!(r"{}\{}", target, "");
            if nt_path.starts_with(&with_slash) {
                let tail = &nt_path[with_slash.len()..];
                return Some(format!(r"{}\{}", drive_spec, tail));
            }

            i += 1; // skip NUL
        }
    }
    None
}

unsafe fn get_ntdll_base_via_its_own_export() -> Option<*mut u8> {
    let process = GetCurrentProcess();
    let addr = NtQueryVirtualMemory as *const () as PVOID;

    // Query MemoryBasicInformation to get AllocationBase (image base)
    let mut mbi: MEMORY_BASIC_INFORMATION64 = mem::zeroed();
    let mut ret_len = 0usize;
    let status = NtQueryVirtualMemory(
        process,
        addr,
        MemoryBasicInformation,
        &mut mbi as *mut _ as PVOID,
        mem::size_of::<MEMORY_BASIC_INFORMATION64>(),
        &mut ret_len,
    );
    if !NT_SUCCESS(status) || mbi.AllocationBase.is_null() {
        return None;
    }
    Some(mbi.AllocationBase as *mut u8)
}

unsafe fn get_module_path_from_base_ntqvm(base: *mut u8) -> Option<String> {
    let process = GetCurrentProcess();

    // Size probe
    let mut ret_len = 0usize;
    let _ = NtQueryVirtualMemory(
        process,
        base as PVOID,
        MemorySectionName,
        ptr::null_mut(),
        0,
        &mut ret_len,
    );
    if ret_len == 0 {
        return None;
    }

    // Fetch blob
    let mut blob = vec![0u8; ret_len];
    let status = NtQueryVirtualMemory(
        process,
        base as PVOID,
        MemorySectionName,
        blob.as_mut_ptr() as PVOID,
        blob.len(),
        &mut ret_len,
    );
    if !NT_SUCCESS(status) {
        return None;
    }

    // Interpret as MEMORY_SECTION_NAME
    let msn = &*(blob.as_ptr() as *const MEMORY_SECTION_NAME);
    let us = &msn.SectionFileName;
    if us.Buffer.is_null() || us.Length == 0 {
        return None;
    }

    let wide = std::slice::from_raw_parts(us.Buffer, (us.Length / 2) as usize);
    let nt_path = OsString::from_wide(wide).to_string_lossy().to_string();

    nt_device_path_to_dos_path(&nt_path).or(Some(nt_path))
}

pub unsafe fn resolve_ntdll_base_no_strings() -> *mut u8 {
    get_ntdll_base_via_its_own_export().unwrap_or(ptr::null_mut())
}

pub unsafe fn buffer(size_out: &mut usize) -> Option<(*const u8, HANDLE)> {
    let ntdll_base = resolve_ntdll_base_no_strings();
    if ntdll_base.is_null() {
        return None;
    }

    let path_str = match get_module_path_from_base_ntqvm(ntdll_base) {
        Some(p) => p,
        None => return None,
    };

    AbOut!("Opening {}", path_str);
    let mut file = match File::open(&path_str) {
        Ok(f) => f,
        Err(e) => {
            AbOut!("File::open failed: {}", e);
            return None;
        }
    };

    let mut buf = Vec::new();
    if let Err(e) = file.read_to_end(&mut buf) {
        AbOut!("read_to_end failed: {}", e);
        return None;
    }

    let alloc = VirtualAlloc(
        null_mut(),
        buf.len(),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    ) as *mut u8;

    if alloc.is_null() {
        AbOut!("VirtualAlloc failed");
        return None;
    }

    ptr::copy_nonoverlapping(buf.as_ptr(), alloc, buf.len());
    *size_out = buf.len();

    // store for drop_ntdll()
    MAPPED_NTDLL_PTR.store(alloc, Ordering::SeqCst);
    MAPPED_NTDLL_SIZE.store(buf.len(), Ordering::SeqCst);

    AbOut!("[+] Mapped ntdll copy @ {:p} ({} bytes)", alloc, buf.len());
    Some((alloc as *const u8, NULL))
}

pub unsafe fn drop_ntdll() {
    let ptr = MAPPED_NTDLL_PTR.swap(null_mut(), Ordering::SeqCst);
    let size = MAPPED_NTDLL_SIZE.swap(0, Ordering::SeqCst);

    if !ptr.is_null() {
        // zero before free
        ptr::write_bytes(ptr, 0, size);
        AbOut!("Unmapping @ {:p} ({} bytes)", ptr, size);
        VirtualFree(ptr as *mut _, 0, MEM_RELEASE);
    } else {
        AbOut!("no mapping present");
    }
}