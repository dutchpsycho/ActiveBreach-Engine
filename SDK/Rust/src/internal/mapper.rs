use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::Read;
use std::mem;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::ptr::{self, null_mut};
use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{HANDLE, NTSTATUS, UNICODE_STRING};
use windows::Win32::Storage::FileSystem::QueryDosDeviceW;
use windows::Win32::System::Memory::{
    VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
};
use windows::Win32::System::Threading::GetCurrentProcess;

use crate::AbOut;

#[inline(always)]
fn nt_success(status: NTSTATUS) -> bool {
    status.0 >= 0
}

#[link(name = "ntdll")]
extern "system" {
    fn NtQueryVirtualMemory(
        ProcessHandle: HANDLE,
        BaseAddress: *const core::ffi::c_void,
        MemoryInformationClass: u32,
        MemoryInformation: *mut core::ffi::c_void,
        MemoryInformationLength: usize,
        ReturnLength: *mut usize,
    ) -> NTSTATUS;
}

static MAPPED_NTDLL_PTR: AtomicPtr<u8> = AtomicPtr::new(null_mut());
static MAPPED_NTDLL_SIZE: AtomicUsize = AtomicUsize::new(0);

#[repr(C)]
struct MEMORY_BASIC_INFORMATION64 {
    BaseAddress: *mut core::ffi::c_void,
    AllocationBase: *mut core::ffi::c_void,
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

const MemoryBasicInformation: u32 = 0;
const MemorySectionName: u32 = 2;

unsafe fn nt_device_path_to_dos_path(nt_path: &str) -> Option<String> {
    for letter in b'A'..=b'Z' {
        let drive = format!("{}:", letter as char);
        let drive_w: Vec<u16> = OsStr::new(&drive).encode_wide().chain(Some(0)).collect();

        let mut buf = vec![0u16; 1024];

        let len = QueryDosDeviceW(PCWSTR(drive_w.as_ptr()), Some(buf.as_mut_slice()));

        if len == 0 {
            continue;
        }

        let mut i = 0usize;
        while i < len as usize && buf[i] != 0 {
            let start = i;
            while i < len as usize && buf[i] != 0 {
                i += 1;
            }

            let target = OsString::from_wide(&buf[start..i])
                .to_string_lossy()
                .to_string();

            if nt_path.starts_with(&target) {
                let tail = &nt_path[target.len()..];
                return Some(format!("{}{}", drive, tail));
            }

            i += 1;
        }
    }
    None
}

unsafe fn get_ntdll_base_via_its_own_export() -> Option<*mut u8> {
    let process = GetCurrentProcess();
    let addr = NtQueryVirtualMemory as *const () as *const core::ffi::c_void;

    let mut mbi: MEMORY_BASIC_INFORMATION64 = mem::zeroed();
    let mut ret_len = 0usize;

    let status = NtQueryVirtualMemory(
        process,
        addr,
        MemoryBasicInformation,
        &mut mbi as *mut _ as _,
        mem::size_of::<MEMORY_BASIC_INFORMATION64>(),
        &mut ret_len,
    );

    if !nt_success(status) || mbi.AllocationBase.is_null() {
        return None;
    }

    Some(mbi.AllocationBase as *mut u8)
}

unsafe fn get_module_path_from_base_ntqvm(base: *mut u8) -> Option<String> {
    let process = GetCurrentProcess();
    let mut ret_len = 0usize;

    NtQueryVirtualMemory(
        process,
        base as _,
        MemorySectionName,
        ptr::null_mut(),
        0,
        &mut ret_len,
    );

    if ret_len == 0 {
        return None;
    }

    let mut buf = vec![0u8; ret_len];
    let status = NtQueryVirtualMemory(
        process,
        base as _,
        MemorySectionName,
        buf.as_mut_ptr() as _,
        buf.len(),
        &mut ret_len,
    );

    if !nt_success(status) {
        return None;
    }

    let msn = &*(buf.as_ptr() as *const MEMORY_SECTION_NAME);
    let us = &msn.SectionFileName;

    if us.Buffer.is_null() || us.Length == 0 {
        return None;
    }

    let wide = std::slice::from_raw_parts(us.Buffer.0, (us.Length / 2) as usize);

    let nt_path = OsString::from_wide(wide).to_string_lossy().to_string();

    nt_device_path_to_dos_path(&nt_path).or(Some(nt_path))
}

pub unsafe fn resolve_ntdll_base_no_strings() -> *mut u8 {
    get_ntdll_base_via_its_own_export().unwrap_or(ptr::null_mut())
}

pub unsafe fn buffer(size_out: &mut usize) -> Option<(*const u8, HANDLE)> {
    let base = resolve_ntdll_base_no_strings();
    if base.is_null() {
        return None;
    }

    let path = get_module_path_from_base_ntqvm(base)?;
    AbOut!("Opening {}", path);

    let mut file = File::open(&path).ok()?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).ok()?;

    let alloc = VirtualAlloc(None, buf.len(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) as *mut u8;

    if alloc.is_null() {
        return None;
    }

    ptr::copy_nonoverlapping(buf.as_ptr(), alloc, buf.len());
    *size_out = buf.len();

    MAPPED_NTDLL_PTR.store(alloc, Ordering::SeqCst);
    MAPPED_NTDLL_SIZE.store(buf.len(), Ordering::SeqCst);

    Some((alloc as *const u8, HANDLE(null_mut())))
}

pub unsafe fn drop_ntdll() {
    let ptr = MAPPED_NTDLL_PTR.swap(null_mut(), Ordering::SeqCst);
    let size = MAPPED_NTDLL_SIZE.swap(0, Ordering::SeqCst);

    if !ptr.is_null() {
        ptr::write_bytes(ptr, 0, size);
        VirtualFree(ptr as _, 0, MEM_RELEASE);
    }
}
