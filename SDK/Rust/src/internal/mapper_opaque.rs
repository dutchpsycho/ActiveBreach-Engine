use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::Read;
use std::mem;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::ptr;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{HANDLE, NTSTATUS, UNICODE_STRING};
use windows::Win32::Storage::FileSystem::QueryDosDeviceW;
use windows::Win32::System::Memory::{
    VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
};

use crate::AbOut;

#[inline(always)]
fn nt_success(status: NTSTATUS) -> bool {
    status.0 >= 0
}

#[inline(always)]
fn current_process() -> HANDLE {
    // Under the hood, GetCurrentProcess() is a pseudo-handle: (HANDLE)-1.
    HANDLE((-1isize) as *mut core::ffi::c_void)
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

/// Opaque mapped-image handle (owned). Drops will wipe and `VirtualFree`.
pub(in crate::internal) struct MappedImage {
    base: usize,
    size: usize,
}

unsafe impl Send for MappedImage {}
unsafe impl Sync for MappedImage {}

impl MappedImage {
    #[inline(always)]
    pub(in crate::internal) fn as_ptr(&self) -> *const u8 {
        self.base as *const u8
    }

    #[inline(always)]
    pub(in crate::internal) fn size(&self) -> usize {
        self.size
    }
}

impl Drop for MappedImage {
    fn drop(&mut self) {
        let p = self.base as *mut u8;
        if p.is_null() || self.size == 0 {
            return;
        }
        unsafe {
            ptr::write_bytes(p, 0, self.size);
            let _ = VirtualFree(p as _, 0, MEM_RELEASE);
        }
        self.base = 0;
        self.size = 0;
    }
}

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
    let process = current_process();
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
    let process = current_process();
    let mut ret_len = 0usize;

    let _ = NtQueryVirtualMemory(
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

pub(in crate::internal) unsafe fn map_ntdll_image() -> Option<MappedImage> {
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

    Some(MappedImage {
        base: alloc as usize,
        size: buf.len(),
    })
}
