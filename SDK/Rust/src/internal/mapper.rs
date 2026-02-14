use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::Read;
use std::mem;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::ptr;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{HANDLE, NTSTATUS, UNICODE_STRING};
use windows::Win32::Storage::FileSystem::QueryDosDeviceW;
#[cfg(feature = "ntdll_backend")]
use windows::Win32::System::Diagnostics::Debug::{IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER};
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE,
};
#[cfg(feature = "ntdll_backend")]
use windows::Win32::System::SystemServices::IMAGE_DOS_HEADER;

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
    buf: Vec<u8>,
}

unsafe impl Send for MappedImage {}
unsafe impl Sync for MappedImage {}

impl MappedImage {
    #[inline(always)]
    pub(in crate::internal) fn as_ptr(&self) -> *const u8 {
        self.buf.as_ptr()
    }

    #[inline(always)]
    pub(in crate::internal) fn size(&self) -> usize {
        self.buf.len()
    }
}

impl Drop for MappedImage {
    fn drop(&mut self) {
        if self.buf.is_empty() {
            return;
        }
        // Best-effort wipe. The allocator will free as part of Vec drop.
        unsafe { ptr::write_bytes(self.buf.as_mut_ptr(), 0, self.buf.len()) };
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

#[cfg(feature = "ntdll_backend")]
pub(in crate::internal) unsafe fn loaded_ntdll_text_range() -> Option<(*const u8, usize)> {
    let base = resolve_ntdll_base_no_strings() as usize;
    if base == 0 {
        return None;
    }

    let dos = &*(base as *const IMAGE_DOS_HEADER);
    if dos.e_magic != 0x5A4D {
        return None;
    }

    let nt = &*((base + dos.e_lfanew as usize) as *const IMAGE_NT_HEADERS64);
    if nt.Signature != 0x0000_4550 {
        return None;
    }

    let num_secs = nt.FileHeader.NumberOfSections as usize;
    let sec_ptr = (nt as *const _ as usize + core::mem::size_of::<IMAGE_NT_HEADERS64>())
        as *const IMAGE_SECTION_HEADER;
    let secs = core::slice::from_raw_parts(sec_ptr, num_secs);

    for s in secs {
        // IMAGE_SECTION_HEADER.Name is an 8-byte, NUL-padded ANSI string.
        if s.Name[..5] == [b'.', b't', b'e', b'x', b't'] {
            let start = base + s.VirtualAddress as usize;
            let size = unsafe { s.Misc.VirtualSize as usize };
            return Some((start as *const u8, size));
        }
    }

    None
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
    // Keep the image in a plain Vec. Avoid using VirtualAlloc/VirtualFree during init.
    let _ = (MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE); // keep constants referenced for callers
    Some(MappedImage { buf })
}
