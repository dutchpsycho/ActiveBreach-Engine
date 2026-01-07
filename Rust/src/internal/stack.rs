#![allow(non_snake_case)]

use once_cell::sync::OnceCell;
use std::ops::Add;
use std::{ptr::null_mut, ffi::CString};

use windows::core::PCSTR;
use windows::Win32::System::LibraryLoader::GetModuleHandleA;
use windows::Win32::System::Memory::{
    VirtualAlloc,
    MEM_COMMIT,
    MEM_RESERVE,
    PAGE_READWRITE,
};
use windows::Win32::System::SystemServices::{
    IMAGE_DOS_HEADER,
    IMAGE_EXPORT_DIRECTORY,
};
use windows::Win32::System::Diagnostics::Debug::{IMAGE_NT_HEADERS64, IMAGE_DIRECTORY_ENTRY_EXPORT};

/// Total size of each synthetic stack page, per thread/profile (in bytes).
const SW_STACK_SIZE: usize = 0x1000;

/// Type alias for base pointer to allocated fake stack.
type StackBase = *mut u64;

/// Classification of NT syscall group to determine appropriate
/// synthetic call stack structure.
#[derive(Copy, Clone)]
enum Profile {
    /// Memory-related syscalls (e.g., `VirtualAlloc`, `VirtualProtect`)
    Memory = 0,
    /// Process-related syscalls (e.g., `OpenProcess`, `CreateProcessW`)
    Process = 1,
    /// Thread-related syscalls (e.g., `CreateRemoteThread`, `SuspendThread`)
    Thread = 2,
    /// File-mapping and image mapping syscalls (e.g., `MapViewOfFile`)
    Mapping = 3,
}

/// Thread-local synthetic stack pages used for stack spoofing.
/// One reserved page per syscall group.
thread_local! {
    static SW_PAGES: std::cell::RefCell<[Option<StackBase>; 4]> =
        std::cell::RefCell::new([None, None, None, None]);
}

/// Static structure holding pre-resolved addresses of common export functions
/// used to simulate realistic call stacks.
struct SwStackProf {
    memory:  &'static [u64],
    process: &'static [u64],
    thread:  &'static [u64],
    mapping: &'static [u64],
}

/// Lazily initialized global singleton containing spoof stack templates
/// categorized by syscall group.
static PROFILES: OnceCell<SwStackProf> = OnceCell::new();

/// Initializes the Sidewinder engine by resolving and storing
/// key export addresses that represent plausible return frames.
///
/// # Safety
/// This function must only be called once before use. It interacts with raw pointers
/// and assumes Windows PE structures are valid.
///
/// # Returns
/// `Ok(())` on success, or `Err(&'static str)` if initialization fails.
pub unsafe fn SidewinderInit() -> Result<(), &'static str> {
    PROFILES.get_or_try_init(|| {
        Ok(SwStackProf {
            memory: _SwAllocStatic(&[
                ("KERNELBASE.DLL", "VirtualAlloc"),
                ("KERNELBASE.DLL", "VirtualFree"),
                ("KERNELBASE.DLL", "VirtualProtect"),
                ("KERNEL32.DLL",   "VirtualQuery"),
                ("KERNEL32.DLL",   "GetProcessHeap"),
                ("KERNEL32.DLL",   "HeapAlloc"),
                ("KERNEL32.DLL",   "HeapFree"),
                ("NTDLL.DLL",      "RtlAllocateHeap"),
                ("NTDLL.DLL",      "RtlFreeHeap"),
                ("KERNELBASE.DLL", "LocalAlloc"),
                ("KERNELBASE.DLL", "LocalFree"),
                ("KERNELBASE.DLL", "MapViewOfFile"),
                ("KERNELBASE.DLL", "UnmapViewOfFile"),
            ])?,
            process: _SwAllocStatic(&[
                ("KERNEL32.DLL", "OpenProcess"),
                ("KERNEL32.DLL", "TerminateProcess"),
                ("KERNEL32.DLL", "CreateProcessW"),
                ("KERNEL32.DLL", "GetCurrentProcess"),
                ("KERNEL32.DLL", "GetCurrentProcessId"),
                ("NTDLL.DLL",    "RtlGetCurrentProcessId"),
                ("ADVAPI32.DLL", "OpenProcessToken"),
                ("ADVAPI32.DLL", "LookupPrivilegeValueW"),
                ("ADVAPI32.DLL", "AdjustTokenPrivileges"),
                ("ADVAPI32.DLL", "GetTokenInformation"),
                ("KERNEL32.DLL", "SetHandleInformation"),
            ])?,
            thread: _SwAllocStatic(&[
                ("KERNEL32.DLL",   "CreateRemoteThreadEx"),
                ("KERNELBASE.DLL", "SuspendThread"),
                ("KERNELBASE.DLL", "ResumeThread"),
                ("KERNEL32.DLL",   "GetCurrentThread"),
                ("KERNEL32.DLL",   "GetCurrentThreadId"),
                ("KERNEL32.DLL",   "SetThreadContext"),
                ("KERNEL32.DLL",   "GetThreadContext"),
                ("KERNEL32.DLL",   "QueueUserAPC"),
                ("KERNEL32.DLL",   "SleepEx"),
                ("NTDLL.DLL",      "RtlNtStatusToDosError"),
            ])?,
            mapping: _SwAllocStatic(&[
                ("KERNEL32.DLL",   "CreateFileMappingW"),
                ("KERNELBASE.DLL", "MapViewOfFile"),
                ("KERNELBASE.DLL", "UnmapViewOfFile"),
                ("KERNEL32.DLL",   "FlushViewOfFile"),
                ("KERNEL32.DLL",   "CreateFileW"),
                ("KERNEL32.DLL",   "ReadFile"),
                ("KERNEL32.DLL",   "WriteFile"),
                ("KERNEL32.DLL",   "CloseHandle"),
                ("KERNELBASE.DLL", "GetFileSize"),
                ("KERNEL32.DLL",   "SetFilePointerEx"),
            ])?,
        })
    })?;
    Ok(())
}

/// Allocates or retrieves a per-thread stack spoofing page
/// for a given syscall profile. Each thread only receives one page per profile.
///
/// # Safety
/// Relies on correct memory layout and page commit by VirtualAlloc.
unsafe fn _SwGetPage(profile: Profile) -> Option<StackBase> {
    SW_PAGES.with(|cell| {
        let mut pages = cell.borrow_mut();
        let idx = profile as usize;
        if let Some(ptr) = pages[idx] {
            Some(ptr)
        } else {
            let p = VirtualAlloc(
                None,
                SW_STACK_SIZE,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            ) as StackBase;
            if p.is_null() {
                return None;
            }
            pages[idx] = Some(p);
            Some(p)
        }
    })
}

/// Constructs a synthetic call stack for the specified NT syscall
/// and returns a pointer to the base of the spoofed stack.
///
/// # Arguments
/// * `nt_name` - Name of the NT syscall (e.g., "NtOpenProcess").
/// * `stub` - Pointer to the instruction following the call to syscall stub.
///
/// # Returns
/// A pointer (`usize`) to the base of the fake stack (SP value).
pub fn AbStackWinder(nt_name: &str, stub: *mut u8) -> Option<usize> {

    let profile = match nt_name {
        n if n.starts_with("NtOpenProcess")
            || n.starts_with("NtTerminateProcess") => Profile::Process,
        n if n.starts_with("NtCreateThread")
            || n.starts_with("NtSuspendThread")   => Profile::Thread,
        n if n.starts_with("NtMapView")
            || n.starts_with("NtUnmapView")       => Profile::Mapping,
        _ => Profile::Memory,
    };

    let stub_ret = unsafe { stub.add(5) as u64 };

    let tbl = PROFILES.get()?;
    let frames: &[u64] = match profile {
        Profile::Memory  => tbl.memory,
        Profile::Process => tbl.process,
        Profile::Thread  => tbl.thread,
        Profile::Mapping => tbl.mapping,
    };

    let base = unsafe { _SwGetPage(profile)? };
    let mut sp =
        unsafe { ((base.add(SW_STACK_SIZE / 8) as usize) & !0xF) as *mut u64 };

    unsafe {
        sp = sp.offset(-1);
        sp.write(stub_ret);
        for &ret in frames.iter().rev() {
            sp = sp.offset(-1);
            sp.write(ret);
        }
    }

    Some(sp as usize)
}

/// Resolves a static list of (module, export) pairs into
/// a leaked slice of absolute return addresses.
///
/// # Safety
/// Assumes all input DLLs are loaded and valid PE format.
unsafe fn _SwAllocStatic(
    pairs: &[(&str, &str)],
) -> Result<&'static [u64], &'static str> {

    let mut v = Vec::with_capacity(pairs.len());
    for &(m, e) in pairs {
        v.push(_SwResExp(m, e)?);
    }
    v.shrink_to_fit();
    Ok(Box::leak(v.into_boxed_slice()))
}

/// Resolves the absolute virtual address of a given export
/// from a loaded module.
///
/// # Safety
/// Raw pointer arithmetic on PE headers. Module must be resident.
///
/// # Arguments
/// * `module` - DLL name (e.g., `"KERNEL32.DLL"`)
/// * `export` - Export function name (e.g., `"OpenProcess"`)
///
/// # Returns
/// Absolute address of the export as `u64`, or error.
unsafe fn _SwResExp(
    module: &str,
    export: &str,
) -> Result<u64, &'static str> {

    let mod_name = cstr(module);

    let hmod = GetModuleHandleA(PCSTR(mod_name.as_ptr() as *const u8))
        .map_err(|_| "GetModuleHandleA failed")?;
    let base = hmod.0 as usize;

    let dos = &*(base as *const IMAGE_DOS_HEADER);
    if dos.e_magic != 0x5A4D {
        return Err("Bad DOS header");
    }

    let nt =
        &*((base + dos.e_lfanew as usize) as *const IMAGE_NT_HEADERS64);
    if nt.Signature != 0x0000_4550 {
        return Err("Bad NT header");
    }

    let dir = nt.OptionalHeader.DataDirectory
        [IMAGE_DIRECTORY_ENTRY_EXPORT.0 as usize]
        .VirtualAddress;
    if dir == 0 {
        return Err("No export dir");
    }

    let exp =
        &*((base + dir as usize) as *const IMAGE_EXPORT_DIRECTORY);
    let names = base + exp.AddressOfNames as usize;
    let funcs = base + exp.AddressOfFunctions as usize;
    let ords  = base + exp.AddressOfNameOrdinals as usize;

    for i in 0..exp.NumberOfNames {
        let name_rva =
            *(names.add(i as usize * 4) as *const u32) as usize;
        let name_ptr = base + name_rva;
        let bytes = core::slice::from_raw_parts(
            name_ptr as *const u8,
            export.len(),
        );
        if bytes == export.as_bytes() {
            let ord_idx =
                *(ords.add(i as usize * 2) as *const u16) as usize;
            let func_rva =
                *(funcs.add(ord_idx * 4) as *const u32) as usize;
            return Ok((base + func_rva) as u64);
        }
    }

    Err("Export not found")
}

/// Constructs a null-terminated `CString` from a Rust `&str`
/// without any validation.
///
/// # Safety
/// Panics if `s` contains interior nulls.
fn cstr(s: &str) -> CString {
    let mut v = Vec::with_capacity(s.len() + 1);
    v.extend_from_slice(s.as_bytes());
    v.push(0);
    unsafe { CString::from_vec_unchecked(v) }
}