//! Memory-management wrappers that avoid importing `VirtualAlloc`/`VirtualProtect`/`VirtualFree`.
//!
//! Design:
//! - Resolve the loaded `ntdll.dll` base via PEB walk (no WinAPI, no IAT).
//! - Resolve `ntdll!Nt{Allocate,Protect,Free}VirtualMemory` export entry.
//! - Scan inside the entry stub for an intact syscall prologue within `.text`.
//! - Call the prologue via an `extern "system"` function pointer.
//!
//! If the export stub is fully hooked (no intact syscall prologue), these wrappers fail
//! (return null/false). That is intentional: there is no safe "jump to entry" fallback.

use std::sync::OnceLock;

use windows::Win32::Foundation::{HANDLE, NTSTATUS};
use windows::Win32::System::Diagnostics::Debug::{IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER};
use windows::Win32::System::Memory::{MEM_COMMIT, MEM_RELEASE, MEM_RESERVE};
use windows::Win32::System::SystemServices::IMAGE_DOS_HEADER;

use crate::internal::stack::{AbGetModuleBasePeb, AbResolveNtdllStub};

type ULONG = u32;
type UlongPtr = usize;
type SizeT = usize;
type PVOID = *mut core::ffi::c_void;

type NtAllocateVirtualMemoryFn = unsafe extern "system" fn(
    ProcessHandle: HANDLE,
    BaseAddress: *mut PVOID,
    ZeroBits: UlongPtr,
    RegionSize: *mut SizeT,
    AllocationType: ULONG,
    Protect: ULONG,
) -> NTSTATUS;

type NtProtectVirtualMemoryFn = unsafe extern "system" fn(
    ProcessHandle: HANDLE,
    BaseAddress: *mut PVOID,
    RegionSize: *mut SizeT,
    NewProtect: ULONG,
    OldProtect: *mut ULONG,
) -> NTSTATUS;

type NtFreeVirtualMemoryFn = unsafe extern "system" fn(
    ProcessHandle: HANDLE,
    BaseAddress: *mut PVOID,
    RegionSize: *mut SizeT,
    FreeType: ULONG,
) -> NTSTATUS;

static NTDLL_TEXT: OnceLock<(usize, usize)> = OnceLock::new(); // (start,end)
static NT_ALLOC_PRO: OnceLock<usize> = OnceLock::new();
static NT_PROTECT_PRO: OnceLock<usize> = OnceLock::new();
static NT_FREE_PRO: OnceLock<usize> = OnceLock::new();

#[inline(always)]
fn nt_success(st: NTSTATUS) -> bool {
    st.0 >= 0
}

fn ntdll_text_range() -> Option<(usize, usize)> {
    let (start, end) = *NTDLL_TEXT.get_or_init(|| unsafe {
        let base = match AbGetModuleBasePeb("NTDLL.DLL") {
            Some(b) => b,
            None => return (0, 0),
        };

        let dos = &*(base as *const IMAGE_DOS_HEADER);
        if dos.e_magic != 0x5A4D {
            return (0, 0);
        }

        let nt = &*((base + dos.e_lfanew as usize) as *const IMAGE_NT_HEADERS64);
        if nt.Signature != 0x0000_4550 {
            return (0, 0);
        }

        let num_secs = nt.FileHeader.NumberOfSections as usize;
        let sec_ptr = (nt as *const _ as usize + core::mem::size_of::<IMAGE_NT_HEADERS64>())
            as *const IMAGE_SECTION_HEADER;
        let secs = core::slice::from_raw_parts(sec_ptr, num_secs);

        for s in secs {
            if s.Name[..5] == [b'.', b't', b'e', b'x', b't'] {
                let s_start = base + s.VirtualAddress as usize;
                let s_size = s.Misc.VirtualSize as usize;
                let s_end = s_start.saturating_add(s_size);
                return (s_start, s_end);
            }
        }

        (0, 0)
    });

    if start == 0 || end <= start {
        None
    } else {
        Some((start, end))
    }
}

#[inline(always)]
fn find_syscall_prologue_offset(code: &[u8]) -> Option<usize> {
    // Require the canonical x64 pattern:
    //   mov r10, rcx; mov eax, imm32; ...; syscall; ret
    //
    // Do NOT accept a bare `mov eax; syscall` since skipping `mov r10, rcx` can break the call.
    let scan_len = code.len().min(96);
    let code = &code[..scan_len];

    for i in 0..code.len().saturating_sub(11) {
        let head = &code[i..];
        let has_mov = head.starts_with(&[0x4C, 0x8B, 0xD1, 0xB8])
            || head.starts_with(&[0x4D, 0x8B, 0xD1, 0xB8]);
        if !has_mov {
            continue;
        }

        // Find `syscall; ret` shortly after the SSN load. We allow the optional `test/jne` block.
        let end = code.len().min(i + 64);
        for j in (i + 4)..end.saturating_sub(2) {
            if code[j] == 0x0F && code[j + 1] == 0x05 && code[j + 2] == 0xC3 {
                return Some(i);
            }
        }
    }

    None
}

fn resolve_ntdll_prologue(nt_name: &str) -> Option<usize> {
    let (tstart, tend) = ntdll_text_range()?;
    let entry = AbResolveNtdllStub(nt_name)? as usize;

    const SCAN_LEN: usize = 96;
    if entry < tstart || entry.checked_add(SCAN_LEN).is_none_or(|e| e > tend) {
        return None;
    }

    // Safe due to `.text` bound check above.
    let code = unsafe { core::slice::from_raw_parts(entry as *const u8, SCAN_LEN) };
    let off = find_syscall_prologue_offset(code)?;
    Some(entry + off)
}

/// Resolves an intact loaded-NTDLL syscall prologue pointer for the given `Nt*` name.
///
/// Returns `None` if:
/// - `ntdll.dll` isn't loaded
/// - export cannot be resolved
/// - export entry isn't inside `.text`
/// - no intact `mov r10, rcx; ...; syscall; ret` prologue exists (fully-hooked stub)
pub fn AbResolveNtdllSyscallPrologue(nt_name: &str) -> Option<usize> {
    resolve_ntdll_prologue(nt_name)
}

#[inline(always)]
fn nt_allocate_prologue() -> Option<usize> {
    if let Some(p) = NT_ALLOC_PRO.get().copied() {
        return Some(p);
    }
    let p = resolve_ntdll_prologue("NtAllocateVirtualMemory")?;
    let _ = NT_ALLOC_PRO.set(p); // allow racing inits; ignore loser
    Some(p)
}

#[inline(always)]
fn nt_protect_prologue() -> Option<usize> {
    if let Some(p) = NT_PROTECT_PRO.get().copied() {
        return Some(p);
    }
    let p = resolve_ntdll_prologue("NtProtectVirtualMemory")?;
    let _ = NT_PROTECT_PRO.set(p);
    Some(p)
}

#[inline(always)]
fn nt_free_prologue() -> Option<usize> {
    if let Some(p) = NT_FREE_PRO.get().copied() {
        return Some(p);
    }
    let p = resolve_ntdll_prologue("NtFreeVirtualMemory")?;
    let _ = NT_FREE_PRO.set(p);
    Some(p)
}

/// Allocate memory in the current process using `ntdll!NtAllocateVirtualMemory` prologue.
pub unsafe fn AbVirtualAlloc(size: usize, protect: u32) -> *mut u8 {
    let pro = match nt_allocate_prologue() {
        Some(p) => p,
        None => return core::ptr::null_mut(),
    };

    let f: NtAllocateVirtualMemoryFn = core::mem::transmute(pro as *const u8);
    let proc = HANDLE((-1isize) as *mut core::ffi::c_void);
    let mut base: PVOID = core::ptr::null_mut();
    let mut region: SizeT = size;

    let st = f(
        proc,
        &mut base as *mut PVOID,
        0,
        &mut region as *mut SizeT,
        (MEM_COMMIT | MEM_RESERVE).0,
        protect,
    );

    if !nt_success(st) {
        return core::ptr::null_mut();
    }
    base as *mut u8
}

/// Change protection using `ntdll!NtProtectVirtualMemory` prologue.
pub unsafe fn AbVirtualProtect(addr: *mut u8, len: usize, new_protect: u32, old_protect: &mut u32) -> bool {
    let pro = match nt_protect_prologue() {
        Some(p) => p,
        None => return false,
    };

    let f: NtProtectVirtualMemoryFn = core::mem::transmute(pro as *const u8);
    let proc = HANDLE((-1isize) as *mut core::ffi::c_void);
    let mut base: PVOID = addr as PVOID;
    let mut region: SizeT = len;
    let mut old: ULONG = 0;

    let st = f(
        proc,
        &mut base as *mut PVOID,
        &mut region as *mut SizeT,
        new_protect,
        &mut old as *mut ULONG,
    );
    *old_protect = old;
    nt_success(st)
}

/// Free memory using `ntdll!NtFreeVirtualMemory` prologue.
pub unsafe fn AbVirtualFree(addr: *mut u8) -> bool {
    let pro = match nt_free_prologue() {
        Some(p) => p,
        None => return false,
    };

    let f: NtFreeVirtualMemoryFn = core::mem::transmute(pro as *const u8);
    let proc = HANDLE((-1isize) as *mut core::ffi::c_void);
    let mut base: PVOID = addr as PVOID;
    let mut region: SizeT = 0;

    let st = f(
        proc,
        &mut base as *mut PVOID,
        &mut region as *mut SizeT,
        MEM_RELEASE.0,
    );
    nt_success(st)
}
