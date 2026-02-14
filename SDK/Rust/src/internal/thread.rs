//! ActiveBreach thread spawner and TEB manipulator.
//!
//! This module provides functions to:
//! - Map a clean copy of `ntdll.dll`, extract syscall stubs, and spawn a hidden thread via `NtCreateThreadEx`.
//! - Build a direct syscall stub in RWX memory.

use std::ptr::null_mut;

use windows::Win32::Foundation::{HANDLE, NTSTATUS};
use windows::Win32::System::Memory::{
    VirtualAlloc, VirtualFree, VirtualProtect, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
    PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
};

use crate::internal::diagnostics::*;
use crate::internal::stub_template::write_syscall_stub_plain;
use crate::internal::{dispatch, exports};

#[link(name = "ntdll")]
extern "system" {
    fn NtClose(Handle: HANDLE) -> NTSTATUS;
}

#[inline(always)]
fn current_process() -> HANDLE {
    // Under the hood, GetCurrentProcess() is a pseudo-handle: (HANDLE)-1.
    HANDLE((-1isize) as *mut core::ffi::c_void)
}

/// Offset of StackBase in the Thread Environment Block (TEB).
const OFFSET_TEB_STACK_BASE: usize = 0x08;
/// Offset of StackLimit in the TEB.
const OFFSET_TEB_STACK_LIMIT: usize = 0x10;
/// Offset of LastErrorValue in the TEB.
const OFFSET_TEB_LAST_ERROR: usize = 0x68;
/// Offset of ArbitraryUserPointer in the TEB (commonly used by debuggers).
const OFFSET_TEB_ARBITRARY_PTR: usize = 0x28;
/// Offset of SubSystemTib.StartAddress in the TEB (used for API call origin spoofing).
const OFFSET_TEB_START_ADDR: usize = 0x1720;

/// Maps `ntdll.dll` into memory, extracts the syscall table, builds a direct
/// `NtCreateThreadEx` stub, and spawns a new thread hidden from the debugger.
///
/// # Safety
/// - Must be called in a context where `file_buffer::buffer` returns a valid mapped copy of `ntdll.dll`.
/// - Relies on `extract_syscalls` having not already been run in this process.
/// - Assumes the caller can `CloseHandle` on the spawned thread safely.
///
/// # Errors
/// Returns `Err(&'static str)` if any step fails:
/// - File buffer mapping fails.
/// - Syscall table is missing.
/// - `NtCreateThreadEx` entry is not found.
/// - Stub creation fails.
/// - The syscall itself returns a non-zero status.
pub unsafe fn _SpawnActiveBreachThread() -> Result<(), u32> {
    exports::ensure_syscall_table_init().map_err(|_| ABErr(ABError::ThreadSyscallInitFail))?;

    let ssn = exports::lookup_ssn("NtCreateThreadEx")
        .ok_or_else(|| ABErr(ABError::ThreadNtCreateMissing))?;

    let stub_ptr =
        VirtualAlloc(None, 0x20, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) as *mut u8;

    if stub_ptr.is_null() {
        return Err(ABErr(ABError::ThreadStubAllocFail));
    }

    write_syscall_stub_plain(stub_ptr, ssn);

    #[cfg(feature = "secure")]
    {
        let mut old = PAGE_EXECUTE_READWRITE;
        let _ = VirtualProtect(stub_ptr as _, 0x20, PAGE_EXECUTE_READ, &mut old);
    }

    let syscall: unsafe extern "system" fn(
        *mut HANDLE,
        u32,
        *mut u8,
        HANDLE,
        *mut u8,
        *mut u8,
        u32,
        usize,
        usize,
        usize,
        *mut u8,
    ) -> i32 = std::mem::transmute(stub_ptr);

    let mut thread: HANDLE = HANDLE(null_mut());
    let status = syscall(
        &mut thread,
        0x1FFFFF,
        null_mut(),
        current_process(),
        dispatch::thread_proc as *mut _,
        null_mut(),
        0x00000004,
        0,
        0,
        0,
        null_mut(),
    );

    #[cfg(feature = "secure")]
    {
        let mut old = PAGE_EXECUTE_READ;
        let _ = VirtualProtect(stub_ptr as _, 0x20, PAGE_EXECUTE_READWRITE, &mut old);
    }
    std::ptr::write_bytes(stub_ptr, 0x00, 0x20);
    let _ = VirtualFree(stub_ptr as _, 0, MEM_RELEASE);

    if status != 0 {
        return Err(ABErr(ABError::ThreadCreateFail));
    }

    // Under the hood, CloseHandle() => NtClose(). Avoid importing Kernel32.
    let _ = NtClose(thread);
    Ok(())
}

/// Builds a tiny in-memory stub at a freshly-allocated RWX page that
/// directly executes the given syscall number (`ssn`), then returns.
///
/// The generated stub has the layout:
/// ```asm
///     mov r10, rcx
///     mov eax, imm32    ; low 32 bits = ssn
///     syscall
///     ret
/// ```
///
/// # Safety
/// - Allocates an executable page with `VirtualAlloc`.
/// - Uses `transmute` to cast a data pointer into a function pointer.
/// - Caller must eventually treat this stub as code and never modify it.
///
/// # Returns
/// - `Some(fn)` if allocation and copy succeed.
/// - `None` if `VirtualAlloc` fails.
pub unsafe fn direct_syscall_stub(
    ssn: u32,
) -> Option<
    unsafe extern "system" fn(
        *mut HANDLE,
        u32,
        *mut u8,
        HANDLE,
        *mut u8,
        *mut u8,
        u32,
        usize,
        usize,
        usize,
        *mut u8,
    ) -> NTSTATUS,
> {
    let stub =
        VirtualAlloc(None, 0x20, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) as *mut u8;

    if stub.is_null() {
        return None;
    }

    write_syscall_stub_plain(stub, ssn);

    #[cfg(feature = "secure")]
    {
        let mut old = PAGE_EXECUTE_READWRITE;
        let _ = VirtualProtect(stub as _, 0x20, PAGE_EXECUTE_READ, &mut old);
    }

    Some(std::mem::transmute(stub))
}
