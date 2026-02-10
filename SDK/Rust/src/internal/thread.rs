//! ActiveBreach thread spawner and TEB manipulator.
//!
//! This module provides functions to:
//! - Map a clean copy of `ntdll.dll`, extract syscall stubs, and spawn a hidden thread via `NtCreateThreadEx`.
//! - Build a direct syscall stub in RWX memory.

use std::ptr::null_mut;

use windows::Win32::Foundation::CloseHandle;
use windows::Win32::Foundation::{HANDLE, NTSTATUS};
use windows::Win32::System::Memory::{
    VirtualAlloc, VirtualFree, VirtualProtect, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
    PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
};
use windows::Win32::System::Threading::GetCurrentProcess;

use crate::internal::diagnostics::*;
use crate::internal::stub_template::write_syscall_stub;
use crate::internal::{dispatch, exports, mapper};

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
    let mut mapped_size = 0;
    let (mapped_base, _) =
        mapper::buffer(&mut mapped_size).ok_or_else(|| ABErr(ABError::ThreadFilemapFail))?;

    if exports::ExSyscalls(mapped_base, mapped_size).is_err() {
        return Err(ABErr(ABError::ThreadSyscallInitFail));
    }

    let table =
        exports::get_syscall_table().ok_or_else(|| ABErr(ABError::ThreadSyscallTableMiss))?;

    let ssn = *table
        .get("NtCreateThreadEx")
        .ok_or_else(|| ABErr(ABError::ThreadNtCreateMissing))?;

    let stub_ptr =
        VirtualAlloc(None, 0x20, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) as *mut u8;

    if stub_ptr.is_null() {
        return Err(ABErr(ABError::ThreadStubAllocFail));
    }

    write_syscall_stub(stub_ptr, ssn);

    #[cfg(feature = "secure")]
    {
        let mut old = PAGE_EXECUTE_READWRITE;
        VirtualProtect(stub_ptr as _, 0x20, PAGE_EXECUTE_READ, &mut old);
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
        GetCurrentProcess(),
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
        VirtualProtect(
            stub_ptr as _,
            0x20,
            PAGE_EXECUTE_READWRITE,
            &mut old,
        );
    }
    std::ptr::write_bytes(stub_ptr, 0x00, 0x20);
    VirtualFree(stub_ptr as _, 0, MEM_RELEASE);

    if status != 0 {
        return Err(ABErr(ABError::ThreadCreateFail));
    }

    CloseHandle(thread);
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

    write_syscall_stub(stub, ssn);

    #[cfg(feature = "secure")]
    {
        let mut old = PAGE_EXECUTE_READWRITE;
        VirtualProtect(stub as _, 0x20, PAGE_EXECUTE_READ, &mut old);
    }

    Some(std::mem::transmute(stub))
}
