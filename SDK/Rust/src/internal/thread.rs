//! ActiveBreach thread spawner and TEB manipulator.
//!
//! This module provides functions to:
//! - Map a clean copy of `ntdll.dll`, extract syscall stubs, and spawn a hidden thread via `NtCreateThreadEx`.
//! - Build a direct syscall stub in RWX memory.

use std::ptr::null_mut;

use windows::Win32::Foundation::{HANDLE, NTSTATUS};

use crate::internal::diagnostics::*;
use crate::internal::{dispatch, exports};
use crate::internal::vm;

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
pub unsafe fn AbSpawnActiveBreachThread() -> Result<(), u32> {
    exports::AbEnsureSyscallTableInit().map_err(|_| AbErr(ABError::ThreadSyscallInitFail))?;

    let pro = vm::AbResolveNtdllSyscallPrologue("NtCreateThreadEx")
        .ok_or_else(|| AbErr(ABError::ThreadNtCreateMissing))?;

    let nt_create_thread_ex: unsafe extern "system" fn(
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
    ) -> NTSTATUS = std::mem::transmute(pro as *const u8);

    let mut thread: HANDLE = HANDLE(null_mut());
    let status = nt_create_thread_ex(
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

    if status.0 != 0 {
        return Err(AbErr(ABError::ThreadCreateFail));
    }

    // Intentionally do not close the returned thread HANDLE here. This avoids introducing
    // a close-call dependency at launch time. If the caller needs the handle, expose it at
    // the API boundary and close it there.
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
pub unsafe fn AbDirectSyscallStub(
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
        vm::AbVirtualAlloc(0x20, windows::Win32::System::Memory::PAGE_EXECUTE_READWRITE.0);

    if stub.is_null() {
        return None;
    }

    crate::internal::stub_template::write_syscall_stub_plain(stub, ssn);

    #[cfg(feature = "secure")]
    {
        let mut old: u32 = windows::Win32::System::Memory::PAGE_EXECUTE_READWRITE.0;
        let _ = vm::AbVirtualProtect(
            stub,
            0x20,
            windows::Win32::System::Memory::PAGE_EXECUTE_READ.0,
            &mut old,
        );
    }

    Some(std::mem::transmute(stub))
}
