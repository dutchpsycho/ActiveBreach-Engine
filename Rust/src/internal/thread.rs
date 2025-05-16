//! ActiveBreach thread spawner and TEB manipulator.
//!
//! This module provides functions to:
//! - Map a clean copy of `ntdll.dll`, extract syscall stubs, and spawn a hidden thread via `NtCreateThreadEx`.
//! - Build a direct syscall stub in RWX memory.
//! - “Soft-nuke” the TEB of the current thread to erase tracking artifacts (last error, user pointer, start address).

use std::ptr::{null_mut, write_bytes};
use winapi::shared::ntdef::{HANDLE, NTSTATUS, PVOID};
use winapi::um::{
    handleapi::CloseHandle,
    libloaderapi::GetModuleHandleA,
    memoryapi::{VirtualAlloc, VirtualProtect},
    winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE},
};

use crate::internal::{dispatch, exports, file_buffer};

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
pub unsafe fn spawn_ab_thread() -> Result<(), &'static str> {
    // 1) Map raw ntdll.dll file into memory
    let mut mapped_size = 0;
    let (mapped_base, map_handle) = file_buffer::buffer(&mut mapped_size)
        .ok_or("ActiveBreach: file buffer fail")?;

    // 2) Extract syscall numbers into the global table
    exports::extract_syscalls(mapped_base, mapped_size);

    // 3) Lookup NtCreateThreadEx in the table
    let table = exports::get_syscall_table()
        .ok_or("ActiveBreach: call table missing")?;
    let ssn = *table
        .get("NtCreateThreadEx")
        .ok_or("ActiveBreach: Call missing")?;

    // 4) Build a small RWX stub that directly invokes the syscall
    let syscall = direct_syscall_stub(ssn)
        .ok_or("ActiveBreach: failed to create stub")?;

    // 5) Invoke NtCreateThreadEx via the stub
    let mut thread: HANDLE = null_mut();
    let status = syscall(
        &mut thread,
        0x1FFFFF,                     // THREAD_ALL_ACCESS
        null_mut(),                   // OBJECT_ATTRIBUTES*
        -1isize as HANDLE,            // Pseudo-handle for current process
        dispatch::thread_proc as *mut _, // LPTHREAD_START_ROUTINE
        null_mut(),                   // Parameter
        0x00000004,                   // THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER
        0, 0, 0,
        null_mut(),                   // ClientId*
    );
    if status != 0 {
        return Err("ActiveBreach: thread creation failed");
    }

    // 6) Clean up mapping and close the thread handle
    file_buffer::unmap_and_close(mapped_base, map_handle);
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
) -> Option<unsafe extern "system" fn(
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
) -> NTSTATUS> {
    // Allocate 0x20 bytes RWX
    let stub = VirtualAlloc(
        null_mut(),
        0x20,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    ) as *mut u8;
    if stub.is_null() {
        return None;
    }

    // Machine code template for mov r10, rcx; mov eax, ssn; syscall; ret
    let tmpl: [u8; 11] = [
        0x4C, 0x8B, 0xD1,             // mov r10, rcx
        0xB8,                         // mov eax, imm32
        (ssn & 0xFF) as u8,
        ((ssn >> 8) & 0xFF) as u8,
        ((ssn >> 16) & 0xFF) as u8,
        ((ssn >> 24) & 0xFF) as u8,
        0x0F, 0x05,                   // syscall
        0xC3,                         // ret
    ];

    // Copy the stub bytes into the page
    std::ptr::copy_nonoverlapping(tmpl.as_ptr(), stub, tmpl.len());

    // Downgrade to RX (optional)
    let mut old = 0;
    VirtualProtect(stub as _, 0x20, PAGE_EXECUTE_READ, &mut old);

    // Cast page to function pointer
    Some(std::mem::transmute(stub))
}

/// “Soft-nukes” the current thread’s TEB for stealth/hardening:
/// - Clears the LastErrorValue field to 0.
/// - Clears the ArbitraryUserPointer to null.
/// - Overwrites the StartAddress (SubSystemTib) with the base of `ntdll.dll`,
///   so ETW / EDR sees the thread entry as a legitimate ntdll call.
///
/// # Safety
/// - Inline assembly reads `gs:[0x30]` to obtain the TEB pointer.
/// - Assumes the TEB layout and offsets are correct for this Windows version.
/// - Must be run at thread start before any critical operations.
pub unsafe fn nuke_teb_soft() {
    // Load TEB base from GS segment
    let teb: *mut u8;
    core::arch::asm!("mov {}, gs:[0x30]", out(reg) teb);

    // Current RSP to confirm we’re on a non-main thread stack
    let rsp: usize;
    core::arch::asm!("mov {}, rsp", out(reg) rsp);

    let stack_base = *(teb.add(OFFSET_TEB_STACK_BASE) as *const usize);
    let stack_limit = *(teb.add(OFFSET_TEB_STACK_LIMIT) as *const usize);
    if rsp < stack_limit || rsp > stack_base {
        // Probably the main thread or invalid stack; skip nuking
        return;
    }

    // Zero out LastErrorValue
    (teb.add(OFFSET_TEB_LAST_ERROR) as *mut u32).write_volatile(0);

    // Clear ArbitraryUserPointer
    (teb.add(OFFSET_TEB_ARBITRARY_PTR) as *mut *mut u8).write_volatile(null_mut());

    // Spoof StartAddress to point into ntdll.dll base
    let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr() as _);
    if !ntdll.is_null() {
        (teb.add(OFFSET_TEB_START_ADDR) as *mut PVOID).write_volatile(ntdll as PVOID);
    }
}