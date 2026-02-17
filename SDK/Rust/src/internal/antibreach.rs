use once_cell::sync::{Lazy, OnceCell};
use std::mem::MaybeUninit;
use std::str;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Mutex;
use windows::Win32::Foundation::HMODULE;
use windows::Win32::System::Diagnostics::Debug::{CONTEXT, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER};
use windows::Win32::System::SystemServices::IMAGE_DOS_HEADER;

use crate::internal::stack::AbResolveNtdllStub;

#[derive(Clone, Copy, Debug)]
pub enum ViolationType {
    TebMismatch,
    SuspiciousCaller,
    DebuggerDetected,
    HardwareBreakpoint,
}

pub type ViolationHandler = fn(ViolationType);

static TEXT_RANGE: OnceCell<(usize, usize)> = OnceCell::new();
static TEXT_RANGE_FAILED: AtomicBool = AtomicBool::new(false);
static VIOLATION_COUNT: AtomicU32 = AtomicU32::new(0);
static VIOLATION_HANDLER: Lazy<Mutex<Option<ViolationHandler>>> = Lazy::new(|| Mutex::new(None));
static RTL_CAPTURE_CONTEXT: OnceCell<usize> = OnceCell::new();

#[cfg(target_arch = "x86_64")]
const CONTEXT_DEBUG_REGISTERS: u32 = 0x0010_0010;
#[cfg(target_arch = "x86")]
const CONTEXT_DEBUG_REGISTERS: u32 = 0x0001_0010;

#[repr(C)]
#[derive(Clone, Copy)]
struct ClientId {
    unique_process: usize,
    unique_thread: usize,
}

#[cfg(target_arch = "x86_64")]
const PEB_IMAGE_BASE_OFFSET: usize = 0x10;
#[cfg(target_arch = "x86")]
const PEB_IMAGE_BASE_OFFSET: usize = 0x08;

#[cfg(target_arch = "x86_64")]
const PEB_BEING_DEBUGGED_OFFSET: usize = 0x02;
#[cfg(target_arch = "x86")]
const PEB_BEING_DEBUGGED_OFFSET: usize = 0x02;

#[cfg(target_arch = "x86_64")]
const TEB_CLIENT_ID_OFFSET: usize = 0x40;
#[cfg(target_arch = "x86")]
const TEB_CLIENT_ID_OFFSET: usize = 0x20;

#[cfg(target_arch = "x86_64")]
const TEB_STACK_BASE_OFFSET: usize = 0x08;
#[cfg(target_arch = "x86")]
const TEB_STACK_BASE_OFFSET: usize = 0x04;

#[cfg(target_arch = "x86_64")]
const TEB_STACK_LIMIT_OFFSET: usize = 0x10;
#[cfg(target_arch = "x86")]
const TEB_STACK_LIMIT_OFFSET: usize = 0x08;

fn read_peb() -> *const u8 {
    #[cfg(target_arch = "x86_64")]
    {
        let peb: usize;
        unsafe {
            // PEB pointer for x64 lives at GS:[0x60].
            core::arch::asm!("mov {0}, gs:[0x60]", out(reg) peb);
        }
        return peb as *const u8;
    }

    #[cfg(target_arch = "x86")]
    {
        let peb: u32;
        unsafe {
            // PEB pointer for x86 lives at FS:[0x30].
            core::arch::asm!("mov {0:e}, fs:[0x30]", out(reg) peb);
        }
        return peb as *const u8;
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
    {
        core::ptr::null()
    }
}

fn get_current_module_handle() -> Option<HMODULE> {
    let peb = read_peb();
    if peb.is_null() {
        return None;
    }

    let base = unsafe { *(peb.add(PEB_IMAGE_BASE_OFFSET) as *const usize) };
    if base == 0 {
        return None;
    }

    Some(HMODULE(base as *mut core::ffi::c_void))
}

fn compute_section_range() -> Option<(usize, usize)> {
    unsafe {
        let module = get_current_module_handle()?;
        let base = module.0 as usize;
        let dos = (base as *const IMAGE_DOS_HEADER).as_ref()?;
        if dos.e_magic != 0x5A4D {
            return None;
        }

        let nt = (base + dos.e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
        let nt = nt.as_ref()?;
        if nt.Signature != 0x0000_4550 {
            return None;
        }

        let optional = &nt.OptionalHeader;
        let optional_ptr = optional as *const _ as *const u8;
        let first_section = optional_ptr.add(nt.FileHeader.SizeOfOptionalHeader as usize)
            as *const IMAGE_SECTION_HEADER;

        for i in 0..nt.FileHeader.NumberOfSections as usize {
            let section = first_section.add(i).as_ref()?;
            let name_bytes = &section.Name;
            let name = str::from_utf8(name_bytes)
                .unwrap_or_default()
                .trim_end_matches(char::from(0));
            if name == ".text" {
                let start = base + section.VirtualAddress as usize;
                let end = start + section.Misc.VirtualSize as usize;
                return Some((start, end));
            }
        }
    }
    None
}

fn ensure_text_range() -> Option<(usize, usize)> {
    if let Some(&bounds) = TEXT_RANGE.get() {
        return Some(bounds);
    }

    if TEXT_RANGE_FAILED.load(Ordering::Relaxed) {
        return None;
    }

    if let Some(bounds) = compute_section_range() {
        let _ = TEXT_RANGE.set(bounds);
        return Some(bounds);
    }

    TEXT_RANGE_FAILED.store(true, Ordering::Relaxed);
    None
}

fn check_teb() -> bool {
    let teb = read_teb();
    if teb.is_null() {
        return false;
    }
    let client_id = unsafe { *(teb.add(TEB_CLIENT_ID_OFFSET) as *const ClientId) };
    let (pid, tid) = current_pid_tid();
    (client_id.unique_process as u32) == pid && (client_id.unique_thread as u32) == tid
}

fn read_teb() -> *const u8 {
    #[cfg(target_arch = "x86_64")]
    {
        let teb: usize;
        unsafe {
            // NtCurrentTeb() for x64: TEB pointer is stored at GS:[0x30].
            core::arch::asm!("mov {0}, gs:[0x30]", out(reg) teb);
        }
        return teb as *const u8;
    }

    #[cfg(target_arch = "x86")]
    {
        let teb: u32;
        unsafe {
            // NtCurrentTeb() for x86: TEB pointer is stored at FS:[0x18].
            core::arch::asm!("mov {0:e}, fs:[0x18]", out(reg) teb);
        }
        return teb as *const u8;
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
    {
        core::ptr::null()
    }
}

#[inline(always)]
fn stack_bounds() -> Option<(usize, usize)> {
    let teb = read_teb();
    if teb.is_null() {
        return None;
    }
    unsafe {
        let base = *(teb.add(TEB_STACK_BASE_OFFSET) as *const usize);
        let limit = *(teb.add(TEB_STACK_LIMIT_OFFSET) as *const usize);
        if base == 0 || limit == 0 || limit >= base {
            return None;
        }
        Some((limit, base)) // [limit, base)
    }
}

#[inline(always)]
fn current_pid_tid() -> (u32, u32) {
    #[cfg(target_arch = "x86_64")]
    {
        let pid: usize;
        let tid: usize;
        unsafe {
            // TEB.ClientId.UniqueProcess / UniqueThread (no Kernel32 import).
            core::arch::asm!("mov {0}, gs:[0x40]", out(reg) pid);
            core::arch::asm!("mov {0}, gs:[0x48]", out(reg) tid);
        }
        return (pid as u32, tid as u32);
    }

    #[cfg(target_arch = "x86")]
    {
        let pid: u32;
        let tid: u32;
        unsafe {
            // TEB.ClientId.UniqueProcess / UniqueThread on x86.
            core::arch::asm!("mov {0:e}, fs:[0x20]", out(reg) pid);
            core::arch::asm!("mov {0:e}, fs:[0x24]", out(reg) tid);
        }
        return (pid, tid);
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
    {
        (0, 0)
    }
}

fn find_suspicious_return() -> Option<usize> {
    let range = ensure_text_range()?;
    let rsp = current_rsp();

    for i in 0..64 {
        let rip = unsafe { *rsp.add(i) };
        if rip < 0x10000 || rip > 0x7FFF_FFFF_FFFF {
            continue;
        }

        if rip >= range.0 && rip <= range.1 {
            continue;
        }

        return Some(rip);
    }

    None
}

#[inline(always)]
fn current_rsp() -> *const usize {
    let addr: usize;
    unsafe {
        core::arch::asm!("lea {}, [rsp]", out(reg) addr);
    }
    addr as *const usize
}

fn notify_violation(kind: ViolationType) {
    VIOLATION_COUNT.fetch_add(1, Ordering::Relaxed);
    let handler = {
        let guard = VIOLATION_HANDLER.lock().unwrap();
        *guard
    };

    if let Some(cb) = handler {
        cb(kind);
    }
}

fn is_debugger_attached() -> bool {
    // Under the hood, IsDebuggerPresent reads PEB.BeingDebugged.
    let peb = read_peb();
    if peb.is_null() {
        return false;
    }
    unsafe { *(peb.add(PEB_BEING_DEBUGGED_OFFSET) as *const u8) != 0 }
}

#[inline(always)]
fn rtl_capture_context_ptr() -> Option<usize> {
    if let Some(&p) = RTL_CAPTURE_CONTEXT.get() {
        return if p == 0 { None } else { Some(p) };
    }
    let p = AbResolveNtdllStub("RtlCaptureContext").unwrap_or(0) as usize;
    let _ = RTL_CAPTURE_CONTEXT.set(p);
    if p == 0 { None } else { Some(p) }
}

#[inline(always)]
fn capture_debug_context() -> Option<CONTEXT> {
    let p = rtl_capture_context_ptr()?;
    let f: extern "system" fn(*mut CONTEXT) = unsafe { core::mem::transmute(p as *const u8) };
    let mut ctx = MaybeUninit::<CONTEXT>::zeroed();
    unsafe {
        (*ctx.as_mut_ptr()).ContextFlags =
            windows::Win32::System::Diagnostics::Debug::CONTEXT_FLAGS(CONTEXT_DEBUG_REGISTERS);
        f(ctx.as_mut_ptr());
        Some(ctx.assume_init())
    }
}

#[inline(always)]
fn debug_regs_enabled(dr7: usize) -> bool {
    (dr7 & 0xFF) != 0
}

#[inline(always)]
fn hw_breakpoint_present(ctx: &CONTEXT) -> bool {
    let dr7 = ctx.Dr7 as usize;
    if !debug_regs_enabled(dr7) {
        return false;
    }
    // Any enabled slot is suspicious, even if address is zeroed.
    true
}

#[inline(always)]
fn hw_breakpoint_on_stack(ctx: &CONTEXT) -> bool {
    let (limit, base) = match stack_bounds() {
        Some(v) => v,
        None => return false,
    };
    let drs = [ctx.Dr0 as usize, ctx.Dr1 as usize, ctx.Dr2 as usize, ctx.Dr3 as usize];
    drs.iter().any(|&dr| dr >= limit && dr < base)
}

#[inline(never)]
fn terminate_hard() -> ! {
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    unsafe {
        core::arch::asm!("ud2", options(noreturn));
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
    unsafe {
        core::intrinsics::abort();
    }
}

pub fn AbEvaluate() {
    if is_debugger_attached() {
        notify_violation(ViolationType::DebuggerDetected);
        #[cfg(all(feature = "secure", not(debug_assertions)))]
        terminate_hard();
        #[cfg(not(all(feature = "secure", not(debug_assertions))))]
        return;
    }

    if !check_teb() {
        notify_violation(ViolationType::TebMismatch);
        return;
    }

    if find_suspicious_return().is_some() {
        notify_violation(ViolationType::SuspiciousCaller);
    }
}

/// Fast hardware-breakpoint detection (DR0-DR3/DR7) with stack-bound check.
///
/// Terminates immediately if any enabled hardware breakpoint is detected.
#[inline(always)]
pub fn AbCheckHWBP() {
    let ctx = match capture_debug_context() {
        Some(c) => c,
        None => return,
    };

    if !debug_regs_enabled(ctx.Dr7 as usize) {
        return;
    }

    if hw_breakpoint_present(&ctx) || hw_breakpoint_on_stack(&ctx) {
        notify_violation(ViolationType::HardwareBreakpoint);
        terminate_hard();
    }
}

/// Registers a violation handler that will be invoked every time a violation fires.
pub fn AbRegisterViolationHandler(handler: ViolationHandler) {
    let mut guard = VIOLATION_HANDLER.lock().unwrap();
    *guard = Some(handler);
}

/// Clears the registered violation handler.
pub fn AbClearViolationHandler() {
    let mut guard = VIOLATION_HANDLER.lock().unwrap();
    *guard = None;
}

/// Returns the number of times a violation was detected.
pub fn AbViolationCount() -> u32 {
    VIOLATION_COUNT.load(Ordering::Relaxed)
}
