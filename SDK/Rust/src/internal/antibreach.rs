use once_cell::sync::{Lazy, OnceCell};
use std::str;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Mutex;
use windows::core::{PCWSTR, Result};
use windows::Win32::Foundation::HMODULE;
use windows::Win32::System::Diagnostics::Debug::{
    IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER, IsDebuggerPresent,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::SystemServices::IMAGE_DOS_HEADER;
use windows::Win32::System::Threading::{GetCurrentProcessId, GetCurrentThreadId};

#[derive(Clone, Copy, Debug)]
pub enum ViolationType {
    TebMismatch,
    SuspiciousCaller,
    DebuggerDetected,
}

pub type ViolationHandler = fn(ViolationType);

static TEXT_RANGE: OnceCell<(usize, usize)> = OnceCell::new();
static TEXT_RANGE_FAILED: AtomicBool = AtomicBool::new(false);
static VIOLATION_COUNT: AtomicU32 = AtomicU32::new(0);
static VIOLATION_HANDLER: Lazy<Mutex<Option<ViolationHandler>>> = Lazy::new(|| Mutex::new(None));

#[repr(C)]
#[derive(Clone, Copy)]
struct ClientId {
    unique_process: usize,
    unique_thread: usize,
}

fn get_current_module_handle() -> Result<HMODULE> {
    unsafe { GetModuleHandleW(PCWSTR::null()) }
}

fn compute_section_range() -> Option<(usize, usize)> {
    unsafe {
        let module = get_current_module_handle().ok()?;
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
        let first_section = optional_ptr
            .add(nt.FileHeader.SizeOfOptionalHeader as usize)
            as *const IMAGE_SECTION_HEADER;

        for i in 0..nt.FileHeader.NumberOfSections as usize {
            let section = first_section.add(i).as_ref()?;
            let name_bytes = &section.Name;
            let name =
                str::from_utf8(name_bytes).unwrap_or_default().trim_end_matches(char::from(0));
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
    let client_id = unsafe { *(teb.add(0x40) as *const ClientId) };
    let (pid, tid) = unsafe { (GetCurrentProcessId(), GetCurrentThreadId()) };
    (client_id.unique_process as u32) == pid && (client_id.unique_thread as u32) == tid
}

fn read_teb() -> *const u8 {
    let teb: usize;
    unsafe {
        core::arch::asm!("mov {0}, gs:[0x30]", out(reg) teb);
    }
    teb as *const u8
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
    unsafe { IsDebuggerPresent().as_bool() }
}

/// Runs the AntiBreach-style integrity checks and triggers alerts.
pub fn evaluate() {
    if is_debugger_attached() {
        notify_violation(ViolationType::DebuggerDetected);
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

/// Registers a violation handler that will be invoked every time a violation fires.
pub fn register_violation_handler(handler: ViolationHandler) {
    let mut guard = VIOLATION_HANDLER.lock().unwrap();
    *guard = Some(handler);
}

/// Clears the registered violation handler.
pub fn clear_violation_handler() {
    let mut guard = VIOLATION_HANDLER.lock().unwrap();
    *guard = None;
}

/// Returns the number of times a violation was detected.
pub fn violation_count() -> u32 {
    VIOLATION_COUNT.load(Ordering::Relaxed)
}
