#![allow(non_snake_case)]

use std::borrow::Cow;
use std::ffi::CString;
use std::ops::Add;

use windows::Win32::Foundation::UNICODE_STRING;
use windows::Win32::System::Diagnostics::Debug::{
    IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_NT_HEADERS64,
};
#[cfg(not(feature = "ntdll_backend"))]
use windows::Win32::System::Memory::{PAGE_READWRITE};
use windows::Win32::System::SystemServices::{IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY};

/// Total size of each synthetic stack page, per thread (in bytes).
#[cfg(not(feature = "ntdll_backend"))]
const SW_STACK_SIZE: usize = 0x1000;

#[repr(C)]
#[derive(Clone, Copy)]
struct LIST_ENTRY {
    flink: *const LIST_ENTRY,
    blink: *const LIST_ENTRY,
}

#[repr(C)]
struct PEB_LDR_DATA {
    _len: u32,
    _initialized: u8,
    _pad0: [u8; 3],
    _ss_handle: *mut core::ffi::c_void,
    _in_load_order: LIST_ENTRY,
    in_memory_order: LIST_ENTRY,
    _in_init_order: LIST_ENTRY,
}

#[cfg(target_pointer_width = "64")]
#[repr(C)]
struct LDR_DATA_TABLE_ENTRY {
    _in_load_order_links: LIST_ENTRY,
    in_memory_order_links: LIST_ENTRY,
    _in_init_order_links: LIST_ENTRY,
    dll_base: *mut core::ffi::c_void,
    _entry_point: *mut core::ffi::c_void,
    _size_of_image: u32,
    _pad0: u32,
    _full_dll_name: UNICODE_STRING,
    base_dll_name: UNICODE_STRING,
}

#[cfg(target_pointer_width = "32")]
#[repr(C)]
struct LDR_DATA_TABLE_ENTRY {
    _in_load_order_links: LIST_ENTRY,
    in_memory_order_links: LIST_ENTRY,
    _in_init_order_links: LIST_ENTRY,
    dll_base: *mut core::ffi::c_void,
    _entry_point: *mut core::ffi::c_void,
    _size_of_image: u32,
    _full_dll_name: UNICODE_STRING,
    base_dll_name: UNICODE_STRING,
}

#[inline(always)]
fn read_peb() -> *const u8 {
    #[cfg(target_arch = "x86_64")]
    {
        let peb: usize;
        unsafe {
            core::arch::asm!("mov {0}, gs:[0x60]", out(reg) peb);
        }
        return peb as *const u8;
    }

    #[cfg(target_arch = "x86")]
    {
        let peb: u32;
        unsafe {
            core::arch::asm!("mov {0:e}, fs:[0x30]", out(reg) peb);
        }
        return peb as *const u8;
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
    {
        core::ptr::null()
    }
}

#[inline(always)]
fn ascii_byte_upper(b: u8) -> u8 {
    if (b'a'..=b'z').contains(&b) {
        b - 32
    } else {
        b
    }
}

unsafe fn unicode_eq_ascii_case_insensitive(us: &UNICODE_STRING, ascii: &str) -> bool {
    if us.Buffer.is_null() {
        return false;
    }
    let wide = core::slice::from_raw_parts(us.Buffer.0, (us.Length as usize) / 2);
    if wide.len() != ascii.len() {
        return false;
    }

    for (w, b) in wide.iter().zip(ascii.bytes()) {
        let w = *w;
        if w > 0x7F {
            return false;
        }
        let wc = ascii_byte_upper(w as u8);
        let bc = ascii_byte_upper(b);
        if wc != bc {
            return false;
        }
    }

    true
}

unsafe fn get_module_base_peb(module: &str) -> Option<usize> {
    // Under the hood, GetModuleHandleA walks PEB->Ldr module lists.
    let peb = read_peb();
    if peb.is_null() {
        return None;
    }

    #[cfg(target_pointer_width = "64")]
    const PEB_LDR_OFFSET: usize = 0x18;
    #[cfg(target_pointer_width = "32")]
    const PEB_LDR_OFFSET: usize = 0x0C;

    let ldr = *(peb.add(PEB_LDR_OFFSET) as *const *const PEB_LDR_DATA);
    let ldr = ldr.as_ref()?;
    let head = &ldr.in_memory_order as *const LIST_ENTRY;

    let mut cur = ldr.in_memory_order.flink;
    let link_off = core::mem::offset_of!(LDR_DATA_TABLE_ENTRY, in_memory_order_links);

    // Avoid infinite loops if the list is corrupted.
    for _ in 0..512 {
        if cur.is_null() || cur == head {
            break;
        }
        let entry = (cur as usize).wrapping_sub(link_off) as *const LDR_DATA_TABLE_ENTRY;
        let entry = entry.as_ref()?;

        if unicode_eq_ascii_case_insensitive(&entry.base_dll_name, module) {
            return Some(entry.dll_base as usize);
        }

        cur = (*cur).flink;
    }

    None
}

/// PEB-based module base lookup (no WinAPI / no IAT).
///
/// This is intentionally exposed for internal modules that must avoid API imports.
pub fn AbGetModuleBasePeb(module: &str) -> Option<usize> {
    unsafe { get_module_base_peb(module) }
}

/// Type alias for base pointer to allocated fake stack.
#[cfg(not(feature = "ntdll_backend"))]
type StackBase = *mut u64;

// Thread-local synthetic stack page used for stack spoofing.
#[cfg(not(feature = "ntdll_backend"))]
thread_local! {
    static SW_PAGE: std::cell::RefCell<Option<StackBase>> =
        std::cell::RefCell::new(None);
}

/// Initializes the Sidewinder engine by ensuring `ntdll.dll` is loaded.
///
/// # Safety
/// This function must only be called once before use. It interacts with raw pointers
/// and assumes Windows PE structures are valid.
///
/// # Returns
/// `Ok(())` on success, or `Err(&'static str)` if initialization fails.
#[cfg(not(feature = "ntdll_backend"))]
pub unsafe fn AbSidewinderInit() -> Result<(), &'static str> {
    get_module_base_peb("NTDLL.DLL").ok_or("NTDLL.DLL not loaded")?;
    Ok(())
}

/// Allocates or retrieves a per-thread stack spoofing page.
///
/// # Safety
/// Relies on correct memory layout and page commit by VirtualAlloc.
#[cfg(not(feature = "ntdll_backend"))]
unsafe fn sw_get_page() -> Option<StackBase> {
    SW_PAGE.with(|cell| {
        let mut page = cell.borrow_mut();
        if let Some(ptr) = *page {
            Some(ptr)
        } else {
            let p = crate::internal::vm::AbVirtualAlloc(SW_STACK_SIZE, PAGE_READWRITE.0) as StackBase;
            if p.is_null() {
                return None;
            }
            *page = Some(p);
            Some(p)
        }
    })
}

/// Constructs a synthetic call stack for the specified NT syscall
/// and returns a pointer to the base of the spoofed stack.
///
/// # Arguments
/// * `nt_stub` - Address of the NT export stub in loaded `ntdll.dll`.
///
/// # Returns
/// A pointer (`usize`) to the base of the fake stack (SP value).
#[cfg(not(feature = "ntdll_backend"))]
pub fn AbStackWinder(nt_stub: u64) -> Option<usize> {
    let base = unsafe { sw_get_page()? };
    let top = unsafe { ((base.add(SW_STACK_SIZE / 8) as usize) & !0xF) as *mut u64 };
    // Reserve headroom so shadow space + 12 stack args (16-arg ABI) stay inside the page.
    const CALL_HEADROOM: isize = 0x80;
    let sp = unsafe { top.offset(-CALL_HEADROOM / 8) };

    unsafe {
        // The compiler will reserve 0x20 shadow space before the call, so
        // place the spoofed return at [rsp_at_call] = (sp - 0x20).
        let slot = sp.offset(-4);
        slot.write(nt_stub);
    }

    Some(sp as usize)
}

/// Resolves the export stub address for a given NT syscall inside loaded `ntdll.dll`.
pub fn AbResolveNtdllStub(nt_name: &str) -> Option<u64> {
    let norm = normalize_sys_name(nt_name);
    unsafe { sw_res_exp("NTDLL.DLL", norm.as_ref()).ok() }
}

#[cfg(all(debug_assertions, not(feature = "ntdll_backend")))]
pub fn AbDebugFakeStackBounds() -> Option<(usize, usize)> {
    SW_PAGE.with(|cell| {
        let base = match *cell.borrow() {
            Some(p) => p,
            None => return None,
        };
        let start = base as usize;
        Some((start, start + SW_STACK_SIZE))
    })
}

#[cfg(all(debug_assertions, not(feature = "ntdll_backend")))]
pub fn AbDebugNtdllImageRange() -> Option<(usize, usize)> {
    unsafe {
        let base = get_module_base_peb("NTDLL.DLL")?;

        let dos = &*(base as *const IMAGE_DOS_HEADER);
        if dos.e_magic != 0x5A4D {
            return None;
        }

        let nt = &*((base + dos.e_lfanew as usize) as *const IMAGE_NT_HEADERS64);
        if nt.Signature != 0x0000_4550 {
            return None;
        }

        let size = nt.OptionalHeader.SizeOfImage as usize;
        Some((base, base.saturating_add(size)))
    }
}

#[inline]
fn normalize_sys_name(name: &str) -> Cow<'_, str> {
    if name.starts_with("Zw") {
        Cow::Owned(format!("Nt{}", &name[2..]))
    } else {
        Cow::Borrowed(name)
    }
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
unsafe fn sw_res_exp(module: &str, export: &str) -> Result<u64, &'static str> {
    let base = get_module_base_peb(module).ok_or("module not loaded")?;

    let dos = &*(base as *const IMAGE_DOS_HEADER);
    if dos.e_magic != 0x5A4D {
        return Err("Bad DOS header");
    }

    let nt = &*((base + dos.e_lfanew as usize) as *const IMAGE_NT_HEADERS64);
    if nt.Signature != 0x0000_4550 {
        return Err("Bad NT header");
    }

    let dir =
        nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT.0 as usize].VirtualAddress;
    if dir == 0 {
        return Err("No export dir");
    }

    let exp = &*((base + dir as usize) as *const IMAGE_EXPORT_DIRECTORY);
    let names = base + exp.AddressOfNames as usize;
    let funcs = base + exp.AddressOfFunctions as usize;
    let ords = base + exp.AddressOfNameOrdinals as usize;

    for i in 0..exp.NumberOfNames {
        let name_rva = *(names.add(i as usize * 4) as *const u32) as usize;
        let name_ptr = base + name_rva;
        let bytes = core::slice::from_raw_parts(name_ptr as *const u8, export.len());
        if bytes == export.as_bytes() {
            let ord_idx = *(ords.add(i as usize * 2) as *const u16) as usize;
            let func_rva = *(funcs.add(ord_idx * 4) as *const u32) as usize;
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
