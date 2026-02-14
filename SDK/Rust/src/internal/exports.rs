use rustc_hash::{FxHashMap, FxHasher};
use std::ptr::write_bytes;
#[cfg(feature = "ntdll_backend")]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::{
    borrow::Cow,
    ffi::CStr,
    hash::Hasher,
    num::NonZeroUsize,
    os::raw::c_char,
    ptr::NonNull,
    slice,
};

use windows::Win32::System::Diagnostics::Debug::{IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER};
use windows::Win32::System::Memory::{MEM_RELEASE, PAGE_READONLY, PAGE_READWRITE};
use windows::Win32::System::SystemServices::{IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY};

use once_cell::sync::Lazy;

use crate::internal::diagnostics::*;
use crate::internal::mapper;
use crate::internal::vm;
use crate::AbOut;

type ULONG = u32;

const SYSCALL_TABLE_PAGE_SIZE: usize = 0x1000;

#[repr(C)]
struct SyscallTablePage {
    table: FxHashMap<String, u32>,
    #[cfg(feature = "ntdll_backend")]
    prologues: FxHashMap<String, Option<NonNull<u8>>>,
}

struct SyscallTableInner {
    page: usize,
    hash: u64,
}

static SYSCALL_TABLE_INNER: Lazy<Mutex<SyscallTableInner>> =
    Lazy::new(|| Mutex::new(SyscallTableInner { page: 0, hash: 0 }));

#[cfg(feature = "ntdll_backend")]
static HOOKED_NTDLL: AtomicBool = AtomicBool::new(false);

#[cfg(feature = "ntdll_backend")]
pub fn AbHookedNtdll() -> bool {
    HOOKED_NTDLL.load(Ordering::Relaxed)
}

fn alloc_syscall_table_page() -> Result<NonZeroUsize, u32> {
    debug_assert!(std::mem::size_of::<SyscallTablePage>() <= SYSCALL_TABLE_PAGE_SIZE);

    let ptr = unsafe { vm::AbVirtualAlloc(SYSCALL_TABLE_PAGE_SIZE, PAGE_READWRITE.0) }
        as *mut SyscallTablePage;

    NonZeroUsize::new(ptr as usize).ok_or_else(|| AbErr(ABError::SyscallTableAllocFail))
}

fn hash_syscall_table(table: &FxHashMap<String, u32>) -> u64 {
    let mut hasher = FxHasher::default();
    hasher.write_usize(table.len());
    for (name, ssn) in table.iter() {
        hasher.write_usize(name.len());
        hasher.write(name.as_bytes());
        hasher.write_u32(*ssn);
    }
    hasher.finish()
}

#[inline]
fn normalize_sys_name(name: &str) -> Cow<'_, str> {
    if name.starts_with("Zw") {
        Cow::Owned(format!("Nt{}", &name[2..]))
    } else {
        Cow::Borrowed(name)
    }
}

unsafe fn rva_to_ptr_or_fault(
    base: *const u8,
    rva: usize,
    size: usize,
    sections: &[IMAGE_SECTION_HEADER],
    fault_code: u32,
) -> Result<*const u8, u32> {
    if base.is_null() {
        AbOut!("base is null");
        return Err(fault_code);
    }
    if rva >= size {
        AbOut!("rva {:X} out of bounds", rva);
        return Err(fault_code + 1);
    }

    for sec in sections {
        let virt_start = sec.VirtualAddress as usize;
        let virt_size = unsafe { sec.Misc.VirtualSize as usize };
        if rva >= virt_start && rva < virt_start + virt_size {
            let file_offset = sec.PointerToRawData as usize + (rva - virt_start);
            if file_offset < size {
                return Ok(base.add(file_offset));
            }
        }
    }

    AbOut!("rva not covered by any section");
    Err(fault_code + 2)
}

unsafe fn ex_syscalls(img: &mapper::MappedImage) -> Result<(), u32> {
    let ntdll = img.as_ptr();
    let size = img.size();
    if ntdll.is_null() {
        AbOut!("ntdll ptr is null");
        return Err(AbErr(ABError::NotInit));
    }
    if size == 0 {
        AbOut!("image size is zero");
        return Err(AbErr(ABError::Null));
    }
    if AbSyscallTableIsInit() {
        AbOut!("syscall table already initialized");
        return Err(AbErr(ABError::AlreadyInit));
    }

    let dos = &*(ntdll as *const IMAGE_DOS_HEADER);
    if dos.e_magic != 0x5A4D {
        AbOut!("invalid DOS header");
        return Err(AbErr(ABError::InvalidImage));
    }

    let nt_offset = dos.e_lfanew as usize;
    let nt = &*(ntdll.add(nt_offset) as *const IMAGE_NT_HEADERS64);
    if nt.Signature != 0x0000_4550 {
        AbOut!("invalid NT signature");
        return Err(AbErr(ABError::InvalidImage));
    }

    let num_secs = nt.FileHeader.NumberOfSections as usize;
    let secs_ptr = ntdll.add(nt_offset + std::mem::size_of::<IMAGE_NT_HEADERS64>())
        as *const IMAGE_SECTION_HEADER;
    let sections = slice::from_raw_parts(secs_ptr, num_secs);

    let export_va = nt.OptionalHeader.DataDirectory[0].VirtualAddress as usize;
    let export_ptr =
        rva_to_ptr_or_fault(ntdll, export_va, size, sections, AbErr(ABError::ExportFail))?
            as *const IMAGE_EXPORT_DIRECTORY;
    let export = &*export_ptr;

    let name_count = export.NumberOfNames as usize;
    let func_count = export.NumberOfFunctions as usize;

    let names = rva_to_ptr_or_fault(
        ntdll,
        export.AddressOfNames as usize,
        size,
        sections,
        AbErr(ABError::ExportFail),
    )? as *const u32;

    let ords = rva_to_ptr_or_fault(
        ntdll,
        export.AddressOfNameOrdinals as usize,
        size,
        sections,
        AbErr(ABError::ExportFail),
    )? as *const u16;

    let funcs = rva_to_ptr_or_fault(
        ntdll,
        export.AddressOfFunctions as usize,
        size,
        sections,
        AbErr(ABError::ExportFail),
    )? as *const u32;

    let mut map = FxHashMap::with_capacity_and_hasher(name_count, Default::default());

    #[cfg(feature = "ntdll_backend")]
    let mut prologues: FxHashMap<String, Option<NonNull<u8>>> =
        FxHashMap::with_capacity_and_hasher(name_count, Default::default());

    #[cfg(feature = "ntdll_backend")]
    let loaded_ntdll = unsafe { mapper::resolve_ntdll_base_no_strings() } as *const u8;
    #[cfg(feature = "ntdll_backend")]
    let loaded_text_range = unsafe { mapper::loaded_ntdll_text_range() };

    for i in 0..name_count {
        let name_rva = std::ptr::read_unaligned(names.add(i)) as usize;
        let name_ptr =
            rva_to_ptr_or_fault(ntdll, name_rva, size, sections, AbErr(ABError::BadSyscall))?
                as *const c_char;

        let name = CStr::from_ptr(name_ptr).to_bytes();
        if name.len() < 3 || &name[..2] != b"Nt" {
            continue;
        }

        let ord = std::ptr::read_unaligned(ords.add(i)) as usize;
        if ord >= func_count {
            return Err(AbErr(ABError::BadSyscall));
        }

        let func_rva = std::ptr::read_unaligned(funcs.add(ord)) as usize;
        let sig_ptr =
            rva_to_ptr_or_fault(ntdll, func_rva, size, sections, AbErr(ABError::BadSyscall))?;

        // Strict mapped-image bounds before any raw slicing.
        let mapped_avail = (ntdll.add(size) as usize).saturating_sub(sig_ptr as usize);
        if mapped_avail < 8 {
            continue;
        }
        let sig = slice::from_raw_parts(sig_ptr, 8);
        let valid = matches!(
            sig,
            [0x4C, 0x8B, 0xD1, 0xB8, ..] | [0xB8, ..] | [0x4D, 0x8B, 0xD1, 0xB8, ..]
        );

        if !valid {
            continue;
        }

        let ssn = u32::from_le_bytes([sig[4], sig[5], sig[6], sig[7]]);
        let key = String::from_utf8_unchecked(name.to_vec());
        map.insert(key.clone(), ssn);

        #[cfg(feature = "ntdll_backend")]
        {
            const MAPPED_SCAN_LEN: usize = 64;
            let mapped_scan_len = MAPPED_SCAN_LEN.min(mapped_avail);
            let mapped_scan = if mapped_scan_len > 0 {
                slice::from_raw_parts(sig_ptr, mapped_scan_len)
            } else {
                &[]
            };

            // Cache absolute syscall prologue pointer in loaded NTDLL .text at init-time.
            // If no intact prologue exists, keep `None` (backend invalid for this syscall).
            let mut prologue_ptr: Option<NonNull<u8>> = None;
            if !loaded_ntdll.is_null() {
                if let Some((tbase, tlen)) = loaded_text_range {
                    let start = tbase as usize;
                    if let Some(end) = start.checked_add(tlen) {
                        let entry = loaded_ntdll.add(func_rva);
                        let p = entry as usize;
                        const LOADED_SCAN_LEN: usize = 96;
                        if p >= start
                            && p.checked_add(LOADED_SCAN_LEN)
                                .is_some_and(|p_end| p_end <= end)
                        {
                            let loaded_scan = slice::from_raw_parts(entry, LOADED_SCAN_LEN);
                            if let Some(off) = find_syscall_prologue_offset(loaded_scan) {
                                let pro = &loaded_scan[(off as usize)..];
                                if loaded_prologue_is_intact(pro) {
                                    prologue_ptr =
                                        NonNull::new(entry.add(off as usize) as *mut u8);
                                } else {
                                    // Intact prologue missing (likely fully-hooked stub).
                                    prologue_ptr = None;
                                }
                            }
                        }
                    }
                }
            }
            prologues.insert(key.clone(), prologue_ptr);

            // Best-effort hook detection: compare mapped bytes to loaded bytes at the same RVA.
            // If the export entry is patched (JMP/CALL) or the syscall prologue is missing,
            // mark NTDLL as hooked globally.
            if !loaded_ntdll.is_null() {
                let loaded_ptr = loaded_ntdll.add(func_rva);
                if let Some((tbase, tlen)) = loaded_text_range {
                    let start = tbase as usize;
                    if let Some(end) = start.checked_add(tlen) {
                        let p = loaded_ptr as usize;
                        let mapped_16 = if mapped_avail >= 16 {
                            Some(slice::from_raw_parts(sig_ptr, 16))
                        } else {
                            None
                        };
                        let loaded_16 = if p >= start
                            && p.checked_add(16).is_some_and(|p_end| p_end <= end)
                        {
                            Some(slice::from_raw_parts(loaded_ptr, 16))
                        } else {
                            None
                        };

                        if let (Some(mapped_16), Some(loaded_16)) = (mapped_16, loaded_16) {
                            if mapped_16 != loaded_16 {
                                let loaded_64 = if p >= start
                                    && p.checked_add(64).is_some_and(|p_end| p_end <= end)
                                {
                                    Some(slice::from_raw_parts(loaded_ptr, 64))
                                } else {
                                    None
                                };
                                let mapped_has =
                                    find_syscall_prologue_offset(mapped_scan).is_some();
                                let loaded_has = loaded_64
                                    .and_then(|b| find_syscall_prologue_offset(b))
                                    .is_some();
                                if loaded_stub_looks_hooked(loaded_16) || (mapped_has && !loaded_has)
                                {
                                    HOOKED_NTDLL.store(true, Ordering::Relaxed);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[cfg(not(feature = "ntdll_backend"))]
    init_syscall_table_from_map(map)?;

    #[cfg(feature = "ntdll_backend")]
    init_syscall_table_from_maps(map, prologues)?;

    Ok(())
}

pub fn AbLookupSsn(name: &str) -> Option<u32> {
    let g = SYSCALL_TABLE_INNER.lock().unwrap();
    if g.page == 0 {
        return None;
    }
    let page = g.page as *const SyscallTablePage;
    let tbl = unsafe { &(*page).table };
    let norm = normalize_sys_name(name);
    let result = tbl.get(norm.as_ref()).copied();

    #[cfg(debug_assertions)]
    if result.is_none() && name.starts_with("Zw") {
        AbOut!("Alias lookup failed: {} -> {}", name, norm);
    }

    result
}

#[cfg(feature = "ntdll_backend")]
pub fn AbLookupNtdllProloguePtr(name: &str) -> Option<usize> {
    let g = SYSCALL_TABLE_INNER.lock().unwrap();
    if g.page == 0 {
        return None;
    }
    let page = g.page as *const SyscallTablePage;
    let tbl = unsafe { &(*page).prologues };
    let norm = normalize_sys_name(name);
    tbl.get(norm.as_ref())
        .copied()
        .flatten()
        .map(|p| p.as_ptr() as usize)
}

pub fn AbSyscallTableIsInit() -> bool {
    let g = SYSCALL_TABLE_INNER.lock().unwrap();
    g.page != 0
}

pub fn AbVerifySyscallTableHash() -> bool {
    let g = SYSCALL_TABLE_INNER.lock().unwrap();
    if g.page == 0 {
        return false;
    }
    let page = g.page as *const SyscallTablePage;
    let tbl = unsafe { &(*page).table };
    hash_syscall_table(tbl) == g.hash
}

pub fn AbEnsureSyscallTableInit() -> Result<(), u32> {
    if AbSyscallTableIsInit() {
        return Ok(());
    }

    let img =
        unsafe { mapper::map_ntdll_image() }.ok_or_else(|| AbErr(ABError::ThreadFilemapFail))?;
    unsafe { ex_syscalls(&img) }?;
    Ok(())
}

pub fn AbDeinitSyscallTable() {
    let mut g = SYSCALL_TABLE_INNER.lock().unwrap();
    if g.page == 0 {
        return;
    }

    unsafe {
        let page_ptr = g.page as *mut SyscallTablePage;
        let mut old: u32 = PAGE_READONLY.0;
        let _ = vm::AbVirtualProtect(
            page_ptr as *mut u8,
            SYSCALL_TABLE_PAGE_SIZE,
            PAGE_READWRITE.0,
            &mut old,
        );

        std::ptr::drop_in_place(page_ptr);
        write_bytes(page_ptr as *mut u8, 0, SYSCALL_TABLE_PAGE_SIZE);
        let _ = vm::AbVirtualFree(page_ptr as *mut u8);
    }

    g.page = 0;
    g.hash = 0;
}

#[cfg(not(feature = "ntdll_backend"))]
fn init_syscall_table_from_map(map: FxHashMap<String, u32>) -> Result<(), u32> {
    let mut g = SYSCALL_TABLE_INNER.lock().unwrap();
    if g.page != 0 {
        return Err(AbErr(ABError::AlreadyInit));
    }

    let page = alloc_syscall_table_page()?;
    let page_ptr = page.get() as *mut SyscallTablePage;
    unsafe {
        page_ptr.write(SyscallTablePage { table: map });
    }

    AbOut!(
        "SYSCALL_TABLE initialized @ {:p} (entries={})",
        page_ptr,
        unsafe { (*page_ptr).table.len() }
    );

    let mut old: u32 = PAGE_READWRITE.0;
    if !unsafe {
        vm::AbVirtualProtect(
            page_ptr as *mut u8,
            SYSCALL_TABLE_PAGE_SIZE,
            PAGE_READONLY.0,
            &mut old,
        )
    }
    {
        return Err(AbErr(ABError::SyscallTableProtectFail));
    }

    AbOut!("SYSCALL_TABLE set to READONLY");

    g.hash = unsafe { hash_syscall_table(&(*page_ptr).table) };
    AbOut!("SYSCALL_TABLE hash = 0x{:016X}", g.hash);

    g.page = page_ptr as usize;
    Ok(())
}

#[cfg(feature = "ntdll_backend")]
fn init_syscall_table_from_maps(
    map: FxHashMap<String, u32>,
    prologues: FxHashMap<String, Option<NonNull<u8>>>,
) -> Result<(), u32> {
    let mut g = SYSCALL_TABLE_INNER.lock().unwrap();
    if g.page != 0 {
        return Err(AbErr(ABError::AlreadyInit));
    }

    let page = alloc_syscall_table_page()?;
    let page_ptr = page.get() as *mut SyscallTablePage;
    unsafe {
        page_ptr.write(SyscallTablePage { table: map, prologues });
    }

    AbOut!(
        "SYSCALL_TABLE initialized @ {:p} (entries={})",
        page_ptr,
        unsafe { (*page_ptr).table.len() }
    );

    let mut old: u32 = PAGE_READWRITE.0;
    if !unsafe {
        vm::AbVirtualProtect(
            page_ptr as *mut u8,
            SYSCALL_TABLE_PAGE_SIZE,
            PAGE_READONLY.0,
            &mut old,
        )
    }
    {
        return Err(AbErr(ABError::SyscallTableProtectFail));
    }

    AbOut!("SYSCALL_TABLE set to READONLY");

    g.hash = unsafe { hash_syscall_table(&(*page_ptr).table) };
    AbOut!("SYSCALL_TABLE hash = 0x{:016X}", g.hash);

    g.page = page_ptr as usize;
    Ok(())
}

#[cfg(feature = "ntdll_backend")]
fn loaded_stub_looks_hooked(b: &[u8]) -> bool {
    if b.is_empty() {
        return false;
    }

    // Common user-mode inline hooks / detours at entry.
    if b[0] == 0xE9 || b[0] == 0xE8 {
        return true;
    }
    if b.len() >= 2 && b[0] == 0xFF && (b[1] == 0x25 || b[1] == 0x15) {
        return true;
    }
    if b.len() >= 2 && b[0] == 0x48 && b[1] == 0xB8 {
        return true;
    }
    false
}

#[cfg(feature = "ntdll_backend")]
#[inline(always)]
fn loaded_prologue_looks_hooked(b: &[u8]) -> bool {
    // Conservative "obvious hook" patterns near the prologue target.
    loaded_stub_looks_hooked(b)
}

#[cfg(feature = "ntdll_backend")]
#[inline(always)]
fn loaded_prologue_is_intact(pro: &[u8]) -> bool {
    // Accept common x64 NTDLL syscall stub shapes.
    //
    // Canonical shape:
    //   4C 8B D1             mov r10, rcx
    //   B8 ?? ?? ?? ??       mov eax, imm32
    //   F6 04 25 .. .. .. .. 01   test byte ptr [abs], 1   (optional)
    //   75 ?? / 0F 85 ....   jne ...                       (optional)
    //   0F 05                syscall
    //   C3                   ret
    //
    // WoW64 fallback sometimes includes:
    //   CD 2E                int 2e
    //   C3                   ret
    if pro.len() < 16 {
        return false;
    }

    // Reject obvious detours even if a later "syscall" exists.
    if loaded_prologue_looks_hooked(&pro[..16]) {
        return false;
    }

    let mut i = 0usize;

    // Skip a few leading NOPs (including multi-byte NOP 0F 1F ...).
    while i < pro.len() {
        match pro[i] {
            0x90 => {
                i += 1;
                continue;
            }
            0x0F if i + 1 < pro.len() && pro[i + 1] == 0x1F => {
                // We don't fully decode, just skip up to 10 bytes of NOP.
                i += 2;
                continue;
            }
            _ => break,
        }
    }

    // Optional mov r10, rcx (some builds use 4D 8B D1).
    if i + 3 <= pro.len() && (pro[i..i + 3] == [0x4C, 0x8B, 0xD1] || pro[i..i + 3] == [0x4D, 0x8B, 0xD1]) {
        i += 3;
    }

    // Must have mov eax, imm32.
    if i + 5 > pro.len() || pro[i] != 0xB8 {
        return false;
    }
    i += 5;

    // Optional: test byte ptr [abs], 1 (F6 04 25 xx xx xx xx 01)
    if i + 9 <= pro.len() && pro[i] == 0xF6 && pro[i + 1] == 0x04 && pro[i + 2] == 0x25 && pro[i + 7] == 0x01 {
        i += 8;
    }

    // Optional: jne short (75 xx) or jne near (0F 85 xx xx xx xx)
    if i + 2 <= pro.len() && pro[i] == 0x75 {
        i += 2;
    } else if i + 6 <= pro.len() && pro[i] == 0x0F && pro[i + 1] == 0x85 {
        i += 6;
    }

    // Find syscall;ret within the next 16 bytes.
    let end = pro.len().min(i + 16);
    for j in i..end.saturating_sub(2) {
        if pro[j] == 0x0F && pro[j + 1] == 0x05 && pro[j + 2] == 0xC3 {
            return true;
        }
    }

    false
}

#[cfg(feature = "ntdll_backend")]
fn find_syscall_prologue_offset(code: &[u8]) -> Option<u16> {
    // Look for: B8 imm32 0F 05 (mov eax, imm32; syscall)
    // Prefer to include a preceding mov r10, rcx if present.
    if code.len() < 8 {
        return None;
    }

    let scan_len = code.len().min(80);
    let code = &code[..scan_len];

    for i in 0..code.len().saturating_sub(7) {
        if code[i] != 0xB8 {
            continue;
        }
        if code[i + 5] != 0x0F || code[i + 6] != 0x05 {
            continue;
        }

        // If we have the canonical `mov r10, rcx` before it, start there.
        if i >= 3 && code[i - 3..i] == [0x4C, 0x8B, 0xD1] {
            return u16::try_from(i - 3).ok();
        }
        if i >= 3 && code[i - 3..i] == [0x4D, 0x8B, 0xD1] {
            return u16::try_from(i - 3).ok();
        }

        return u16::try_from(i).ok();
    }

    None
}
