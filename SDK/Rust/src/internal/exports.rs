use rustc_hash::{FxHashMap, FxHasher};
use std::{borrow::Cow, ffi::CStr, hash::Hasher, os::raw::c_char, num::NonZeroUsize, slice};

use windows::Win32::System::Diagnostics::Debug::RaiseException;
use windows::Win32::System::Diagnostics::Debug::{IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER};
use windows::Win32::System::Memory::{VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE, PAGE_READONLY, PAGE_READWRITE};
use windows::Win32::System::SystemServices::{IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY};

use once_cell::sync::OnceCell;

use crate::internal::diagnostics::*;
use crate::internal::mapper::drop_ntdll;
use crate::AbOut;

type ULONG = u32;

const SYSCALL_TABLE_PAGE_SIZE: usize = 0x1000;

#[repr(C)]
struct SyscallTablePage {
    table: FxHashMap<String, u32>,
}

pub struct SyscallTable {
    page: OnceCell<NonZeroUsize>,
    hash: OnceCell<u64>,
}

impl SyscallTable {
    pub const fn new() -> Self {
        Self {
            page: OnceCell::new(),
            hash: OnceCell::new(),
        }
    }

    pub fn is_init(&self) -> bool {
        self.page.get().is_some()
    }

    pub fn get(&self) -> Option<&'static FxHashMap<String, u32>> {
        let addr = self.page.get()?.get();
        let page = addr as *const SyscallTablePage;
        unsafe { Some(&(*page).table) }
    }

    pub fn init(&self, map: FxHashMap<String, u32>) -> Result<(), u32> {
        if self.page.get().is_some() {
            return Err(ABErr(ABError::AlreadyInit));
        }

        let page = alloc_syscall_table_page()?;
        let page_ptr = page.get() as *mut SyscallTablePage;
        unsafe {
            page_ptr.write(SyscallTablePage { table: map });
        }

        if self.page.set(page).is_err() {
            return Err(ABErr(ABError::AlreadyInit));
        }

        AbOut!("SYSCALL_TABLE initialized @ {:p} (entries={})", page_ptr, unsafe {
            (*page_ptr).table.len()
        });

        let mut old = PAGE_READWRITE;
        if !unsafe {
            VirtualProtect(
                page_ptr as _,
                SYSCALL_TABLE_PAGE_SIZE,
                PAGE_READONLY,
                &mut old,
            )
        }
        .is_ok()
        {
            return Err(ABErr(ABError::SyscallTableProtectFail));
        }

        AbOut!("SYSCALL_TABLE set to READONLY");

        let hash = unsafe { hash_syscall_table(&(*page_ptr).table) };
        if self.hash.set(hash).is_err() {
            return Err(ABErr(ABError::AlreadyInit));
        }

        AbOut!("SYSCALL_TABLE hash = 0x{:016X}", hash);

        Ok(())
    }

    pub fn verify_hash_with(&self, table: &FxHashMap<String, u32>) -> bool {
        let expected = match self.hash.get() {
            Some(h) => *h,
            None => return false,
        };

        let current = hash_syscall_table(table);
        current == expected
    }
}

pub static SYSCALL_TABLE: SyscallTable = SyscallTable::new();

fn alloc_syscall_table_page() -> Result<NonZeroUsize, u32> {
    debug_assert!(
        std::mem::size_of::<SyscallTablePage>() <= SYSCALL_TABLE_PAGE_SIZE
    );

    let ptr = unsafe {
        VirtualAlloc(
            None,
            SYSCALL_TABLE_PAGE_SIZE,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        ) as *mut SyscallTablePage
    };

    NonZeroUsize::new(ptr as usize).ok_or_else(|| ABErr(ABError::SyscallTableAllocFail))
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
            let file_offset =
                sec.PointerToRawData as usize + (rva - virt_start);
            if file_offset < size {
                return Ok(base.add(file_offset));
            }
        }
    }

    AbOut!("rva not covered by any section");
    Err(fault_code + 2)
}

pub unsafe fn ExSyscalls(ntdll: *const u8, size: usize) -> Result<(), u32> {
    if ntdll.is_null() {
        AbOut!("ntdll ptr is null");
        return Err(ABErr(ABError::NotInit));
    }
    if size == 0 {
        AbOut!("image size is zero");
        return Err(ABErr(ABError::Null));
    }
    if SYSCALL_TABLE.is_init() {
        AbOut!("syscall table already initialized");
        return Err(ABErr(ABError::AlreadyInit));
    }

    let dos = &*(ntdll as *const IMAGE_DOS_HEADER);
    if dos.e_magic != 0x5A4D {
        AbOut!("invalid DOS header");
        return Err(ABErr(ABError::InvalidImage));
    }

    let nt_offset = dos.e_lfanew as usize;
    let nt = &*(ntdll.add(nt_offset) as *const IMAGE_NT_HEADERS64);
    if nt.Signature != 0x0000_4550 {
        AbOut!("invalid NT signature");
        return Err(ABErr(ABError::InvalidImage));
    }

    let num_secs = nt.FileHeader.NumberOfSections as usize;
    let secs_ptr = ntdll.add(nt_offset + std::mem::size_of::<IMAGE_NT_HEADERS64>())
        as *const IMAGE_SECTION_HEADER;
    let sections = slice::from_raw_parts(secs_ptr, num_secs);

    let export_va = nt.OptionalHeader.DataDirectory[0].VirtualAddress as usize;
    let export_ptr =
        rva_to_ptr_or_fault(ntdll, export_va, size, sections, ABErr(ABError::ExportFail))?
            as *const IMAGE_EXPORT_DIRECTORY;
    let export = &*export_ptr;

    let name_count = export.NumberOfNames as usize;
    let func_count = export.NumberOfFunctions as usize;

    let names = rva_to_ptr_or_fault(
        ntdll,
        export.AddressOfNames as usize,
        size,
        sections,
        ABErr(ABError::ExportFail),
    )? as *const u32;

    let ords = rva_to_ptr_or_fault(
        ntdll,
        export.AddressOfNameOrdinals as usize,
        size,
        sections,
        ABErr(ABError::ExportFail),
    )? as *const u16;

    let funcs = rva_to_ptr_or_fault(
        ntdll,
        export.AddressOfFunctions as usize,
        size,
        sections,
        ABErr(ABError::ExportFail),
    )? as *const u32;

    let mut map =
        FxHashMap::with_capacity_and_hasher(name_count, Default::default());

    for i in 0..name_count {
        let name_rva = std::ptr::read_unaligned(names.add(i)) as usize;
        let name_ptr =
            rva_to_ptr_or_fault(ntdll, name_rva, size, sections, ABErr(ABError::BadSyscall))?
                as *const c_char;

        let name = CStr::from_ptr(name_ptr).to_bytes();
        if name.len() < 3 || &name[..2] != b"Nt" {
            continue;
        }

        let ord = std::ptr::read_unaligned(ords.add(i)) as usize;
        if ord >= func_count {
            return Err(ABErr(ABError::BadSyscall));
        }

        let func_rva = std::ptr::read_unaligned(funcs.add(ord)) as usize;
        let sig_ptr =
            rva_to_ptr_or_fault(ntdll, func_rva, size, sections, ABErr(ABError::BadSyscall))?;

        let sig = slice::from_raw_parts(sig_ptr, 8);
        let valid = matches!(
            sig,
            [0x4C, 0x8B, 0xD1, 0xB8, ..] | [0xB8, ..] | [0x4D, 0x8B, 0xD1, 0xB8, ..]
        );

        if !valid {
            continue;
        }

        let ssn =
            u32::from_le_bytes([sig[4], sig[5], sig[6], sig[7]]);
        let key = String::from_utf8_unchecked(name.to_vec());
        map.insert(key, ssn);
    }

    SYSCALL_TABLE.init(map)?;

    drop_ntdll();
    Ok(())
}

pub fn get_syscall_table() -> Option<&'static FxHashMap<String, u32>> {
    SYSCALL_TABLE.get()
}

pub fn lookup_ssn(name: &str) -> Option<u32> {
    let tbl = SYSCALL_TABLE.get()?;
    let norm = normalize_sys_name(name);
    let result = tbl.get(norm.as_ref()).copied();

    #[cfg(debug_assertions)]
    if result.is_none() && name.starts_with("Zw") {
        AbOut!("Alias lookup failed: {} -> {}", name, norm);
    }

    result
}
