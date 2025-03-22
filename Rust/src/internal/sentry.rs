
use std::ffi::c_void;

use core::arch::asm;

use winapi::um::winnt::LIST_ENTRY;
use winapi::um::errhandlingapi::RaiseException;
use winapi::shared::minwindef::{DWORD, ULONG};
use winapi::shared::basetsd::ULONG_PTR;

const AB_SYSCALL_STACK_CORRUPT: DWORD = 0xEAB10001;
const AB_SYSCALL_RETADDR_CORRUPT: DWORD = 0xEAB10002;
const AB_SYSCALL_TIME_EXCEEDED:  DWORD = 0xEAB10003;

#[repr(C)]
pub struct PEB {
    pub reserved1: [u8; 2],
    pub being_debugged: u8,
    pub reserved2: [u8; 1],
    pub reserved3: [*mut c_void; 2],
    pub ldr: *mut PEB_LDR_DATA,
}

#[repr(C)]
pub struct PEB_LDR_DATA {
    pub reserved1: [u8; 8],
    pub in_memory_order_module_list: LIST_ENTRY,
}

#[repr(C)]
pub struct LDR_DATA_TABLE_ENTRY {
    pub reserved1: [u8; 16],
    pub in_memory_order_links: LIST_ENTRY,
    pub reserved2: [u8; 16],
    pub dll_base: *mut c_void,
}

pub unsafe fn get_ntdll_base() -> *mut c_void {
    let peb: *mut PEB;
    asm!(
        "mov {}, gs:[0x60]",
        out(reg) peb
    );
    let ldr = (*peb).ldr as *mut PEB_LDR_DATA;
    let mut module_list = (*ldr).in_memory_order_module_list.Flink;
    module_list = (*module_list).Flink;
    let ntdll_entry = module_list as *mut LDR_DATA_TABLE_ENTRY;
    (*ntdll_entry).dll_base
}

pub unsafe fn sp() -> usize {
    let sp: usize;
    asm!("mov {}, rsp", out(reg) sp);
    sp
}

pub unsafe fn ret_addr() -> usize {
    let ret: usize;
    asm!("mov {}, [rsp]", out(reg) ret);
    ret
}

pub unsafe fn get_rdtsc() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        core::arch::x86_64::_rdtsc()
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        0
    }
}   

#[repr(C)]
pub struct SyscallState {
    pub start_time: u64,
    pub stack_ptr: usize,
    pub ret_addr: usize,
}

impl SyscallState {
    pub fn capture() -> Self {
        unsafe {
            Self {
                start_time: get_rdtsc(),
                stack_ptr: sp(),
                ret_addr: ret_addr(),
            }
        }
    }

    pub fn validate(&self) {
        unsafe {
            let end_time = get_rdtsc();
            let elapsed = end_time - self.start_time;
            let current_stack_ptr = sp();
            let current_ret_addr = ret_addr();

            if current_stack_ptr != self.stack_ptr {
                RaiseException(AB_SYSCALL_STACK_CORRUPT, 0, 0, std::ptr::null());
            }
            if current_ret_addr != self.ret_addr {
                RaiseException(AB_SYSCALL_RETADDR_CORRUPT, 0, 0, std::ptr::null());
            }
            if elapsed > 100_000 {
                RaiseException(AB_SYSCALL_TIME_EXCEEDED, 0, 0, std::ptr::null());
            }
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn ab_callback(state: *const SyscallState) {
    if state.is_null() {
        return;
    }

    let state = &*state;
    let end_time = get_rdtsc();
    let elapsed = end_time - state.start_time;
    let current_stack_ptr = sp();
    let current_ret_addr = ret_addr();

    if current_stack_ptr != state.stack_ptr {
        RaiseException(AB_SYSCALL_STACK_CORRUPT, 0, 0, std::ptr::null());
    }
    if current_ret_addr != state.ret_addr {
        RaiseException(AB_SYSCALL_RETADDR_CORRUPT, 0, 0, std::ptr::null());
    }
    if elapsed > 100_000 {
        RaiseException(AB_SYSCALL_TIME_EXCEEDED, 0, 0, std::ptr::null());
    }
}