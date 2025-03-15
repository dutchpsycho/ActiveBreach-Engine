use std::ffi::c_void;
use core::arch::asm;
use winapi::um::winnt::LIST_ENTRY;

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

pub unsafe fn activebreach_callback(state: &SyscallState) {
    let end_time = get_rdtsc();
    let elapsed = end_time - state.start_time;
    let current_stack_ptr = sp();
    let current_ret_addr = ret_addr();

    if current_stack_ptr != state.stack_ptr {
        panic!("ACTIVEBREACH_SYSCALL_STACKPTRMODIFIED");
    }
    if current_ret_addr != state.ret_addr {
        panic!("ACTIVEBREACH_SYSCALL_RETURNMODIFIED");
    }
    const SYSCALL_TIME_THRESHOLD: u64 = 100000;
    if elapsed > SYSCALL_TIME_THRESHOLD {
        panic!("ACTIVEBREACH_SYSCALL_LONGSYSCALL");
    }
}