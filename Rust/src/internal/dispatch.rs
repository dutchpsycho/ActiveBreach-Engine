use std::mem::MaybeUninit;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicU32, Ordering, AtomicBool};
use crate::internal::stub::G_STUB_POOL;
use winapi::um::memoryapi::VirtualProtect;
use crate::internal::stub::STUB_SIZE;
use winapi::um::winnt::{PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_READ};

#[repr(C)]
pub struct ABOpFrame {
    pub status: AtomicU32, // 0 = free, 1 = pending, 2 = complete
    pub syscall_id: u32,
    pub arg_count: usize,
    pub args: [usize; 16],
    pub ret: usize,
}

impl Default for ABOpFrame {
    fn default() -> Self {
        Self {
            status: AtomicU32::new(0),
            syscall_id: 0,
            arg_count: 0,
            args: [0; 16],
            ret: 0,
        }
    }
}

pub type ABStubFn = unsafe extern "system" fn(
    usize, usize, usize, usize, usize, usize, usize, usize,
    usize, usize, usize, usize, usize, usize, usize, usize,
) -> usize;

pub static mut G_OPFRAME: MaybeUninit<ABOpFrame> = MaybeUninit::uninit();
pub static G_READY: AtomicBool = AtomicBool::new(false);

pub unsafe extern "system" fn thread_proc(_: *mut winapi::ctypes::c_void) -> u32 {
    G_OPFRAME.write(ABOpFrame::default());
    G_READY.store(true, Ordering::Release);

    let frame = &mut *G_OPFRAME.as_mut_ptr();

    loop {
        if frame.status.load(Ordering::Acquire) != 1 {
            std::thread::yield_now();
            continue;
        }

        let stub = match G_STUB_POOL.acquire() {
            Some(ptr) if !ptr.is_null() => ptr,
            _ => {
                eprintln!("[AB] failed to acquire stub — skipping frame");
                continue;
            }
        };

        // verify alignment + memory before writing to stub
        debug_assert_eq!(stub as usize % 16, 0, "[AB] stub alignment fail");
        let ssn_ptr = stub.add(4) as *mut u32;

        if ssn_ptr.is_null() {
            eprintln!("[AB] invalid SSN ptr (null)");
            G_STUB_POOL.release(stub);
            continue;
        }

        let mut old = 0;
        if VirtualProtect(stub as _, STUB_SIZE, PAGE_EXECUTE_READWRITE, &mut old) == 0 {
            eprintln!("[AB] failed to set stub RWX before SSN write");
            G_STUB_POOL.release(stub);
            continue;
        }

        ssn_ptr.write_volatile(frame.syscall_id);

        if VirtualProtect(stub as _, STUB_SIZE, PAGE_EXECUTE_READ, &mut old) == 0 {
            eprintln!("[AB] failed to restore stub RX after SSN write");
        }

        let fn_ptr: ABStubFn = std::mem::transmute(stub);

        let mut padded = [0usize; 16];
        padded[..frame.arg_count].copy_from_slice(&frame.args[..frame.arg_count]);

        let ret = fn_ptr(
            padded[0], padded[1], padded[2], padded[3],
            padded[4], padded[5], padded[6], padded[7],
            padded[8], padded[9], padded[10], padded[11],
            padded[12], padded[13], padded[14], padded[15],
        );

        frame.ret = ret;
        frame.status.store(2, Ordering::Release);

        G_STUB_POOL.release(stub);
    }
}