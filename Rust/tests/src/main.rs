#![cfg(windows)]
#![allow(non_snake_case)]

//! # ActiveBreach Overhead Tester
//!
//! This is a performance benchmarking harness for the ActiveBreach syscall dispatch system.
//!
//! It compares native NTDLL syscalls (direct invocation) against the ActiveBreach syscall dispatcher
//! under three stress levels (`Low`, `Medium`, `High`). The results are printed in a formatted table,
//! including absolute time (in ms) and percentage overhead.
//!
//! ## Goals
//! - Quantify dispatch overhead introduced by stub encryption, thread-mediator, etc
//! - Validate syscall result equivalency under high throughput
//! - Confirm dispatcher stability under 100k+ syscall loads
//!
//! ## Key Concepts
//! - **Native Call**: Calls syscall directly via `ntdll.dll` FFI
//! - **AB Call**: Calls via `ab_call()` which dispatches through an encrypted stub pool
//! - **Stress Levels**:
//!     - Low: 1,000 calls
//!     - Medium: 10,000 calls
//!     - High: 100,000 calls
//!
//! ## Notes
//! - ActiveBreach is initialized via TLS callback on `DLL_PROCESS_ATTACH`
//! - Benchmark tests are built as closures (boxed) to support reentrant setup
//! - The test suite auto-generates syscall arguments per test iteration
//!
//! ## Safety
//! This program uses unsafe NT API calls and raw pointers but is isolated in test context.
//! All handles are either self handles or ephemeral.

use std::{
    ptr::null_mut,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread,
    time::{Duration, Instant},
};

use winapi::{
    shared::{
        minwindef::{DWORD, LPVOID, ULONG},
        ntdef::{HANDLE, BOOLEAN},
    },
    um::{
        processthreadsapi::{GetCurrentThreadId, OpenThread},
        winnt::{DLL_PROCESS_ATTACH, THREAD_ALL_ACCESS},
    },
};

use activebreach::{ab_call, activebreach_launch};
use activebreach::internal::exports::{get_syscall_table, SYSCALL_TABLE};
use winapi::shared::ntdef::OBJECT_ATTRIBUTES;

////////////////////////////////////////////////////////////////////////////////
// Direct NT syscall FFI declarations (ntdll.dll)
extern "system" {
    fn NtQueryInformationThread(
        ThreadHandle: HANDLE,
        ThreadInformationClass: ULONG,
        ThreadInformation: LPVOID,
        ThreadInformationLength: ULONG,
        ReturnLength: *mut ULONG,
    ) -> ULONG;

    fn NtQueryInformationProcess(
        ProcessHandle: HANDLE,
        ProcessInformationClass: ULONG,
        ProcessInformation: LPVOID,
        ProcessInformationLength: ULONG,
        ReturnLength: *mut ULONG,
    ) -> ULONG;

    fn NtSetInformationThread(
        ThreadHandle: HANDLE,
        ThreadInformationClass: ULONG,
        ThreadInformation: LPVOID,
        ThreadInformationLength: ULONG,
    ) -> ULONG;

    fn NtDelayExecution(
        Alertable: BOOLEAN,
        DelayInterval: *mut i64,
    ) -> ULONG;

    fn NtClose(Handle: HANDLE) -> ULONG;

    fn NtDuplicateObject(
        SourceProcessHandle: HANDLE,
        SourceHandle: HANDLE,
        TargetProcessHandle: HANDLE,
        TargetHandle: *mut HANDLE,
        DesiredAccess: ULONG,
        HandleAttributes: ULONG,
        Options: ULONG,
    ) -> ULONG;
}

////////////////////////////////////////////////////////////////////////////////
// Stress levels
enum StressLevel {
    Low,    // 1_000 calls
    Medium, // 10_000 calls
    High,   //100_000 calls
}

impl StressLevel {
    fn runs(&self) -> usize {
        match self {
            StressLevel::Low => 1_000,
            StressLevel::Medium => 10_000,
            StressLevel::High => 100_000,
        }
    }
    fn name(&self) -> &'static str {
        match self {
            StressLevel::Low => "Low",
            StressLevel::Medium => "Medium",
            StressLevel::High => "High",
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// TLS callback to launch ActiveBreach
#[link_section = ".CRT$XLB"]
#[used]
static TLS_INIT: extern "system" fn(LPVOID, DWORD, LPVOID) = tls_callback;

extern "system" fn tls_callback(_: LPVOID, reason: DWORD, _: LPVOID) {
    if reason == DLL_PROCESS_ATTACH {
        unsafe { let _ = activebreach_launch(); }
    }
}

////////////////////////////////////////////////////////////////////////////////
// CLIENT_ID struct for NtOpenThread
#[repr(C)]
struct CLIENT_ID {
    UniqueProcess: LPVOID,
    UniqueThread: LPVOID,
}

////////////////////////////////////////////////////////////////////////////////
// Descriptor for a single syscall test
struct SyscallTest {
    name:        &'static str,
    ab_args:     Box<dyn Fn() -> Vec<usize> + 'static>,
    direct_call: Box<dyn Fn() -> ULONG + 'static>,
}

impl SyscallTest {
    #[inline(always)]
    fn measure<F>(&self, runs: usize, mut invoke: F) -> Duration
    where
        F: FnMut() -> ULONG,
    {
        let start = Instant::now();
        for _ in 0..runs {
            let _ = invoke();
        }
        start.elapsed()
    }
}

fn main() {

    use std::{
        io::{self, Write},
        ptr::null_mut,
        sync::{
            atomic::{AtomicBool, Ordering},
            mpsc, Arc,
        },
        thread,
        time::Duration,
    };
    use winapi::{
        shared::{
            minwindef::ULONG,
            ntdef::{HANDLE, OBJECT_ATTRIBUTES},
        },
        um::{
            processthreadsapi::{GetCurrentThreadId, OpenThread},
            winnt::THREAD_ALL_ACCESS,
        },
    };

    #[repr(C)]
struct CLIENT_ID {
    UniqueProcess: winapi::shared::ntdef::HANDLE,
    UniqueThread: winapi::shared::ntdef::HANDLE,
}

    

    if let Some(table) = get_syscall_table() {
        for (name, id) in table.iter() {
            println!("{:<32} = 0x{:X}", name, id);
        }
    } else {
        println!("syscall table is uninitialized");
    }

    let self_process = (-1isize) as HANDLE;
    let self_thread = (-2isize) as HANDLE;

    // ===== Spawn helper to get real TID (not psuedo) =====
    let (tx, rx) = mpsc::channel();
    let keepalive = Arc::new(AtomicBool::new(true));
    let ka_clone = keepalive.clone();
    let helper = thread::spawn(move || {
        let tid = unsafe { GetCurrentThreadId() };
        tx.send(tid).unwrap();
        while ka_clone.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_millis(50));
        }
    });
    let real_tid = rx.recv().unwrap();

    // ===== Syscall test suite =====
    let tests = vec![
        SyscallTest {
            name: "NtQueryInformationThread",
            ab_args: Box::new(move || {
                let buf = Box::new([0u8; 48]);
                let len = Box::new(0u32);
                vec![
                    self_thread as usize,
                    0,
                    buf.as_ptr() as usize,
                    buf.len(),
                    Box::into_raw(len) as usize,
                ]
            }),
            direct_call: Box::new(move || unsafe {
                let mut buf = [0u8; 48];
                let mut len = 0u32;
                NtQueryInformationThread(
                    self_thread,
                    0,
                    buf.as_mut_ptr() as _,
                    buf.len() as _,
                    &mut len,
                )
            }),
        },
        SyscallTest {
            name: "NtQueryInformationProcess",
            ab_args: Box::new(move || {
                let buf = Box::new([0u8; 48]);
                let len = Box::new(0u32);
                vec![
                    self_process as usize,
                    0,
                    buf.as_ptr() as usize,
                    buf.len(),
                    Box::into_raw(len) as usize,
                ]
            }),
            direct_call: Box::new(move || unsafe {
                let mut buf = [0u8; 48];
                let mut len = 0u32;
                NtQueryInformationProcess(
                    self_process,
                    0,
                    buf.as_mut_ptr() as _,
                    buf.len() as _,
                    &mut len,
                )
            }),
        },
        SyscallTest {
            name: "NtSetInformationThread",
            ab_args: Box::new(move || vec![self_thread as usize, 0x11, 0, 0]),
            direct_call: Box::new(move || unsafe {
                NtSetInformationThread(self_thread, 0x11, null_mut(), 0)
            }),
        },
        SyscallTest {
            name: "NtDelayExecution",
            ab_args: Box::new(move || {
                let p = Box::new(0i64);
                vec![0, Box::into_raw(p) as usize]
            }),
            direct_call: Box::new(move || unsafe { NtDelayExecution(0, &mut 0) }),
        },
        SyscallTest {
            name: "NtClose",
            ab_args: Box::new(move || vec![self_process as usize]),
            direct_call: Box::new(move || unsafe { NtClose(self_process) }),
        },
        SyscallTest {
            name: "NtDuplicateObject",
            ab_args: Box::new(move || {
                let out = Box::new(null_mut::<HANDLE>());
                vec![
                    self_process as usize,
                    self_process as usize,
                    self_process as usize,
                    Box::into_raw(out) as usize,
                    0x1F0000,
                    0,
                    0,
                ]
            }),
            direct_call: Box::new(move || unsafe {
                let mut h: HANDLE = null_mut();
                NtDuplicateObject(
                    self_process,
                    self_process,
                    self_process,
                    &mut h,
                    0x1F0000,
                    0,
                    0,
                )
            }),
        },
        SyscallTest {
            name: "NtOpenThread",
            ab_args: Box::new(move || {
                let oa = Box::new(OBJECT_ATTRIBUTES {
                    Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
                    RootDirectory: null_mut(),
                    ObjectName: null_mut(),
                    Attributes: 0,
                    SecurityDescriptor: null_mut(),
                    SecurityQualityOfService: null_mut(),
                });
                let cid = Box::new(CLIENT_ID {
                    UniqueProcess: null_mut(),
                    UniqueThread: real_tid as _,
                });
                let out = Box::new(null_mut::<HANDLE>());

                vec![
                    Box::into_raw(out) as usize,
                    THREAD_ALL_ACCESS as usize,
                    Box::into_raw(oa) as usize,
                    Box::into_raw(cid) as usize,
                ]
            }),
            direct_call: Box::new(move || unsafe {
                let h = OpenThread(THREAD_ALL_ACCESS, 0, real_tid);
                NtClose(h);
                0
            }),
        },
    ];

    // ===== Run benchmarks =====
    println!("\n\n=== Benchmark Summary ===");
    println!(
        "{:<25} {:>10} {:>12} {:>12} {:>12}  {}",
        "Syscall", "Native ms", "AB ms", "Overhead", "Runs", "Match?"
    );

    for level in &[StressLevel::Low, StressLevel::Medium, StressLevel::High] {
        let runs = level.runs();

        for test in &tests {
            let mut native_status = 0;
            let native = test.measure(runs, || {
                let status = (test.direct_call)();
                native_status = status;
                status
            });

            let mut ab_status = 0;
            let ab = test.measure(runs, || unsafe {
                let status = ab_call(test.name, &(test.ab_args)()) as ULONG;
                ab_status = status;
                status
            });

            let match_text = if native_status == ab_status {
                "✓"
            } else {
                "✗"
            };

            let overhead = (ab.as_secs_f64() / native.as_secs_f64() - 1.0) * 100.0;
            println!(
                "{:<25} {:>10.3} {:>12.3} {:>11.1}% {:>12}  {}",
                format!("{}({})", test.name, level.name()),
                native.as_secs_f64() * 1_000.0,
                ab.as_secs_f64() * 1_000.0,
                overhead,
                runs,
                match_text
            );
        }
    }

    // ===== Teardown helper =====
    keepalive.store(false, Ordering::Relaxed);
    let _ = helper.join();

    println!("\nPress <Enter> to exit…");
    let _ = io::stdout().flush();
    let mut input = String::new();
    let _ = io::stdin().read_line(&mut input);
}
