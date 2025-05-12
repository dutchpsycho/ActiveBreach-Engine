/*!
 * ==================================================================================
 *  Repository:   Syscall Proxy
 *  Project:      ActiveBreach
 *  File:         lib.rs
 *  Author:       CrisisEvasion
 *  Organization: TITAN Softwork Solutions
 *  Inspired by:  MDSEC Research
 *
 *  Description:
 *      ActiveBreach is a syscall abstraction layer that dynamically proxies syscalls
 *      by extracting system service numbers (SSNs) from ntdll.dll and locating valid
 *      syscall prologue gadgets from within the hooked ntdll. When a ab_call is made via
 *      the dispatcher, the ab_call is ROP-chained through the located gadget, so that
 *      the syscall appears to originate from ntdll.
 *
 *  License:      Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)
 *  Copyright:    (C) 2025 TITAN Softwork Solutions. All rights reserved.
 *
 *  Licensing Terms:
 *  ----------------------------------------------------------------------------------
 *   - You are free to use, modify, and share this software.
 *   - Commercial use is strictly prohibited.
 *   - Proper credit must be given to TITAN Softwork Solutions.
 *   - Modifications must be clearly documented.
 *   - This software is provided "as-is" without warranties of any kind.
 *
 *  Full License: https://creativecommons.org/licenses/by-nc/4.0/
 * ==================================================================================
 */

 #![allow(non_snake_case)]
 #![allow(dead_code)]
 
 pub mod internal;
 
 use std::ptr::{null_mut, null};
 use winapi::um::{handleapi::CloseHandle, processthreadsapi::CreateThread};
 
 /// Initialize the ActiveBreach syscall system.
 pub unsafe fn activebreach_launch() -> Result<(), &'static str> {
     let mut mapped_size = 0;
 
     let mapped = internal::file_buffer::buffer(&mut mapped_size)
         .ok_or("ActiveBreach: file buffer fail")?;
 
     internal::exports::extract_syscalls(mapped as *const u8, mapped_size);
 
     let hThread = CreateThread(
         null_mut(),
         0,
         Some(internal::dispatch::thread_proc),
         null_mut(),
         0,
         null_mut(),
     );
 
     if hThread.is_null() {
         return Err("ActiveBreach: thread creation failed");
     }
 
     internal::file_buffer::zero_and_free(mapped, mapped_size);
     CloseHandle(hThread);
     Ok(())
 }
 
 /// Call a syscall by name with up to 16 usize args.
 pub unsafe fn ab_call(name: &str, args: &[usize]) -> usize {
     if name.len() >= 64 { panic!("ab_call: name too long"); }
     if args.len() > 16 { panic!("ab_call: too many args"); }
 
     if !internal::dispatch::G_READY.load(std::sync::atomic::Ordering::Acquire) {
         panic!("ab_call: dispatcher not ready");
     }
 
     let tbl = internal::exports::SYSCALL_TABLE.get()
         .expect("ab_call: syscall table not ready");
 
     let ssn = *tbl.get(name)
         .unwrap_or_else(|| panic!("ab_call: syscall not found: {name}"));
 
     let op = internal::dispatch::G_OPFRAME.as_mut_ptr();
     let frame = &mut *op;
 
     while frame.status.load(std::sync::atomic::Ordering::Acquire) != 0 {}
 
     frame.syscall_id = ssn;
     frame.arg_count = args.len();
     frame.args[..args.len()].copy_from_slice(args);
     frame.status.store(1, std::sync::atomic::Ordering::Release);
 
     while frame.status.load(std::sync::atomic::Ordering::Acquire) != 2 {}
 
     let ret = frame.ret;
     frame.status.store(0, std::sync::atomic::Ordering::Release);
     ret
 } 