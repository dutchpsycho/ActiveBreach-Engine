use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use std::process;

// Symbolic error enum
#[derive(Clone, Copy, Hash, Eq, PartialEq, Debug)]
pub enum ABError {
    NotInit,
    AlreadyInit,
    Null,
    InvalidImage,
    InvalidSection,
    InvalidRva,
    ExportFail,
    BadSyscall,
    StubAllocFail,
    StubAlignFail,
    StubProtectRwFail,
    StubProtectRxFail,
    StubProtectNoAccessFail,
    StubEncryptFail,
    StubDecryptFail,
    StubPoolExhausted,
    StubReleaseMiss,
    ThreadFilemapFail,
    ThreadSyscallInitFail,
    ThreadSyscallTableMiss,
    ThreadNtCreateMissing,
    ThreadStubAllocFail,
    ThreadCreateFail,
    ThreadTEBCorruptSkip,
    DispatchNameTooLong,
    DispatchArgTooMany,
    DispatchNotReady,
    DispatchTableMissing,
    DispatchSyscallMissing,
    DispatchFrameTimeout,
}

// Simple string -> u32 LCG-style hasher
fn hash_err(name: &str, seed: u64) -> u32 {
    let mut acc = seed;
    for b in name.bytes() {
        acc = acc.wrapping_mul(0x45d9f3b).wrapping_add(b as u64);
    }
    (acc as u32) | 0xAB00_0000 // Always prefix with AB for semantic tracking
}

// Lazy init table
pub static ERROR_CODES: Lazy<Mutex<HashMap<ABError, u32>>> = Lazy::new(|| {
    let mut map = HashMap::new();

    // Use timestamp XOR PID as salt
    let t = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let p = process::id() as u64;
    let salt = t ^ p as u64;

    for err in [
        ABError::NotInit, ABError::AlreadyInit, ABError::Null,
        ABError::InvalidImage, ABError::InvalidSection, ABError::InvalidRva,
        ABError::ExportFail, ABError::BadSyscall,
        ABError::StubAllocFail, ABError::StubAlignFail, ABError::StubProtectRwFail,
        ABError::StubProtectRxFail, ABError::StubProtectNoAccessFail,
        ABError::StubEncryptFail, ABError::StubDecryptFail,
        ABError::StubPoolExhausted, ABError::StubReleaseMiss,
        ABError::ThreadFilemapFail, ABError::ThreadSyscallInitFail, ABError::ThreadSyscallTableMiss,
        ABError::ThreadNtCreateMissing, ABError::ThreadStubAllocFail,
        ABError::ThreadCreateFail, ABError::ThreadTEBCorruptSkip,
        ABError::DispatchNameTooLong, ABError::DispatchArgTooMany,
        ABError::DispatchNotReady, ABError::DispatchTableMissing,
        ABError::DispatchSyscallMissing, ABError::DispatchFrameTimeout,
    ] {
        let key = format!("{:?}", err);
        let code = hash_err(&key, salt);
        map.insert(err, code);
    }

    Mutex::new(map)
});

/// Runtime accessor
#[inline(always)]
pub fn ab_err_code(kind: ABError) -> u32 {
    *ERROR_CODES.lock().unwrap().get(&kind).unwrap_or(&0xABDE_DEAD)
}

#[macro_export]
macro_rules! printdev {
    ($($arg:tt)*) => {
        #[cfg(debug_assertions)]
        {
            let module_path = module_path!();
            let tag = module_path.split("::").last().unwrap_or("UNKNOWN");
            println!("[AB:{}] {}", tag.to_uppercase(), format!($($arg)*));
        }
    };
}