#[cfg(debug_assertions)]
use once_cell::sync::Lazy;
#[cfg(debug_assertions)]
use std::collections::HashMap;
#[cfg(debug_assertions)]
use std::sync::Mutex;

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
    DispatchStubAllocFail,
    DispatchStubMisaligned,
    DispatchProtectFail,
}

#[cfg(debug_assertions)]
fn hash_err(name: &str) -> u32 {
    let mut acc = 0u64;
    for b in name.bytes() {
        acc = acc.wrapping_mul(0x45D9F3B).wrapping_add(b as u64);
    }
    (acc as u32) | 0xAB00_0000
}

#[cfg(debug_assertions)]
pub static ERROR_CODES: Lazy<Mutex<HashMap<ABError, u32>>> = Lazy::new(|| {
    let mut map = HashMap::new();
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
        ABError::DispatchStubAllocFail, ABError::DispatchStubMisaligned,
        ABError::DispatchProtectFail,
    ] {
        let key = format!("{:?}", err);
        let code = hash_err(&key);
        map.insert(err, code);
    }
    Mutex::new(map)
});

#[inline(always)]
pub fn ABErr(kind: ABError) -> u32 {
    #[cfg(debug_assertions)]
    {
        *ERROR_CODES.lock().unwrap().get(&kind).unwrap_or(&0xABDE_DEAD)
    }

    #[cfg(not(debug_assertions))]
    {
        0
    }
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