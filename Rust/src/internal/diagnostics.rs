pub const AB_NOT_INIT:        u32 = 0xAB00_0002;
pub const AB_ALREADY_INIT:    u32 = 0xAB00_0003;
pub const AB_NULL:            u32 = 0xAB00_0004;

pub const AB_INVALID_IMAGE:   u32 = 0xAB01_0001;
pub const AB_INVALID_SECTION: u32 = 0xAB01_0002;
pub const AB_INVALID_RVA:     u32 = 0xAB01_0003;

pub const AB_EXPORT_FAIL:     u32 = 0xAB02_0001;
pub const AB_BAD_SYSCALL:     u32 = 0xAB02_0002;

pub const AB_STUB_ALLOC_FAIL:       u32 = 0xAB04_0001;
pub const AB_STUB_ALIGN_FAIL:       u32 = 0xAB04_0002;
pub const AB_STUB_PROTECT_RW_FAIL:  u32 = 0xAB04_0003;
pub const AB_STUB_PROTECT_RX_FAIL:  u32 = 0xAB04_0004;
pub const AB_STUB_PROTECT_NOACC_FAIL: u32 = 0xAB04_0005;
pub const AB_STUB_ENCRYPT_FAIL:     u32 = 0xAB04_0006;
pub const AB_STUB_DECRYPT_FAIL:     u32 = 0xAB04_0007;
pub const AB_STUB_POOL_EXHAUSTED:   u32 = 0xAB04_0008;
pub const AB_STUB_RELEASE_MISS:     u32 = 0xAB04_0009;

pub const AB_THREAD_FILEMAP_FAIL:      u32 = 0xAB05_0001;
pub const AB_THREAD_SYSCALL_INIT_FAIL: u32 = 0xAB05_0002;
pub const AB_THREAD_SYSCALL_TABLE_MISS:u32 = 0xAB05_0003;
pub const AB_THREAD_NTCREATE_MISSING:  u32 = 0xAB05_0004;
pub const AB_THREAD_STUB_ALLOC_FAIL:   u32 = 0xAB05_0005;
pub const AB_THREAD_CREATE_FAIL:       u32 = 0xAB05_0006;
pub const AB_THREAD_TEBCORRUPT_SKIP:   u32 = 0xAB05_0007;

pub const AB_DISPATCH_NAME_TOO_LONG:   u32 = 0xAB06_0001;
pub const AB_DISPATCH_ARG_TOO_MANY:    u32 = 0xAB06_0002;
pub const AB_DISPATCH_NOT_READY:       u32 = 0xAB06_0003;
pub const AB_DISPATCH_TABLE_MISSING:   u32 = 0xAB06_0004;
pub const AB_DISPATCH_SYSCALL_MISSING: u32 = 0xAB06_0005;
pub const AB_DISPATCH_FRAME_TIMEOUT:   u32 = 0xAB06_0006;

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