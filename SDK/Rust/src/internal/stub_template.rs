//! Build-time generated, encrypted syscall stub template.
//! Decrypted only when writing into executable memory.

pub const STUB_SIZE: usize = 32;
pub const STUB_JMP64_TARGET_OFF: usize = 2;

include!(concat!(env!("OUT_DIR"), "/stub_template.rs"));

#[inline(always)]
fn derive_key() -> [u8; 16] {
    let mut k = [0u8; 16];
    for i in 0..16 {
        k[i] = STUB_KEY_A[i] ^ STUB_KEY_B[i];
    }
    k
}

#[inline(always)]
fn decrypt_template(enc: &[u8; STUB_SIZE], out: &mut [u8; STUB_SIZE]) {
    let key = derive_key();
    for i in 0..STUB_SIZE {
        let mix = (i as u8).wrapping_mul(17).wrapping_add(STUB_SEED);
        out[i] = enc[i] ^ key[i % 16] ^ mix;
    }
}

/// Writes a decrypted syscall stub template into `dst` and patches the SSN.
///
/// # Safety
/// - `dst` must be writable and have at least `STUB_SIZE` bytes.
#[inline(always)]
pub unsafe fn write_syscall_stub(dst: *mut u8, ssn: u32) {
    let mut buf = [0u8; STUB_SIZE];
    decrypt_template(&STUB_TEMPLATE_ENC_SPOOF, &mut buf);
    buf[4..8].copy_from_slice(&ssn.to_le_bytes());
    std::ptr::copy_nonoverlapping(buf.as_ptr(), dst, STUB_SIZE);
}

/// Writes a plain (non-stack-adjusting) syscall stub template into `dst` and patches the SSN.
///
/// # Safety
/// - `dst` must be writable and have at least `STUB_SIZE` bytes.
#[inline(always)]
pub unsafe fn write_syscall_stub_plain(dst: *mut u8, ssn: u32) {
    let mut buf = [0u8; STUB_SIZE];
    decrypt_template(&STUB_TEMPLATE_ENC_PLAIN, &mut buf);
    buf[4..8].copy_from_slice(&ssn.to_le_bytes());
    std::ptr::copy_nonoverlapping(buf.as_ptr(), dst, STUB_SIZE);
}

/// Writes a JMP stub into `dst` and patches the 64-bit target immediate.
///
/// Layout (x86_64):
/// - `49 BB <imm64>`: mov r11, imm64
/// - `41 FF E3`     : jmp r11
///
/// # Safety
/// - `dst` must be writable and have at least `STUB_SIZE` bytes.
#[inline(always)]
pub unsafe fn write_jmp64_stub(dst: *mut u8, target: u64) {
    let mut buf = [0u8; STUB_SIZE];
    decrypt_template(&STUB_TEMPLATE_ENC_JMP64, &mut buf);
    buf[STUB_JMP64_TARGET_OFF..STUB_JMP64_TARGET_OFF + 8].copy_from_slice(&target.to_le_bytes());
    std::ptr::copy_nonoverlapping(buf.as_ptr(), dst, STUB_SIZE);
}
