//! Build-time generated, encrypted syscall stub template.
//! Decrypted only when writing into executable memory.

pub const STUB_SIZE: usize = 32;

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
fn decrypt_template(out: &mut [u8; STUB_SIZE]) {
    let key = derive_key();
    for i in 0..STUB_SIZE {
        let mix = (i as u8).wrapping_mul(17).wrapping_add(STUB_SEED);
        out[i] = STUB_TEMPLATE_ENC[i] ^ key[i % 16] ^ mix;
    }
}

/// Writes a decrypted syscall stub template into `dst` and patches the SSN.
///
/// # Safety
/// - `dst` must be writable and have at least `STUB_SIZE` bytes.
#[inline(always)]
pub unsafe fn write_syscall_stub(dst: *mut u8, ssn: u32) {
    let mut buf = [0u8; STUB_SIZE];
    decrypt_template(&mut buf);
    buf[4..8].copy_from_slice(&ssn.to_le_bytes());
    std::ptr::copy_nonoverlapping(buf.as_ptr(), dst, STUB_SIZE);
}
