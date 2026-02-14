//! AES-128-CTR memory encryption for syscall stubs and other short-lived sensitive regions.
//!
//! The goal here is **fast in-place non-recognizability**, not authenticated encryption.
//! We use AES-CTR so encryption/decryption are identical (XOR with keystream).
//!
//! Performance notes:
//! - The key schedule is cached process-wide (no per-call expansion).
//! - IV/counter is derived deterministically from (ptr,len) + per-process salt to avoid reuse
//!   between different regions while keeping decryption trivial.
//! - AES-NI is used when available; otherwise a scalar AES implementation is used.

#![allow(non_camel_case_types)]
#![cfg_attr(
    not(any(target_arch = "x86", target_arch = "x86_64")),
    allow(dead_code)
)]

use std::sync::OnceLock;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use core::arch::x86_64::*;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use std::is_x86_feature_detected;

/// Cached 128-bit per-process key derived from CPUID+TSC (x86/x64) or a best-effort fallback.
static KEY_BYTES: OnceLock<[u8; 16]> = OnceLock::new();

/// Cached AES-128 expanded encryption round keys (11 round keys).
static AES_CTX: OnceLock<Aes128Ctx> = OnceLock::new();

#[inline(always)]
fn splitmix64(mut x: u64) -> u64 {
    // Standard SplitMix64 mixer.
    x = x.wrapping_add(0x9E3779B97F4A7C15);
    let mut z = x;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^ (z >> 31)
}

/// Returns a stable per-process 128-bit key.
pub fn AbAesCtrKey() -> [u8; 16] {
    *KEY_BYTES.get_or_init(|| {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        unsafe {
            // Keep it simple: CPUID(0) + RDTSC. This is not meant to be a CSPRNG.
            let cpu = __cpuid(0);
            let tsc = _rdtsc();
            let mut k = [0u8; 16];
            k[0..4].copy_from_slice(&cpu.eax.to_le_bytes());
            k[4..8].copy_from_slice(&cpu.ebx.to_le_bytes());
            k[8..12].copy_from_slice(&(tsc as u32).to_le_bytes());
            k[12..16].copy_from_slice(&((tsc >> 32) as u32).to_le_bytes());
            k
        }

        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
        {
            // Fallback: mix some addresses. Not strong, but avoids a fixed all-zero key.
            let a = key as usize as u64;
            let b = (&KEY_BYTES as *const _ as usize) as u64;
            let s0 = splitmix64(a ^ (b.rotate_left(17)));
            let s1 = splitmix64(b ^ (a.rotate_left(31)));
            let mut out = [0u8; 16];
            out[0..8].copy_from_slice(&s0.to_le_bytes());
            out[8..16].copy_from_slice(&s1.to_le_bytes());
            out
        }
    })
}

#[inline(always)]
fn u64_from_key_salt(k: &[u8; 16]) -> u64 {
    // Mix two u64 lanes of the key into one salt.
    let a = u64::from_le_bytes(k[0..8].try_into().unwrap());
    let b = u64::from_le_bytes(k[8..16].try_into().unwrap());
    splitmix64(a ^ b.rotate_left(13) ^ 0xA5A5_A5A5_A5A5_A5A5)
}

#[inline(always)]
fn derive_iv(ptr: *const u8, len: usize) -> [u8; 16] {
    // Deterministic (ptr,len,key-salt) -> 128-bit initial counter.
    // This avoids reusing the same counter for different regions while remaining reversible.
    let k = AbAesCtrKey();
    let salt = u64_from_key_salt(&k);
    let p = ptr as usize as u64;
    let l = len as u64;

    let c0 = splitmix64(salt ^ p ^ (l.rotate_left(23)));
    let c1 = splitmix64(salt ^ l ^ (p.rotate_left(7)) ^ 0xD1B5_4A32_D192_ED03);

    let mut iv = [0u8; 16];
    iv[0..8].copy_from_slice(&c0.to_le_bytes());
    iv[8..16].copy_from_slice(&c1.to_le_bytes());
    iv
}

#[inline(always)]
fn ctr_inc(counter: &mut [u8; 16]) {
    // Increment as a 128-bit little-endian integer.
    let mut carry: u16 = 1;
    for b in counter.iter_mut() {
        let v = (*b as u16) + carry;
        *b = v as u8;
        carry = v >> 8;
        if carry == 0 {
            break;
        }
    }
}

struct Aes128Ctx {
    rk: [[u8; 16]; 11], // encryption round keys

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    rk_sse: Option<[__m128i; 11]>,
}

impl Aes128Ctx {
    fn new(k: &[u8; 16]) -> Self {
        let rk = aes128_expand_key_scalar(k);

        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            // Prepare SSE keys lazily only if AES-NI exists at runtime.
            let rk_sse = if is_x86_feature_detected!("aes") && is_x86_feature_detected!("sse2") {
                Some(unsafe { aes128_expand_key_aesni_to_sse(k) })
            } else {
                None
            };
            Self { rk, rk_sse }
        }

        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
        {
            Self { rk }
        }
    }

    #[inline(always)]
    fn keystream_block(&self, counter: &[u8; 16]) -> [u8; 16] {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            if let Some(rk) = &self.rk_sse {
                if is_x86_feature_detected!("aes") {
                    return unsafe { aes128_encrypt_block_aesni(counter, rk) };
                }
            }
        }

        aes128_encrypt_block_scalar(counter, &self.rk)
    }
}

#[inline(always)]
fn ctx() -> &'static Aes128Ctx {
    AES_CTX.get_or_init(|| Aes128Ctx::new(&AbAesCtrKey()))
}

/// In-place AES-128-CTR XOR. Encryption and decryption are identical.
///
/// # Safety
/// - `ptr` must be valid for reads/writes of `len` bytes.
pub unsafe fn aes_ctr_xor_in_place(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }

    let c = ctx();
    let mut counter = derive_iv(ptr as *const u8, len);

    let mut off = 0usize;
    while off < len {
        let ks = c.keystream_block(&counter);
        let n = (len - off).min(16);
        for i in 0..n {
            let p = ptr.add(off + i);
            *p ^= ks[i];
        }
        off += n;
        ctr_inc(&mut counter);
    }
}

/// Encrypts a memory region in-place (AES-128-CTR).
///
/// # Safety
/// `ptr` must be valid for reads/writes of `len` bytes.
pub fn AbAesCtrEncryptBlock(ptr: *mut u8, len: usize) {
    unsafe { aes_ctr_xor_in_place(ptr, len) }
}

/// Decrypts a memory region in-place (AES-128-CTR).
///
/// # Safety
/// `ptr` must be valid for reads/writes of `len` bytes.
pub fn AbAesCtrDecryptBlock(ptr: *mut u8, len: usize) {
    unsafe { aes_ctr_xor_in_place(ptr, len) }
}

/// Pads & encrypts a UTF-8 string into a heap-backed `Vec<u8>`.
pub fn AbAesCtrEncryptStr(input: &str, key: &[u8; 16]) -> Vec<u8> {
    let ctx = Aes128Ctx::new(key);

    let mut buf = input.as_bytes().to_vec();
    let pad_len = (16 - (buf.len() % 16)) % 16;
    buf.extend(std::iter::repeat(0).take(pad_len));

    let mut out = buf.clone();
    let mut counter = derive_iv(out.as_ptr(), out.len());
    let mut off = 0usize;
    while off < out.len() {
        let ks = ctx.keystream_block(&counter);
        let n = (out.len() - off).min(16);
        for i in 0..n {
            out[off + i] ^= ks[i];
        }
        off += n;
        ctr_inc(&mut counter);
    }
    out
}

/// Decrypts a byte buffer using the given key and returns the original UTF-8 string.
pub fn AbAesCtrDecryptBytes(encrypted: &[u8], key: &[u8; 16]) -> String {
    let ctx = Aes128Ctx::new(key);

    let mut buf = encrypted.to_vec();
    let mut counter = derive_iv(buf.as_ptr(), buf.len());
    let mut off = 0usize;
    while off < buf.len() {
        let ks = ctx.keystream_block(&counter);
        let n = (buf.len() - off).min(16);
        for i in 0..n {
            buf[off + i] ^= ks[i];
        }
        off += n;
        ctr_inc(&mut counter);
    }

    if let Some(pos) = buf.iter().rposition(|&b| b != 0) {
        buf.truncate(pos + 1);
    } else {
        buf.clear();
    }

    String::from_utf8_lossy(&buf).to_string()
}

// -----------------------------------------------------------------------------
// Scalar AES-128 implementation (encryption only)
// -----------------------------------------------------------------------------

const SBOX: [u8; 256] = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7,
    0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF,
    0x9C, 0xA4, 0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5,
    0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15, 0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
    0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E,
    0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED,
    0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF, 0xD0, 0xEF,
    0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF,
    0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D,
    0x64, 0x5D, 0x19, 0x73, 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE,
    0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5,
    0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08, 0xBA, 0x78, 0x25, 0x2E,
    0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E,
    0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55,
    0x28, 0xDF, 0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F,
    0xB0, 0x54, 0xBB, 0x16,
];

const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];

#[inline(always)]
fn xtime(x: u8) -> u8 {
    (x << 1) ^ (((x >> 7) & 1) * 0x1B)
}

#[inline(always)]
fn mix_column(a: &mut [u8; 4]) {
    // Standard AES MixColumns for one column.
    let t = a[0] ^ a[1] ^ a[2] ^ a[3];
    let u = a[0];
    a[0] ^= t ^ xtime(a[0] ^ a[1]);
    a[1] ^= t ^ xtime(a[1] ^ a[2]);
    a[2] ^= t ^ xtime(a[2] ^ a[3]);
    a[3] ^= t ^ xtime(a[3] ^ u);
}

#[inline(always)]
fn sub_bytes(state: &mut [u8; 16]) {
    for b in state.iter_mut() {
        *b = SBOX[*b as usize];
    }
}

#[inline(always)]
fn shift_rows(state: &mut [u8; 16]) {
    // State is column-major: [0,4,8,12] is row 0, etc.
    // Row 1 shift left by 1: [1,5,9,13]
    // Row 2 shift left by 2: [2,6,10,14]
    // Row 3 shift left by 3: [3,7,11,15]
    let t1 = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = t1;

    let t2 = state[2];
    let t6 = state[6];
    state[2] = state[10];
    state[6] = state[14];
    state[10] = t2;
    state[14] = t6;

    let t3 = state[3];
    state[3] = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = t3;
}

#[inline(always)]
fn mix_columns(state: &mut [u8; 16]) {
    for c in 0..4 {
        let mut col = [state[c * 4], state[c * 4 + 1], state[c * 4 + 2], state[c * 4 + 3]];
        mix_column(&mut col);
        state[c * 4] = col[0];
        state[c * 4 + 1] = col[1];
        state[c * 4 + 2] = col[2];
        state[c * 4 + 3] = col[3];
    }
}

#[inline(always)]
fn add_round_key(state: &mut [u8; 16], rk: &[u8; 16]) {
    for i in 0..16 {
        state[i] ^= rk[i];
    }
}

fn aes128_expand_key_scalar(k: &[u8; 16]) -> [[u8; 16]; 11] {
    let mut rks = [[0u8; 16]; 11];
    rks[0] = *k;

    for i in 1..=10 {
        let prev = rks[i - 1];
        let mut t = [prev[13], prev[14], prev[15], prev[12]]; // rotword
        for b in t.iter_mut() {
            *b = SBOX[*b as usize];
        }
        t[0] ^= RCON[i - 1];

        let mut next = [0u8; 16];
        // w0 = prev.w0 ^ t
        next[0] = prev[0] ^ t[0];
        next[1] = prev[1] ^ t[1];
        next[2] = prev[2] ^ t[2];
        next[3] = prev[3] ^ t[3];
        // w1 = prev.w1 ^ w0
        for j in 0..4 {
            next[4 + j] = prev[4 + j] ^ next[j];
        }
        // w2 = prev.w2 ^ w1
        for j in 0..4 {
            next[8 + j] = prev[8 + j] ^ next[4 + j];
        }
        // w3 = prev.w3 ^ w2
        for j in 0..4 {
            next[12 + j] = prev[12 + j] ^ next[8 + j];
        }

        rks[i] = next;
    }

    rks
}

fn aes128_encrypt_block_scalar(block: &[u8; 16], rk: &[[u8; 16]; 11]) -> [u8; 16] {
    let mut state = *block;
    add_round_key(&mut state, &rk[0]);

    for r in 1..10 {
        sub_bytes(&mut state);
        shift_rows(&mut state);
        mix_columns(&mut state);
        add_round_key(&mut state, &rk[r]);
    }

    sub_bytes(&mut state);
    shift_rows(&mut state);
    add_round_key(&mut state, &rk[10]);
    state
}

// -----------------------------------------------------------------------------
// AES-NI fast path (x86/x64)
// -----------------------------------------------------------------------------

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "aes,sse2")]
unsafe fn aes128_encrypt_block_aesni(block: &[u8; 16], rk: &[__m128i; 11]) -> [u8; 16] {
    let mut m = _mm_loadu_si128(block.as_ptr() as *const __m128i);
    m = _mm_xor_si128(m, rk[0]);
    for i in 1..10 {
        m = _mm_aesenc_si128(m, rk[i]);
    }
    m = _mm_aesenclast_si128(m, rk[10]);

    let mut out = [0u8; 16];
    _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, m);
    out
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "aes,sse2")]
unsafe fn aes128_expand_key_aesni_to_sse(k: &[u8; 16]) -> [__m128i; 11] {
    // `_mm_aeskeygenassist_si128` requires the RCON immediate to be a compile-time constant.
    macro_rules! key_assist {
        ($key:expr, $rcon:expr) => {{
            let mut tmp = _mm_aeskeygenassist_si128($key, $rcon);
            tmp = _mm_shuffle_epi32(tmp, 0xff);
            let mut key2 = $key;
            key2 = _mm_xor_si128(key2, _mm_slli_si128(key2, 4));
            key2 = _mm_xor_si128(key2, _mm_slli_si128(key2, 4));
            key2 = _mm_xor_si128(key2, _mm_slli_si128(key2, 4));
            _mm_xor_si128(key2, tmp)
        }};
    }

    let mut rks = [_mm_setzero_si128(); 11];
    rks[0] = _mm_loadu_si128(k.as_ptr() as *const __m128i);
    rks[1] = key_assist!(rks[0], 0x01);
    rks[2] = key_assist!(rks[1], 0x02);
    rks[3] = key_assist!(rks[2], 0x04);
    rks[4] = key_assist!(rks[3], 0x08);
    rks[5] = key_assist!(rks[4], 0x10);
    rks[6] = key_assist!(rks[5], 0x20);
    rks[7] = key_assist!(rks[6], 0x40);
    rks[8] = key_assist!(rks[7], 0x80);
    rks[9] = key_assist!(rks[8], 0x1B);
    rks[10] = key_assist!(rks[9], 0x36);
    rks
}
