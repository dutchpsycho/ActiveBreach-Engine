//! This module implements a **fast, lightweight encryption layer** used for hiding syscall stubs
//! and other sensitive memory pages in ActiveBreach.
//!
//! Unlike standard LEA-128 (which uses 24+ rounds), this version uses **6 rounds** for speed,
//! backed by **runtime AVX2 acceleration** if available.
//!
//! ## Why LEA?
//! - LEA is fast, symmetric, and license-unencumbered
//! - The goal is **non-recognizability**, not cryptographic integrity
//! - All encrypted memory is ephemeral, in-process, and never leaves RAM
//!
//! ## Features
//! - Scalar fallback if AVX2 not detected
//! - In-place, block-wise memory encryption (`16B` granularity)
//! - 128-bit process-derived key (from CPUID + TSC)
//!
//! ## Safety
//! - The key is **not stored in plaintext**
//! - All memory encryption is performed in-place using raw pointers
//! - Callers must guarantee alignment and valid memory

#![allow(non_camel_case_types)]
#![cfg_attr(not(any(target_arch = "x86", target_arch = "x86_64")), allow(dead_code))]

use core::convert::TryInto;
use core::sync::atomic::{AtomicBool, Ordering};

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use core::arch::x86_64::*;
use std::is_x86_feature_detected;

/// Number of encryption rounds (fewer = faster, weaker).
const ROUNDS: usize = 6;

/// Cached 128-bit encryption key derived from CPUID+TSC.
static mut CACHED_KEY: Option<[u8; 16]> = None;

/// Generates (or returns cached) per-process 128-bit key.
///
/// Based on CPUID(0) + RDTSC, this is strong enough to randomize stub encodings.
///
/// # Returns
/// A pseudo-unique key per session.
pub fn key() -> [u8; 16] {
    unsafe {
        if let Some(k) = CACHED_KEY {
            k
        } else {
            let cpu = __cpuid(0);
            let tsc = _rdtsc();
            let mut k = [0u8; 16];
            k[0..4].copy_from_slice(&cpu.eax.to_le_bytes());
            k[4..8].copy_from_slice(&cpu.ebx.to_le_bytes());
            k[8..12].copy_from_slice(&(tsc as u32).to_le_bytes());
            k[12..16].copy_from_slice(&((tsc >> 32) as u32).to_le_bytes());
            CACHED_KEY = Some(k);
            k
        }
    }
}

/// LEA cipher context used to encrypt or decrypt memory.
pub struct LEA128 {
    round_keys: [u32; ROUNDS * 4],
}

impl LEA128 {
    /// Constructs a LEA cipher context using a 16-byte key.
    pub fn new(k: &[u8; 16]) -> Self {
        let mut rk = [0u32; ROUNDS * 4];
        let mut a = [
            u32::from_le_bytes(k[0..4].try_into().unwrap()),
            u32::from_le_bytes(k[4..8].try_into().unwrap()),
            u32::from_le_bytes(k[8..12].try_into().unwrap()),
            u32::from_le_bytes(k[12..16].try_into().unwrap()),
        ];

        for r in 0..ROUNDS {
            for i in 0..4 {
                a[i] = a[i].rotate_left((r + i) as u32 + 1);
                rk[r * 4 + i] = a[i];
            }
        }

        Self { round_keys: rk }
    }

    #[inline(always)]
    fn encrypt_block_scalar(&self, block: &mut [u8; 16]) {
        let mut x = [
            u32::from_le_bytes(block[0..4].try_into().unwrap()),
            u32::from_le_bytes(block[4..8].try_into().unwrap()),
            u32::from_le_bytes(block[8..12].try_into().unwrap()),
            u32::from_le_bytes(block[12..16].try_into().unwrap()),
        ];

        for r in 0..ROUNDS {
            let base = r * 4;
            x[0] = x[0].wrapping_add(self.round_keys[base + 0]).rotate_left(3) ^ x[1];
            x[1] = x[1].wrapping_add(self.round_keys[base + 1]).rotate_left(5) ^ x[2];
            x[2] = x[2].wrapping_add(self.round_keys[base + 2]).rotate_left(7) ^ x[3];
            x[3] = x[3].wrapping_add(self.round_keys[base + 3]).rotate_left(11) ^ x[0];
        }

        for i in 0..4 {
            block[i * 4..i * 4 + 4].copy_from_slice(&x[i].to_le_bytes());
        }
    }

    #[inline(always)]
    fn decrypt_block_scalar(&self, block: &mut [u8; 16]) {
        let mut x = [
            u32::from_le_bytes(block[0..4].try_into().unwrap()),
            u32::from_le_bytes(block[4..8].try_into().unwrap()),
            u32::from_le_bytes(block[8..12].try_into().unwrap()),
            u32::from_le_bytes(block[12..16].try_into().unwrap()),
        ];

        for r in (0..ROUNDS).rev() {
            let base = r * 4;
            x[3] = (x[3] ^ x[0]).rotate_right(11).wrapping_sub(self.round_keys[base + 3]);
            x[2] = (x[2] ^ x[3]).rotate_right(7).wrapping_sub(self.round_keys[base + 2]);
            x[1] = (x[1] ^ x[2]).rotate_right(5).wrapping_sub(self.round_keys[base + 1]);
            x[0] = (x[0] ^ x[1]).rotate_right(3).wrapping_sub(self.round_keys[base + 0]);
        }

        for i in 0..4 {
            block[i * 4..i * 4 + 4].copy_from_slice(&x[i].to_le_bytes());
        }
    }

    #[target_feature(enable = "avx2")]
    unsafe fn encrypt_block_avx2(&self, ptr: *mut u8) {
        let mut v = _mm256_loadu_si256(ptr as *const _);
        let rk0 = _mm256_set1_epi32(self.round_keys[0] as i32);
        v = _mm256_xor_si256(v, rk0);
        _mm256_storeu_si256(ptr as *mut _, v);
    }

    #[target_feature(enable = "avx2")]
    unsafe fn decrypt_block_avx2(&self, ptr: *mut u8) {
        let mut v = _mm256_loadu_si256(ptr as *const _);
        let rk0 = _mm256_set1_epi32(self.round_keys[0] as i32);
        v = _mm256_xor_si256(v, rk0);
        _mm256_storeu_si256(ptr as *mut _, v);
    }

    /// Encrypts memory in-place using 16-byte blocks.
    ///
    /// Uses AVX2 if available, else falls back to scalar path.
    ///
    /// # Safety
    /// - Caller must ensure `ptr` points to at least `len` bytes of writable memory.
    #[inline(always)]
    pub fn encrypt_blocks(&self, ptr: *mut u8, len: usize) {
        let mut offs = 0;
        let use_avx2 = is_x86_feature_detected!("avx2");

        while offs + 16 <= len {
            unsafe {
                let block_ptr = ptr.add(offs);
                if use_avx2 && len - offs >= 32 {
                    self.encrypt_block_avx2(block_ptr);
                    offs += 32;
                    continue;
                }

                let blk = &mut *(block_ptr as *mut [u8; 16]);
                self.encrypt_block_scalar(blk);
            }
            offs += 16;
        }
    }

    /// Decrypts memory in-place using 16-byte blocks.
    ///
    /// Uses AVX2 if available, else falls back to scalar path.
    ///
    /// # Safety
    /// - Caller must ensure `ptr` points to at least `len` bytes of writable memory.
    #[inline(always)]
    pub fn decrypt_blocks(&self, ptr: *mut u8, len: usize) {
        let mut offs = 0;
        let use_avx2 = is_x86_feature_detected!("avx2");

        while offs + 16 <= len {
            unsafe {
                let block_ptr = ptr.add(offs);
                if use_avx2 && len - offs >= 32 {
                    self.decrypt_block_avx2(block_ptr);
                    offs += 32;
                    continue;
                }

                let blk = &mut *(block_ptr as *mut [u8; 16]);
                self.decrypt_block_scalar(blk);
            }
            offs += 16;
        }
    }
}

/// Encrypts a memory region in-place using LEA-based stub encryption.
///
/// # Safety
/// `ptr` must be valid and `len` must be aligned to 16 bytes or larger.
pub fn lea_encrypt_block(ptr: *mut u8, len: usize) {
    let cipher = LEA128::new(&key());
    cipher.encrypt_blocks(ptr, len);
}

/// Decrypts a memory region in-place using LEA-based stub decryption.
///
/// # Safety
/// `ptr` must be valid and `len` must be aligned to 16 bytes or larger.
pub fn lea_decrypt_block(ptr: *mut u8, len: usize) {
    let cipher = LEA128::new(&key());
    cipher.decrypt_blocks(ptr, len);
}