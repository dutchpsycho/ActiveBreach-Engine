//! "Own" entropy helpers (no bcrypt, no dynamic DLL loading).
//!
//! Strategy:
//! - Prefer CPU instructions `RDSEED` then `RDRAND` when available (no IAT imports).
//! - Fallback: jitter-based mixing from `RDTSC`, stack pointer, and addresses.
//!   This is best-effort and primarily intended to randomize small ranges (e.g. stub count).

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::{__cpuid, __cpuid_count, _rdrand64_step, _rdseed64_step};

#[inline(always)]
fn splitmix64_next(x: &mut u64) -> u64 {
    *x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *x;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn has_rdseed() -> bool {
    unsafe {
        let r = __cpuid_count(7, 0);
        (r.ebx & (1 << 18)) != 0
    }
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn has_rdrand() -> bool {
    unsafe {
        let r = __cpuid(1);
        (r.ecx & (1 << 30)) != 0
    }
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn rdtsc() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack));
    }
    ((hi as u64) << 32) | (lo as u64)
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn rsp() -> u64 {
    let v: u64;
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) v, options(nomem, nostack));
    }
    v
}

#[inline(always)]
fn strong_fill(buf: &mut [u8]) {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        // Try RDSEED first.
        if has_rdseed() {
            let mut i = 0usize;
            while i < buf.len() {
                let mut x: u64 = 0;
                for _ in 0..128 {
                    if _rdseed64_step(&mut x) == 1 {
                        let n = core::cmp::min(8, buf.len() - i);
                        buf[i..i + n].copy_from_slice(&x.to_le_bytes()[..n]);
                        i += n;
                        break;
                    }
                    core::hint::spin_loop();
                }
            }
            return;
        }

        // Then RDRAND.
        if has_rdrand() {
            let mut i = 0usize;
            while i < buf.len() {
                let mut x: u64 = 0;
                for _ in 0..128 {
                    if _rdrand64_step(&mut x) == 1 {
                        let n = core::cmp::min(8, buf.len() - i);
                        buf[i..i + n].copy_from_slice(&x.to_le_bytes()[..n]);
                        i += n;
                        break;
                    }
                    core::hint::spin_loop();
                }
            }
            return;
        }
    }

    // Best-effort fallback. Not cryptographic, but good enough for small-range randomization.
    let mut s =
        (buf.as_ptr() as usize as u64) ^ (buf.len() as u64).wrapping_mul(0xD6E8_FEB8_6659_FD93);

    #[cfg(target_arch = "x86_64")]
    {
        s ^= rdtsc();
        s ^= rsp().rotate_left(17);
    }

    // Add jitter by timing a tiny loop; differences in scheduling/caches perturb `rdtsc`.
    #[cfg(target_arch = "x86_64")]
    {
        let mut acc = 0u64;
        for _ in 0..64 {
            let t0 = rdtsc();
            core::hint::spin_loop();
            let t1 = rdtsc();
            acc = acc.wrapping_add(t1.wrapping_sub(t0));
        }
        s ^= acc.rotate_left(9);
    }

    for b in buf {
        let x = splitmix64_next(&mut s);
        *b = (x >> 56) as u8;
    }
}

#[inline(always)]
pub fn strong_u32() -> u32 {
    let mut b = [0u8; 4];
    strong_fill(&mut b);
    u32::from_le_bytes(b)
}

#[inline(always)]
pub fn strong_range_u8_inclusive(min: u8, max: u8) -> u8 {
    debug_assert!(min <= max);
    let span = (max as u32).wrapping_sub(min as u32) + 1;
    let v = strong_u32() % span;
    (min as u32 + v) as u8
}
