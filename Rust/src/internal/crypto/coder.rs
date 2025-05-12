/// UTF-16 encoded, obfuscated version of the string "ntdll.dll", generated via custom encoder.
///
/// Decoded at runtime using [`decode()`] into a null-terminated UTF-16 path component.
pub static ENC: [u16; 9] = [
    0x83EE,
    0x91AF,
    0xD9FC,
    0x4113,
    0xC5CA,
    0x36F9,
    0x6AC0,
    0x81E3,
    0x8DF6,
];

/// Decrypts the obfuscated UTF-16 word array used to encode DLL names.
///
/// This uses a 5-stage reversible transformation:
/// 1. Bitwise XOR with `(i * 13) ^ 0xAA`  
/// 2. Right-rotate 16-bit value by `(i % 7) + 1`  
/// 3. Bitwise NOT + subtract `0x1337`  
/// 4. Multiply by modular inverse of `7` in GF(2^16) (hardcoded)  
/// 5. Subtract `0x1234 ^ (i * 73)`
///
/// # Arguments
/// - `enc`: encoded UTF-16 word slice (e.g. [`ENC`])
///
/// # Returns
/// Decoded UTF-16 vector, null-terminated (last element is `0`).
pub fn decode(enc: &[u16]) -> Vec<u16> {
    /// Performs a 16-bit right rotation.
    fn ror16(x: u16, r: u32) -> u16 {
        ((x >> r) | (x << (16 - r))) & 0xFFFF
    }

    let inv7: u16 = 28087; // modular inverse of 7 mod 65536
    let mut out = Vec::with_capacity(enc.len() + 1);

    for (i, &val) in enc.iter().rev().enumerate() {
        let mut x = val;

        x = x.wrapping_sub(0x1234 ^ (i as u16 * 73));
        x = x.wrapping_mul(inv7);
        x = !(x.wrapping_sub(0x1337));
        x = ror16(x, (i % 7 + 1) as u32);
        x ^= (i as u16 * 13) ^ 0xAA;

        out.push(x);
    }

    out.push(0); // null-terminate for Windows wide string
    out
}