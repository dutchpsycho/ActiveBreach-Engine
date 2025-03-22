pub static ENC: [u16; 9] = [ // ntdll.dll, encoded w crypter.go
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

pub fn decode(enc: &[u16]) -> Vec<u16> {

    fn ror16(x: u16, r: u32) -> u16 {
        ((x >> r) | (x << (16 - r))) & 0xFFFF
    }
    
    let inv7: u16 = 28087;
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
    
    out.push(0);

    out
}