use std::ffi::OsString;
use std::os::windows::ffi::{OsStringExt, OsStrExt};

const XOR_KEY: u16 = 0x5A;
static ENC: [u16; 9] = [
    0x0036, 0x0036, 0x003E, 0x0074, 0x0036, 0x0036, 0x003E, 0x002E, 0x0034,
];

pub fn decode() -> Vec<u16> {
    let size = ENC.len() - 1;
    let mut decoded = vec![0u16; size + 1];
    for i in 0..size {
        decoded[i] = ENC[size - i - 1] ^ XOR_KEY;
    }
    decoded[size] = 0;
    decoded
}

pub fn wide_null(s: &str) -> Vec<u16> {
    OsString::from(s).encode_wide().chain(Some(0)).collect()
}