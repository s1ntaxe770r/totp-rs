use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::time::SystemTime;

// interval in seconds
const TOTP_INTERVAL: u64 = 30;

type HmacSha256 = Hmac<Sha256>;

// number of digits in the final otp
const TOTP_DIGITS: usize = 8;

fn main() {
    let secret_key = b"friedfieldnotsomuch";
    let time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let password = create_totp(secret_key, time);
    println!("One-time password: {}", password);
}

fn create_totp(secret_key: &[u8], time: u64) -> String {
    // type HmacSha256 = Hmac<Sha256>;
    // time_step is the interval used to generate a new one time password
    let time_step = time / TOTP_INTERVAL;

    let mut mac = HmacSha256::new_from_slice(secret_key).expect("unable to create mac");

    // update HMAC with the time step in bytes 
    mac.update(&time_step.to_be_bytes());

    let final_hmac = mac.finalize();

    let result_bytes = final_hmac.into_bytes();
    
    // The 0x7fffffff value is used to ensure that the truncated hash value is a positive integer.
    // When using the HMAC algorithm, the resulting hash is a binary value, and it may contain bits that are set in the most significant (left-most) position, which would cause it to be interpreted as a negative number when cast to a signed integer type.
    let offset = (result_bytes[result_bytes.len() - 1] & 0xf) as usize;

    let mut truncated_hash = 0;
    for i in 0..4 {
        truncated_hash <<= 8;
        truncated_hash |= result_bytes[offset + i] as u32;
    }
    truncated_hash &= 0x7fffffff;
    truncated_hash %= 10_u32.pow(TOTP_DIGITS as u32);

    // Return the one-time password as a string

    let password = format!("{:0width$}", truncated_hash, width=TOTP_DIGITS);
    password
}
