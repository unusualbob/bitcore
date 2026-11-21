use sha2::{Digest, Sha256};
use zeroize::Zeroize;

const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const RADIX: u64 = 58u64.pow(5);
const DIGITS: [u8; 256] = {
    let mut digits = [u8::MAX; 256];
    let mut i = 0;
    while i < ALPHABET.len() {
        digits[ALPHABET[i] as usize] = i as u8;
        i += 1;
    }
    digits
};

// Bound the quadratic conversion and use stack storage for wallet-sized values.
pub const MAX_BYTES: usize = 128;
pub const MAX_TEXT: usize = MAX_BYTES * 138 / 100 + 1;
const CHECKSUM_BYTES: usize = 4;

pub struct Scratch<T: Zeroize>(pub T);

impl<T: Zeroize> Drop for Scratch<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub fn encode<'a>(bytes: &[u8], output: &'a mut [u8; MAX_TEXT]) -> Option<&'a [u8]> {
    if bytes.len() > MAX_BYTES {
        return None;
    }

    let zeroes = bytes.iter().take_while(|&&byte| byte == 0).count();
    let mut limbs = Scratch([0u32; MAX_TEXT.div_ceil(5)]);
    let mut used = 0;
    // Accumulate four bytes at a time in little-endian base-58^5 limbs.
    for chunk in bytes[zeroes..].chunks(4) {
        let mut carry = chunk
            .iter()
            .fold(0u64, |value, &byte| (value << 8) | u64::from(byte));
        let shift = chunk.len() * 8;
        for limb in &mut limbs.0[..used] {
            carry += u64::from(*limb) << shift;
            *limb = (carry % RADIX) as u32;
            carry /= RADIX;
        }
        while carry != 0 {
            limbs.0[used] = (carry % RADIX) as u32;
            carry /= RADIX;
            used += 1;
        }
    }

    let mut start = output.len();
    for (i, &limb) in limbs.0[..used].iter().enumerate() {
        let mut value = limb;
        for _ in 0..5 {
            start -= 1;
            output[start] = ALPHABET[(value % 58) as usize];
            value /= 58;
            if value == 0 && i + 1 == used {
                break;
            }
        }
    }
    output[start - zeroes..start].fill(b'1');
    Some(&output[start - zeroes..])
}

pub fn decode<'a>(text: &[u8], output: &'a mut [u8; MAX_TEXT]) -> Option<&'a [u8]> {
    if text.len() > MAX_TEXT {
        return None;
    }

    let zeroes = text.iter().take_while(|&&byte| byte == b'1').count();
    let mut limbs = Scratch([0u32; MAX_TEXT.div_ceil(4)]);
    let mut used = 0;
    // Accumulate five digits at a time in little-endian base-2^32 limbs.
    for chunk in text[zeroes..].chunks(5) {
        let mut carry = 0;
        for &byte in chunk {
            let digit = DIGITS[byte as usize];
            if digit == u8::MAX {
                return None;
            }
            carry = carry * 58 + u64::from(digit);
        }
        let factor = if chunk.len() == 5 {
            RADIX
        } else {
            58u64.pow(chunk.len() as u32)
        };
        for limb in &mut limbs.0[..used] {
            carry += u64::from(*limb) * factor;
            *limb = carry as u32;
            carry >>= 32;
        }
        if carry != 0 {
            limbs.0[used] = carry as u32;
            used += 1;
        }
    }

    let mut start = output.len();
    if let Some((&head, tail)) = limbs.0[..used].split_last() {
        for limb in tail {
            start -= 4;
            output[start..start + 4].copy_from_slice(&limb.to_be_bytes());
        }
        let bytes = head.to_be_bytes();
        let length = 4 - head.leading_zeros() as usize / 8;
        start -= length;
        output[start..start + length].copy_from_slice(&bytes[4 - length..]);
    }
    output[start - zeroes..start].fill(0);
    Some(&output[start - zeroes..])
}

fn checksum(bytes: &[u8]) -> [u8; CHECKSUM_BYTES] {
    Sha256::digest(Sha256::digest(bytes))[..CHECKSUM_BYTES]
        .try_into()
        .unwrap()
}

pub fn encode_check<'a>(bytes: &[u8], output: &'a mut [u8; MAX_TEXT]) -> Option<&'a [u8]> {
    if bytes.len() > MAX_BYTES - CHECKSUM_BYTES {
        return None;
    }
    let mut checked = Scratch([0; MAX_BYTES]);
    let checked = &mut checked.0[..bytes.len() + CHECKSUM_BYTES];
    let (data, suffix) = checked.split_at_mut(bytes.len());
    data.copy_from_slice(bytes);
    suffix.copy_from_slice(&checksum(bytes));
    encode(checked, output)
}

pub fn decode_checked<'a>(text: &[u8], output: &'a mut [u8; MAX_TEXT]) -> Option<&'a [u8]> {
    let checked = decode(text, output)?;
    let (data, suffix) = checked.split_last_chunk::<CHECKSUM_BYTES>()?;
    // Node returns a payload view of the full checked buffer, including the
    // checksum immediately after the visible payload.
    (checksum(data) == *suffix).then_some(checked)
}
