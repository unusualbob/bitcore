//! Hashes and signatures used by the EVM and XRP wallet providers.

use bitcore_ecdsa::Error;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256, Sha512};
use sha3::Keccak256;

pub fn keccak256(bytes: &[u8]) -> [u8; 32] {
    Keccak256::digest(bytes).into()
}

pub fn evm_address(coordinates: &[u8; 64]) -> [u8; 42] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = keccak256(coordinates);
    let mut address = [0; 42];
    address[..2].copy_from_slice(b"0x");
    for (byte, pair) in digest[12..].iter().zip(address[2..].chunks_exact_mut(2)) {
        pair.copy_from_slice(&[HEX[(byte >> 4) as usize], HEX[(byte & 15) as usize]]);
    }
    checksum_address(&mut address[2..]);
    address
}

fn checksum_address(body: &mut [u8]) {
    let checksum = keccak256(body);
    for (byte, pair) in checksum.iter().zip(body.chunks_exact_mut(2)) {
        if byte & 0x80 != 0 {
            pair[0].make_ascii_uppercase();
        }
        if byte & 0x08 != 0 {
            pair[1].make_ascii_uppercase();
        }
    }
}

pub fn valid_evm_address(input: &[u8; 40]) -> bool {
    if !input.iter().all(u8::is_ascii_hexdigit) {
        return false;
    }
    if !input.iter().any(u8::is_ascii_uppercase) || !input.iter().any(u8::is_ascii_lowercase) {
        return true;
    }
    let mut body = *input;
    body.make_ascii_lowercase();
    checksum_address(&mut body);
    body == *input
}

pub fn format_evm_address(input: &[u8; 40]) -> Option<[u8; 42]> {
    if !input.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let mut address = [0; 42];
    address[..2].copy_from_slice(b"0x");
    address[2..].copy_from_slice(input);
    address[2..].make_ascii_lowercase();
    checksum_address(&mut address[2..]);
    Some(address)
}

pub fn evm_recover_address(
    digest: &[u8; 32],
    signature: &[u8; 64],
    parity: u8,
) -> Result<[u8; 42], Error> {
    let key = bitcore_ecdsa::recover_public_key(digest, signature, parity, false)?;
    Ok(evm_address(
        key[1..].try_into().expect("uncompressed public key"),
    ))
}

pub fn xrp_hash(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha512::digest(bytes);
    digest[..32].try_into().expect("SHA512 digest")
}

pub fn xrp_address(public_key: &[u8]) -> [u8; 20] {
    Ripemd160::digest(Sha256::digest(public_key)).into()
}

pub fn xrp_sign(bytes: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, Error> {
    bitcore_ecdsa::sign_der(&xrp_hash(bytes), key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evm_address_and_recovery_use_keccak_and_eip55() {
        let mut key = [0; 32];
        key[31] = 1;
        let digest = keccak256(b"");
        assert_eq!(digest[..4], [0xc5, 0xd2, 0x46, 0x01]);
        let signature = bitcore_ecdsa::sign_recoverable(&digest, &key).unwrap();
        let address =
            evm_recover_address(&digest, signature[..64].try_into().unwrap(), signature[64])
                .unwrap();
        assert_eq!(&address, b"0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf");
    }
}
