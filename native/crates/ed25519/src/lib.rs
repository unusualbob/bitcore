use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{Signer, SigningKey};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256, Sha512};
use zeroize::{Zeroize, Zeroizing};

/// Derives a SLIP-0010 Ed25519 child path from a serialized key and chain code.
/// The path supplies serialized big-endian child index values as u32s.
pub fn derive_path(key: &[u8; 32], chain_code: &[u8; 32], path: &[u32]) -> Zeroizing<[u8; 64]> {
    let mut child = Zeroizing::new([0; 64]);
    child[..32].copy_from_slice(key);
    child[32..].copy_from_slice(chain_code);
    for index in path {
        let mut mac =
            <Hmac<Sha512> as KeyInit>::new_from_slice(&child[32..]).expect("valid HMAC key length");
        mac.update(&[0]);
        mac.update(&child[..32]);
        mac.update(&index.to_be_bytes());
        let mut digest = mac.finalize().into_bytes();
        child.copy_from_slice(digest.as_slice());
        digest.as_mut_slice().zeroize();
    }
    child
}

/// Finds a Solana associated-token PDA, returning the address followed by its bump.
pub fn associated_token_address(seeds: &[u8; 96], program_address: &[u8; 32]) -> Option<[u8; 33]> {
    let initial = Sha256::new().chain_update(seeds);
    for bump in (1..=255u8).rev() {
        let address = initial
            .clone()
            .chain_update([bump])
            .chain_update(program_address)
            .chain_update(b"ProgramDerivedAddress")
            .finalize()
            .into();
        if !solana_point_is_on_curve(address) {
            let mut found = [0; 33];
            found[..32].copy_from_slice(&address);
            found[32] = bump;
            return Some(found);
        }
    }
    None
}

fn solana_point_is_on_curve(address: [u8; 32]) -> bool {
    CompressedEdwardsY(address)
        .decompress()
        .is_some_and(|point| {
            // Solana Kit rejects the noncanonical negative encoding of x = 0.
            address[31] & 128 == 0 || point.compress().to_bytes()[31] & 128 != 0
        })
}

/// Expands a 32-byte Ed25519 seed to its public key.
pub fn public_key(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

/// Signs a message with a 32-byte Ed25519 seed, returning its public key and signature.
pub fn sign(seed: &[u8; 32], message: &[u8]) -> ([u8; 32], [u8; 64]) {
    let key = SigningKey::from_bytes(seed);
    (key.verifying_key().to_bytes(), key.sign(message).to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes<const N: usize>(hex: &str) -> [u8; N] {
        assert_eq!(hex.len(), 2 * N);
        std::array::from_fn(|index| u8::from_str_radix(&hex[2 * index..2 * index + 2], 16).unwrap())
    }

    #[test]
    fn matches_slip10_ed25519_vector_two() {
        let master = bytes("171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012");
        let chain = bytes("ef70a74db9c3a5af931b5fe73ed8e1a53464133654fd55e7a66f8570b8e33c3b");
        let derived = derive_path(&master, &chain, &[0x80000000, 0xffffffff]);
        assert_eq!(
            *derived,
            bytes(concat!(
                "ea4f5bfe8694d8bb74b7b59404632fd5968b774ed545e810de9c32a4fb4192f4",
                "138f0b2551bcafeca6ff2aa88ba8ed0ed8de070841f0c4ef0165df8181eaad7f"
            ))
        );
        assert_eq!(
            public_key(derived[..32].try_into().unwrap()),
            bytes("5ba3b9ac6e90e83effcd25ac4e58a1365a9e35a3d3ae5eb07b9e4d90bcf7506d")
        );
    }

    #[test]
    fn matches_rfc8032_ed25519_first_vector() {
        let seed = bytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let expected_public =
            bytes("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let expected_signature = bytes(concat!(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        ));
        assert_eq!(sign(&seed, b""), (expected_public, expected_signature));
    }

    #[test]
    fn solana_point_parser_matches_noncanonical_edges() {
        let mut positive_zero_x = [0; 32];
        positive_zero_x[0] = 1;
        assert!(solana_point_is_on_curve(positive_zero_x));
        let mut negative_zero_x = positive_zero_x;
        negative_zero_x[31] = 0x80;
        assert!(!solana_point_is_on_curve(negative_zero_x));

        // At p + 1 the y coordinate reduces to 1, also giving x = 0.
        let mut noncanonical_y = [0xff; 32];
        noncanonical_y[0] = 0xee;
        noncanonical_y[31] = 0x7f;
        assert!(solana_point_is_on_curve(noncanonical_y));
        noncanonical_y[31] = 0xff;
        assert!(!solana_point_is_on_curve(noncanonical_y));
    }
}
