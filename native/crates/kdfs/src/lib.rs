use hmac::Hmac;
use sha2::{Digest, Sha512};

/// Derives a BIP39 seed from the already normalized phrase and salt bytes.
pub fn bip39_seed(phrase: &[u8], salt: &[u8], seed: &mut [u8; 64]) {
    pbkdf2::pbkdf2::<Hmac<Sha512>>(phrase, salt, 2048, seed)
        .expect("HMAC supports keys of any length");
}

/// Hashes a Bitcoin Core wallet's passphrase followed by its salt, then rehashes the digest.
pub fn bitcoin_core_wallet_key(input: &[u8], rounds: u32, key: &mut [u8; 64]) {
    let mut hash = Sha512::new();
    hash.update(input);
    hash.finalize_into_reset((&mut *key).into());
    for _ in 1..rounds {
        hash.update(key.as_slice());
        hash.finalize_into_reset((&mut *key).into());
    }
}

/// Hashes the 80-byte proof-of-work header for Dogecoin or Litecoin.
pub fn scrypt_proof_of_work(header: &[u8; 80]) -> [u8; 32] {
    let params = scrypt::Params::new(10, 1, 1).expect("valid proof-of-work parameters");
    let mut hash = [0; 32];
    scrypt::scrypt(header, header, &params, &mut hash).expect("valid 32-byte hash output");
    hash
}

#[cfg(test)]
mod tests {
    use super::{bip39_seed, scrypt_proof_of_work};

    fn hex<const N: usize>(text: &str) -> [u8; N] {
        assert_eq!(text.len(), 2 * N);
        std::array::from_fn(|index| {
            u8::from_str_radix(&text[2 * index..2 * index + 2], 16).unwrap()
        })
    }

    #[test]
    fn bip39_trezor_vector() {
        let phrase = b"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mut seed = [0; 64];
        bip39_seed(phrase, b"mnemonicTREZOR", &mut seed);
        assert_eq!(
            seed,
            hex(concat!(
                "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531",
                "f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
            ))
        );
    }

    #[test]
    fn litecoin_proof_of_work_vector() {
        let header = hex(concat!(
            "020000004c1271c211717198227392b029a64a7971931d351b387bb80db027f270411e398a",
            "07046f7d4a08dd815412a8712f874a7ebf0507e3878bd24e20a3b73fd750a667d2f451eac7471b00de6659"
        ));
        let mut hash = scrypt_proof_of_work(&header);
        hash.reverse();
        assert_eq!(
            hash,
            hex("00000000002bef4107f882f6115e0b01f348d21195dacd3582aa2dabd7985806")
        );
    }
}
