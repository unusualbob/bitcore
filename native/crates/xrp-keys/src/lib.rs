use std::sync::LazyLock;

use bitcore_secp_context::{signing_context, verification_context};
use ed25519_dalek::{Signer, SigningKey};
use secp256k1::{Message, PublicKey, Scalar, SecretKey};
use sha2::{Digest, Sha512};
use zeroize::{Zeroize, Zeroizing};

pub enum KeyKind {
    Secp256k1Account(u32),
    Secp256k1Validator,
    Ed25519,
}

#[derive(Debug)]
pub struct SelfTestFailed;

static SELF_TEST_MESSAGE: LazyLock<[u8; 32]> =
    LazyLock::new(|| *sha512_half(Sha512::new_with_prefix(b"This test message should verify.")));
static SECP_SELF_TEST_DIGEST: LazyLock<Message> = LazyLock::new(|| {
    // ripple-keypairs hashes the test message again in the secp256k1 signer.
    Message::from_digest(*sha512_half(Sha512::new_with_prefix(*SELF_TEST_MESSAGE)))
});

/// Derives a ripple-keypairs family-seed keypair. Returns the prefixed private
/// key followed by the compressed (secp256k1) or prefixed (Ed25519) public key.
/// `None` lets the caller defer to the SDK if native derivation is unavailable.
pub fn derive(
    entropy: &[u8; 16],
    kind: KeyKind,
) -> Result<Option<Zeroizing<[u8; 66]>>, SelfTestFailed> {
    match kind {
        KeyKind::Secp256k1Account(index) => derive_secp256k1(entropy, Some(index)),
        KeyKind::Secp256k1Validator => derive_secp256k1(entropy, None),
        KeyKind::Ed25519 => derive_ed25519(entropy).map(Some),
    }
}

fn sha512_half(hash: Sha512) -> Zeroizing<[u8; 32]> {
    let mut digest = hash.finalize();
    let mut half = Zeroizing::new([0; 32]);
    half.copy_from_slice(&digest[..32]);
    digest.as_mut_slice().zeroize();
    half
}

struct PrivateScalar(SecretKey);

impl Drop for PrivateScalar {
    fn drop(&mut self) {
        self.0.non_secure_erase();
    }
}

fn derive_scalar(prefix: Sha512) -> Option<PrivateScalar> {
    for counter in 0..=u32::MAX {
        let candidate = sha512_half(prefix.clone().chain_update(counter.to_be_bytes()));
        // SecretKey accepts exactly the nonzero scalars below the curve order.
        if let Ok(scalar) = SecretKey::from_byte_array(*candidate) {
            return Some(PrivateScalar(scalar));
        }
    }
    None
}

fn derive_secp256k1(
    entropy: &[u8; 16],
    index: Option<u32>,
) -> Result<Option<Zeroizing<[u8; 66]>>, SelfTestFailed> {
    let (Ok(context), Some(mut secret)) = (
        signing_context(),
        derive_scalar(Sha512::new_with_prefix(entropy)),
    ) else {
        return Ok(None);
    };
    if let Some(index) = index {
        let generator = PublicKey::from_secret_key(context, &secret.0).serialize();
        let prefix = Sha512::new_with_prefix(generator).chain_update(index.to_be_bytes());
        let Some(account) = derive_scalar(prefix) else {
            return Ok(None);
        };
        let mut tweak = Scalar::from(account.0);
        let sum = secret.0.add_tweak(&tweak);
        tweak.non_secure_erase();
        let Ok(sum) = sum else {
            // A zero sum cannot produce a keypair. Let the SDK handle this case.
            return Ok(None);
        };
        secret = PrivateScalar(sum);
    }

    let public = PublicKey::from_secret_key(context, &secret.0);
    let signature = context.sign_ecdsa(*SECP_SELF_TEST_DIGEST, &secret.0);
    verification_context()
        .verify_ecdsa(*SECP_SELF_TEST_DIGEST, &signature, &public)
        .map_err(|_| SelfTestFailed)?;

    let mut packed = Zeroizing::new([0; 66]);
    packed[1..33].copy_from_slice(secret.0.as_ref());
    packed[33..].copy_from_slice(&public.serialize());
    Ok(Some(packed))
}

fn derive_ed25519(entropy: &[u8; 16]) -> Result<Zeroizing<[u8; 66]>, SelfTestFailed> {
    let secret = sha512_half(Sha512::new_with_prefix(entropy));
    let key = SigningKey::from_bytes(&secret);
    let public = key.verifying_key();
    let signature = key.sign(&*SELF_TEST_MESSAGE);
    public
        .verify_strict(&*SELF_TEST_MESSAGE, &signature)
        .map_err(|_| SelfTestFailed)?;

    let mut packed = Zeroizing::new([0; 66]);
    packed[0] = 0xed;
    packed[1..33].copy_from_slice(&*secret);
    packed[33] = 0xed;
    packed[34..].copy_from_slice(public.as_bytes());
    Ok(packed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_ripple_keypairs_1_3_1() {
        for (kind, private, public) in [
            (
                KeyKind::Secp256k1Account(0),
                "002512BBDFDBB77510883B7DCCBEF270B86DEAC8B64AC762873D75A1BEE6298665",
                "0390A196799EE412284A5D80BF78C3E84CBB80E1437A0AECD9ADF94D7FEAAFA284",
            ),
            (
                KeyKind::Secp256k1Account(u32::MAX),
                "00222D1A02A86272818E520C8849E8E0851B01C9F986092C85F1DDDA0A539A8388",
                "035F91BC326A331CF35F70F554AD4178213172648EDFA7AC377B2C5DA899AA19B4",
            ),
            (
                KeyKind::Secp256k1Validator,
                "00D296B892B3A7964BD0CC882FC7C0BE948B6BBD8EB1EFF8C13942FCAABF1F3877",
                "02F400467FA7FC3C1432BFEB8EDE23299AF25CDCF5DE76E9CB05BF6C567F4B09D8",
            ),
            (
                KeyKind::Ed25519,
                "ED0B6CBAC838DFE7F47EA1BD0DF00EC282FDF45510C92161072CCFB84035390C4D",
                "ED1A7C082846CFF58FF9A892BA4BA2593151CCF1DBA59F37714CC9ED39824AF85F",
            ),
        ] {
            let expected = private.to_owned() + public;
            let actual = derive(&[0; 16], kind).unwrap().unwrap();
            for (byte, hex) in actual.iter().zip(expected.as_bytes().chunks_exact(2)) {
                let hex = std::str::from_utf8(hex).unwrap();
                assert_eq!(*byte, u8::from_str_radix(hex, 16).unwrap());
            }
        }
    }
}
