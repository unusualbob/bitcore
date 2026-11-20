use std::fmt;

use bitcore_secp_context::{signing_context, verification_context};
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId, Signature};
use secp256k1::{Message, PublicKey, SecretKey, constants};

pub mod random_nonce;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    DigestOutOfRange,
    InvalidSecretKey,
    ContextRandomizationFailed,
    InvalidPublicKey,
    InvalidSignature,
    InvalidRecoveryId,
    RecoveryFailed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::DigestOutOfRange => "digest requires the legacy deterministic signing algorithm",
            Self::InvalidSecretKey => "invalid ECDSA secret key",
            Self::ContextRandomizationFailed => "could not obtain OS entropy for ECDSA signing",
            Self::InvalidPublicKey => "invalid ECDSA public key",
            Self::InvalidSignature => "invalid compact ECDSA signature",
            Self::InvalidRecoveryId => "ECDSA recovery ID must be between 0 and 3",
            Self::RecoveryFailed => "could not recover ECDSA public key",
        })
    }
}

impl std::error::Error for Error {}

/// Signs a big-endian digest and produces a compact low-S signature (r || s).
pub fn sign(digest: &[u8; 32], secret_key: &[u8; 32]) -> Result<[u8; 64], Error> {
    // libsecp256k1 reduces the digest before seeding RFC6979. Bitcore uses
    // the original bytes, so JS handles these rare digests to preserve output.
    if digest >= &constants::CURVE_ORDER {
        return Err(Error::DigestOutOfRange);
    }

    let context = signing_context().map_err(|_| Error::ContextRandomizationFailed)?;
    let mut secret_key =
        SecretKey::from_byte_array(*secret_key).map_err(|_| Error::InvalidSecretKey)?;
    let signature = context.sign_ecdsa(Message::from_digest(*digest), &secret_key);
    secret_key.non_secure_erase();
    Ok(signature.serialize_compact())
}

/// Signs for RFC6979 callers which seed their nonce with the reduced digest.
pub fn sign_recoverable(digest: &[u8; 32], secret_key: &[u8; 32]) -> Result<[u8; 65], Error> {
    let context = signing_context().map_err(|_| Error::ContextRandomizationFailed)?;
    let mut secret_key =
        SecretKey::from_byte_array(*secret_key).map_err(|_| Error::InvalidSecretKey)?;
    let signature = context.sign_ecdsa_recoverable(Message::from_digest(*digest), &secret_key);
    secret_key.non_secure_erase();
    let (recovery_id, signature) = signature.serialize_compact();
    let mut packed = [0; 65];
    packed[..64].copy_from_slice(&signature);
    packed[64] = i32::from(recovery_id) as u8;
    Ok(packed)
}

/// Produces a low-S, DER encoded RFC6979 signature for XRP.
pub fn sign_der(digest: &[u8; 32], secret_key: &[u8; 32]) -> Result<Vec<u8>, Error> {
    let context = signing_context().map_err(|_| Error::ContextRandomizationFailed)?;
    let mut secret_key =
        SecretKey::from_byte_array(*secret_key).map_err(|_| Error::InvalidSecretKey)?;
    let signature = context.sign_ecdsa(Message::from_digest(*digest), &secret_key);
    secret_key.non_secure_erase();
    Ok(signature.serialize_der().to_vec())
}

/// Verifies a compact signature against a big-endian digest and SEC1 public key.
pub fn verify(digest: &[u8; 32], signature: &[u8; 64], public_key: &[u8]) -> Result<bool, Error> {
    let public_key = PublicKey::from_slice(public_key).map_err(|_| Error::InvalidPublicKey)?;
    let mut signature = Signature::from_compact(signature).map_err(|_| Error::InvalidSignature)?;

    // Bitcore accepts both canonical low-S signatures and their high-S equivalents.
    signature.normalize_s();
    Ok(verification_context()
        .verify_ecdsa(Message::from_digest(*digest), &signature, &public_key)
        .is_ok())
}

/// Recovers a SEC1 public key from a big-endian digest, compact signature and recovery ID.
pub fn recover_public_key(
    digest: &[u8; 32],
    signature: &[u8; 64],
    recovery_id: u8,
    compressed: bool,
) -> Result<Vec<u8>, Error> {
    let recovery_id =
        RecoveryId::try_from(i32::from(recovery_id)).map_err(|_| Error::InvalidRecoveryId)?;
    let signature = RecoverableSignature::from_compact(signature, recovery_id)
        .map_err(|_| Error::InvalidSignature)?;
    let public_key = verification_context()
        .recover_ecdsa(Message::from_digest(*digest), &signature)
        .map_err(|_| Error::RecoveryFailed)?;

    Ok(if compressed {
        public_key.serialize().to_vec()
    } else {
        public_key.serialize_uncompressed().to_vec()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes<const N: usize>(hex: &str) -> [u8; N] {
        assert_eq!(hex.len(), N * 2);
        std::array::from_fn(|index| {
            let start = 2 * index;
            u8::from_str_radix(&hex[start..start + 2], 16).unwrap()
        })
    }

    #[test]
    fn matches_bitcore_ecdsa_vector() {
        // First independent test vector from bitcore-lib/test/data/ecdsa.json.
        let digest = bytes("06ef2b193b83b3d701f765f1db34672ab84897e1252343cc2197829af3a30456");
        let mut secret_key = [0; 32];
        secret_key[31] = 1;
        let public_key =
            bytes::<33>("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
        let signature = bytes(concat!(
            "33a69cd2065432a30f3d1ce4eb0d59b8ab58c74f27c41a7fdb5696ad4e6108c9",
            "6f807982866f785d3f6418d24163ddae117b7db4d5fdf0071de069fa54342262"
        ));

        assert_eq!(sign(&digest, &secret_key).unwrap(), signature);
        assert!(verify(&digest, &signature, &public_key).unwrap());
        assert_eq!(
            recover_public_key(&digest, &signature, 0, true).unwrap(),
            public_key
        );

        let high_s_signature = bytes(concat!(
            "33a69cd2065432a30f3d1ce4eb0d59b8ab58c74f27c41a7fdb5696ad4e6108c9",
            "907f867d799087a2c09be72dbe9c2250a9335f31d94ab034a1f1f4927c021edf"
        ));
        assert!(verify(&digest, &high_s_signature, &public_key).unwrap());
        assert_eq!(
            recover_public_key(&digest, &high_s_signature, 1, true).unwrap(),
            public_key
        );
    }

    #[test]
    fn instructs_js_to_sign_unreduced_digests() {
        let mut secret_key = [0; 32];
        secret_key[31] = 1;
        assert_eq!(
            sign(&constants::CURVE_ORDER, &secret_key),
            Err(Error::DigestOutOfRange)
        );
    }
}
