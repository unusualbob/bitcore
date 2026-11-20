use std::ffi::{c_int, c_void};
use std::panic::catch_unwind;
use std::sync::OnceLock;

use bitcore_secp_context::{ContextRandomizationError, signing_context, verification_context};
use secp256k1::ffi::{self, CPtr};
use secp256k1::schnorr::Signature;
use secp256k1::{Keypair, Parity, Scalar, SecretKey, XOnlyPublicKey, constants};
use sha2::{Digest, Sha256};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SigningError {
    ContextRandomization(ContextRandomizationError),
    NonceFailed,
    VerificationFailed,
}

fn nonce_digest(masked: &[u8; 32], public: &[u8; 32], message: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    static NONCE: OnceLock<Sha256> = OnceLock::new();
    let tag = tagged_sha256(&NONCE, b"BIP0340/nonce");
    let mut nonce = Zeroizing::new([0; 32]);
    let mut leading_zeroes = Choice::from(1);
    for (start, byte) in masked.iter().enumerate() {
        // Bitcore serializes the masked scalar as an unsigned minimal integer.
        // Evaluate every suffix and select without branching on secret data.
        let nonzero = !byte.ct_eq(&0);
        let last_byte = Choice::from(u8::from(start == 31));
        let chosen = leading_zeroes & (nonzero | last_byte);
        leading_zeroes &= !nonzero;
        let mut candidate = tag
            .clone()
            .chain_update(&masked[start..])
            .chain_update(public)
            .chain_update(message)
            .finalize();
        for (output, value) in nonce.iter_mut().zip(&candidate) {
            output.conditional_assign(value, chosen);
        }
        candidate.as_mut_slice().zeroize();
    }
    nonce
}

unsafe extern "C" fn bitcore_nonce(
    output: *mut u8,
    message: *const u8,
    message_len: usize,
    normalized_secret: *const u8,
    public: *const u8,
    _algorithm: *const u8,
    _algorithm_len: usize,
    aux: *mut c_void,
) -> c_int {
    if message_len != 32
        || message.is_null()
        || aux.is_null()
        || normalized_secret.is_null()
        || public.is_null()
        || output.is_null()
    {
        return 0;
    }
    // This callback is registered only below. libsecp256k1 supplies the
    // parity-normalized secret, x-only public key and output of 32 bytes each.
    // The message and auxiliary inputs are borrowed from that same call.
    let result = catch_unwind(|| unsafe {
        let message = &*message.cast::<[u8; 32]>();
        let public = &*public.cast::<[u8; 32]>();
        let normalized_secret = &*normalized_secret.cast::<[u8; 32]>();
        let aux = &*aux.cast::<[u8; 32]>();
        static AUX: OnceLock<Sha256> = OnceLock::new();
        let mut aux_hash = tagged_sha256(&AUX, b"BIP0340/aux")
            .chain_update(aux)
            .finalize();
        let mut masked = Zeroizing::new([0; 32]);
        for (index, byte) in masked.iter_mut().enumerate() {
            *byte = normalized_secret[index] ^ aux_hash[index];
        }
        aux_hash.as_mut_slice().zeroize();
        let digest = nonce_digest(&masked, public, message);
        std::ptr::copy_nonoverlapping(digest.as_ptr(), output, digest.len());
    });
    i32::from(result.is_ok())
}

struct PrivateKey(SecretKey);

impl Drop for PrivateKey {
    fn drop(&mut self) {
        self.0.non_secure_erase();
    }
}

struct PrivateKeypair(Keypair);

impl Drop for PrivateKeypair {
    fn drop(&mut self) {
        self.0.non_secure_erase();
    }
}

fn tagged_sha256(state: &OnceLock<Sha256>, tag: &[u8]) -> Sha256 {
    state
        .get_or_init(|| {
            let tag_hash = Sha256::digest(tag);
            let mut state = Sha256::new();
            state.update(tag_hash);
            state.update(tag_hash);
            state
        })
        .clone()
}

/// Produces a BIP340 signature using Bitcore's historical deterministic nonce encoding.
pub fn sign(
    key: &[u8; 32],
    message: &[u8; 32],
    aux: &[u8; 32],
) -> Result<Option<[u8; 64]>, SigningError> {
    let Ok(key) = SecretKey::from_byte_array(*key) else {
        return Ok(None);
    };
    let key = PrivateKey(key);
    let context = signing_context().map_err(SigningError::ContextRandomization)?;
    let pair = PrivateKeypair(Keypair::from_secret_key(context, &key.0));
    let (public, _) = pair.0.x_only_public_key();
    let extra = ffi::SchnorrSigExtraParams::new(Some(bitcore_nonce), aux.as_ptr().cast());
    let mut signature = [0; 64];
    // All references are live across this synchronous libsecp256k1 call.
    let signed = unsafe {
        ffi::secp256k1_schnorrsig_sign_custom(
            context.ctx().as_ptr(),
            signature.as_mut_ptr(),
            message.as_ptr(),
            message.len(),
            pair.0.as_c_ptr(),
            &extra,
        )
    };
    if signed != 1 {
        return Err(SigningError::NonceFailed);
    }

    verification_context()
        .verify_schnorr(&Signature::from_byte_array(signature), message, &public)
        .map_err(|_| SigningError::VerificationFailed)?;
    Ok(Some(signature))
}

/// Checks a BIP340 signature. JavaScript handles noncanonical x coordinates.
pub fn verify(key: &[u8; 32], message: &[u8; 32], signature: &[u8; 64]) -> Option<bool> {
    // elliptic reduces out-of-field x coordinates. Allow it to preserve that
    // behavior for this narrow range while libsecp256k1 handles canonical x.
    if key >= &constants::FIELD_SIZE {
        return None;
    }
    Some(XOnlyPublicKey::from_byte_array(*key).is_ok_and(|key| {
        verification_context()
            .verify_schnorr(&Signature::from_byte_array(*signature), message, &key)
            .is_ok()
    }))
}

/// Adds a BIP341 tweak to the even lift of the internal public key.
pub fn tweak_public(key: &[u8; 32], tweak: &[u8; 32]) -> Option<(Parity, [u8; 32])> {
    let key = XOnlyPublicKey::from_byte_array(*key).ok()?;
    let tweak = Scalar::from_be_bytes(*tweak).ok()?;
    let (key, parity) = key.add_tweak(verification_context(), &tweak).ok()?;
    Some((parity, key.serialize()))
}

/// Computes the matching private tweak. JavaScript handles zero or invalid results.
pub fn tweak_private(
    key: &[u8; 32],
    merkle_root: Option<&[u8; 32]>,
) -> Result<Option<Zeroizing<[u8; 32]>>, ContextRandomizationError> {
    let Ok(key) = SecretKey::from_byte_array(*key) else {
        return Ok(None);
    };
    let key = PrivateKey(key);
    let (public, parity) = key.0.x_only_public_key(signing_context()?);
    static TAP_TWEAK: OnceLock<Sha256> = OnceLock::new();
    let mut tag = tagged_sha256(&TAP_TWEAK, b"TapTweak");
    tag.update(public.serialize());
    if let Some(root) = merkle_root {
        tag.update(root);
    }
    let Ok(tweak) = Scalar::from_be_bytes(tag.finalize().into()) else {
        return Ok(None);
    };
    let key = if parity == Parity::Odd {
        PrivateKey(key.0.negate())
    } else {
        key
    };
    let result = key.0.add_tweak(&tweak).ok().map(PrivateKey);
    Ok(result.map(|key| Zeroizing::new(key.0.secret_bytes())))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes<const N: usize>(hex: &str) -> [u8; N] {
        assert_eq!(hex.len(), N * 2);
        std::array::from_fn(|index| u8::from_str_radix(&hex[2 * index..2 * index + 2], 16).unwrap())
    }

    #[test]
    fn matches_bip340_vector_zero_and_preserves_legacy_aux() {
        let mut key = [0; 32];
        key[31] = 3;
        let public = bytes("f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9");
        let signature = bytes(concat!(
            "e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca8215",
            "25f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0"
        ));
        assert_eq!(sign(&key, &[0; 32], &[0; 32]).unwrap(), Some(signature));
        assert_eq!(verify(&public, &[0; 32], &signature), Some(true));
        assert_eq!(verify(&public, &[1; 32], &signature), Some(false));
        assert_eq!(verify(&constants::FIELD_SIZE, &[0; 32], &signature), None);

        let mut legacy_aux = [0; 32];
        legacy_aux[30..].copy_from_slice(&446u16.to_be_bytes());
        let legacy_signature = bytes(concat!(
            "8db434e147d101e877679894a4980755232c7e15dc7f890516aacbe58debc9784a",
            "9bce5f3d56d548726e6daae9b6015b3cb06f930b4508fc542791cbb5c882c5"
        ));
        assert_eq!(
            sign(&key, &[0; 32], &legacy_aux).unwrap(),
            Some(legacy_signature)
        );
        assert_eq!(verify(&public, &[0; 32], &legacy_signature), Some(true));
    }

    #[test]
    fn nonce_serializes_a_minimal_unsigned_integer() {
        let public = [17; 32];
        let message = [23; 32];
        let tag = Sha256::digest(b"BIP0340/nonce");
        for leading_zeroes in [0, 1, 2, 17, 31, 32] {
            let mut masked = [25; 32];
            masked[..leading_zeroes].fill(0);
            let expected: [u8; 32] = Sha256::new()
                .chain_update(tag)
                .chain_update(tag)
                .chain_update(&masked[leading_zeroes.min(31)..])
                .chain_update(public)
                .chain_update(message)
                .finalize()
                .into();
            assert_eq!(*nonce_digest(&masked, &public, &message), expected);
        }
    }

    #[test]
    fn matches_bip341_wallet_vector_with_merkle_root() {
        let private = bytes("1e4da49f6aaf4e5cd175fe08a32bb5cb4863d963921255f33d3bc31e1343907f");
        let public = bytes("187791b6f712a8ea41c8ecdd0ee77fab3e85263b37e1ec18a3651926b3a6cf27");
        let root = bytes("5b75adecf53548f3ec6ad7d78383bf84cc57b55a3127c72b9a2481752dd88b21");
        let tweak = bytes("cbd8679ba636c1110ea247542cfbd964131a6be84f873f7f3b62a777528ed001");
        let private = tweak_private(&private, Some(&root)).unwrap().unwrap();
        assert_eq!(
            *private,
            bytes("ea260c3b10e60f6de018455cd0278f2f5b7e454be1999572789e6a9565d26080")
        );
        let (parity, public) = tweak_public(&public, &tweak).unwrap();
        assert_eq!(
            public,
            bytes("147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3")
        );
        let private_key = SecretKey::from_byte_array(*private).unwrap();
        let (derived, derived_parity) = private_key.x_only_public_key(signing_context().unwrap());
        assert_eq!(derived_parity, parity);
        assert_eq!(derived.serialize(), public);
    }
}
