//! Bitcoin Cash's May 2019 Schnorr signatures over secp256k1.

use bitcore_secp_context::{ContextRandomizationError, signing_context};
use hmac::{Hmac, KeyInit, Mac};
use k256::elliptic_curve::{
    PrimeField,
    bigint::U256,
    group::{Group, prime::PrimeCurveAffine},
    ops::{LinearCombination, Reduce},
    sec1::{FromEncodedPoint, ToEncodedPoint},
    subtle::{Choice, ConditionallySelectable},
};
use k256::{AffinePoint, EncodedPoint, FieldElement, ProjectivePoint, Scalar};
use secp256k1::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const ALGORITHM: &[u8; 16] = b"Schnorr+SHA256  ";

struct Secret(SecretKey);

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.non_secure_erase();
    }
}

fn hmac(key: &[u8; 32], parts: &[&[u8]]) -> Zeroizing<[u8; 32]> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    for part in parts {
        mac.update(part);
    }
    Zeroizing::new(mac.finalize().into_bytes().into())
}

fn nonce(secret: &[u8; 32], digest: &[u8; 32]) -> (Zeroizing<[u8; 32]>, Secret) {
    let mut v = Zeroizing::new([1; 32]);
    let mut k = Zeroizing::new([0; 32]);
    k = hmac(&k, &[&v[..], &[0], secret, digest, ALGORITHM]);
    v = hmac(&k, &[&v[..]]);
    k = hmac(&k, &[&v[..], &[1], secret, digest, ALGORITHM]);
    v = hmac(&k, &[&v[..]]);
    loop {
        v = hmac(&k, &[&v[..]]);
        if let Ok(candidate) = SecretKey::from_byte_array(*v) {
            return (v, Secret(candidate));
        }
        k = hmac(&k, &[&v[..], &[0]]);
        v = hmac(&k, &[&v[..]]);
    }
}

fn has_square_y(encoded: &EncodedPoint) -> Choice {
    // Secp256k1 has no finite point whose Y is zero. An existing square root
    // therefore gives the positive Jacobi symbol required by BCH.
    FieldElement::from_bytes(encoded.y().expect("point has affine coordinates"))
        .and_then(|y| y.sqrt())
        .is_some()
}

fn challenge(r: &[u8], public: &[u8], digest: &[u8; 32]) -> Scalar {
    let mut hash = Sha256::new();
    hash.update(r);
    hash.update(public);
    hash.update(digest);
    let bytes: [u8; 32] = hash.finalize().into();
    <Scalar as Reduce<U256>>::reduce_bytes(&bytes.into())
}

pub fn sign(
    digest: &[u8; 32],
    key: &[u8; 32],
) -> Result<Option<[u8; 64]>, ContextRandomizationError> {
    let Ok(secret) = SecretKey::from_byte_array(*key) else {
        return Ok(None);
    };
    let secret = Secret(secret);
    let (nonce_bytes, nonce_secret) = nonce(key, digest);
    let context = signing_context()?;
    let public = PublicKey::from_secret_key(context, &secret.0).serialize();
    let r = PublicKey::from_secret_key(context, &nonce_secret.0).serialize_uncompressed();
    let encoded = EncodedPoint::from_bytes(r).expect("libsecp256k1 emits canonical points");
    let r = encoded.x().expect("point has affine coordinates");
    let k = Zeroizing::new(Scalar::from_repr((*nonce_bytes).into()).expect("canonical nonce"));
    let neg_k = Zeroizing::new(-*k);
    let k = Zeroizing::new(Scalar::conditional_select(
        &neg_k,
        &k,
        has_square_y(&encoded),
    ));
    let d = Zeroizing::new(Scalar::from_repr((*key).into()).expect("canonical secret key"));
    let e = challenge(r, &public, digest);
    let ed = Zeroizing::new(e * *d);
    let s = Zeroizing::new(*ed + *k);
    let mut signature = [0; 64];
    signature[..32].copy_from_slice(r);
    signature[32..].copy_from_slice(&s.to_bytes());
    Ok(Some(signature))
}

pub fn verify(digest: &[u8; 32], signature: &[u8; 64], sec_key: &[u8]) -> bool {
    if !matches!(
        (sec_key.first().copied(), sec_key.len()),
        (Some(2 | 3), 33) | (Some(4), 65)
    ) {
        return false;
    }
    let Ok(encoded) = EncodedPoint::from_bytes(sec_key) else {
        return false;
    };
    let Some(public) = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded))
    else {
        return false;
    };
    if bool::from(public.is_identity()) {
        return false;
    }
    let r = &signature[..32];
    let s: [u8; 32] = signature[32..].try_into().expect("fixed-width signature");
    let Some(s) = Option::<Scalar>::from(Scalar::from_repr(s.into())) else {
        return false;
    };
    let compressed = public.to_encoded_point(true);
    let e = challenge(r, compressed.as_bytes(), digest);
    let point = ProjectivePoint::lincomb(&ProjectivePoint::GENERATOR, &s, &public.into(), &-e);
    if bool::from(point.is_identity()) {
        return false;
    }
    let point = point.to_affine().to_encoded_point(false);
    point.x().is_some_and(|x| &x[..] == r) && bool::from(has_square_y(&point))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes<const N: usize>(hex: &str) -> [u8; N] {
        assert_eq!(hex.len(), 2 * N);
        std::array::from_fn(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
    }

    #[test]
    fn matches_cash_signature_with_a_leading_zero() {
        let key = bytes("12b004fff7f4b69ef8650e767f18f11ede158148b425660723b9f9a66e61f747");
        let digest = Sha256::digest(b"Very deterministic messageg6").into();
        let signature = sign(&digest, &key).unwrap().unwrap();
        assert_eq!(
            signature,
            bytes(concat!(
                "005e7ab0906a0164306975916350214a69fb80210cf7e37533f197c3d18b23d1b7",
                "94262dc663d9e99605784b14ee1ecfca27b602e88dbc87af85f9907c214ea3"
            ))
        );
        let secret = Secret(SecretKey::from_byte_array(key).unwrap());
        let public = PublicKey::from_secret_key(signing_context().unwrap(), &secret.0);
        assert!(verify(&digest, &signature, &public.serialize()));
        assert!(verify(
            &digest,
            &signature,
            &public.serialize_uncompressed()
        ));
        let mut invalid = public.serialize_uncompressed();
        invalid[0] = 6;
        assert!(!verify(&digest, &signature, &invalid));
        let mut invalid = public.serialize();
        invalid[0] = 4;
        assert!(!verify(&digest, &signature, &invalid));
        assert!(!verify(&[0; 32], &signature, &public.serialize()));
        assert!(!verify(&digest, &[255; 64], &public.serialize()));
        assert!(!verify(&digest, &signature, &[0]));
        assert_eq!(sign(&digest, &[0; 32]).unwrap(), None);
    }
}
