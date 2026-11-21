pub use bitcore_secp_context::ContextRandomizationError;
use bitcore_secp_context::{signing_context, verification_context};
use hmac::{Hmac, KeyInit, Mac};
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey, SignOnly};
use sha2::Sha512;
use zeroize::{Zeroize, Zeroizing};

const HARDENED: u32 = 1 << 31;

/// Return canonical affine coordinates only after libsecp256k1 validates the point.
pub fn parse_public_key(sec: &[u8]) -> Option<[u8; 65]> {
    if !matches!((sec.len(), sec.first()), (33, Some(2 | 3)) | (65, Some(4))) {
        return None;
    }
    Some(PublicKey::from_slice(sec).ok()?.serialize_uncompressed())
}

pub struct PrivateChild {
    pub secret_key: [u8; 32],
    pub chain_code: [u8; 32],
    pub parent_public_key: Option<[u8; 33]>,
}

impl Drop for PrivateChild {
    fn drop(&mut self) {
        self.secret_key.zeroize();
        self.chain_code.zeroize();
    }
}

pub struct PublicChild {
    pub public_key: [u8; 33],
    pub chain_code: [u8; 32],
    pub parent_public_key: Option<[u8; 33]>,
}

struct PrivateKey(SecretKey);

impl Drop for PrivateKey {
    fn drop(&mut self) {
        self.0.non_secure_erase();
    }
}

struct Tweak(Scalar);

impl Drop for Tweak {
    fn drop(&mut self) {
        self.0.non_secure_erase();
    }
}

/// Computes the SEC1 public key of a valid 32-byte private key.
pub fn public_key(
    secret_key: &[u8; 32],
    compressed: bool,
) -> Result<Option<Vec<u8>>, ContextRandomizationError> {
    let Ok(secret_key) = SecretKey::from_byte_array(*secret_key) else {
        return Ok(None);
    };
    let secret_key = PrivateKey(secret_key);
    let public_key = PublicKey::from_secret_key(signing_context()?, &secret_key.0);
    Ok(Some(if compressed {
        public_key.serialize().to_vec()
    } else {
        public_key.serialize_uncompressed().to_vec()
    }))
}

/// Derives a nonempty path whose hardened indexes already have their high bit set.
/// An optional SEC1 key supplies the existing parent's HMAC input for the first normal step.
/// A compatibility case returns `None` for the JavaScript derivation to handle.
pub fn derive_private(
    secret_key: &[u8; 32],
    chain_code: &[u8; 32],
    path: &[u32],
    non_compliant: bool,
    first_public_key: Option<&[u8; 33]>,
) -> Result<Option<PrivateChild>, ContextRandomizationError> {
    let Ok(secret_key) = SecretKey::from_byte_array(*secret_key) else {
        return Ok(None);
    };
    let secret_key = PrivateKey(secret_key);
    if path.is_empty() {
        return Ok(None);
    }
    Ok(derive_private_path(
        signing_context()?,
        secret_key,
        chain_code,
        path,
        non_compliant,
        first_public_key,
    ))
}

fn derive_private_path(
    context: &Secp256k1<SignOnly>,
    mut secret_key: PrivateKey,
    chain_code: &[u8; 32],
    path: &[u32],
    non_compliant: bool,
    first_public_key: Option<&[u8; 33]>,
) -> Option<PrivateChild> {
    let mut chain_code = Zeroizing::new(*chain_code);
    let mut parent_public_key = None;
    for (position, &index) in path.iter().enumerate() {
        let need_parent = position != 0 && position + 1 == path.len();
        let hardened = index >= HARDENED;
        let supplied = if position == 0 {
            first_public_key
        } else {
            None
        };
        let compressed = (need_parent || !hardened).then(|| {
            supplied
                .copied()
                .unwrap_or_else(|| PublicKey::from_secret_key(context, &secret_key.0).serialize())
        });
        let key_data = if hardened {
            let bytes = secret_key.0.as_ref();
            // The legacy mode HMACs the minimal private integer after the 0x00 prefix.
            let skipped = if non_compliant {
                bytes.iter().take_while(|&&byte| byte == 0).count()
            } else {
                0
            };
            &bytes[skipped..]
        } else {
            compressed.as_ref().expect("unhardened parent key exists")
        };
        let tweak = derive_tweak(&mut chain_code, key_data, index)?;
        secret_key = PrivateKey(secret_key.0.add_tweak(&tweak.0).ok()?);
        parent_public_key = compressed.filter(|_| need_parent);
    }

    Some(PrivateChild {
        secret_key: secret_key.0.secret_bytes(),
        chain_code: *chain_code,
        parent_public_key,
    })
}

/// Derives an unhardened path from a compressed SEC1 public key.
/// A compatibility case returns `None` for the JavaScript derivation to handle.
pub fn derive_public(
    public_key: &[u8; 33],
    chain_code: &[u8; 32],
    path: &[u32],
) -> Option<PublicChild> {
    if path.is_empty() || path.iter().any(|&index| index >= HARDENED) {
        return None;
    }
    let context = verification_context();
    let mut public_key = PublicKey::from_slice(public_key).ok()?;
    let mut chain_code = *chain_code;
    let mut parent_public_key = None;
    for (position, &index) in path.iter().enumerate() {
        let compressed = public_key.serialize();
        let tweak = derive_tweak(&mut chain_code, &compressed, index)?;
        public_key = public_key.add_exp_tweak(context, &tweak.0).ok()?;
        parent_public_key = (position != 0).then_some(compressed);
    }

    Some(PublicChild {
        public_key: public_key.serialize(),
        chain_code,
        parent_public_key,
    })
}

/// Writes consecutive, non-hardened child public keys as packed 33-byte SEC1 keys.
/// A failed tweak leaves the result unusable, so callers can retry with the legacy path.
pub fn derive_public_children(
    public_key: &[u8; 33],
    chain_code: &[u8; 32],
    start: u32,
    children: &mut [[u8; 33]],
) -> Option<()> {
    let count = u32::try_from(children.len()).ok()?;
    if count == 0 || start.checked_add(count)? > HARDENED {
        return None;
    }
    let parent = PublicKey::from_slice(public_key).ok()?;
    let context = verification_context();
    let mut hmac = Hmac::<Sha512>::new_from_slice(chain_code).ok()?;
    hmac.update(public_key);
    for (index, child) in (start..).zip(children) {
        let mut mac = hmac.clone();
        mac.update(&index.to_be_bytes());
        let mut next_chain = [0; 32];
        let tweak = split_digest(mac.finalize().into_bytes().as_ref(), &mut next_chain)?;
        *child = parent.add_exp_tweak(context, &tweak.0).ok()?.serialize();
    }
    Some(())
}

fn derive_tweak(chain_code: &mut [u8; 32], key_data: &[u8], index: u32) -> Option<Tweak> {
    let mut mac = Hmac::<Sha512>::new_from_slice(chain_code).expect("valid HMAC key length");
    if index >= HARDENED {
        mac.update(&[0]);
    }
    mac.update(key_data);
    mac.update(&index.to_be_bytes());
    let mut digest = mac.finalize().into_bytes();
    let tweak = split_digest(digest.as_ref(), chain_code);
    digest.as_mut_slice().zeroize();
    tweak
}

fn split_digest(digest: &[u8; 64], chain_code: &mut [u8; 32]) -> Option<Tweak> {
    let (left, right) = digest.split_at(32);
    // Use libsecp256k1's constant-time secret-key parser for IL. Bitcore's
    // JavaScript path interprets a zero IL or reduces an out-of-range IL modulo n.
    let left = PrivateKey(SecretKey::from_byte_array(left.try_into().ok()?).ok()?);
    let tweak = Tweak(Scalar::from(left.0));
    chain_code.copy_from_slice(right);
    Some(tweak)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes<const N: usize>(hex: &str) -> [u8; N] {
        assert_eq!(hex.len(), 2 * N);
        std::array::from_fn(|index| u8::from_str_radix(&hex[2 * index..2 * index + 2], 16).unwrap())
    }

    #[test]
    fn matches_bip32_vector_one_for_mixed_and_public_paths() {
        // Decode the published BIP32 vector 1 extended keys (m, m/0', m/0'/1).
        let root_key = bytes("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35");
        let root_chain = bytes("873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508");
        let parent_key =
            bytes("035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56");
        let parent_chain =
            bytes("47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141");
        let expected_public =
            bytes("03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c");
        let expected_secret =
            bytes("3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368");
        let expected_chain =
            bytes("2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19");

        let private = derive_private(&root_key, &root_chain, &[HARDENED, 1], false, None)
            .unwrap()
            .unwrap();
        assert_eq!(private.secret_key, expected_secret);
        assert_eq!(private.chain_code, expected_chain);
        assert_eq!(private.parent_public_key, Some(parent_key));
        assert_eq!(
            public_key(&private.secret_key, true).unwrap().unwrap(),
            expected_public
        );

        let public = derive_public(&parent_key, &parent_chain, &[1]).unwrap();
        assert_eq!(public.public_key, expected_public);
        assert_eq!(public.chain_code, expected_chain);
        assert!(public.parent_public_key.is_none());
    }

    #[test]
    fn keeps_legacy_hardened_integer_serialization() {
        let mut parent_key = [0; 32];
        parent_key[31] = 1;
        let legacy = derive_private(&parent_key, &[0; 32], &[HARDENED], true, None)
            .unwrap()
            .unwrap();
        let standard = derive_private(&parent_key, &[0; 32], &[HARDENED], false, None)
            .unwrap()
            .unwrap();

        // HMAC-SHA512 with a zero chain code over 000180000000 or 00||ser256(1)||80000000.
        assert_eq!(
            legacy.secret_key,
            bytes("6f9cff81e074d295e0be48536002a65506c0248d9b5c7f030d3e07834ce15027")
        );
        assert_eq!(
            legacy.chain_code,
            bytes("3cd8adcfbf9d389348c15ddb0dd8f995abf515677e625ba848c8a0dd7b6438ab")
        );
        assert_eq!(
            standard.secret_key,
            bytes("277235a7ea459f13b110c22beaa54a4f134f6bcaff462997ab183d2402404ff4")
        );
        assert_eq!(
            standard.chain_code,
            bytes("58b9edb7a0a938c112f137b0b08e55f3a79550c299a0ff8291f94464e4222ac9")
        );
    }

    #[test]
    fn sibling_keys_match_scalar_derivation_at_range_boundaries() {
        let parent = bytes("035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56");
        let chain = bytes("47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141");
        let mut children = [[0; 33]; 256];
        for start in [0, 500, HARDENED - 256] {
            derive_public_children(&parent, &chain, start, &mut children).unwrap();
            for (index, child) in (start..).zip(children) {
                assert_eq!(
                    child,
                    derive_public(&parent, &chain, &[index]).unwrap().public_key
                );
            }
        }
        assert!(derive_public_children(&parent, &chain, HARDENED - 255, &mut children).is_none());
        assert!(derive_public_children(&parent, &chain, u32::MAX, &mut children).is_none());
        assert!(derive_public_children(&[0; 33], &chain, 0, &mut children).is_none());
        assert!(derive_public_children(&parent, &chain, 0, &mut []).is_none());
    }

    #[test]
    fn defers_rare_tweak_boundaries_to_javascript() {
        let mut digest = [0; 64];
        let mut chain_code = [42; 32];
        assert!(split_digest(&digest, &mut chain_code).is_none());

        digest[..32].copy_from_slice(&secp256k1::constants::CURVE_ORDER);
        assert!(split_digest(&digest, &mut chain_code).is_none());
        assert_eq!(chain_code, [42; 32]);

        let mut secret = [0; 32];
        secret[31] = 1;
        let secret = SecretKey::from_byte_array(secret).unwrap();
        digest[..32].copy_from_slice(&secret.negate().secret_bytes());
        let tweak = split_digest(&digest, &mut chain_code).unwrap();
        assert!(secret.add_tweak(&tweak.0).is_err());
        let public = PublicKey::from_secret_key(signing_context().unwrap(), &secret);
        assert!(
            public
                .add_exp_tweak(verification_context(), &tweak.0)
                .is_err()
        );
    }
}
