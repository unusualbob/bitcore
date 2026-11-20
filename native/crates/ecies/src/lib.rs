use secp256k1::{PublicKey, SecretKey, ecdh::shared_secret_point};
use zeroize::Zeroizing;

/// Bitcore ECIES uses the raw affine x coordinate, including leading zeros.
/// Preserve both supplied public keys for the directional HKDF salt.
pub fn key_material(
    secret: &[u8; 32],
    peer: &[u8; 65],
    local: &[u8; 65],
) -> Option<Zeroizing<[u8; 98]>> {
    if peer[0] != 4 || local[0] != 4 {
        return None;
    }
    let peer = PublicKey::from_slice(peer).ok()?;
    let local = PublicKey::from_slice(local).ok()?;
    let mut secret = SecretKey::from_byte_array(*secret).ok()?;
    let shared = Zeroizing::new(shared_secret_point(&peer, &secret));
    secret.non_secure_erase();
    let mut result = Zeroizing::new([0; 98]);
    result[..32].copy_from_slice(&shared[..32]);
    result[32..65].copy_from_slice(&peer.serialize());
    result[65..].copy_from_slice(&local.serialize());
    Some(result)
}
