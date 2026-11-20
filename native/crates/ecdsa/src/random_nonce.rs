use std::ffi::{c_int, c_uint, c_void};

use bitcore_secp_context::{ContextRandomizationError, signing_context};
use secp256k1::ffi;

unsafe extern "C" fn supply_nonce(
    output: *mut u8,
    _digest: *const u8,
    _key: *const u8,
    _algorithm: *const u8,
    data: *mut c_void,
    attempt: c_uint,
) -> c_int {
    if attempt != 0 {
        return 0;
    }
    // libsecp256k1 supplies a writable 32-byte output. `sign` supplies a
    // distinct, readable 32-byte candidate that lives through this call.
    unsafe { std::ptr::copy_nonoverlapping(data.cast::<u8>(), output, 32) };
    1
}

/// Tries one caller-supplied big-endian nonce and returns compact low-S r || s.
/// Invalid scalars or a zero r or s produce `None` so the caller owns retries.
pub fn sign(
    digest: &[u8; 32],
    key: &[u8; 32],
    nonce: &[u8; 32],
) -> Result<Option<[u8; 64]>, ContextRandomizationError> {
    let context = signing_context()?;
    let mut compact = [0; 64];
    // The blinded signing context and all input buffers outlive this call.
    // libsecp256k1 initializes the opaque signature before serialization.
    unsafe {
        let mut signature = ffi::Signature::new();
        let signed = ffi::secp256k1_ecdsa_sign(
            context.ctx().as_ptr(),
            &mut signature,
            digest.as_ptr(),
            key.as_ptr(),
            Some(supply_nonce),
            nonce.as_ptr().cast(),
        );
        if signed == 0 {
            return Ok(None);
        }
        ffi::secp256k1_ecdsa_signature_serialize_compact(
            context.ctx().as_ptr(),
            compact.as_mut_ptr(),
            &signature,
        );
    }
    Ok(Some(compact))
}
