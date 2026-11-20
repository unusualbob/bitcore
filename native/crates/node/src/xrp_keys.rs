use bitcore_xrp_keys::KeyKind;

use super::*;

unsafe extern "C" {
    fn napi_get_value_uint32(env: Env, value: Value, result: *mut u32) -> Status;
}

// The caller selects the algorithm from the SDK-decoded seed. A numeric
// account index uses ToUint32, matching the SDK's big-endian bitwise encoding.
unsafe extern "C" fn derive_keypair(env: Env, info: CallbackInfo) -> Value {
    entry_point(env, || {
        let [entropy, ed25519, account_index, validator] = arguments(env, info)?;
        let mut seed = SecretBytes([0; 16]);
        seed.read(env, entropy, c"Expected 16 bytes of XRP seed entropy")?;
        let kind = if boolean(env, ed25519, c"Expected a boolean XRP Ed25519 flag")? {
            KeyKind::Ed25519
        } else if boolean(env, validator, c"Expected a boolean XRP validator flag")? {
            KeyKind::Secp256k1Validator
        } else {
            let mut index = 0;
            check(
                unsafe { napi_get_value_uint32(env, account_index, &mut index) },
                c"Expected a numeric XRP account index",
            )?;
            KeyKind::Secp256k1Account(index)
        };
        match bitcore_xrp_keys::derive(&seed.0, kind) {
            Ok(Some(keys)) => output_buffer(env, &keys[..]),
            Ok(None) => null_value(env),
            Err(_) => Err(c"derived keypair did not generate verifiable signature"),
        }
    })
}

pub(super) const FUNCTIONS: [(&CStr, Callback); 1] = [(c"xrpDeriveKeypair", derive_keypair)];
