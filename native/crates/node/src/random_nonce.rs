use std::ffi::CStr;

use super::{
    Callback, CallbackInfo, Env, SecretBytes, Value, arguments, entry_point, fixed_buffer,
    null_value, output_buffer,
};

pub(super) const FUNCTIONS: [(&CStr, Callback); 1] = [(c"signWithNonce", sign)];

unsafe extern "C" fn sign(env: Env, info: CallbackInfo) -> Value {
    entry_point(env, || {
        let [digest, key, nonce] = arguments(env, info)?;
        let digest = fixed_buffer(env, digest)?;
        let mut secret_key = SecretBytes([0; 32]);
        secret_key.read(env, key, c"Incorrect native ECDSA secret key length")?;
        let mut candidate = SecretBytes([0; 32]);
        candidate.read(env, nonce, c"Incorrect native ECDSA nonce length")?;
        match bitcore_ecdsa::random_nonce::sign(&digest, &secret_key.0, &candidate.0) {
            Ok(Some(signature)) => output_buffer(env, &signature),
            Ok(None) => null_value(env),
            Err(_) => Err(c"Cannot initialize ECDSA signing: OS entropy unavailable"),
        }
    })
}
