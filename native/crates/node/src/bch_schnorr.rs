use super::{
    CallbackInfo, Env, SecretBytes, Value, arguments, copy_buffer, entry_point, fixed_buffer,
    js_value, napi_get_boolean, null_value, output_buffer,
};

pub(super) unsafe extern "C" fn sign(env: Env, info: CallbackInfo) -> Value {
    entry_point(env, || {
        let [digest, key] = arguments(env, info)?;
        let digest = fixed_buffer(env, digest)?;
        let mut secret_key = SecretBytes([0; 32]);
        secret_key.read(env, key, c"Incorrect BCH Schnorr secret key length")?;
        match bitcore_bch_schnorr::sign(&digest, &secret_key.0) {
            Ok(Some(signature)) => output_buffer(env, &signature),
            Ok(None) => null_value(env),
            Err(_) => Err(c"Cannot initialize BCH Schnorr signing: OS entropy unavailable"),
        }
    })
}

pub(super) unsafe extern "C" fn verify(env: Env, info: CallbackInfo) -> Value {
    entry_point(env, || {
        let [digest, signature, public_key] = arguments(env, info)?;
        let digest = fixed_buffer(env, digest)?;
        let signature = fixed_buffer(env, signature)?;
        let mut key = [0; 65];
        let length = copy_buffer(env, public_key, &mut key)?;
        if !matches!(length, 33 | 65) {
            return Err(c"Expected a 33-byte or 65-byte public key");
        }
        let valid = bitcore_bch_schnorr::verify(&digest, &signature, &key[..length]);
        js_value(|value| unsafe { napi_get_boolean(env, valid, value) })
    })
}
