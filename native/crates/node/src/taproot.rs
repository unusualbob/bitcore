use super::*;

unsafe extern "C" fn sign(env: Env, info: CallbackInfo) -> Value {
    entry_point(env, || {
        let [key, message, aux] = arguments(env, info)?;
        let mut secret = SecretBytes([0; 32]);
        secret.read(env, key, c"Expected a 32-byte Schnorr private key")?;
        let message = fixed_buffer(env, message)?;
        let mut aux_random = SecretBytes([0; 32]);
        aux_random.read(
            env,
            aux,
            c"Expected 32 bytes of Schnorr auxiliary randomness",
        )?;
        match bitcore_taproot::sign(&secret.0, &message, &aux_random.0) {
            Ok(Some(signature)) => output_buffer(env, &signature),
            Ok(None) => null_value(env),
            Err(bitcore_taproot::SigningError::ContextRandomization(_)) => {
                Err(c"Cannot initialize Schnorr signing: OS entropy unavailable")
            }
            Err(bitcore_taproot::SigningError::NonceFailed) => {
                Err(c"Error creating schnorr signature")
            }
            Err(bitcore_taproot::SigningError::VerificationFailed) => {
                Err(c"Error creating schnorr signature. Verification failed")
            }
        }
    })
}

unsafe extern "C" fn verify(env: Env, info: CallbackInfo) -> Value {
    entry_point(env, || {
        let [key, message, signature] = arguments(env, info)?;
        let key = fixed_buffer(env, key)?;
        let message = fixed_buffer(env, message)?;
        let signature = fixed_buffer(env, signature)?;
        match bitcore_taproot::verify(&key, &message, &signature) {
            Some(valid) => js_value(|value| unsafe { napi_get_boolean(env, valid, value) }),
            None => null_value(env),
        }
    })
}

unsafe extern "C" fn tweak_public(env: Env, info: CallbackInfo) -> Value {
    entry_point(env, || {
        let [key, tweak] = arguments(env, info)?;
        let key = fixed_buffer(env, key)?;
        let tweak = fixed_buffer(env, tweak)?;
        let Some((parity, tweaked)) = bitcore_taproot::tweak_public(&key, &tweak) else {
            return null_value(env);
        };
        let mut output = [0; 33];
        output[0] = parity.to_u8();
        output[1..].copy_from_slice(&tweaked);
        output_buffer(env, &output)
    })
}

unsafe extern "C" fn tweak_private(env: Env, info: CallbackInfo) -> Value {
    entry_point(env, || {
        let [key, root] = arguments(env, info)?;
        let mut secret = SecretBytes([0; 32]);
        secret.read(env, key, c"Expected a 32-byte Taproot private key")?;
        let mut value_type = NAPI_UNDEFINED;
        check(
            unsafe { napi_typeof(env, root, &mut value_type) },
            c"Expected an undefined or 32-byte Taproot Merkle root",
        )?;
        let root = (value_type != NAPI_UNDEFINED)
            .then(|| fixed_buffer(env, root))
            .transpose()?;
        let tweaked = bitcore_taproot::tweak_private(&secret.0, root.as_ref())
            .map_err(|_| c"Cannot initialize Taproot private tweak: OS entropy unavailable")?;
        match tweaked {
            Some(tweaked) => output_buffer(env, &tweaked[..]),
            None => null_value(env),
        }
    })
}

pub(super) const FUNCTIONS: [(&CStr, Callback); 4] = [
    (c"schnorrSign", sign),
    (c"schnorrVerify", verify),
    (c"taprootPublicTweak", tweak_public),
    (c"taprootPrivateTweak", tweak_private),
];
