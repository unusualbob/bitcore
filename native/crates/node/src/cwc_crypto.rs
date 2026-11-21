use std::ffi::CStr;

use super::{
    Callback, CallbackInfo, Env, SecretBytes, Value, arguments, check, copy_buffer, entry_point,
    fixed_buffer, napi_get_value_double, null_value, output_buffer,
};

const MAX_WALLET_INPUT: usize = 4096;

pub(super) const FUNCTIONS: [(&CStr, Callback); 10] = [
    (c"cwcKeccak256", keccak256),
    (c"cwcKeccak256Large", keccak256_large),
    (c"cwcEvmAddress", evm_address),
    (c"cwcEvmValidAddress", evm_valid_address),
    (c"cwcChecksumAddress", checksum_address),
    (c"cwcEvmRecoverAddress", evm_recover_address),
    (c"cwcSignRecoverable", sign_recoverable),
    (c"cwcXrpSign", xrp_sign),
    (c"cwcXrpSignLarge", xrp_sign_large),
    (c"cwcXrpAddress", xrp_address),
];

unsafe extern "C" fn checksum_address(env: Env, info: CallbackInfo) -> Value {
    entry_point(env, || {
        let [input] = arguments(env, info)?;
        match bitcore_cwc_crypto::format_evm_address(&fixed_buffer(env, input)?) {
            Some(bytes) => output_buffer(env, &bytes),
            None => null_value(env),
        }
    })
}

unsafe extern "C" fn evm_valid_address(env: Env, info: CallbackInfo) -> Value {
    entry_point(env, || {
        let [input] = arguments(env, info)?;
        let bytes = fixed_buffer(env, input)?;
        let valid = bitcore_cwc_crypto::valid_evm_address(&bytes);
        super::js_value(|value| unsafe { super::napi_get_boolean(env, valid, value) })
    })
}

unsafe extern "C" fn keccak256(env: Env, info: CallbackInfo) -> Value {
    entry_point(env, || {
        let [input] = arguments(env, info)?;
        let mut bytes = [0; MAX_WALLET_INPUT];
        let length = copy_buffer(env, input, &mut bytes)?;
        output_buffer(env, &bitcore_cwc_crypto::keccak256(&bytes[..length]))
    })
}

unsafe extern "C" fn keccak256_large(env: Env, info: CallbackInfo) -> Value {
    entry_point(env, || {
        let [input] = arguments(env, info)?;
        let digest = super::with_byte_view(env, input, bitcore_cwc_crypto::keccak256)?;
        output_buffer(env, &digest)
    })
}

unsafe extern "C" fn evm_address(env: Env, info: CallbackInfo) -> Value {
    entry_point(env, || {
        let [coordinates] = arguments(env, info)?;
        let coordinates = fixed_buffer(env, coordinates)?;
        output_buffer(env, &bitcore_cwc_crypto::evm_address(&coordinates))
    })
}

unsafe extern "C" fn evm_recover_address(env: Env, info: CallbackInfo) -> Value {
    entry_point(env, || {
        let [digest, signature, parity] = arguments(env, info)?;
        let digest = fixed_buffer(env, digest)?;
        let signature = fixed_buffer(env, signature)?;
        let mut value = 0.0;
        check(
            unsafe { napi_get_value_double(env, parity, &mut value) },
            c"Expected a numeric EVM signature parity",
        )?;
        if !matches!(value, 0.0 | 1.0) {
            return Err(c"Expected EVM signature parity of 0 or 1");
        }
        match bitcore_cwc_crypto::evm_recover_address(&digest, &signature, value as u8) {
            Ok(address) => output_buffer(env, &address),
            Err(_) => null_value(env),
        }
    })
}

unsafe extern "C" fn sign_recoverable(env: Env, info: CallbackInfo) -> Value {
    entry_point(env, || {
        let [digest, key] = arguments(env, info)?;
        let digest = fixed_buffer(env, digest)?;
        let mut secret = SecretBytes([0; 32]);
        secret.read(env, key, c"Expected a 32-byte EVM secret key")?;
        match bitcore_ecdsa::sign_recoverable(&digest, &secret.0) {
            Ok(signature) => output_buffer(env, &signature),
            Err(bitcore_ecdsa::Error::InvalidSecretKey) => null_value(env),
            Err(_) => Err(c"Cannot initialize EVM signing: OS entropy unavailable"),
        }
    })
}

unsafe extern "C" fn xrp_sign(env: Env, info: CallbackInfo) -> Value {
    entry_point(env, || {
        let [input, key] = arguments(env, info)?;
        let mut bytes = [0; MAX_WALLET_INPUT];
        let length = copy_buffer(env, input, &mut bytes)?;
        let mut secret = SecretBytes([0; 32]);
        secret.read(env, key, c"Expected a 32-byte XRP secret key")?;
        output_xrp_signature(
            env,
            bitcore_cwc_crypto::xrp_sign(&bytes[..length], &secret.0),
        )
    })
}

unsafe extern "C" fn xrp_sign_large(env: Env, info: CallbackInfo) -> Value {
    entry_point(env, || {
        let [input, key] = arguments(env, info)?;
        let mut secret = SecretBytes([0; 32]);
        secret.read(env, key, c"Expected a 32-byte XRP secret key")?;
        let signature = super::with_byte_view(env, input, |bytes| {
            bitcore_cwc_crypto::xrp_sign(bytes, &secret.0)
        })?;
        output_xrp_signature(env, signature)
    })
}

fn output_xrp_signature(
    env: Env,
    result: std::result::Result<Vec<u8>, bitcore_ecdsa::Error>,
) -> super::Result<Value> {
    match result {
        Ok(signature) => output_buffer(env, &signature),
        Err(bitcore_ecdsa::Error::InvalidSecretKey) => null_value(env),
        Err(_) => Err(c"Cannot initialize XRP signing: OS entropy unavailable"),
    }
}

unsafe extern "C" fn xrp_address(env: Env, info: CallbackInfo) -> Value {
    entry_point(env, || {
        let [input] = arguments(env, info)?;
        let mut bytes = [0; 65];
        let length = copy_buffer(env, input, &mut bytes)?;
        output_buffer(env, &bitcore_cwc_crypto::xrp_address(&bytes[..length]))
    })
}
