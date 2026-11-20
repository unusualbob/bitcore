use super::{Callback, CallbackInfo, Env, SecretBytes, Value, arguments, copy_buffer, entry_point};
use super::{check, fixed_buffer, napi_get_value_double, output_buffer};
use std::ffi::CStr;

const MAX_BIP39_INPUT_BYTES: usize = 4096;
const MAX_WALLET_INPUT_BYTES: usize = 4096;

unsafe extern "C" fn bip39_seed(env: Env, info: CallbackInfo) -> Value {
    entry_point(env, || {
        let [phrase, salt] = arguments(env, info)?;
        let mut phrase_bytes = SecretBytes([0; MAX_BIP39_INPUT_BYTES]);
        let mut salt_bytes = SecretBytes([0; MAX_BIP39_INPUT_BYTES]);
        let phrase_len = copy_buffer(env, phrase, &mut phrase_bytes.0)?;
        let salt_len = copy_buffer(env, salt, &mut salt_bytes.0)?;
        let mut seed = SecretBytes([0; 64]);
        bitcore_kdfs::bip39_seed(
            &phrase_bytes.0[..phrase_len],
            &salt_bytes.0[..salt_len],
            &mut seed.0,
        );
        output_buffer(env, &seed.0)
    })
}

unsafe extern "C" fn scrypt_proof_of_work(env: Env, info: CallbackInfo) -> Value {
    entry_point(env, || {
        let [header] = arguments(env, info)?;
        let header = fixed_buffer(env, header)?;
        output_buffer(env, &bitcore_kdfs::scrypt_proof_of_work(&header))
    })
}

unsafe extern "C" fn bitcoin_core_wallet_key(env: Env, info: CallbackInfo) -> Value {
    entry_point(env, || {
        let [input, rounds] = arguments(env, info)?;
        let mut iterations = 0.0;
        let message = c"Expected a positive integer Bitcoin Core wallet round count";
        check(
            unsafe { napi_get_value_double(env, rounds, &mut iterations) },
            message,
        )?;
        if !(1.0..=u32::MAX as f64).contains(&iterations) || iterations.fract() != 0.0 {
            return Err(message);
        }

        let mut bytes = SecretBytes([0; MAX_WALLET_INPUT_BYTES]);
        let length = copy_buffer(env, input, &mut bytes.0)?;
        let mut key = SecretBytes([0; 64]);
        bitcore_kdfs::bitcoin_core_wallet_key(&bytes.0[..length], iterations as u32, &mut key.0);
        output_buffer(env, &key.0)
    })
}

pub(crate) const FUNCTIONS: [(&CStr, Callback); 3] = [
    (c"bip39Seed", bip39_seed),
    (c"scryptProofOfWork", scrypt_proof_of_work),
    (c"bitcoinCoreWalletKey", bitcoin_core_wallet_key),
];
