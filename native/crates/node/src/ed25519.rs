use super::*;

const MAX_MESSAGE_BYTES: usize = 1232;

unsafe extern "C" fn derive_path(env: Env, info: CallbackInfo) -> Value {
    entry_point(env, || {
        let [key, chain_code, indices] = arguments(env, info)?;
        let mut key_bytes = SecretBytes([0; 32]);
        key_bytes.read(env, key, c"Expected a 32-byte SLIP-0010 Ed25519 seed")?;
        let mut chain_bytes = SecretBytes([0; 32]);
        chain_bytes.read(env, chain_code, c"Expected a 32-byte SLIP-0010 chain code")?;
        let mut path = [0; MAX_PATH_DEPTH];
        let size = read_path(env, indices, &mut path)?;
        let derived = bitcore_ed25519::derive_path(&key_bytes.0, &chain_bytes.0, &path[..size]);
        output_buffer(env, &derived[..])
    })
}

unsafe extern "C" fn public_key(env: Env, info: CallbackInfo) -> Value {
    entry_point(env, || {
        let [key] = arguments(env, info)?;
        let mut key_bytes = SecretBytes([0; 32]);
        key_bytes.read(env, key, c"Expected a 32-byte Ed25519 seed")?;
        output_buffer(env, &bitcore_ed25519::public_key(&key_bytes.0))
    })
}

unsafe extern "C" fn sign(env: Env, info: CallbackInfo) -> Value {
    entry_point(env, || {
        let [key, message] = arguments(env, info)?;
        let mut key_bytes = SecretBytes([0; 32]);
        key_bytes.read(env, key, c"Expected a 32-byte Ed25519 seed")?;
        let mut bytes = [0; MAX_MESSAGE_BYTES];
        let size = copy_buffer(env, message, &mut bytes)?;
        let (public_key, signature) = bitcore_ed25519::sign(&key_bytes.0, &bytes[..size]);
        let mut signed = [0; 96];
        signed[..32].copy_from_slice(&public_key);
        signed[32..].copy_from_slice(&signature);
        output_buffer(env, &signed)
    })
}

unsafe extern "C" fn associated_token_address(env: Env, info: CallbackInfo) -> Value {
    entry_point(env, || {
        let [seeds, program] = arguments(env, info)?;
        let seeds = fixed_buffer(env, seeds)?;
        let program = fixed_buffer(env, program)?;
        match bitcore_ed25519::associated_token_address(&seeds, &program) {
            Some(address) => output_buffer(env, &address),
            None => null_value(env),
        }
    })
}

pub(super) const FUNCTIONS: [(&CStr, Callback); 4] = [
    (c"slip10DeriveEd25519", derive_path),
    (c"ed25519PublicKey", public_key),
    (c"ed25519Sign", sign),
    (c"solAssociatedTokenAddress", associated_token_address),
];
