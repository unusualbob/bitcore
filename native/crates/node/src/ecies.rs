use super::*;

pub(super) unsafe extern "C" fn key_material(env: Env, info: CallbackInfo) -> Value {
    entry_point(env, || {
        let [secret, peer, local] = arguments(env, info)?;
        let mut key = SecretBytes([0; 32]);
        key.read(env, secret, c"Expected a 32-byte ECIES secret key")?;
        let peer = fixed_buffer(env, peer)?;
        let local = fixed_buffer(env, local)?;
        match bitcore_ecies::key_material(&key.0, &peer, &local) {
            Some(material) => output_buffer(env, material.as_ref()),
            None => null_value(env),
        }
    })
}
