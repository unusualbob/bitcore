use super::*;

pub(super) unsafe extern "C" fn parse(env: Env, info: CallbackInfo) -> Value {
    entry_point(env, || {
        let [value] = arguments(env, info)?;
        let mut bytes = [0; 65];
        let size = copy_buffer(env, value, &mut bytes)?;
        match bitcore_hdkeys::parse_public_key(&bytes[..size]) {
            Some(sec) => output_buffer(env, &sec),
            None => null_value(env),
        }
    })
}
