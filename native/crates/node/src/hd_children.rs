use super::{
    CallbackInfo, Env, Result, Value, arguments, check, entry_point, fixed_buffer,
    napi_get_value_double, null_value, output_buffer,
};

const MAX_CHILDREN: u32 = 256;

fn integer(env: Env, value: Value, min: u32, max: u32) -> Result<u32> {
    let mut number = 0.0;
    let message = c"Invalid native HD child range";
    check(
        unsafe { napi_get_value_double(env, value, &mut number) },
        message,
    )?;
    if !(f64::from(min)..=f64::from(max)).contains(&number) || number.fract() != 0.0 {
        return Err(message);
    }
    Ok(number as u32)
}

pub(super) unsafe extern "C" fn derive_public_children(env: Env, info: CallbackInfo) -> Value {
    entry_point(env, || {
        let [key, chain, start, count] = arguments(env, info)?;
        let key = fixed_buffer(env, key)?;
        let chain = fixed_buffer(env, chain)?;
        let start = integer(env, start, 0, super::HARDENED - 1)?;
        let count = integer(env, count, 1, MAX_CHILDREN)?;
        if start + count > super::HARDENED {
            return Err(c"Invalid native HD child range");
        }
        let mut output = [[0; 33]; MAX_CHILDREN as usize];
        let output = &mut output[..count as usize];
        match bitcore_hdkeys::derive_public_children(&key, &chain, start, output) {
            Some(()) => output_buffer(env, output.as_flattened()),
            None => null_value(env),
        }
    })
}
