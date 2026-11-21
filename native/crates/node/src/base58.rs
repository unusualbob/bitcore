use std::ffi::{CStr, c_char};

use bitcore_base58::{MAX_TEXT, Scratch};

use super::{
    Callback, CallbackInfo, Env, Status, Value, arguments, byte_view, check, entry_point, js_value,
    null_value, output_buffer,
};

unsafe extern "C" {
    fn napi_create_string_latin1(
        env: Env,
        text: *const c_char,
        length: usize,
        result: *mut Value,
    ) -> Status;
    fn napi_get_value_string_utf8(
        env: Env,
        value: Value,
        buffer: *mut c_char,
        size: usize,
        result: *mut usize,
    ) -> Status;
}

pub const FUNCTIONS: [(&CStr, Callback); 4] = [
    (c"base58Encode", encode::<false>),
    (c"base58Decode", decode::<false>),
    (c"base58CheckEncode", encode::<true>),
    (c"base58DecodeChecked", decode::<true>),
];

unsafe extern "C" fn encode<const CHECK: bool>(env: Env, info: CallbackInfo) -> Value {
    entry_point(env, || {
        let [value] = arguments(env, info)?;
        let Ok((data, len)) = byte_view(env, value) else {
            return null_value(env);
        };
        // byte_view verifies that the buffer is unshared. The slice is used
        // only during conversion, before the next Node-API call.
        let bytes = unsafe { std::slice::from_raw_parts(data, len) };
        let mut output = Scratch([0; MAX_TEXT]);
        let encoded = if CHECK {
            bitcore_base58::encode_check(bytes, &mut output.0)
        } else {
            bitcore_base58::encode(bytes, &mut output.0)
        };
        let Some(encoded) = encoded else {
            return null_value(env);
        };
        js_value(|result| unsafe {
            napi_create_string_latin1(env, encoded.as_ptr().cast(), encoded.len(), result)
        })
    })
}

unsafe extern "C" fn decode<const CHECK: bool>(env: Env, info: CallbackInfo) -> Value {
    entry_point(env, || {
        let [value] = arguments(env, info)?;
        // UTF-8 keeps every non-ASCII input outside the Base58 alphabet.
        // Leave room for a four-byte code point beyond the limit and a NUL
        // so truncation cannot leave an apparently valid prefix.
        let mut text = Scratch([0; MAX_TEXT + 5]);
        let mut len = 0;
        let message = c"Expected a Base58 string";
        check(
            unsafe {
                napi_get_value_string_utf8(
                    env,
                    value,
                    text.0.as_mut_ptr().cast(),
                    text.0.len(),
                    &mut len,
                )
            },
            message,
        )?;
        let mut output = Scratch([0; MAX_TEXT]);
        let decoded = if CHECK {
            bitcore_base58::decode_checked(&text.0[..len], &mut output.0)
        } else {
            bitcore_base58::decode(&text.0[..len], &mut output.0)
        };
        match decoded {
            Some(bytes) => output_buffer(env, bytes),
            None => null_value(env),
        }
    })
}
