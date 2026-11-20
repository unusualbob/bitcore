use std::ffi::CStr;

use bitcore_merkle::{HASH_BYTES, append_parents};

use super::{
    Callback, CallbackInfo, Env, Value, arguments, check, copy_buffer, entry_point,
    napi_get_value_double, output_buffer,
};

const MAX_LEAVES: usize = 65_536;

unsafe extern "C" fn merkle_parents(env: Env, info: CallbackInfo) -> Value {
    entry_point(env, || {
        let [leaves, count] = arguments(env, info)?;
        let message = c"Expected a Merkle leaf count between 2 and 65536";
        let mut number = 0.0;
        check(
            unsafe { napi_get_value_double(env, count, &mut number) },
            message,
        )?;
        if !(2.0..=MAX_LEAVES as f64).contains(&number) || number.fract() != 0.0 {
            return Err(message);
        }
        let count = number as usize;
        let len = count * HASH_BYTES;
        let mut tree = Vec::with_capacity(2 * count + usize::BITS as usize);
        tree.resize(count, [0; HASH_BYTES]);
        if copy_buffer(env, leaves, tree.as_flattened_mut())? != len {
            return Err(c"Merkle leaf count does not match the input length");
        }
        append_parents(&mut tree);
        output_buffer(env, tree[count..].as_flattened())
    })
}

pub(crate) const FUNCTIONS: [(&CStr, Callback); 1] = [(c"merkleParents", merkle_parents)];
