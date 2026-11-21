use std::ffi::CStr;

use bitcore_merkle::{
    HASH_BYTES, HASH160_BYTES, append_parents, escrow_root, hash160, partial_root, root,
};

use super::{
    Callback, CallbackInfo, Env, Value, arguments, boolean, byte_view, check, copy_buffer,
    entry_point, napi_get_value_double, null_value, output_buffer,
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

fn read_count(env: Env, value: Value, max: usize) -> super::Result<usize> {
    let message = c"Expected a bounded positive Merkle count";
    let mut number = 0.0;
    check(
        unsafe { napi_get_value_double(env, value, &mut number) },
        message,
    )?;
    if !(1.0..=max as f64).contains(&number) || number.fract() != 0.0 {
        return Err(message);
    }
    Ok(number as usize)
}

fn read_leaves<const N: usize>(env: Env, value: Value) -> super::Result<Vec<[u8; N]>> {
    let (data, len) = byte_view(env, value)?;
    if len == 0 || len % N != 0 || len / N > MAX_LEAVES {
        return Err(c"Invalid packed Merkle leaves");
    }
    // No call into Node while borrowing these bytes.
    let bytes = unsafe { std::slice::from_raw_parts(data, len) };
    bytes
        .chunks_exact(N)
        .map(|hash| hash.try_into().map_err(|_| c"Invalid packed Merkle leaf"))
        .collect()
}

unsafe extern "C" fn merkle_root(env: Env, info: CallbackInfo) -> Value {
    entry_point(env, || {
        let [leaves] = arguments(env, info)?;
        let mut leaves = read_leaves::<HASH_BYTES>(env, leaves)?;
        output_buffer(env, &root(&mut leaves).ok_or(c"Missing Merkle leaves")?)
    })
}

unsafe extern "C" fn partial_merkle(env: Env, info: CallbackInfo) -> Value {
    entry_point(env, || {
        let [hashes, flags, count, digest] = arguments(env, info)?;
        // The JS width calculation uses signed 32-bit shifts.
        let count = read_count(env, count, 1 << 30)?;
        let digest = boolean(env, digest, c"Expected a Boolean partial Merkle mode")?;
        let hashes = read_leaves::<HASH_BYTES>(env, hashes)?;
        let (flags, len) = byte_view(env, flags)?;
        if len > MAX_LEAVES || hashes.len() > count || hashes.len() > len * 8 {
            return null_value(env);
        }
        // No call into Node during traversal of the flag bytes.
        let flags = unsafe { std::slice::from_raw_parts(flags, len) };
        let mut matches = Vec::new();
        let Some(root) = partial_root(count, &hashes, flags, digest, |index| {
            if !digest {
                matches.extend_from_slice(&(index as u32).to_le_bytes());
            }
        }) else {
            return null_value(env);
        };
        if digest {
            output_buffer(env, &root)
        } else {
            output_buffer(env, &matches)
        }
    })
}

unsafe extern "C" fn escrow_merkle_root(env: Env, info: CallbackInfo) -> Value {
    entry_point(env, || {
        let [leaves] = arguments(env, info)?;
        let mut leaves = read_leaves::<HASH160_BYTES>(env, leaves)?;
        output_buffer(
            env,
            &escrow_root(&mut leaves).ok_or(c"Missing escrow leaves")?,
        )
    })
}

unsafe extern "C" fn escrow_key_root(env: Env, info: CallbackInfo) -> Value {
    entry_point(env, || {
        let [keys, count] = arguments(env, info)?;
        let count = read_count(env, count, MAX_LEAVES)?;
        let (data, len) = byte_view(env, keys)?;
        if !(34 * count..=66 * count).contains(&len) {
            return Err(c"Invalid packed escrow public keys");
        }
        // Each key is prefixed with its byte length. JS has already sorted and
        // parsed the SEC encodings with the chain's PublicKey implementation.
        let mut keys = unsafe { std::slice::from_raw_parts(data, len) };
        let mut leaves = Vec::with_capacity(count.next_power_of_two());
        for _ in 0..count {
            let [length, rest @ ..] = keys else {
                return Err(c"Missing packed escrow public key");
            };
            if !matches!(length, 33 | 65) || rest.len() < *length as usize {
                return Err(c"Invalid packed escrow public key length");
            }
            let (key, remaining) = rest.split_at(*length as usize);
            leaves.push(hash160(key));
            keys = remaining;
        }
        if !keys.is_empty() {
            return Err(c"Trailing packed escrow public key data");
        }
        if count != count.next_power_of_two() {
            leaves.resize(count.next_power_of_two(), hash160(&[]));
        }
        output_buffer(
            env,
            &escrow_root(&mut leaves).ok_or(c"Missing escrow leaves")?,
        )
    })
}

unsafe extern "C" fn hash256(env: Env, info: CallbackInfo) -> Value {
    entry_point(env, || {
        let [bytes] = arguments(env, info)?;
        let hash = super::with_byte_view(env, bytes, bitcore_merkle::sha256d)?;
        output_buffer(env, &hash)
    })
}

unsafe extern "C" fn hash160_digest(env: Env, info: CallbackInfo) -> Value {
    entry_point(env, || {
        let [bytes] = arguments(env, info)?;
        let hash = super::with_byte_view(env, bytes, hash160)?;
        output_buffer(env, &hash)
    })
}

pub(crate) const FUNCTIONS: [(&CStr, Callback); 7] = [
    (c"merkleParents", merkle_parents),
    (c"merkleRoot", merkle_root),
    (c"partialMerkle", partial_merkle),
    (c"escrowMerkleRoot", escrow_merkle_root),
    (c"escrowKeyRoot", escrow_key_root),
    (c"hash256", hash256),
    (c"hash160", hash160_digest),
];
