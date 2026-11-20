use std::ffi::{CStr, c_char, c_int, c_void};
use std::panic::catch_unwind;
use std::ptr::null_mut;
use std::sync::atomic::{Ordering, compiler_fence};

mod bch_schnorr;
mod cwc_crypto;
mod ecies;
mod ed25519;
mod kdfs;
mod merkle;
mod points;
mod random_nonce;
mod taproot;
mod xrp_keys;

type Env = *mut c_void;
type Value = *mut c_void;
type CallbackInfo = *mut c_void;
type Callback = unsafe extern "C" fn(Env, CallbackInfo) -> Value;
type Status = c_int;

const NAPI_OK: Status = 0;
const NAPI_UNDEFINED: c_int = 0;
const NAPI_UINT8_ARRAY: c_int = 1;
const HARDENED: u32 = 1 << 31;
const MAX_PATH_DEPTH: usize = 255;

// Stable Node-API symbols provided by Node when it loads the addon.
unsafe extern "C" {
    fn napi_create_uint32(env: Env, number: u32, result: *mut Value) -> Status;
    fn napi_get_cb_info(
        env: Env,
        info: CallbackInfo,
        argc: *mut usize,
        argv: *mut Value,
        this_arg: *mut Value,
        data: *mut *mut c_void,
    ) -> Status;
    fn napi_is_arraybuffer(env: Env, value: Value, result: *mut bool) -> Status;
    fn napi_get_typedarray_info(
        env: Env,
        value: Value,
        array_type: *mut c_int,
        length: *mut usize,
        data: *mut *mut c_void,
        array_buffer: *mut Value,
        byte_offset: *mut usize,
    ) -> Status;
    fn napi_typeof(env: Env, value: Value, result: *mut c_int) -> Status;
    fn napi_get_value_bool(env: Env, value: Value, result: *mut bool) -> Status;
    fn napi_get_value_double(env: Env, value: Value, result: *mut f64) -> Status;
    fn napi_get_boolean(env: Env, value: bool, result: *mut Value) -> Status;
    fn napi_get_null(env: Env, result: *mut Value) -> Status;
    fn napi_create_buffer_copy(
        env: Env,
        length: usize,
        data: *const c_void,
        result_data: *mut *mut c_void,
        result: *mut Value,
    ) -> Status;
    fn napi_create_function(
        env: Env,
        name: *const c_char,
        length: usize,
        callback: Callback,
        data: *mut c_void,
        result: *mut Value,
    ) -> Status;
    fn napi_set_named_property(
        env: Env,
        object: Value,
        name: *const c_char,
        value: Value,
    ) -> Status;
    fn napi_is_exception_pending(env: Env, result: *mut bool) -> Status;
    fn napi_throw_error(env: Env, code: *const c_char, message: *const c_char) -> Status;
}

type Result<T> = std::result::Result<T, &'static CStr>;

fn check(status: Status, message: &'static CStr) -> Result<()> {
    if status == NAPI_OK {
        Ok(())
    } else {
        Err(message)
    }
}

fn js_value(call: impl FnOnce(*mut Value) -> Status) -> Result<Value> {
    let mut value = null_mut();
    check(call(&mut value), c"Could not create Node-API value")?;
    Ok(value)
}

// All calls receive handles owned by Node and use them only during the callback.
// Each entry point converts errors and panics into JavaScript exceptions.
fn entry_point(env: Env, run: impl FnOnce() -> Result<Value> + std::panic::UnwindSafe) -> Value {
    let message = match catch_unwind(run) {
        Ok(Ok(value)) => return value,
        Ok(Err(message)) => message,
        Err(_) => c"Unexpected failure in native ECDSA addon",
    };
    let mut pending = false;
    unsafe {
        if napi_is_exception_pending(env, &mut pending) == NAPI_OK && !pending {
            napi_throw_error(env, std::ptr::null(), message.as_ptr());
        }
    }
    null_mut()
}

fn arguments<const N: usize>(env: Env, info: CallbackInfo) -> Result<[Value; N]> {
    let mut arguments = [null_mut(); N];
    let mut argc = arguments.len();
    check(
        unsafe {
            napi_get_cb_info(
                env,
                info,
                &mut argc,
                arguments.as_mut_ptr(),
                null_mut(),
                null_mut(),
            )
        },
        c"Could not read native ECDSA arguments",
    )?;
    if argc < N {
        return Err(c"Missing native ECDSA arguments");
    }
    Ok(arguments)
}

fn copy_buffer(env: Env, value: Value, output: &mut [u8]) -> Result<usize> {
    let mut array_type = 0;
    let mut length = 0;
    let mut data = null_mut();
    let mut backing = null_mut();
    let mut is_array_buffer = false;
    let message = c"Expected a Uint8Array with an unshared ArrayBuffer";
    unsafe {
        check(
            napi_get_typedarray_info(
                env,
                value,
                &mut array_type,
                &mut length,
                &mut data,
                &mut backing,
                null_mut(),
            ),
            message,
        )?;
        check(
            napi_is_arraybuffer(env, backing, &mut is_array_buffer),
            message,
        )?;
        if !is_array_buffer || array_type != NAPI_UINT8_ARRAY || data.is_null() {
            return Err(message);
        }
        if length > output.len() {
            return Err(c"Incorrect native ECDSA buffer length");
        }
        // The callback keeps the typed array alive. The backing store is unshared,
        // and the Node-API calls above do not execute JavaScript that could detach it.
        std::ptr::copy_nonoverlapping(data.cast::<u8>(), output.as_mut_ptr(), length);
    }
    Ok(length)
}

fn fixed_buffer<const N: usize>(env: Env, value: Value) -> Result<[u8; N]> {
    let mut bytes = [0; N];
    if copy_buffer(env, value, &mut bytes)? != N {
        return Err(c"Incorrect native ECDSA buffer length");
    }
    Ok(bytes)
}

struct SecretBytes<const N: usize>([u8; N]);

impl<const N: usize> SecretBytes<N> {
    fn read(&mut self, env: Env, value: Value, message: &'static CStr) -> Result<()> {
        if copy_buffer(env, value, &mut self.0)? != self.0.len() {
            return Err(message);
        }
        Ok(())
    }
}

impl<const N: usize> Drop for SecretBytes<N> {
    fn drop(&mut self) {
        for byte in &mut self.0 {
            // Volatile writes prevent the compiler from eliding these stores.
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
        compiler_fence(Ordering::SeqCst);
    }
}

fn output_buffer(env: Env, bytes: &[u8]) -> Result<Value> {
    // Node copies the bytes before the call returns.
    js_value(|value| unsafe {
        napi_create_buffer_copy(env, bytes.len(), bytes.as_ptr().cast(), null_mut(), value)
    })
}

fn null_value(env: Env) -> Result<Value> {
    js_value(|value| unsafe { napi_get_null(env, value) })
}

fn boolean(env: Env, value: Value, message: &'static CStr) -> Result<bool> {
    let mut flag = false;
    check(
        unsafe { napi_get_value_bool(env, value, &mut flag) },
        message,
    )?;
    Ok(flag)
}

fn read_path(env: Env, value: Value, path: &mut [u32; MAX_PATH_DEPTH]) -> Result<usize> {
    let mut bytes = [0; MAX_PATH_DEPTH * size_of::<u32>()];
    let length = copy_buffer(env, value, &mut bytes)?;
    if length == 0 || length % size_of::<u32>() != 0 {
        return Err(c"Expected 1 to 255 big-endian child indices");
    }
    for (index, bytes) in path.iter_mut().zip(bytes[..length].chunks_exact(4)) {
        *index = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    }
    Ok(length / size_of::<u32>())
}

unsafe extern "C" fn sign(env: Env, info: CallbackInfo) -> Value {
    entry_point(env, || {
        let [digest, key] = arguments(env, info)?;
        let digest = fixed_buffer(env, digest)?;
        let mut secret_key = SecretBytes([0; 32]);
        secret_key.read(env, key, c"Incorrect native ECDSA secret key length")?;
        match bitcore_ecdsa::sign(&digest, &secret_key.0) {
            Ok(signature) => output_buffer(env, &signature),
            Err(bitcore_ecdsa::Error::DigestOutOfRange) => null_value(env),
            Err(bitcore_ecdsa::Error::ContextRandomizationFailed) => {
                Err(c"Cannot initialize ECDSA signing: OS entropy unavailable")
            }
            Err(_) => Err(c"Cannot sign with the supplied native ECDSA inputs"),
        }
    })
}

unsafe extern "C" fn verify(env: Env, info: CallbackInfo) -> Value {
    entry_point(env, || {
        let [digest, signature, key] = arguments(env, info)?;
        let digest = fixed_buffer(env, digest)?;
        let signature = fixed_buffer(env, signature)?;
        let mut public_key = [0; 65];
        let length = copy_buffer(env, key, &mut public_key)?;
        if !matches!(length, 33 | 65) {
            return Err(c"Expected a 33-byte or 65-byte public key");
        }
        let valid =
            bitcore_ecdsa::verify(&digest, &signature, &public_key[..length]).unwrap_or(false);
        js_value(|value| unsafe { napi_get_boolean(env, valid, value) })
    })
}

unsafe extern "C" fn recover(env: Env, info: CallbackInfo) -> Value {
    entry_point(env, || {
        let [digest, signature, recovery_id, compression] = arguments(env, info)?;
        let digest = fixed_buffer(env, digest)?;
        let signature = fixed_buffer(env, signature)?;
        let mut id = 0.0;
        let id_error = c"Expected a recovery ID between 0 and 3";
        check(
            unsafe { napi_get_value_double(env, recovery_id, &mut id) },
            id_error,
        )?;
        if !matches!(id, 0.0 | 1.0 | 2.0 | 3.0) {
            return Err(id_error);
        }
        let compressed = boolean(env, compression, c"Expected a Boolean compression flag")?;
        match bitcore_ecdsa::recover_public_key(&digest, &signature, id as u8, compressed) {
            Ok(public_key) => output_buffer(env, &public_key),
            Err(_) => null_value(env),
        }
    })
}

unsafe extern "C" fn public_key_create(env: Env, info: CallbackInfo) -> Value {
    entry_point(env, || {
        let [key, compression] = arguments(env, info)?;
        let mut secret_key = SecretBytes([0; 32]);
        secret_key.read(env, key, c"Incorrect native secret key length")?;
        let compressed = boolean(env, compression, c"Expected a Boolean compression flag")?;
        let public_key = bitcore_hdkeys::public_key(&secret_key.0, compressed)
            .map_err(|_| c"Cannot initialize public key creation: OS entropy unavailable")?;
        match public_key {
            Some(public_key) => output_buffer(env, &public_key),
            None => null_value(env),
        }
    })
}

unsafe extern "C" fn derive_private_path(env: Env, info: CallbackInfo) -> Value {
    entry_point(env, || {
        let [key, chain, indices, compatibility, first_parent] = arguments(env, info)?;
        let mut secret_key = SecretBytes([0; 32]);
        secret_key.read(env, key, c"Incorrect native secret key length")?;
        let mut chain_code = SecretBytes([0; 32]);
        chain_code.read(env, chain, c"Incorrect native chain code length")?;
        let mut path = [0; MAX_PATH_DEPTH];
        let length = read_path(env, indices, &mut path)?;
        let non_compliant = boolean(env, compatibility, c"Expected a Boolean compatibility flag")?;
        let first_parent = if path[0] < HARDENED {
            Some(fixed_buffer(env, first_parent)?)
        } else {
            let message = c"Expected an undefined public key for a hardened first index";
            let mut value_type = NAPI_UNDEFINED;
            check(
                unsafe { napi_typeof(env, first_parent, &mut value_type) },
                message,
            )?;
            if value_type != NAPI_UNDEFINED {
                return Err(message);
            }
            None
        };

        let child = bitcore_hdkeys::derive_private(
            &secret_key.0,
            &chain_code.0,
            &path[..length],
            non_compliant,
            first_parent.as_ref(),
        )
        .map_err(|_| c"Cannot initialize private key derivation: OS entropy unavailable")?;
        let Some(child) = child else {
            return null_value(env);
        };
        let mut packed = SecretBytes([0; 97]);
        packed.0[..32].copy_from_slice(&child.secret_key);
        packed.0[32..64].copy_from_slice(&child.chain_code);
        // With one step, JavaScript takes the fingerprint from the root object.
        if let Some(parent) = child.parent_public_key {
            packed.0[64..].copy_from_slice(&parent);
        }
        output_buffer(env, &packed.0)
    })
}

unsafe extern "C" fn derive_public_path(env: Env, info: CallbackInfo) -> Value {
    entry_point(env, || {
        let [key, chain_code, indices] = arguments(env, info)?;
        let public_key = fixed_buffer(env, key)?;
        let chain_code = fixed_buffer(env, chain_code)?;
        let mut path = [0; MAX_PATH_DEPTH];
        let length = read_path(env, indices, &mut path)?;

        let Some(child) = bitcore_hdkeys::derive_public(&public_key, &chain_code, &path[..length])
        else {
            return null_value(env);
        };
        let mut packed = [0; 98];
        packed[..33].copy_from_slice(&child.public_key);
        packed[33..65].copy_from_slice(&child.chain_code);
        // The final slot stays zero when JavaScript already has the parent fingerprint.
        if let Some(parent) = child.parent_public_key {
            packed[65..].copy_from_slice(&parent);
        }
        output_buffer(env, &packed)
    })
}

/// # Safety
/// Node must supply a live environment and its module exports object.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn napi_register_module_v1(env: Env, exports: Value) -> Value {
    entry_point(env, || {
        let version = js_value(|value| unsafe { napi_create_uint32(env, 3, value) })?;
        check(
            unsafe { napi_set_named_property(env, exports, c"abiVersion".as_ptr(), version) },
            c"Could not register the Bitcore addon ABI version",
        )?;
        for (name, callback) in [
            (c"sign", sign as Callback),
            (c"verify", verify),
            (c"recover", recover),
            (c"publicKeyCreate", public_key_create),
            (c"derivePrivatePath", derive_private_path),
            (c"derivePublicPath", derive_public_path),
            (c"publicKeyParse", points::parse),
            (c"eciesKeyMaterial", ecies::key_material),
            (c"signBchSchnorr", bch_schnorr::sign),
            (c"verifyBchSchnorr", bch_schnorr::verify),
        ]
        .into_iter()
        .chain(cwc_crypto::FUNCTIONS)
        .chain(ed25519::FUNCTIONS)
        .chain(kdfs::FUNCTIONS)
        .chain(random_nonce::FUNCTIONS)
        .chain(merkle::FUNCTIONS)
        .chain(taproot::FUNCTIONS)
        .chain(xrp_keys::FUNCTIONS)
        {
            let function = js_value(|value| unsafe {
                napi_create_function(
                    env,
                    name.as_ptr(),
                    name.to_bytes().len(),
                    callback,
                    null_mut(),
                    value,
                )
            })?;
            check(
                unsafe { napi_set_named_property(env, exports, name.as_ptr(), function) },
                c"Could not register native ECDSA function",
            )?;
        }
        Ok(exports)
    })
}
