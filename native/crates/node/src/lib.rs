use std::ffi::{CStr, c_char, c_int, c_void};
use std::panic::catch_unwind;
use std::ptr::null_mut;
use std::sync::atomic::{Ordering, compiler_fence};

type Env = *mut c_void;
type Value = *mut c_void;
type CallbackInfo = *mut c_void;
type Callback = unsafe extern "C" fn(Env, CallbackInfo) -> Value;
type Status = c_int;

const NAPI_OK: Status = 0;
const NAPI_UINT8_ARRAY: c_int = 1;

// Stable Node-API symbols provided by Node when it loads the addon.
unsafe extern "C" {
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

struct SecretKeyBytes([u8; 32]);

impl Drop for SecretKeyBytes {
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

unsafe extern "C" fn sign(env: Env, info: CallbackInfo) -> Value {
    entry_point(env, || {
        let [digest, key] = arguments(env, info)?;
        let digest = fixed_buffer(env, digest)?;
        let mut secret_key = SecretKeyBytes([0; 32]);
        if copy_buffer(env, key, &mut secret_key.0)? != secret_key.0.len() {
            return Err(c"Incorrect native ECDSA secret key length");
        }
        match bitcore_ecdsa::sign(&digest, &secret_key.0) {
            Ok(signature) => output_buffer(env, &signature),
            Err(bitcore_ecdsa::Error::DigestOutOfRange) => {
                js_value(|value| unsafe { napi_get_null(env, value) })
            }
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
        let mut compressed = false;
        let id_error = c"Expected a recovery ID between 0 and 3";
        check(
            unsafe { napi_get_value_double(env, recovery_id, &mut id) },
            id_error,
        )?;
        if !matches!(id, 0.0 | 1.0 | 2.0 | 3.0) {
            return Err(id_error);
        }
        check(
            unsafe { napi_get_value_bool(env, compression, &mut compressed) },
            c"Expected a Boolean compression flag",
        )?;
        match bitcore_ecdsa::recover_public_key(&digest, &signature, id as u8, compressed) {
            Ok(public_key) => output_buffer(env, &public_key),
            Err(_) => js_value(|value| unsafe { napi_get_null(env, value) }),
        }
    })
}

/// # Safety
/// Node must supply a live environment and its module exports object.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn napi_register_module_v1(env: Env, exports: Value) -> Value {
    entry_point(env, || {
        for (name, callback) in [
            (c"sign", sign as Callback),
            (c"verify", verify),
            (c"recover", recover),
        ] {
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
