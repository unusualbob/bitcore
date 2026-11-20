'use strict';

let native;
if (typeof module.require === 'function' && typeof process !== 'undefined' && process.versions?.node) {
  const backend = process.env.BITCORE_ECDSA_BACKEND || 'auto';
  if (backend !== 'auto' && backend !== 'native' && backend !== 'js') {
    throw new Error('BITCORE_ECDSA_BACKEND must be auto, native, or js');
  }

  if (backend !== 'js') {
    try {
      native = module.require('../native/bitcore_ecdsa.node');
    } catch (err) {
      if (backend === 'native' || (err.code !== 'MODULE_NOT_FOUND' && err.code !== 'ERR_DLOPEN_FAILED')) {
        throw err;
      }
      if (err.code === 'ERR_DLOPEN_FAILED') {
        process.emitWarning(`Using JavaScript ECDSA because the native addon failed to load. ${err.message}`, {
          code: 'BITCORE_ECDSA_NATIVE_LOAD_FAILED'
        });
      }
    }
  }
}

module.exports = { native };
