'use strict';

let native;
if (typeof module.require === 'function' && typeof process !== 'undefined' && process.versions?.node) {
  const backend = process.env.BITCORE_ECDSA_BACKEND || 'auto';
  if (backend !== 'auto' && backend !== 'native' && backend !== 'js') {
    throw new Error('BITCORE_ECDSA_BACKEND must be auto, native, or js');
  }

  if (backend !== 'js') {
    try {
      const addon = module.require('../native/bitcore_ecdsa.node');
      // The ECDSA-only pilot had exactly these three entry points and no ABI version.
      const legacy = addon.abiVersion === undefined &&
        Object.keys(addon).sort().join(',') === 'recover,sign,verify';
      if (addon.abiVersion === 2 || legacy) {
        native = addon;
      } else {
        const message = 'Incompatible Bitcore addon ABI. Rebuild with node native/build-node.cjs.';
        if (backend === 'native') throw new Error(message);
        process.emitWarning(message, { code: 'BITCORE_NATIVE_ABI_MISMATCH' });
      }
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
