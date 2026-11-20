'use strict';

let native;
if (typeof module.require === 'function' && typeof process !== 'undefined' && process.versions?.node) {
  // A global native setting predates this fork's addon. Keep it optional here.
  const backend = process.env.BITCORE_BCH_BACKEND || (process.env.BITCORE_ECDSA_BACKEND === 'js' ? 'js' : 'auto');
  if (backend !== 'auto' && backend !== 'native' && backend !== 'js') {
    throw new Error('BITCORE_BCH_BACKEND must be auto, native, or js');
  }

  if (backend !== 'js') {
    try {
      const addon = module.require('../native/bitcore_ecdsa.node');
      // The ECDSA-only pilot had exactly these three entry points and no ABI version.
      const legacy = addon.abiVersion === undefined &&
        Object.keys(addon).sort().join(',') === 'recover,sign,verify';
      // ABI 2 shipped the earlier secp256k1 and KDF functions. New callers
      // probe each optional export so previous local builds stay usable.
      if (addon.abiVersion === 3 || addon.abiVersion === 2 || legacy) {
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
