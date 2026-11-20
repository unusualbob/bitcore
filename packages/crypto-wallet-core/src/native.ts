function loadNativeCrypto() {
  if (typeof module === 'undefined' || typeof module.require !== 'function' ||
      typeof process === 'undefined' || !process.versions?.node) return;
  const path = '@bitpay-labs/bitcore-lib/lib/crypto/ecdsa-native';
  try {
    return module.require(path).native;
  } catch (err) {
    // Older releases of bitcore-lib predate the optional Node backend.
    if (err.code !== 'ERR_PACKAGE_PATH_NOT_EXPORTED' &&
        (err.code !== 'MODULE_NOT_FOUND' || !err.message.startsWith(`Cannot find module '${path}'`))) throw err;
  }
}

export const nativeCrypto = loadNativeCrypto();
