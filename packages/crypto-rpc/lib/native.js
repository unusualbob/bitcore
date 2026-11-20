import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

function isMissingModule(err, path) {
  return err.code === 'MODULE_NOT_FOUND' && err.message.startsWith(`Cannot find module '${path}'`);
}

function loadNativeCrypto() {
  // Resolve the same Bitcore dependency as CWC, including nested npm installs.
  const walletPath = '@bitpay-labs/crypto-wallet-core';
  const path = '@bitpay-labs/bitcore-lib/lib/crypto/ecdsa-native';
  try {
    const walletRequire = createRequire(require.resolve(walletPath));
    return walletRequire(path).native;
  } catch (err) {
    // Older standalone releases may lack the optional loader.
    if (err.code !== 'ERR_PACKAGE_PATH_NOT_EXPORTED' && !isMissingModule(err, path) && !isMissingModule(err, walletPath)) throw err;
  }
}

export const nativeCrypto = loadNativeCrypto();
