type ClientCrypto = {
  sign(digest: Buffer, key: Buffer): Buffer | null;
  bitcoinCoreWalletKey?(input: Buffer, rounds: number): Buffer;
};

function loadNative(): ClientCrypto | undefined {
  if (typeof window !== 'undefined' || typeof process === 'undefined' || !process.versions?.node ||
      typeof module === 'undefined' || typeof module.require !== 'function' ||
      typeof require.resolve !== 'function') return;
  let fromWallet: NodeJS.Require;
  try {
    // Follow the installed wallet package, including non-hoisted dependencies.
    const { createRequire } = module.require('module') as typeof import('node:module');
    fromWallet = createRequire(require.resolve('@bitpay-labs/crypto-wallet-core'));
  } catch {
    // Browser and bundled CommonJS runtimes may not provide a filesystem resolver.
    return;
  }
  const path = '@bitpay-labs/bitcore-lib/lib/crypto/ecdsa-native';
  try {
    return fromWallet(path).native;
  } catch (err) {
    if (err.code !== 'ERR_PACKAGE_PATH_NOT_EXPORTED' &&
        (err.code !== 'MODULE_NOT_FOUND' || !err.message.startsWith(`Cannot find module '${path}'`))) throw err;
  }
}

export const native = loadNative();
