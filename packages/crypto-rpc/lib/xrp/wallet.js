import { xrpl } from '@bitpay-labs/crypto-wallet-core';
import { nativeCrypto } from '../native.js';

export function walletFromSeed(seed, options) {
  const derive = nativeCrypto?.xrpDeriveKeypair;
  if (typeof derive !== 'function' || typeof seed !== 'string' || options === null) {
    return xrpl.Wallet.fromSeed(seed, options);
  }

  const { algorithm, masterAddress } = options ?? {};
  const { bytes, type } = xrpl.decodeSeed(seed);
  const ed25519 = type === 'ed25519';
  let keys;
  try {
    // xrpl 2.13.0 forwards only the algorithm to ripple-keypairs 1.3.1.
    // ripple-keypairs selects by seed type, irrespective of the algorithm option.
    keys = derive(bytes, ed25519, 0, false);
    if (keys !== null) {
      if (!Buffer.isBuffer(keys) || keys.length !== 66 ||
          (ed25519 ? keys[0] !== 0xed || keys[33] !== 0xed
            : keys[0] !== 0 || (keys[33] !== 2 && keys[33] !== 3))) {
        throw new Error('Invalid native XRP keypair');
      }
      const privateKey = keys.toString('hex', 0, 33).toUpperCase();
      const publicKey = keys.toString('hex', 33).toUpperCase();
      return new xrpl.Wallet(publicKey, privateKey, { seed, masterAddress });
    }
  } finally {
    bytes.fill(0);
    if (Buffer.isBuffer(keys)) keys.fill(0);
  }
  return xrpl.Wallet.fromSeed(seed, { algorithm, masterAddress });
}
