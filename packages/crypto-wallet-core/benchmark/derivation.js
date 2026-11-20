/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone CommonJS benchmark. */
'use strict';

const assert = require('node:assert/strict');
const benchmark = require('../../bitcore-lib/benchmark/backends');

function confirmNativeDispatch(native, method, operation, chain) {
  const original = native?.[method];
  assert.equal(typeof original, 'function', 'Rebuild the addon to benchmark ' + method);
  let used = false;
  native[method] = (...args) => {
    const result = original(...args);
    if (result) used = true;
    return result;
  };
  try {
    operation(0);
    assert(used, chain + ' skipped native ' + method);
  } finally {
    native[method] = original;
  }
}

benchmark(__filename, wallet => {
  const chains = {
    BTC: wallet.BitcoreLib, BCH: wallet.BitcoreLibCash,
    LTC: wallet.BitcoreLibLtc, DOGE: wallet.BitcoreLibDoge,
    ETH: wallet.BitcoreLib, XRP: wallet.BitcoreLib, SOL: wallet.BitcoreLib
  };
  const fixtures = Array.from({ length: 4 }, (_, i) => i);
  const operations = {};
  const packages = { BCH: 'bitcore-lib-cash', DOGE: 'bitcore-lib-doge', LTC: 'bitcore-lib-ltc' };
  for (const [chain, lib] of Object.entries(chains)) {
    const seed = Buffer.alloc(32, 13);
    const xpriv = lib.HDPrivateKey.fromSeed(seed).toString();
    const derived = fixtures.map(i => wallet.Deriver.derivePrivateKey(chain, 'livenet', xpriv, i, false));
    for (const key of derived) {
      assert.equal(wallet.Deriver.getAddress(chain, 'livenet', key.pubKey), key.address);
    }
    operations[chain + 'AddressFromKey'] = i => wallet.Deriver.getAddress(chain, 'livenet', derived[i].pubKey);
    // Advance through new addresses so Dogecoin's HD cache cannot satisfy the final step.
    let nextIndex = fixtures.length;
    operations[chain + 'DeriveReceiveKey'] = () => wallet.Deriver.derivePrivateKey(chain, 'livenet', xpriv, nextIndex++, false);
    if (process.env.BITCORE_ECDSA_BACKEND === 'native') {
      const { native } = require(`@bitpay-labs/${packages[chain] || 'bitcore-lib'}/lib/crypto/ecdsa-native`);
      // Solana reads the extended key through Bitcore, then derives children in ed25519-hd-key.
      const method = chain === 'SOL' ? 'publicKeyCreate' : 'derivePrivatePath';
      confirmNativeDispatch(native, method, operations[chain + 'DeriveReceiveKey'], chain);
      if (chain !== 'XRP' && chain !== 'SOL') {
        confirmNativeDispatch(native, 'publicKeyParse', operations[chain + 'AddressFromKey'], chain);
      }
    }
  }
  return { fixtures, operations };
}, { load: () => require('..') });
