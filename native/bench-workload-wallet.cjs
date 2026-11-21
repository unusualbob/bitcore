/* eslint @typescript-eslint/no-require-imports: "off" -- Offline two-checkout benchmark. */
'use strict';

const assert = require('node:assert/strict');
const { createRequire } = require('node:module');
const path = require('node:path');

module.exports = function makeWalletWorkloads(root) {
  const pkg = name => path.resolve(root, 'packages', name);
  const walletRequire = createRequire(path.join(pkg('bitcore-wallet-client'), 'package.json'));
  const { BitcoreLib } = walletRequire('@bitpay-labs/crypto-wallet-core');
  assert.ok(BitcoreLib.HDPrivateKey === require(pkg('bitcore-lib')).HDPrivateKey,
    'wallet-client must use this checkout’s Bitcoin library');
  assert.equal(walletRequire.resolve('@bitpay-labs/crypto-wallet-core'), require.resolve(pkg('crypto-wallet-core')));
  const { Utils } = walletRequire('./ts_build/src/lib/common/utils');
  const { Key } = walletRequire('./ts_build/src/lib/key');
  const rootPath = "m/44'/0'/0'";
  const master = BitcoreLib.HDPrivateKey.fromSeed(Buffer.alloc(32, 19));
  const account = master.deriveChild(rootPath);
  const key = new Key({ seedType: 'extendedPrivateKey', seedData: master.toString() });
  const childKeys = Array.from({ length: 32 }, (_, i) => account.deriveChild(`m/0/${i}`).privateKey);
  const toAddress = account.deriveChild('m/0/400').privateKey.toAddress().toString();

  function workload(addressType, type) {
    const inputs = childKeys.map((child, i) => {
      const address = child.toAddress(undefined, type).toString();
      return {
        path: `m/0/${i}`, address, txId: (i + 1).toString(16).padStart(64, '0'), outputIndex: 0,
        script: BitcoreLib.Script.fromAddress(address).toHex(), satoshis: 20000
      };
    });
    const proposal = {
      chain: 'BTC', addressType, version: 3, inputs, signingMethod: 'ecdsa',
      toAddress, sendMax: true, amount: inputs.length * 20000 - 5000, fee: 5000
    };
    return {
      run: () => key.sign(rootPath, proposal),
      check(signatures) {
        assert.equal(signatures.length, inputs.length);
        if (addressType !== 'P2TR') return signatures;
        // Taproot uses fresh auxiliary randomness. Verify each signature against its
        // expected spent output and compare the ordered signing digests across revisions.
        const tx = Utils.buildTx(proposal);
        return signatures.map((hex, index) => {
          const signature = BitcoreLib.crypto.Signature.fromSchnorr(Buffer.from(hex, 'hex'));
          assert(tx.inputs[index].isValidSignature(tx, { signature }), `invalid Taproot signature at input ${index}`);
          return tx.inputs[index].getSighash(tx, null, index).toString('hex');
        });
      }
    };
  }
  return {
    walletP2PKH32: workload('P2PKH'),
    walletP2WPKH32: workload('P2WPKH', 'witnesspubkeyhash'),
    walletP2TR32: workload('P2TR', 'taproot')
  };
};
