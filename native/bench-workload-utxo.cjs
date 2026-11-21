/* eslint @typescript-eslint/no-require-imports: "off" -- Offline two-checkout benchmark. */
'use strict';

const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const path = require('node:path');

// Match the 32-input, three-output fixtures in bench-utxo.cjs.
function workload(chain, type) {
  const key = new chain.PrivateKey(chain.crypto.BN.fromBuffer(Buffer.alloc(32, 1)));
  const address = chain.Address.fromPublicKey(key.publicKey, undefined, type);
  const recipient = new chain.PrivateKey(chain.crypto.BN.fromBuffer(Buffer.alloc(32, 2))).toAddress();
  const script = chain.Script.fromAddress(address).toHex();
  const utxos = Array.from({ length: 32 }, (_, index) => ({
    txId: chain.crypto.Hash.sha256(Buffer.from(`utxo benchmark ${type} ${index}`)).toString('hex'),
    outputIndex: index % 3,
    script,
    satoshis: 100000 + index
  }));
  const taproot = type === 'taproot';
  return {
    run() {
      return new chain.Transaction().from(utxos)
        .to(recipient, 50000).to(recipient, 25000).to(recipient, 10000).sign(key);
    },
    check(tx) {
      assert.equal(tx.inputs.length, utxos.length);
      assert.ok(tx.inputs.every(input => input.isFullySigned()));
      if (taproot) {
        // BIP340 auxiliary randomness changes the witness bytes. Verify every
        // witness against its prevout before comparing the stripped transaction.
        for (const input of tx.inputs) {
          const witnesses = input.getWitnesses();
          assert.equal(witnesses.length, 1);
          assert.equal(witnesses[0].length, 64);
          const signature = chain.crypto.Signature.fromSchnorr(witnesses[0]);
          assert.ok(input.isValidSignature(tx, { signature }));
        }
      }
      return createHash('sha256').update(tx.toBuffer(taproot)).digest('hex');
    }
  };
}

module.exports = function utxoWorkloads(root) {
  const load = suffix => require(path.resolve(root, 'packages', 'bitcore-lib' + suffix));
  const btc = load('');
  const cash = load('-cash');
  const doge = load('-doge');
  const ltc = load('-ltc');
  return {
    'BTC transaction, 32 P2PKH inputs': workload(btc, btc.Address.PayToPublicKeyHash),
    'BTC transaction, 32 P2WPKH inputs': workload(btc, btc.Address.PayToWitnessPublicKeyHash),
    'BTC transaction, 32 Taproot inputs': workload(btc, btc.Address.PayToTaproot),
    'BCH transaction, 32 fork-ID P2PKH inputs': workload(cash, cash.Address.PayToPublicKeyHash),
    'DOGE transaction, 32 P2PKH inputs': workload(doge, doge.Address.PayToPublicKeyHash),
    'LTC transaction, 32 P2WPKH inputs': workload(ltc, ltc.Address.PayToWitnessPublicKeyHash)
  };
};
