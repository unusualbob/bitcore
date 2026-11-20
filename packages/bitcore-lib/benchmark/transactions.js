'use strict';

const assert = require('node:assert/strict');
const benchmark = require('./backends');

benchmark(__filename, ({ Transaction, PrivateKey, PublicKey, Script, crypto }) => {
  const fixtures = Array.from({ length: 4 }, (_, i) => {
    const key = new PrivateKey(crypto.BN.fromBuffer(crypto.Hash.sha256(Buffer.from('transaction profile ' + i))));
    const address = key.toAddress();
    const script = Script.buildPublicKeyHashOut(address);
    const tx = new Transaction();
    for (let j = 0; j < 8; j++) {
      const txId = crypto.Hash.sha256(Buffer.from([i, j])).toString('hex');
      tx.from({ txId, outputIndex: 0, script: script.toHex(), satoshis: 100000 });
    }
    tx.to(address, 790000);
    const signatures = tx.getSignatures(key);
    assert.equal(signatures.length, 8);
    assert(signatures.every((s, j) => tx.inputs[j].isValidSignature(tx, s)));
    const compressed = key.publicKey.toBuffer();
    const uncompressed = PublicKey.fromPoint(key.publicKey.point, false).toBuffer();
    return { tx, key, signatures, script, compressed, uncompressed };
  });
  if (process.env.BITCORE_ECDSA_BACKEND === 'native') {
    const { native } = require('../lib/crypto/ecdsa-native');
    const parse = native.publicKeyParse;
    assert.equal(typeof parse, 'function', 'Rebuild the addon for the SEC parser benchmark');
    let calls = 0;
    native.publicKeyParse = sec => {
      const result = parse(sec);
      if (result) calls++;
      return result;
    };
    try {
      new PublicKey(fixtures[0].compressed);
      PublicKey.fromBuffer(fixtures[0].uncompressed);
      assert.equal(calls, 2);
    } finally {
      native.publicKeyParse = parse;
    }
  }
  return { fixtures, operations: {
    parseCompressed: f => new PublicKey(f.compressed),
    parseUncompressed: f => PublicKey.fromBuffer(f.uncompressed),
    hashEightLegacyInputs: f => {
      for (let j = 0; j < f.tx.inputs.length; j++) Transaction.Sighash.sighash(f.tx, 1, j, f.script);
    },
    signEightLegacyInputs: f => f.tx.getSignatures(f.key),
    verifyEightLegacyInputs: f => {
      for (const [j, signature] of f.signatures.entries()) f.tx.inputs[j].isValidSignature(f.tx, signature);
    }
  } };
});
