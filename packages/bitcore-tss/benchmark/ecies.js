/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone CommonJS benchmark. */
'use strict';

const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const benchmark = require('../../bitcore-lib/benchmark/backends');

benchmark(__filename, bitcore => {
  const ECIES = require('../ecies/ecies');
  const fixtures = Array.from({ length: 8 }, (_, index) => {
    const key = label => bitcore.PrivateKey.fromBuffer(createHash('sha256').update(label + index).digest());
    const privateKey = key('local');
    const receiver = key('peer');
    const publicKey = receiver.publicKey;
    const message = Buffer.alloc(256, index);
    const payload = ECIES.encrypt({ message, privateKey, publicKey });
    assert.deepEqual(ECIES.decrypt({ privateKey: receiver, payload }), message);
    return { privateKey, receiver, publicKey, message, payload };
  });
  if (process.env.BITCORE_ECDSA_BACKEND === 'native') {
    const { native } = require('@bitpay-labs/bitcore-lib/lib/crypto/ecdsa-native');
    const original = native.eciesKeyMaterial;
    let called = false;
    native.eciesKeyMaterial = (...args) => {
      const result = original(...args);
      called ||= result?.length === 98;
      return result;
    };
    try {
      ECIES.KDF(fixtures[0].privateKey, fixtures[0].publicKey);
      assert(called, 'ECIES skipped native ECDH');
    } finally {
      native.eciesKeyMaterial = original;
    }
  }
  return { fixtures, operations: {
    deriveKeys: f => ECIES.KDF(f.privateKey, f.publicKey),
    encrypt256Bytes: f => ECIES.encrypt(f),
    decrypt256Bytes: f => ECIES.decrypt({ privateKey: f.receiver, payload: f.payload })
  } };
});
