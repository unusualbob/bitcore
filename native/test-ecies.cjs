/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone CommonJS test. */
'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const bitcore = require('@bitpay-labs/bitcore-lib');
const { native } = require('@bitpay-labs/bitcore-lib/lib/crypto/ecdsa-native');
const { KDF } = require('../packages/bitcore-tss/ecies/ecies');

const local = crypto.createECDH('secp256k1');
const peer = crypto.createECDH('secp256k1');
local.setPrivateKey(crypto.createHash('sha256').update('ECIES interoperability fixture').digest());
const localSec = local.getPublicKey();
let shared;
for (let index = 0; index < 4096; index++) {
  peer.setPrivateKey(crypto.createHash('sha256').update(String(index)).digest());
  shared = local.computeSecret(peer.getPublicKey());
  if (shared[0] === 0) break;
}
assert.equal(shared[0], 0, 'fixture must preserve a leading zero in the x coordinate');
const peerSec = peer.getPublicKey();
const expected = Buffer.concat([shared, peer.getPublicKey(null, 'compressed'), local.getPublicKey(null, 'compressed')]);
assert.deepEqual(native.eciesKeyMaterial(local.getPrivateKey(), peerSec, localSec), expected);
assert.equal(native.eciesKeyMaterial(Buffer.alloc(32), peerSec, localSec), null);
assert.equal(native.eciesKeyMaterial(local.getPrivateKey(), Buffer.alloc(65), localSec), null);
assert.throws(() => native.eciesKeyMaterial(local.getPrivateKey(), peerSec.subarray(1), localSec));
const priv = bitcore.PrivateKey.fromBuffer(local.getPrivateKey());
const pub = bitcore.PublicKey.fromBuffer(peerSec);
for (const decrypt of [false, true]) {
  const salt = decrypt ? Buffer.concat([expected.subarray(65), expected.subarray(32, 65)]) : expected.subarray(32);
  const keys = ['ecies-kE', 'ecies-kM'].map(info => Buffer.from(crypto.hkdfSync('sha256', shared, salt, info, 32)));
  assert.deepEqual(KDF(priv, pub, decrypt), keys);
}
console.log('ECIES raw ECDH, compressed salt order, HKDF and invalid inputs passed.');
