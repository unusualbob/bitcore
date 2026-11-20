/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone CommonJS script. */
'use strict';

const assert = require('node:assert/strict');
const { createECDH } = require('node:crypto');
const native = require('../packages/bitcore-lib/lib/native/bitcore_ecdsa.node');

const digest = Buffer.from('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', 'hex');
const secretKey = Buffer.alloc(32);
secretKey[31] = 1;

const signature = native.sign(digest, secretKey);
assert.ok(Buffer.isBuffer(signature));
assert.equal(signature.length, 64);
assert.deepEqual(native.sign(digest, secretKey), signature);

const ecdh = createECDH('secp256k1');
ecdh.setPrivateKey(secretKey);
const compressed = ecdh.getPublicKey(undefined, 'compressed');
const uncompressed = ecdh.getPublicKey(undefined, 'uncompressed');
assert.equal(native.verify(digest, signature, compressed), true);
assert.equal(native.verify(digest, signature, uncompressed), true);
assert.equal(native.verify(Buffer.alloc(32), signature, compressed), false);
assert.equal(native.verify(digest, Buffer.alloc(64), compressed), false);

const id = [0, 1, 2, 3].find(candidate =>
  native.recover(digest, signature, candidate, true)?.equals(compressed));
assert.notEqual(id, undefined);
assert.deepEqual(native.recover(digest, signature, id, false), uncompressed);
assert.equal(native.recover(digest, Buffer.alloc(64), id, true), null);
assert.equal(native.sign(Buffer.alloc(32, 0xff), secretKey), null);

assert.throws(() => native.sign(digest));
assert.throws(() => native.sign('digest', secretKey));
assert.throws(() => native.sign(digest, Buffer.alloc(32)));
assert.throws(() => native.verify(digest, Buffer.alloc(63), compressed));
assert.throws(() => native.verify(digest, signature, Buffer.alloc(34)));
for (const length of [31, 33]) {
  assert.throws(() => native.sign(Buffer.alloc(length), secretKey));
  assert.throws(() => native.sign(digest, Buffer.alloc(length)));
}
for (const invalidId of [-1, 0.5, 4, NaN, Infinity, '1']) {
  assert.throws(() => native.recover(digest, signature, invalidId, true));
}
assert.throws(() => native.recover(digest, signature, id, 1));

const offsetBuffer = Buffer.alloc(34);
digest.copy(offsetBuffer, 1);
assert.deepEqual(native.sign(offsetBuffer.subarray(1, 33), secretKey), signature);

const shared = Buffer.from(new SharedArrayBuffer(32));
assert.throws(() => native.sign(shared, secretKey));
secretKey.copy(shared);
assert.throws(() => native.sign(digest, shared));

const detached = Buffer.allocUnsafeSlow(32);
structuredClone(detached.buffer, { transfer: [detached.buffer] });
assert.equal(detached.length, 0);
assert.throws(() => native.sign(detached, secretKey));

console.log('Native ECDSA binding checks passed.');
