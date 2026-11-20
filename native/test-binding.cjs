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

assert.deepEqual(native.publicKeyCreate(secretKey, true), compressed);
assert.deepEqual(native.publicKeyCreate(secretKey, false), uncompressed);
assert.equal(native.publicKeyCreate(Buffer.alloc(32), true), null);
assert.throws(() => native.publicKeyCreate(secretKey));
assert.throws(() => native.publicKeyCreate(secretKey, 1));
assert.throws(() => native.publicKeyCreate(Buffer.alloc(33), true));
assert.throws(() => native.publicKeyCreate(shared, true));

// BIP32 test vector 1, master to m/0'.
const masterSecret = Buffer.from('e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35', 'hex');
const masterChain = Buffer.from('873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508', 'hex');
const childSecret = Buffer.from('edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea', 'hex');
const childChain = Buffer.from('47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141', 'hex');
const childPublic = Buffer.from('035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56', 'hex');
const hardened = Buffer.from('80000000', 'hex');
assert.deepEqual(native.derivePrivatePath(masterSecret, masterChain, hardened, false, undefined), Buffer.concat([
  childSecret, childChain, Buffer.alloc(33)
]));

const offsetPath = Buffer.from('ab0000000100000002cd', 'hex');
const path = new Uint8Array(offsetPath.buffer, offsetPath.byteOffset + 1, 8);
const derivedPrivate = native.derivePrivatePath(childSecret, childChain, path, false, childPublic);
const derivedPublic = native.derivePublicPath(childPublic, childChain, path);
const immediateParent = native.derivePublicPath(childPublic, childChain, path.subarray(0, 4));
const expectedParent = immediateParent.subarray(0, 33);
assert.equal(derivedPrivate.length, 97);
assert.equal(derivedPublic.length, 98);
assert.deepEqual(immediateParent.subarray(65), Buffer.alloc(33));
assert.deepEqual(derivedPrivate.subarray(32, 64), derivedPublic.subarray(33, 65));
assert.deepEqual(derivedPrivate.subarray(64), expectedParent);
assert.deepEqual(derivedPublic.subarray(65), expectedParent);
ecdh.setPrivateKey(derivedPrivate.subarray(0, 32));
assert.deepEqual(ecdh.getPublicKey(undefined, 'compressed'), derivedPublic.subarray(0, 33));

assert.notDeepEqual(native.derivePrivatePath(secretKey, masterChain, hardened, false, undefined),
  native.derivePrivatePath(secretKey, masterChain, hardened, true, undefined));
assert.notDeepEqual(native.derivePrivatePath(childSecret, childChain, path, false, compressed), derivedPrivate);
assert.equal(native.derivePrivatePath(Buffer.alloc(32), masterChain, path, false, childPublic), null);
assert.equal(native.derivePublicPath(Buffer.alloc(33), masterChain, path), null);
assert.equal(native.derivePublicPath(childPublic, childChain, Buffer.concat([path, hardened])), null);
assert.equal(native.derivePublicPath(childPublic, childChain, Buffer.alloc(255 * 4)).length, 98);
assert.throws(() => native.derivePrivatePath(childSecret, childChain, path, false));
assert.throws(() => native.derivePrivatePath(childSecret, childChain, path, 0, childPublic));
assert.throws(() => native.derivePrivatePath(childSecret, childSecret.subarray(1), path, false, childPublic));
assert.throws(() => native.derivePrivatePath(childSecret, childChain, path, false, undefined));
assert.throws(() => native.derivePrivatePath(childSecret, childChain, path, false, uncompressed));
assert.throws(() => native.derivePrivatePath(childSecret, childChain, hardened, false, childPublic));
assert.throws(() => native.derivePublicPath(uncompressed, childChain, path));
assert.throws(() => native.derivePublicPath(childPublic, shared, path));
for (const invalidPath of [
  Buffer.alloc(0), Buffer.alloc(5), Buffer.alloc(256 * 4), new Uint32Array([1, 2]),
  shared, detached, [1, 2]
]) {
  assert.throws(() => native.derivePrivatePath(childSecret, childChain, invalidPath, false, childPublic));
  assert.throws(() => native.derivePublicPath(childPublic, childChain, invalidPath));
}

console.log('Native cryptography binding checks passed.');
