/* eslint @typescript-eslint/no-require-imports: "off", import/order: "off" -- Set the backend before loading packages. */
'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');

process.env.BITCORE_ECDSA_BACKEND = 'native';

const { native } = require('../packages/bitcore-lib/lib/crypto/ecdsa-native');
const dogecoin = require('../packages/bitcore-lib-doge');
const dogeAddon = require('../packages/bitcore-lib-doge/lib/crypto/ecdsa-native').native;
const dogeFixture = require('../packages/bitcore-lib-doge/test/data/blk160775-testnet');
const litecoin = require('../packages/bitcore-lib-ltc');
const ltcAddon = require('../packages/bitcore-lib-ltc/lib/crypto/ecdsa-native').native;
const Mnemonic = require('../packages/bitcore-mnemonic');
const pbkdf2 = require('../packages/bitcore-mnemonic/lib/pbkdf2');
const vectors = require('../packages/bitcore-mnemonic/test/data/bip39-vectors.json');

function withOverrides(overrides, test) {
  const originals = overrides.map(([object, key]) => object[key]);
  try {
    for (const [object, key, value] of overrides) object[key] = value;
    test();
  } finally {
    for (const [index, [object, key]] of overrides.entries()) object[key] = originals[index];
  }
}

const [[, phrase, seed]] = vectors.english;
const phraseBytes = Buffer.from(phrase);
const saltBytes = Buffer.from('mnemonicTREZOR');
const expectedSeed = Buffer.from(seed, 'hex');
const words = new Mnemonic(phrase);
const shared = new SharedArrayBuffer(80);
assert.deepEqual(native.bip39Seed(phraseBytes, saltBytes), expectedSeed);
assert.deepEqual(words.toSeed('TREZOR'), expectedSeed);
assert.throws(() => native.bip39Seed(Buffer.alloc(4097), saltBytes));
assert.throws(() => native.bip39Seed(phraseBytes, new Uint8Array(shared)));
assert.throws(() => native.bip39Seed(phrase, saltBytes));

const { pbkdf2Sync } = crypto;
let nativeCalls = 0;
const { bip39Seed } = native;
withOverrides([[native, 'bip39Seed', (...args) => {
  nativeCalls++;
  return bip39Seed(...args);
}]], () => {
  for (const length of [4096, 4097]) {
    const key = Buffer.alloc(length, 0x61);
    const salt = Buffer.alloc(length, 0xa5);
    assert.deepEqual(pbkdf2(key, salt, 2048, 64), pbkdf2Sync(key, salt, 2048, 64, 'sha512'));
    assert.deepEqual(key, Buffer.alloc(length, 0x61));
    assert.deepEqual(salt, Buffer.alloc(length, 0xa5));
    assert.equal(nativeCalls, 1);
  }
});
assert.deepEqual(pbkdf2(phraseBytes, saltBytes, 2048, 65), pbkdf2Sync(phraseBytes, saltBytes, 2048, 65, 'sha512'));
assert.deepEqual(phraseBytes, Buffer.from(phrase));
assert.deepEqual(saltBytes, Buffer.from('mnemonicTREZOR'));

const blockHeader = Buffer.from(dogeFixture.blockheaderhex, 'hex');
const rawHash = crypto.scryptSync(blockHeader, blockHeader, 32, { N: 1024, r: 1, p: 1 });
const expectedHash = Buffer.from(rawHash).reverse();
assert.deepEqual(native.scryptProofOfWork(blockHeader), rawHash);
assert.throws(() => native.scryptProofOfWork(blockHeader.subarray(1)));
assert.throws(() => native.scryptProofOfWork(new Uint8Array(shared)));

for (const chain of [dogecoin, litecoin]) {
  const offset = new Uint8Array(82).fill(0xab);
  offset.set(blockHeader, 1);
  const original = offset.slice();
  const publicHash = chain.crypto.Hash.scrypt(offset.subarray(1, 81));
  assert.ok(Buffer.isBuffer(publicHash));
  assert.deepEqual(publicHash, expectedHash);
  assert.deepEqual(offset, original);
  assert.equal(chain.crypto.Hash.scrypt(new Uint8Array([1])).toString('hex'),
    '10d75b80825e35e2c28a18c8e8ac422dc95b9dbba0749dcefe88aae03ab1718a');
}

function throws(code, message) {
  const error = Object.assign(new Error(message), { code });
  return () => { throw error; };
}

const longKey = Buffer.alloc(4097, 0x61);
const longSalt = Buffer.alloc(4097, 0xa5);
const expectedLongSeed = pbkdf2Sync(longKey, longSalt, 2048, 64, 'sha512');
const { createHash } = crypto;
for (const code of ['ERR_OSSL_EVP_UNSUPPORTED', 'ERR_CRYPTO_INVALID_DIGEST']) {
  let prehashes = 0;
  withOverrides([
    [native, 'bip39Seed', undefined], [crypto, 'pbkdf2Sync', throws(code)],
    [crypto, 'createHash', (...args) => {
      if (args[0] === 'sha512') prehashes++;
      return createHash(...args);
    }]
  ], () => {
    assert.deepEqual(words.toSeed('TREZOR'), expectedSeed);
    assert.deepEqual(pbkdf2(longKey, longSalt, 2048, 64), expectedLongSeed);
    assert.equal(prehashes, 1);
    assert.deepEqual(longKey, Buffer.alloc(4097, 0x61));
    assert.deepEqual(longSalt, Buffer.alloc(4097, 0xa5));
  });
}

for (const [code, message] of [
  ['ERR_CRYPTO_INVALID_KEYLEN', 'invalid key length'], [undefined, 'Deriving bits failed']
]) {
  withOverrides([[native, 'bip39Seed', undefined], [crypto, 'pbkdf2Sync', throws(code, message)]], () => {
    assert.throws(() => words.toSeed('TREZOR'), { code, message });
  });
}

for (const [chain, addon] of [[dogecoin, dogeAddon], [litecoin, ltcAddon]]) {
  const hash = chain.crypto.Hash.scrypt;
  for (const [code, message] of [
    ['ERR_CRYPTO_SCRYPT_NOT_SUPPORTED'],
    ['ERR_OSSL_EVP_UNSUPPORTED'],
    ['ERR_CRYPTO_INVALID_SCRYPT_PARAMS', 'Invalid scrypt params: error:0308010C:digital envelope routines::unsupported']
  ]) {
    withOverrides([[addon, 'scryptProofOfWork', undefined], [crypto, 'scryptSync', throws(code, message)]], () => {
      assert.deepEqual(hash(blockHeader), expectedHash);
    });
  }
  const code = 'ERR_CRYPTO_INVALID_SCRYPT_PARAMS';
  withOverrides([[addon, 'scryptProofOfWork', undefined], [crypto, 'scryptSync', throws(code, 'memory limit exceeded')]], () => {
    assert.throws(() => hash(blockHeader), { code, message: 'memory limit exceeded' });
  });
}

const failFips = () => assert.fail('Optimized KDF called with FIPS enabled');
withOverrides([
  [crypto, 'getFips', () => 1], [crypto, 'scryptSync', failFips],
  [native, 'bip39Seed', failFips], [dogeAddon, 'scryptProofOfWork', failFips], [ltcAddon, 'scryptProofOfWork', failFips],
  [crypto, 'pbkdf2Sync', (...args) => {
    assert.equal(args[2], 1); // scryptsy uses one-iteration PBKDF2 internally.
    return pbkdf2Sync(...args);
  }]
], () => {
  assert.deepEqual(words.toSeed('TREZOR'), expectedSeed);
  for (const chain of [dogecoin, litecoin]) {
    assert.deepEqual(chain.crypto.Hash.scrypt(blockHeader), expectedHash);
  }
});

console.log('Native KDF binding and compatibility checks passed.');
