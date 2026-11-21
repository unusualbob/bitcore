/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone CommonJS parity test. */
'use strict';

const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { test } = require('node:test');
const solKit = require('@solana/kit');
const bs58 = require('bs58');

const fixtures = Array.from({ length: 184 }, (_, length) => {
  if (length === 0) return Buffer.alloc(0);
  const data = createHash('shake256', { outputLength: length }).update(String(length)).digest();
  return data.fill(0, 0, length % 13);
});
const sha256 = data => createHash('sha256').update(data).digest();
const check = data => sha256(sha256(data)).subarray(0, 4);

for (const name of ['bitcore-lib', 'bitcore-lib-cash', 'bitcore-lib-ltc', 'bitcore-lib-doge']) {
  const { native } = require('../packages/' + name + '/lib/crypto/ecdsa-native');
  const calls = Object.create(null);
  if (native) {
    for (const key of ['base58Encode', 'base58Decode', 'base58CheckEncode', 'base58DecodeChecked']) {
      const fn = native[key];
      assert.equal(typeof fn, 'function', 'Rebuild the addon before testing native Base58');
      native[key] = value => {
        calls[key] = (calls[key] || 0) + 1;
        return fn(value);
      };
    }
  }
  const { Address, HDPrivateKey, HDPublicKey, PrivateKey, crypto: { Hash },
    encoding: { Base58, Base58Check } } = require('../packages/' + name);

  test(name + ' routes wallet formats through the selected codecs', () => {
    const address = new Address(Buffer.alloc(20, 0xff), 'livenet');
    const addr = name.endsWith('-cash') ? address.toLegacyAddress() : address.toString();
    assert.deepEqual(Address.fromString(addr).hashBuffer, address.hashBuffer);
    const key = new PrivateKey(Buffer.alloc(32, 1));
    assert.equal(PrivateKey.fromWIF(key.toWIF()).toString(), key.toString());
    const root = HDPrivateKey.fromSeed(Buffer.alloc(32, 7));
    assert.equal(new HDPrivateKey(root.xprivkey).xprivkey, root.xprivkey);
    assert.equal(new HDPublicKey(root.xpubkey).xpubkey, root.xpubkey);
    if (!native) return;
    assert(calls.base58CheckEncode >= 4);
    assert(calls.base58DecodeChecked >= 4);

    const short = Buffer.alloc(25, 0xff);
    const long = Buffer.alloc(64, 0xff);
    const before = calls.base58Decode || 0;
    assert.deepEqual(Base58.decode(Base58.encode(short)), short);
    assert.equal(calls.base58Decode || 0, before);
    assert.deepEqual(Base58.decode(Base58.encode(long)), long);
    assert.equal(calls.base58Decode, before + 1);
    assert(calls.base58Encode >= 2);
  });

  test(name + ' preserves parity, malformed-input errors and oversized fallbacks', () => {
    for (const data of [...fixtures, Buffer.alloc(128, 0xff), Buffer.alloc(177)]) {
      const raw = bs58.encode(data);
      assert.equal(Base58.encode(data), raw);
      assert.deepEqual(Base58.decode(raw), data);
      const checked = bs58.encode(Buffer.concat([data, check(data)]));
      assert.equal(Base58Check.encode(data), checked);
      const decoded = Base58Check.decode(checked);
      assert.deepEqual(decoded, data);
      const trailing = Buffer.from(decoded.buffer, decoded.byteOffset + decoded.length, 4);
      assert.deepEqual(trailing, check(data));
      if (!native) continue;
      if (data.length > 0 && data.length <= 128) assert.equal(native.base58Encode(data), raw);
      if (raw.length <= 177) assert.deepEqual(native.base58Decode(raw), data);
      if (data.length > 0 && data.length <= 124) assert.equal(native.base58CheckEncode(data), checked);
      if (checked.length <= 177) {
        assert.deepEqual(native.base58DecodeChecked(checked), Buffer.concat([data, check(data)]));
      }
    }
    const sliced = Buffer.alloc(96, 0xff).subarray(7, 71);
    assert.equal(Base58.encode(sliced), bs58.encode(sliced));
    const shared = Buffer.from(new SharedArrayBuffer(64)).fill(0xff);
    assert.equal(Base58.encode(shared), bs58.encode(shared));
    assert.equal(Base58Check.encode(shared), bs58.encode(Buffer.concat([shared, check(shared)])));
    for (const suffix of ['0', '\0', 'ñ', '💰', '\ud800']) {
      for (const length of [45, 80, 174, 175, 176, 177, 178]) {
        const invalid = 'z'.repeat(length) + suffix;
        assert.throws(() => Base58.decode(invalid), { message: 'Non-base58 character' });
        assert.throws(() => Base58Check.decode(invalid), { message: 'Non-base58 character' });
        if (native) assert.equal(native.base58Decode(invalid), null);
      }
    }
    assert.throws(() => Base58Check.decode('z'.repeat(64)), { message: 'Checksum mismatch' });
    assert.throws(() => Base58Check.decode('111'), { message: 'Input string too short' });
    if (native) {
      assert.equal(native.base58Decode('1'.repeat(178)), null);
      assert.equal(native.base58Encode(Buffer.alloc(129)), null);
      assert.equal(native.base58CheckEncode(Buffer.alloc(125)), null);
    }
  });

  test(name + ' honors replacements of public checksum and codec functions', () => {
    const data = Buffer.alloc(32, 19);
    const { encode, decode } = Base58;
    const { checksum } = Base58Check;
    const { sha256 } = Hash;
    try {
      Base58.encode = () => 'replacement';
      assert.equal(Base58Check.encode(data), 'replacement');
      Base58.encode = encode;
      Base58.decode = () => Buffer.concat([data, check(data)]);
      assert.deepEqual(Base58Check.decode('z'.repeat(64)), data);
      Base58.decode = decode;
      Base58Check.checksum = () => Buffer.alloc(4);
      assert.equal(Base58Check.encode(data), bs58.encode(Buffer.concat([data, Buffer.alloc(4)])));
      Base58Check.checksum = checksum;
      Hash.sha256 = () => Buffer.alloc(32, 1);
      const custom = bs58.encode(Buffer.concat([data, Buffer.alloc(4, 1)]));
      assert.equal(Base58Check.encode(data), custom);
      assert.deepEqual(Base58Check.decode(custom), data);
    } finally {
      Object.assign(Base58, { encode, decode });
      Base58Check.checksum = checksum;
      Hash.sha256 = sha256;
    }
  });
}

test('SOL codec matches Solana Kit for valid inputs and preserves its errors', () => {
  const { encodeBase58, decodeBase58 } = require('../packages/crypto-wallet-core/ts_build/src/base58');
  for (const bytes of [...fixtures, new Uint8Array(32), new Uint8Array(64).fill(0xff)]) {
    const encoded = solKit.getBase58Decoder().decode(bytes);
    assert.equal(encodeBase58(Uint8Array.from(bytes)), encoded);
    assert.deepEqual(decodeBase58(encoded), Uint8Array.from(bytes));
  }
  const shared = new Uint8Array(new SharedArrayBuffer(72)).fill(0xee).subarray(4, 68);
  assert.equal(encodeBase58(shared), solKit.getBase58Decoder().decode(shared));
  const detached = new Uint8Array(64);
  structuredClone(null, { transfer: [detached.buffer] });
  assert.equal(encodeBase58(detached), solKit.getBase58Decoder().decode(detached));
  for (const suffix of ['0', '💰']) {
    const input = 'z'.repeat(42) + suffix;
    let expected;
    assert.throws(() => solKit.getBase58Encoder().encode(input), error => {
      expected = error;
      return true;
    });
    assert.throws(() => decodeBase58(input), { name: expected.name, message: expected.message });
  }
});
