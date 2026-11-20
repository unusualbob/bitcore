'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { resolve } = require('node:path');
const { Readable } = require('node:stream');
const { test } = require('node:test');
const vm = require('node:vm');
const bs58 = require('bs58');
const { bech32, bech32m } = require('bech32');

const packages = ['bitcore-lib', 'bitcore-lib-cash', 'bitcore-lib-ltc', 'bitcore-lib-doge'];
const sha256 = data => crypto.createHash('sha256').update(data).digest();
const sha256d = data => sha256(sha256(data));
const source = Buffer.concat(Array.from({ length: 10 }, (_, i) => sha256(Buffer.from([i]))));

for (const name of packages) {
  const { crypto: { Hash }, encoding: { Base58, Base58Check } } = require('../packages/' + name);

  test(name + ' Base58 and Base58Check match the original codec', () => {
    for (let length = 0; length <= source.length; length++) {
      const data = Buffer.from(source.subarray(0, length));
      data.fill(0, 0, Math.min(length, length % 11));
      const raw = bs58.encode(data);
      assert.equal(Base58.encode(data), raw);
      assert.deepEqual(Base58.decode(raw), data);
      assert.deepEqual(new Base58(raw).toBuffer(), data);

      const checksum = sha256d(data).subarray(0, 4);
      const checked = bs58.encode(Buffer.concat([data, checksum]));
      assert.equal(Base58Check.encode(data), checked);
      assert.deepEqual(Base58Check.decode(checked), data);
      assert(Base58Check.validChecksum(checked));
      assert(Base58Check.validChecksum(raw, bs58.encode(checksum)));
    }
    assert.deepEqual(Base58.decode('1'.repeat(100)), Buffer.alloc(100));
    const fullBytes = Buffer.alloc(82, 255);
    assert.equal(Base58.encode(fullBytes), bs58.encode(fullBytes));
    assert.deepEqual(Base58.decode(bs58.encode(fullBytes)), fullBytes);
    for (const invalid of ['0', '111O', '12I', '1l', 'z z', 'z💰']) {
      assert.throws(() => Base58.decode(invalid), { message: 'Non-base58 character' });
      assert.throws(() => Base58Check.decode(invalid), { message: 'Non-base58 character' });
    }
    assert.throws(() => Base58.encode(new Uint8Array(4)), { message: 'Input should be a buffer' });
    assert.throws(() => Base58.decode(42), { message: 'Input should be a string' });
    assert.throws(() => Base58Check.encode(new Uint8Array(4)), { message: 'Input must be a buffer' });
    assert.throws(() => Base58Check.decode(42), { message: 'Input must be a string' });
    assert.throws(() => Base58Check.decode('111'), { message: 'Input string too short' });
    assert.throws(() => Base58Check.decode('1111'), { message: 'Checksum mismatch' });
    assert(!Base58Check.validChecksum('1111'));
  });

  test(name + ' SHA256 and HMAC match the streaming digests', t => {
    const nativeHmac = crypto.createHmac;
    const oneShot = typeof crypto.hash === 'function' && t.mock.method(crypto, 'hash');
    const createHmac = t.mock.method(crypto, 'createHmac');
    const typed = Uint8Array.from(source);
    const dataInputs = [Buffer.alloc(0), source.subarray(3, 40), typed.subarray(4, 84), source];
    for (const data of dataInputs) {
      assert.deepEqual(Hash.sha256(data), sha256(data));
      assert.deepEqual(Hash.sha256sha256(data), sha256d(data));
    }
    assert.throws(() => Hash.sha256('abc'), /Invalid Argument/i);
    if (oneShot && !crypto.getFips()) assert.equal(oneShot.mock.callCount(), 3 * dataInputs.length);

    for (const [algorithm, blockBytes] of [['sha256', 64], ['sha512', 128]]) {
      const hmac = Hash[algorithm + 'hmac'];
      for (const keyBytes of [0, 1, 32, blockBytes - 1, blockBytes, blockBytes + 1, 131, 256]) {
        const key = source.subarray(0, keyBytes);
        for (const data of dataInputs) {
          const expected = nativeHmac(algorithm, key).update(data).digest();
          assert.deepEqual(hmac(data, key), expected);
          assert.deepEqual(Hash.hmac(Hash[algorithm], data, key), expected);
        }
      }
      const typedKey = new Uint8Array([1, 2]);
      assert.deepEqual(hmac(source, typedKey), nativeHmac(algorithm, typedKey).update(source).digest());
      assert.throws(() => hmac(source, new Uint8Array()), { name: 'TypeError', message: 'key.copy is not a function' });
      assert.throws(() => hmac('abc', source), /Invalid Argument/i);
      assert.throws(() => hmac(source, 'abc'), /Invalid Argument/i);

      // Generic HMAC still invokes custom hash functions, including for long keys.
      let calls = 0;
      const custom = data => {
        calls++;
        return crypto.createHash(algorithm).update(data).digest();
      };
      custom.blocksize = blockBytes * 8;
      assert.deepEqual(Hash.hmac(custom, source, source), nativeHmac(algorithm, source).update(source).digest());
      assert.equal(calls, 3);
    }
    if (!crypto.getFips()) assert.equal(createHmac.mock.callCount(), 96);
    t.mock.method(crypto, 'getFips', () => 1);
    if (oneShot) oneShot.mock.resetCalls();
    createHmac.mock.resetCalls();
    assert.deepEqual(Hash.sha256(source), sha256(source));
    assert.deepEqual(Hash.sha256hmac(source, source), nativeHmac('sha256', source).update(source).digest());
    if (oneShot) assert.equal(oneShot.mock.callCount(), 0);
    assert.equal(createHmac.mock.callCount(), 0);
  });
}

test('witness addresses retain their checksum, version, padding and case rules', () => {
  const btc = require('../packages/bitcore-lib');
  const ltc = require('../packages/bitcore-lib-ltc');
  const btcCodec = require('../packages/bitcore-lib/lib/encoding/bech32');
  const ltcCodec = require('../packages/bitcore-lib-ltc/lib/encoding/bech32');
  for (const [lib, prefix, codec] of [[btc, 'bc', btcCodec], [ltc, 'ltc', ltcCodec]]) {
    const { Address } = lib;
    for (const [type, data] of [[Address.PayToWitnessPublicKeyHash, source.subarray(0, 20)],
      [Address.PayToWitnessScriptHash, source.subarray(0, 32)]]) {
      const text = bech32.encode(prefix, [0, ...bech32.toWords(data)]);
      assert.equal(new Address(data, 'livenet', type).toString(), text);
      assert.deepEqual(Address.fromString(text.toUpperCase()).hashBuffer, data);
      assert.throws(() => Address.fromString(text[0].toUpperCase() + text.slice(1), 'livenet', type),
        /Mixed-case string/);
    }
    assert.throws(() => codec.decode(bech32.encode(prefix, [0, 0])), { message: 'Excess padding' });
    assert.throws(() => codec.decode(bech32.encode(prefix, [0, 0, 1])), { message: 'Non-zero padding' });
  }
  const program = source.subarray(0, 32);
  const words = bech32.toWords(program);
  const taproot = bech32m.encode('bc', [1, ...words]);
  assert.equal(new btc.Address(program, 'livenet', btc.Address.PayToTaproot).toString(), taproot);
  assert.deepEqual(btc.Address.fromString(taproot.toUpperCase()).hashBuffer, program);
  assert.throws(() => btcCodec.decode(bech32.encode('bc', [1, ...words])),
    { message: 'Version 1+ witness address must use Bech32m checksum' });
  assert.deepEqual(btcCodec.decode(bech32m.encode('bc', [0, ...words])).data, program);
  const wrong = taproot.slice(0, -1) + (taproot.endsWith('q') ? 'p' : 'q');
  assert.throws(() => btcCodec.decode(wrong), { message: 'Invalid checksum for ' + wrong });
});

test('CashAddr preserves prefix, hash sizes, checksum and error handling', () => {
  const { Address } = require('../packages/bitcore-lib-cash');
  const fixtures = require('../packages/bitcore-lib-cash/test/data/cashaddr.json');
  for (const { cashaddr, payload, payloadSize, type } of fixtures) {
    if (type === 15 || !/^(bitcoincash|bchtest):/.test(cashaddr)) continue;
    const decoded = Address._decodeCashAddress(cashaddr.toUpperCase());
    assert.equal(decoded.hashBuffer.length, payloadSize);
    assert.equal(decoded.hashBuffer.toString('hex'), payload.toLowerCase());
    assert.equal(Address.prototype.toCashAddress.call(decoded), cashaddr);
    const stripped = Address.prototype.toCashAddress.call(decoded, true);
    assert.equal(stripped, cashaddr.split(':')[1]);
    assert.deepEqual(Address._decodeCashAddress(stripped), decoded);
  }
  const address = fixtures[0].cashaddr;
  const wrong = address.slice(0, -1) + (address.endsWith('q') ? 'p' : 'q');
  assert.throws(() => Address.fromString(wrong), /Invalid checksum/);
  assert.throws(() => Address.fromString('B' + address.slice(1)), /Mixed case/);
  assert.throws(() => Address.fromString(address.slice(0, -1) + 'i'), /value i/);
});

test('the bundled codecs use the browser crypto fallback and produce the same bytes', async () => {
  const browserify = require('browserify');
  const entry = Readable.from([`
    const crypto = require('crypto');
    const btc = require('./packages/bitcore-lib/lib/encoding/bech32');
    const ltc = require('./packages/bitcore-lib-ltc/lib/encoding/bech32');
    const base32 = require('./packages/bitcore-lib-cash/lib/util/base32');
    const convertBits = require('./packages/bitcore-lib-cash/lib/util/convertBits');
    const keys = Buffer.alloc(32, 0xff);
    const hash = Buffer.alloc(20, 0x42);
    const taproot = btc.encode('bc', 1, keys, btc.encodings.BECH32M);
    const segwit = ltc.encode('ltc', 0, hash);
    module.exports = [
      typeof crypto.hash, typeof crypto.getFips,
      [
        taproot, btc.decode(taproot).data.toString('hex'),
        segwit, ltc.decode(segwit).data.toString('hex'),
        base32.encode(convertBits(Array.from(hash), 8, 5))
      ],
      ${packages.map(name => `{
        Hash: require('./packages/${name}/lib/crypto/hash'),
        Base58: require('./packages/${name}/lib/encoding/base58'),
        Base58Check: require('./packages/${name}/lib/encoding/base58check')
      }`).join(',\n')}
    ].map(lib => {
      if (typeof lib === 'string' || Array.isArray(lib)) return lib;
      const { Hash, Base58, Base58Check } = lib;
      return [
        Hash.sha256(keys).toString('hex'),
        Hash.sha256hmac(hash, keys).toString('hex'), Hash.sha512hmac(hash, keys).toString('hex'),
        Base58.decode(Base58.encode(keys)).toString('hex'),
        Base58Check.decode(Base58Check.encode(keys)).toString('hex')
      ];
    });
  `]);
  const bundler = browserify(entry, { basedir: resolve(__dirname, '..'), standalone: 'BitcoreEncodingTest' });
  const bundle = await new Promise((resolve, reject) => {
    bundler.bundle((error, output) => error ? reject(error) : resolve(output));
  });
  const context = { module: { exports: {} }, exports: {}, setTimeout, clearTimeout };
  vm.runInNewContext(bundle.toString(), context);
  const key = Buffer.alloc(32, 0xff);
  const hash = Buffer.alloc(20, 0x42);
  const expectedCodecs = [
    bech32m.encode('bc', [1, ...bech32m.toWords(key)]), key.toString('hex'),
    bech32.encode('ltc', [0, ...bech32.toWords(hash)]), hash.toString('hex'),
    'gfpyysjzgfpyysjzgfpyysjzgfpyysjz'
  ];
  const expected = ['undefined', 'undefined', expectedCodecs, ...packages.map(() => {
    return [sha256(key).toString('hex'),
      crypto.createHmac('sha256', key).update(hash).digest('hex'),
      crypto.createHmac('sha512', key).update(hash).digest('hex'),
      key.toString('hex'), key.toString('hex')];
  })];
  assert.equal(JSON.stringify(context.module.exports), JSON.stringify(expected));
});
