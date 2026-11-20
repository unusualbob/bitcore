/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone CommonJS script. */
'use strict';

const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const { createHash } = require('node:crypto');
const Module = require('node:module');

const selectors = { cash: 'BITCORE_BCH_BACKEND', ltc: 'BITCORE_LTC_BACKEND', doge: 'BITCORE_DOGE_BACKEND' };

function exerciseStandaloneFallback() {
  const paths = new Map(Object.keys(selectors).map(coin => [
    require.resolve('../packages/bitcore-lib-' + coin + '/lib/crypto/ecdsa-native'), coin
  ]));
  const original = Module._load;
  let missing = 'MODULE_NOT_FOUND';
  let attempts = 0;
  Module._load = function(request, parent, ...args) {
    if (request === '../native/bitcore_ecdsa.node' && paths.has(parent?.filename)) {
      attempts++;
      throw Object.assign(new Error('Test fixture for unavailable fork addon'), { code: missing });
    }
    return original.call(this, request, parent, ...args);
  };
  try {
    assert(require('../packages/bitcore-lib/lib/crypto/ecdsa-native').native);
    for (const [loader, coin] of paths) {
      const selector = selectors[coin];
      const reload = () => {
        delete require.cache[loader];
        return require(loader).native;
      };
      missing = 'MODULE_NOT_FOUND';
      const fork = require('../packages/bitcore-lib-' + coin);
      const publicKey = new fork.PrivateKey(fork.crypto.BN.One).toPublicKey();
      assert.equal(publicKey.toString(), '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
      assert.equal(require(loader).native, undefined);
      missing = 'ERR_DLOPEN_FAILED';
      assert.equal(reload(), undefined);
      process.env[selector] = 'native';
      assert.throws(reload, { code: 'ERR_DLOPEN_FAILED' });
      missing = 'MODULE_NOT_FOUND';
      assert.throws(reload, { code: 'MODULE_NOT_FOUND' });
      process.env[selector] = 'js';
      const previousAttempts = attempts;
      assert.equal(reload(), undefined);
      assert.equal(attempts, previousAttempts);
      delete process.env[selector];
    }
  } finally {
    Module._load = original;
  }
}

function instrument(coin) {
  if (process.env.BITCORE_ECDSA_BACKEND !== 'native') return () => {};
  const addon = require('../packages/bitcore-lib-' + coin + '/lib/native/bitcore_ecdsa.node');
  const methods = [
    'publicKeyCreate', 'publicKeyParse', 'sign', 'verify', 'recover',
    'derivePrivatePath', 'derivePublicPath'
  ];
  if (coin === 'cash') methods.push('signBchSchnorr', 'verifyBchSchnorr');
  const counts = new Map();
  for (const method of methods) {
    const original = addon[method];
    assert.equal(typeof original, 'function', 'Rebuild the addon to test ' + method);
    counts.set(method, 0);
    addon[method] = (...args) => {
      counts.set(method, counts.get(method) + 1);
      return original(...args);
    };
  }
  return () => {
    for (const [method, count] of counts) {
      assert(count > 0, coin + ' did not call ' + method);
    }
  };
}

function exercise(coin, library) {
  const { HDPrivateKey, HDPublicKey, PrivateKey, PublicKey, crypto: { BN, ECDSA, Hash, Point, Schnorr, Signature } } = library;
  const results = [];
  for (let i = 0; i < 16; i++) {
    const seed = Hash.sha256(Buffer.from(coin + ' fork differential seed ' + i));
    const digest = i === 0 ? Buffer.alloc(32, 255) : Hash.sha256(seed);
    const endian = i % 2 ? 'big' : 'little';
    const network = i % 2 ? 'testnet' : 'livenet';
    const privateKey = new PrivateKey(i % 3 ? BN.fromBuffer(seed) : seed, network);
    const publicKey = privateKey.toPublicKey();
    const sec = publicKey.toBuffer();
    assert(publicKey instanceof PublicKey);
    assert.equal(PublicKey.fromPrivateKey(privateKey).network, privateKey.network);
    assert.equal(new PublicKey(sec, { network }).toString(), publicKey.toString());
    assert.equal(PublicKey.fromDER(sec).compressed, publicKey.compressed);
    assert.equal(PublicKey.fromString(sec.toString('hex')).toString(), publicKey.toString());
    assert.equal(new PublicKey(privateKey).toString(), publicKey.toString());
    results.push(publicKey.toString(), publicKey.toAddress().toString());

    const signature = ECDSA.sign(digest, privateKey, { endian });
    assert(ECDSA.verify(digest, signature, sec, { endian }));
    const highS = new Signature({ r: signature.r, s: Point.getN().sub(signature.s) });
    assert(ECDSA.verify(digest, highS, publicKey, { endian }));
    const normalized = endian === 'little' ? Buffer.from(digest).reverse() : digest;
    ECDSA.calci(normalized, signature, publicKey);
    assert.equal(ECDSA.recoverPublicKey(normalized, signature).toString(), publicKey.toString());
    assert(!ECDSA.verify(Hash.sha256(digest), signature, publicKey));
    results.push(signature.toString(), signature.i, signature.compressed);

    const root = HDPrivateKey.fromSeed(seed, network);
    const watch = new HDPublicKey(root.xpubkey);
    assert.equal(root.deriveChild('m'), root);
    assert.equal(watch.deriveChild('M'), watch);
    const path = 'm/0/' + i + '/2147483647';
    const mixed = "m/44'/0'/2'/0/" + i;
    const child = root.deriveChild(path);
    assert.equal(watch.deriveChild(path).xpubkey, child.xpubkey);
    assert.equal(root.deriveChild(mixed).xprivkey,
      root.deriveChild(44, true).deriveChild(0, true).deriveChild(2, true).deriveChild(0).deriveChild(i).xprivkey);
    if (coin === 'doge') {
      assert.equal(root.deriveChild(path), child);
      assert.equal(root.deriveChild(0), root.deriveChild(0));
      assert.equal(watch.deriveChild(path), watch.deriveChild(path));
    }
    results.push(root.deriveChild(mixed).toObject(), child.toObject(), watch.deriveChild(path).toObject());

    if (Schnorr) {
      const signature = Schnorr.sign(digest, privateKey, endian);
      assert(Schnorr.verify(digest, signature, publicKey, endian));
      assert(!Schnorr.verify(Hash.sha256(digest), signature, publicKey, endian));
      if (i === 0) {
        const badR = new Signature({ r: new BN('f'.repeat(64), 'hex'), s: signature.s });
        const badS = new Signature({ r: signature.r, s: Point.getN() });
        assert(!Schnorr.verify(digest, badR, publicKey, endian));
        assert(!Schnorr.verify(digest, badS, publicKey, endian));
      }
      results.push(signature.toBuffer('schnorr').toString('hex'));
    }
  }

  const small = new HDPrivateKey({ network: 'livenet', depth: 254, parentFingerPrint: 0,
    childIndex: 0, chainCode: Buffer.alloc(32, 7), privateKey: BN.One.toBuffer({ size: 32 }) });
  const path = "m/1'/2/3'";
  assert.equal(small.deriveChild(path).depth, 1);
  if (small.deriveNonCompliantChild) {
    const legacy = small.deriveNonCompliantChild(path);
    assert.notEqual(legacy.xprivkey, small.deriveChild(path).xprivkey);
    results.push(legacy.toObject());
  }
  small.fingerPrint.fill(0x56);
  assert.equal(small.deriveChild(14).toObject().parentFingerPrint, 0x56565656);
  results.push(small.deriveChild(5, 1).toObject(), small.hdPublicKey.deriveChild(3.5).toObject());
  const hybrid = new PrivateKey(Buffer.alloc(32, 2)).toPublicKey().toBuffer();
  hybrid[0] = 6;
  assert.equal(PublicKey.fromDER(hybrid, false).compressed, false);
  for (const parseOrDerive of [
    () => PublicKey.fromDER(hybrid),
    () => PublicKey.fromDER(Buffer.from([4, 0, 1])),
    () => small.deriveChild(0x100000000),
    () => small.hdPublicKey.deriveChild("m/1'"),
    () => small.deriveChild('m//1')
  ]) {
    assert.throws(parseOrDerive, error => {
      results.push([error.name, error.message]);
      return true;
    });
  }
  return results;
}

function runCorpus(reverse) {
  const coins = ['cash', 'ltc', 'doge'];
  const checkCalls = coins.map(instrument);
  // Load Bitcoin and all three forks together so the shared elliptic prototypes
  // are exercised in the same process as a wallet that supports multiple coins.
  const libraries = new Map();
  const order = reverse ? ['doge', 'ltc', 'cash', 'btc'] : ['btc', ...coins];
  for (const coin of order) {
    const name = coin === 'btc' ? 'bitcore-lib' : 'bitcore-lib-' + coin;
    const library = require('../packages/' + name);
    const { BN } = library.crypto;
    for (const digits of ['0', '1', 'f', 'abc', '12345', 'f'.repeat(63), 'f'.repeat(64)]) {
      const value = new BN(digits, 'hex');
      assert(value.toBuffer().equals(value.toArrayLike(Buffer, 'be')));
      assert(value.toBuffer({ size: 32 }).equals(value.toArrayLike(Buffer, 'be', 32)));
    }
    libraries.set(coin, library);
  }
  const results = coins.map(coin => exercise(coin, libraries.get(coin)));
  for (const assertCalled of checkCalls) assertCalled();
  return createHash('sha256').update(JSON.stringify(results)).digest('hex');
}

if (process.argv[2] === '--corpus') {
  process.stdout.write(runCorpus(process.argv[3] === '--reverse'));
} else if (process.argv[2] === '--standalone') {
  exerciseStandaloneFallback();
} else {
  const env = { ...process.env };
  for (const selector of Object.values(selectors)) delete env[selector];
  const run = (backend, extra = ['--corpus']) => execFileSync(process.execPath, [__filename, ...extra], {
    env: { ...env, BITCORE_ECDSA_BACKEND: backend }, encoding: 'utf8'
  });
  const expected = run('js');
  assert.equal(run('native'), expected);
  assert.equal(run('js', ['--corpus', '--reverse']), expected);
  assert.equal(run('native', ['--corpus', '--reverse']), expected);
  run('native', ['--standalone']);
  console.log('Bitcoin Cash, Litecoin and Dogecoin public APIs matched across both backends.');
}
