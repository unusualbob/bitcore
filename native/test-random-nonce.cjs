/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone CommonJS script. */
'use strict';

const assert = require('node:assert/strict');

const packages = ['bitcore-lib', 'bitcore-lib-cash', 'bitcore-lib-ltc', 'bitcore-lib-doge'];
const one = Buffer.from('01'.padStart(64, '0'), 'hex');
const zero = Buffer.alloc(32);
const order = Buffer.from('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141', 'hex');
const maxDigest = Buffer.alloc(32, 255);
// For d = k = 1, e = n - x(G) makes s zero and requires a fresh draw.
const zeroSDigest = Buffer.from('8641998106234453aa5f9d6a3178f4f7b812e00b817a776265dfdd31b93e29a9', 'hex');
const afterZeroS = '3045022100c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5' +
  '022059dcf3755bf79f1f92ad91139c634716b069a5bb2813c636b70c6b17455edcfa';
const maxDigestDer = '3044022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798' +
  '022079be667ef9dcbbac55a06295ce870b0847ed1ff47e85889d9a2022ce46c1d656';
const messageText = 'Random nonce parity λ';
const messageDigest = '76cf380fb59e2f2769006ed5a8372ef5ccab301b3c201da6f85cd2919f2b5fb8';
// The unnormalized s for this fixture is high. The compact header encodes
// the recovery factor for the normalized signature and the key compression.
const compressedSignature = 'IHm+Zn753LusVaBilc6HCwcCm/zbLc4o2VnygVsW+BeYD3JhcVCFFSxBXy6UiUHGAetnr/BFWlm7bYMKoBoSyfE=';
const uncompressedSignature = 'HHm+Zn753LusVaBilc6HCwcCm/zbLc4o2VnygVsW+BeYD3JhcVCFFSxBXy6UiUHGAetnr/BFWlm7bYMKoBoSyfE=';
const expectNative = process.env.BITCORE_ECDSA_BACKEND !== 'js';

function stubRandom(random, samples, sign) {
  const initial = samples.map(bytes => Buffer.from(bytes));
  const existing = random.getRandomBuffer;
  let calls = 0;
  random.getRandomBuffer = function(size) {
    assert.equal(this, random);
    assert.equal(size, 32);
    assert.ok(calls < samples.length, 'unexpected nonce draw');
    return samples[calls++];
  };
  try {
    const signature = sign();
    assert.equal(calls, samples.length);
    assert.deepEqual(samples.map(bytes => Buffer.from(bytes)), initial, 'RNG-owned buffers changed');
    return signature;
  } finally {
    random.getRandomBuffer = existing;
  }
}

for (const name of packages) {
  const bitcore = require(`../packages/${name}`);
  const { ECDSA, Random } = bitcore.crypto;
  const { native } = require(`../packages/${name}/lib/crypto/ecdsa-native`);
  const key = new bitcore.PrivateKey(one.toString('hex'));
  const dispatches = [];
  if (expectNative) {
    const signWithNonce = native.signWithNonce;
    assert.equal(typeof signWithNonce, 'function', name);
    assert.equal(signWithNonce(zeroSDigest, one, one), null);
    assert.equal(signWithNonce(zeroSDigest, one, zero), null);
    assert.equal(signWithNonce(zeroSDigest, one, order), null);
    assert.equal(signWithNonce(zeroSDigest, zero, one), null);
    assert.throws(() => signWithNonce(zeroSDigest, one, Buffer.from([1])), /nonce length/);
    native.signWithNonce = (digest, secret, nonce) => {
      dispatches.push(nonce.toString('hex'));
      return signWithNonce(digest, secret, nonce);
    };
  }

  const shortTwo = new Uint8Array([2]);
  const fromRetries = stubRandom(Random, [zero, order, maxDigest, one, shortTwo], () =>
    ECDSA.sign(zeroSDigest, key, { randomK: true }));
  assert.equal(fromRetries.toDER().toString('hex'), afterZeroS, name);
  assert.deepEqual(dispatches.splice(0), expectNative ? [one.toString('hex'), '02'.padStart(64, '0')] : [], name);
  assert.equal(ECDSA.verify(zeroSDigest, fromRetries, key.toPublicKey()), true, name);

  const extendedOne = Buffer.concat([Buffer.from([0]), one]);
  const fromMax = stubRandom(Random, [extendedOne], () => ECDSA.sign(maxDigest, key, { randomK: true }));
  assert.equal(fromMax.toDER().toString('hex'), maxDigestDer, name);
  const littleEndianDigest = Buffer.from(zeroSDigest).reverse();
  const fromLittle = stubRandom(Random, [one, shortTwo], () =>
    ECDSA.sign(littleEndianDigest, key, { endian: 'little', randomK: true }));
  assert.equal(fromLittle.toDER().toString('hex'), afterZeroS, name);
  assert.deepEqual(littleEndianDigest, Buffer.from(zeroSDigest).reverse());
  assert.deepEqual(dispatches.splice(0), expectNative ? [
    one.toString('hex'), one.toString('hex'), '02'.padStart(64, '0')
  ] : [], name);

  const existingRandom = Random.getRandomBuffer;
  const randomError = new Error('stub RNG failed');
  Random.getRandomBuffer = () => { throw randomError; };
  try {
    assert.throws(() => ECDSA.sign(maxDigest, key, { randomK: true }), error => error === randomError);
  } finally {
    Random.getRandomBuffer = existingRandom;
  }
  assert.deepEqual(dispatches, [], name);

  // BTC is the public signed-message implementation for all four CWC chains.
  if (bitcore.Message) {
    const message = new bitcore.Message(messageText);
    assert.equal(message.magicHash().toString('hex'), messageDigest);
    const uncompressed = new bitcore.PrivateKey(one);
    for (const [privateKey, expected] of [[key, compressedSignature], [uncompressed, uncompressedSignature]]) {
      const signature = stubRandom(Random, [zero, order, extendedOne], () => message.sign(privateKey));
      assert.equal(signature, expected);
      assert.equal(message.verify(privateKey.toAddress(), signature), true);
      assert.equal(message.recoverPublicKey(privateKey.toAddress(), signature), privateKey.toPublicKey().toString());
    }

    const cwc = require('../packages/crypto-wallet-core').Message;
    const hdPrivateKey = bitcore.HDPrivateKey.fromSeed(Buffer.alloc(32, 3));
    const derivationPath = "m/44'/0'/0'/0/7";
    const child = hdPrivateKey.deriveChild(derivationPath).privateKey;
    for (const chain of ['btc', 'bch', 'ltc', 'doge']) {
      assert.equal(cwc.getMessageHash({ chain, message: messageText, encoding: 'hex' }), messageDigest);
      assert.deepEqual(stubRandom(Random, [one], () => cwc.signMessage({
        chain, message: messageText, privateKey: key.toWIF(), encoding: 'base64'
      })), { signature: compressedSignature, publicKey: key.toPublicKey().toString() });
      const path = stubRandom(Random, [one], () => cwc.signMessageWithPath({
        chain, message: messageText, hdPrivateKey: hdPrivateKey.toString(), derivationPath, encoding: 'base64'
      }));
      assert.equal(path.publicKey, child.toPublicKey().toString());
      assert.equal(message.verify(child.toAddress(), path.signature), true);
    }
    assert.deepEqual(dispatches.splice(0), expectNative ? Array(10).fill(one.toString('hex')) : []);
  }
  console.log(`${name} random nonce parity passed`);
}
