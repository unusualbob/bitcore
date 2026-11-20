'use strict';

const benchmark = require('./backends');

const coins = { cash: 145, ltc: 2, doge: 3 };

function load() {
  return {
    cash: require('../../bitcore-lib-cash'),
    ltc: require('../../bitcore-lib-ltc'),
    doge: require('../../bitcore-lib-doge')
  };
}

function requireNativeDispatch(coin, expected, operations, fixture) {
  if (process.env.BITCORE_ECDSA_BACKEND !== 'native') return;
  const addon = require('../../bitcore-lib-' + coin + '/lib/native/bitcore_ecdsa.node');
  for (const [operation, method] of Object.entries(expected)) {
    const original = addon[method];
    if (typeof original !== 'function') throw new Error('Rebuild the addon to benchmark ' + coin + '.' + method);
    let called = false;
    addon[method] = (...args) => {
      called = true;
      return original(...args);
    };
    try {
      operations[coin + '.' + operation](fixture);
      if (!called) throw new Error(coin + '.' + operation + ' did not use the native addon');
    } finally {
      addon[method] = original;
    }
  }
}

benchmark(__filename, libraries => {
  const fixtures = Array.from({ length: 16 }, () => ({}));
  const operations = {};

  for (const [coin, coinType] of Object.entries(coins)) {
    const { HDPrivateKey, PrivateKey, PublicKey, crypto: { BN, ECDSA, Hash, Schnorr } } = libraries[coin];
    for (const [index, row] of fixtures.entries()) {
      const seed = Hash.sha256(Buffer.from(coin + ' fork benchmark ' + index));
      const digest = Hash.sha256(seed);
      const scalar = BN.fromBuffer(seed);
      const secret = new PrivateKey(scalar);
      const publicKey = secret.toPublicKey();
      const root = HDPrivateKey.fromSeed(seed);
      row[coin] = {
        scalar, secret, publicKey, root, watch: root.hdPublicKey, digest,
        der: publicKey.toBuffer(),
        signature: ECDSA.sign(digest, secret),
        schnorrSignature: Schnorr?.sign(digest, secret),
        privateIndex: 0,
        publicIndex: 0
      };
    }

    const add = (name, operation) => { operations[coin + '.' + name] = row => operation(row[coin]); };
    const expected = {
      ecdsaSign: 'sign', ecdsaVerify: 'verify', publicKeyCreate: 'publicKeyCreate',
      publicKeyParse: 'publicKeyParse', privatePath: 'derivePrivatePath', watchPath: 'derivePublicPath'
    };
    add('ecdsaSign', f => ECDSA.sign(f.digest, f.secret));
    add('ecdsaVerify', f => ECDSA.verify(f.digest, f.signature, f.publicKey));
    add('publicKeyCreate', f => new PrivateKey(f.scalar).toPublicKey());
    add('publicKeyParse', f => PublicKey.fromDER(f.der));
    // Vary the account and branch indexes so Dogecoin's cache does not return a finished path.
    add('privatePath', f => f.root.deriveChild("m/44'/" + coinType + "'/" + f.privateIndex++ + "'/0/0"));
    add('watchPath', f => f.watch.deriveChild('m/' + f.publicIndex++ + '/0'));
    if (Schnorr) {
      add('schnorrSign', f => Schnorr.sign(f.digest, f.secret));
      add('schnorrVerify', f => Schnorr.verify(f.digest, f.schnorrSignature, f.publicKey));
      expected.schnorrSign = 'signBchSchnorr';
      expected.schnorrVerify = 'verifyBchSchnorr';
    }
    requireNativeDispatch(coin, expected, operations, fixtures[0]);
  }

  return { fixtures, operations };
}, { load, warmupMs: 100, sampleMs: 300 });
