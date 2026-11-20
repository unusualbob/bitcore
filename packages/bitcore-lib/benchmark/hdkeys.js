'use strict';

const benchmark = require('./backends');

benchmark(__filename, bitcore => {
  const { HDPrivateKey, PrivateKey, crypto: { Hash, BN } } = bitcore;
  const fixtures = Array.from({ length: 16 }, (_, index) => {
    const seed = Hash.sha256(Buffer.from('bitcore derivation benchmark ' + index));
    const root = HDPrivateKey.fromSeed(seed);
    const watch = root.hdPublicKey;
    const path = "m/84'/0'/0'/0/" + index;
    const publicPath = 'm/0/' + index;
    if (root.deriveChild(publicPath).xpubkey !== watch.deriveChild(publicPath).xpubkey) {
      throw new Error('Public and private derivation disagree');
    }
    return { scalar: BN.fromBuffer(seed), root, watch, index, path, publicPath };
  });
  const operations = {
    freshPublicKey: f => new PrivateKey(f.scalar).toPublicKey(),
    privateChild: f => f.root.deriveChild(f.index),
    hardenedChild: f => f.root.deriveChild(f.index, true),
    publicChild: f => f.watch.deriveChild(f.index),
    receivePath: f => f.root.deriveChild(f.path),
    watchOnlyPath: f => f.watch.deriveChild(f.publicPath),
    receiveAddress: f => f.root.deriveChild(f.path).publicKey.toAddress().toString()
  };
  if (process.env.BITCORE_ECDSA_BACKEND === 'native') {
    const addon = require('../lib/native/bitcore_ecdsa.node');
    const expected = {
      freshPublicKey: 'publicKeyCreate', privateChild: 'derivePrivatePath', hardenedChild: 'derivePrivatePath',
      publicChild: 'derivePublicPath', receivePath: 'derivePrivatePath', watchOnlyPath: 'derivePublicPath',
      receiveAddress: 'derivePrivatePath'
    };
    for (const [name, method] of Object.entries(expected)) {
      const original = addon[method];
      let called = false;
      addon[method] = (...args) => {
        called = true;
        return original(...args);
      };
      try {
        operations[name](fixtures[0]);
        if (!called) throw new Error(name + ' did not use the native addon');
      } finally {
        addon[method] = original;
      }
    }
  }
  return { fixtures, operations };
});
