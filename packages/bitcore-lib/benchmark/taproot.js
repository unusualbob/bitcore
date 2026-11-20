'use strict';

const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const benchmark = require('./backends');

const hash = (label, index) => createHash('sha256').update(`${label}-${index}`).digest();

benchmark(__filename, bitcore => {
  const { PrivateKey, Script, Transaction, crypto: { Schnorr } } = bitcore;
  const fixtures = Array.from({ length: 16 }, (_, index) => {
    const secret = hash('key', index);
    const privateKey = new PrivateKey(secret);
    const publicKey = privateKey.publicKey;
    const message = hash('message', index);
    const aux = hash('aux', index);
    const signature = Schnorr.sign(secret, message, aux);
    const output = {
      txId: hash('output', index).toString('hex'), outputIndex: 0,
      script: Script.buildWitnessV1Out(publicKey), satoshis: 100000
    };
    return { secret, privateKey, publicKey, message, aux, signature, output,
      merkleRoot: hash('root', index), address: privateKey.toAddress() };
  });
  const operations = {
    schnorrSign: f => Schnorr.sign(f.secret, f.message, f.aux),
    schnorrVerify: f => Schnorr.verify(f.publicKey, f.message, f.signature),
    taprootPublicTweak: f => f.publicKey.createTapTweak(f.merkleRoot),
    taprootPrivateTweak: f => f.privateKey.createTapTweak(f.merkleRoot),
    constructAndSignP2tr: f => new Transaction().from(f.output).to(f.address, 90000).sign(f.privateKey)
  };
  if (process.env.BITCORE_ECDSA_BACKEND === 'native') {
    const { native } = require('../lib/crypto/ecdsa-native');
    const names = ['schnorrSign', 'schnorrVerify', 'taprootPublicTweak', 'taprootPrivateTweak'];
    const originals = Object.fromEntries(names.map(name => [name, native?.[name]]));
    const used = new Set();
    for (const name of names) {
      assert.equal(typeof originals[name], 'function', `Rebuild the addon to benchmark ${name}`);
      native[name] = (...args) => {
        const result = originals[name](...args);
        if (result !== null) used.add(name);
        return result;
      };
    }
    try {
      for (const operation of Object.values(operations)) operation(fixtures[0]);
      for (const name of names) assert(used.has(name), `${name} did not use the native addon`);
    } finally {
      Object.assign(native, originals);
    }
  }
  return { fixtures, operations };
});
