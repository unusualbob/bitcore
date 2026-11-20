/* eslint @typescript-eslint/no-require-imports: "off" */
'use strict';

const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');

if (process.argv[2] !== '--sample') {
  const run = backend => execFileSync(process.execPath, [__filename, '--sample'], {
    env: { ...process.env, BITCORE_ECDSA_BACKEND: backend }, encoding: 'utf8'
  });
  assert.equal(run('native'), run('js'));
  console.log('Bitcoin Schnorr and Taproot parity passed');
} else {
  const bitcore = require('../packages/bitcore-lib');
  const vectors = require('../packages/bitcore-lib/test/data/bip340');
  const { PrivateKey, PublicKey, Script, Transaction, crypto: { Schnorr, Signature } } = bitcore;
  const { native } = require('../packages/bitcore-lib/lib/crypto/ecdsa-native');
  const calls = {};
  if (native) {
    for (const name of ['schnorrSign', 'schnorrVerify', 'taprootPrivateTweak', 'taprootPublicTweak']) {
      const operation = native[name];
      assert.equal(typeof operation, 'function');
      native[name] = (...args) => {
        const result = operation(...args);
        if (result !== null) calls[name] = (calls[name] || 0) + 1;
        return result;
      };
    }
  }

  const results = [];
  for (const vector of vectors) {
    const key = Buffer.from(vector.public_key, 'hex');
    assert.equal(Schnorr.verify(key, vector.message, vector.signature), vector.verification_result);
    if (vector.secret_key) {
      const signature = Schnorr.sign(Buffer.from(vector.secret_key, 'hex'), vector.message, vector.aux_rand);
      assert.equal(signature.toString('hex').toUpperCase(), vector.signature);
    }
  }

  const vector = vectors[0];
  const message = Buffer.from(vector.message, 'hex');
  const secret = Buffer.from(vector.secret_key, 'hex');
  const key = new PrivateKey(secret);
  const legacyAux = Buffer.alloc(32);
  legacyAux.writeUInt16BE(446, 30); // BIP0340/aux starts with 00 for this randomness.
  const legacySignature = Schnorr.sign(secret, message, legacyAux);
  if (native) assert.deepEqual(native.schnorrSign(secret, message, legacyAux), legacySignature);
  assert(Schnorr.verify(key.publicKey, message, legacySignature));
  results.push(legacySignature.toString('hex'));
  results.push(Schnorr.sign(secret, message, Buffer.alloc(17, 7)).toString('hex'));

  const nonDefaultSignature = Buffer.concat([legacySignature, Buffer.from([Signature.SIGHASH_ALL])]);
  assert(Schnorr.verify(key.publicKey, message, Signature.fromSchnorr(nonDefaultSignature)));
  assert.throws(() => Schnorr.verify(key.publicKey, message, nonDefaultSignature), /Got 65 bytes/);
  assert.throws(() => Schnorr.sign(Buffer.alloc(32), message, legacyAux), /Invalid private key/);
  assert.throws(() => Schnorr.sign(secret, Buffer.alloc(31), legacyAux), /Message should be a 32 byte buffer/);

  const verify = Schnorr.verify;
  Schnorr.verify = () => false;
  assert.throws(() => Schnorr.sign(secret, message, Buffer.alloc(32)), /Verification failed/);
  Schnorr.verify = verify;

  for (const root of [undefined, Buffer.alloc(32), Buffer.alloc(32, 0xff)]) {
    for (const privateKey of [key, new PrivateKey('05')]) {
      const output = privateKey.publicKey.createTapTweak(root);
      const tweaked = new PrivateKey(privateKey.createTapTweak(root).tweakedPrivKey);
      const outputKey = PublicKey.fromTaproot(output.tweakedPubKey);
      assert(outputKey.checkTapTweak(privateKey.publicKey, root, [output.parity]));
      assert(!outputKey.checkTapTweak(privateKey.publicKey, root, [1 - output.parity]));
      assert.equal(Number(tweaked.publicKey.point.getY().isOdd()), output.parity);
      assert.deepEqual(tweaked.publicKey.point.getX().toBuffer({ size: 32 }), output.tweakedPubKey);
      results.push([output.parity, output.tweakedPubKey.toString('hex'), tweaked.toString()]);
    }
  }

  const script = Script.buildWitnessV1Out(key.publicKey);
  const utxo = { txId: '01'.repeat(32), outputIndex: 0, script, satoshis: 100000 };
  const Interpreter = Script.Interpreter;
  // eslint-disable-next-line no-bitwise
  const flags = Interpreter.SCRIPT_VERIFY_P2SH | Interpreter.SCRIPT_VERIFY_WITNESS | Interpreter.SCRIPT_VERIFY_TAPROOT;
  for (const type of [Signature.SIGHASH_DEFAULT, Signature.SIGHASH_ALL]) {
    const spend = new Transaction().from(utxo).to(key.toAddress(), 90000).sign(key, type);
    const input = spend.inputs[0];
    const witnesses = input.getWitnesses();
    assert.equal(witnesses[0].length, type === Signature.SIGHASH_DEFAULT ? 64 : 65);
    const interpreter = new Interpreter();
    assert(interpreter.verify(input.script, script, spend, 0, flags, witnesses, utxo.satoshis), interpreter.errstr);
    const invalid = Buffer.from(witnesses[0]);
    invalid[5] = (invalid[5] + 1) % 256;
    assert(!interpreter.verify(input.script, script, spend, 0, flags, [invalid], utxo.satoshis));
    results.push(spend.id);
  }

  if (native) {
    for (const count of Object.values(calls)) assert(count > 1);
    assert.equal(Object.keys(calls).length, 4);
  }
  console.log(JSON.stringify(results));
}
