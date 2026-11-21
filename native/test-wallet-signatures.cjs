/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone offline wallet signing test. */
'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { performance } = require('node:perf_hooks');
const { native } = require('../packages/bitcore-lib/lib/crypto/ecdsa-native');
// Install the counter before the wallet modules capture their default signer.
// Instrument only this test process; benchmark runs use the original export.
let nativeSignCalls = 0;
if (native && !process.argv.includes('--bench')) {
  const sign = native.schnorrSign;
  assert.equal(typeof sign, 'function');
  native.schnorrSign = (...args) => {
    nativeSignCalls++;
    return sign(...args);
  };
}
const SighashSchnorr = require('../packages/bitcore-lib/lib/transaction/sighashschnorr');
const { Utils } = require('../packages/bitcore-wallet-client/ts_build/src/lib/common/utils');
const { Key } = require('../packages/bitcore-wallet-client/ts_build/src/lib/key');
const { BitcoreLib, BitcoreLibCash, BitcoreLibDoge, BitcoreLibLtc } = require('../packages/crypto-wallet-core');

const libraries = { BTC: BitcoreLib, BCH: BitcoreLibCash, DOGE: BitcoreLibDoge, LTC: BitcoreLibLtc };
const rootPath = "m/44'/0'/0'";
const root = BitcoreLib.HDPrivateKey.fromSeed(Buffer.alloc(32, 19));
const account = root.deriveChild(rootPath);
const key = new Key({ seedType: 'extendedPrivateKey', seedData: root.toString() });

function createInput(chain, addressType, keyIndex, outpoint = keyIndex + 1) {
  const lib = libraries[chain];
  const path = `m/0/${keyIndex}`;
  const pk = new lib.PrivateKey(account.deriveChild(path).privateKey.toString());
  const type = { P2TR: 'taproot', P2WPKH: 'witnesspubkeyhash' }[addressType];
  const address = pk.toAddress(undefined, type).toString();
  return {
    path,
    address,
    txId: outpoint.toString(16).padStart(64, '0'),
    outputIndex: 0,
    script: lib.Script.fromAddress(address).toHex(),
    satoshis: 20000
  };
}

function proposal(chain, addressType, inputs) {
  return {
    chain, addressType, version: 3, inputs, signingMethod: chain === 'BCH' ? 'schnorr' : 'ecdsa',
    toAddress: createInput(chain, 'P2PKH', 400).address,
    sendMax: true, amount: inputs.length * 20000 - 5000, fee: 5000
  };
}

function fixture(chain, addressType, size) {
  return proposal(chain, addressType, Array.from({ length: size }, (_, i) => createInput(chain, addressType, i)));
}

async function legacySign(txp) {
  const tx = libraries[txp.chain].Transaction.prototype;
  const batch = tx._getWalletSignatures;
  assert.equal(typeof batch, 'function');
  try {
    tx._getWalletSignatures = undefined;
    return await key.sign(rootPath, txp);
  } finally {
    tx._getWalletSignatures = batch;
  }
}

function verifyTaproot(txp, signatures, positions) {
  const tx = Utils.buildTx(txp);
  assert.equal(signatures.length, positions.length);
  for (const [index, signature] of signatures.entries()) {
    assert(tx.inputs[positions[index]].isValidSignature(tx, {
      signature: BitcoreLib.crypto.Signature.fromSchnorr(Buffer.from(signature, 'hex'))
    }));
  }
}

async function test() {
  // SHA-256 of the ordered JSON signature arrays produced by the wallet signer
  // and four coin libraries from d80bd65ce, before the Rust migration.
  const fingerprint = values => crypto.createHash('sha256').update(JSON.stringify(values)).digest('hex');
  const bitcoinP2pkh = '5b89d6a5ec0d82d4065415d22b731b311880a60d2fdf141f0695e4a2c0fd6419';
  const cashP2pkh = '160e8723b6a3ad6b88c1a35775064524eaca2199f3f99bbb2bb733bd400a95fe';
  for (const chain of Object.keys(libraries)) {
    const txp = fixture(chain, 'P2PKH', 4);
    const expected = await legacySign(txp);
    assert.equal(expected.length, txp.inputs.length);
    assert.equal(fingerprint(expected), chain === 'BCH' ? cashP2pkh : bitcoinP2pkh);
    assert.deepEqual(await key.sign(rootPath, txp), expected);
  }

  const witness = fixture('BTC', 'P2WPKH', 4);
  assert.equal(fingerprint(await key.sign(rootPath, witness)), '72e8741b57b15d4e646b46ec049270c0262aeeb20bb36e0656da31fbced8041a');
  assert.deepEqual(await key.sign(rootPath, witness), await legacySign(witness));

  const externalAccount = BitcoreLib.HDPrivateKey.fromSeed(Buffer.alloc(32, 37)).deriveChild(rootPath);
  const multisig = proposal('BTC', 'P2SH', witness.inputs.map(input => {
    const publicKeys = [account, externalAccount].map(parent => parent.deriveChild(input.path).publicKey.toString());
    const address = BitcoreLib.Address.createMultisig(publicKeys, 2).toString();
    return { ...input, address, publicKeys, script: BitcoreLib.Script.fromAddress(address).toHex() };
  }));
  multisig.requiredSignatures = 2;
  const multisigSignatures = await legacySign(multisig);
  assert.equal(multisigSignatures.length, 4);
  assert.deepEqual(await key.sign(rootPath, multisig), multisigSignatures);

  const taproot = fixture('BTC', 'P2TR', 4);
  // Taproot signatures use fresh auxiliary randomness. Verify signatures made
  // by the original signer and pin its ordered per-input signing digests.
  verifyTaproot(taproot, [
    '3cc885f04b9ab3a96d92691e0ec2d6ed26d6346b734ff91b8acf97da8933a741394d50007da8e98bf1038ee338e597a620db889b8b05da2141efc4e2312551f7',
    '3c87b59a870db140a5d564f11335ae69e700d7fbd7033f0385cf15cb5aa9b36b88c5992f98a65cb9aab786c0cda8fc5aae1a646561d324c4cf7814cd697def63',
    '166136191163aca0452c5d51f79c080fa61e197d29fee112b11d5169cf9a1aac005fb659805b05e2605aaa3bd066992a297483f1d7f1ca59c681914f81526257',
    '5f9f3a581b02d5e3ae781358adda0bc863a60e114c1a3f2ec0d95a71894a8c2bbe311dff08b87a4425011ec2c60c250f7a816bcfc81aba517676d7ff746c64e1',
  ], [0, 1, 2, 3]);
  const tx = Utils.buildTx(taproot);
  const digests = tx.inputs.map((input, i) => input.getSighash(tx, null, i).toString('hex'));
  assert.equal(fingerprint(digests), 'eb8ba03ab36cf90d3a22a991bd15a0c40cf3e570239c9eadc3faab31d02559e5');
  const inputs = taproot.inputs.slice().reverse().map((input, i) => ({ ...input, path: taproot.inputs[i].path }));
  const duplicate = { ...inputs[0], txId: 'fe'.repeat(32), path: 'm/0/03' };
  const external = { ...createInput('BTC', 'P2TR', 400), path: inputs[0].path };
  const shuffled = proposal('BTC', 'P2TR', [...inputs, duplicate, external]);
  // Reversing path labels is legal. Two distinct labels resolve to the same
  // signing key, with two matching UTXOs. The external output has no local key.
  const signaturePositions = [0, 0, 1, 2, 3, 4, 4];
  nativeSignCalls = 0;
  verifyTaproot(shuffled, await legacySign(shuffled), signaturePositions);
  const scalarCalls = nativeSignCalls;
  nativeSignCalls = 0;
  verifyTaproot(shuffled, await key.sign(rootPath, shuffled), signaturePositions);
  if (native) {
    assert.equal(nativeSignCalls, signaturePositions.length);
    assert.ok(scalarCalls > nativeSignCalls);
  }

  const invalid = proposal('BTC', 'P2TR', [...taproot.inputs, { ...external, script: '5120' + 'ff'.repeat(32) }]);
  verifyTaproot(invalid, await key.sign(rootPath, invalid), [0, 1, 2, 3]);

  const randomBytes = crypto.randomBytes;
  // Overriding randomness selects the scalar path and preserves its draw order.
  let rounds = 0;
  try {
    crypto.randomBytes = size => Buffer.alloc(size, ++rounds);
    const expected = await legacySign(shuffled);
    const draws = rounds;
    rounds = 0;
    assert.deepEqual(await key.sign(rootPath, shuffled), expected);
    assert.equal(rounds, draws);
  } finally {
    crypto.randomBytes = randomBytes;
  }

  const sign = SighashSchnorr.sign;
  const failure = new Error('Test sighash override');
  try {
    SighashSchnorr.sign = (...args) => {
      if (args[3] === 1) throw failure;
      return sign(...args);
    };
    await assert.rejects(key.sign(rootPath, taproot), error => error === failure);
  } finally {
    SighashSchnorr.sign = sign;
  }
  console.log('Wallet signature batching, Taproot matching, and fallback passed');
}

async function measure(run, txp) {
  const start = performance.now();
  let count = 0;
  do {
    await run(txp);
    count++;
  } while (performance.now() - start < 250);
  return (performance.now() - start) / count;
}

async function benchmark() {
  const runs = [legacySign, txp => key.sign(rootPath, txp)];
  for (const addressType of ['P2PKH', 'P2WPKH', 'P2TR']) {
    for (const size of [32, 100]) {
      const txp = fixture('BTC', addressType, size);
      const samples = [[], []];
      for (let round = 0; round < 5; round++) {
        for (const mode of [round % 2, 1 - round % 2]) {
          samples[mode].push(await measure(runs[mode], txp));
        }
      }
      const [previous, current] = samples.map(part => part.sort((left, right) => left - right)[2]);
      console.log(`${addressType}, ${size} distinct keys: ${previous.toFixed(2)} → ${current.toFixed(2)} ms (${(previous / current).toFixed(2)}×)`);
    }
  }
}

(process.argv.includes('--bench') ? benchmark() : test()).catch(error => {
  console.error(error);
  process.exitCode = 1;
});
