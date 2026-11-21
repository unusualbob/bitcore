/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone CommonJS benchmark. */
'use strict';

const assert = require('node:assert/strict');
const { performance } = require('node:perf_hooks');
const BitcoreLib = require('@bitpay-labs/bitcore-lib');
const { XrpDeriver } = require('../ts_build/src/derivation/xrp');
const { deriveXrpAddress } = require('../ts_build/src/wallet-crypto');

const iterations = Number(process.argv[2] ?? 1500);
assert(Number.isSafeInteger(iterations) && iterations > 0);
const network = 'livenet';
const xpriv = BitcoreLib.HDPrivateKey.fromSeed(Buffer.alloc(32, 13)).toString();
const deriver = new XrpDeriver();

function legacy(path) {
  const key = new BitcoreLib.HDPrivateKey(xpriv, network).derive(path);
  const privKey = key.toObject().privateKey.toUpperCase();
  const pubKey = key.hdPublicKey.toObject().publicKey.toUpperCase();
  return { address: deriveXrpAddress(pubKey), privKey, pubKey, path };
}

function direct(path) {
  return deriver.derivePrivateKeyWithPath(network, xpriv, path);
}

function run(operation, count, firstIndex) {
  const start = performance.now();
  for (let i = firstIndex; i < firstIndex + count; i++) operation('m/0/' + i);
  return (performance.now() - start) * 1000 / count;
}

for (let i = 0; i < 256; i++) {
  const path = 'm/0/' + i;
  assert.deepEqual(direct(path), legacy(path));
}
run(legacy, 1000, 256);
run(direct, 1000, 1256);

const samples = new Map([[legacy, []], [direct, []]]);
let firstIndex = 2256;
for (let round = 0; round < 7; round++) {
  for (const operation of round % 2 ? [direct, legacy] : [legacy, direct]) {
    samples.get(operation).push(run(operation, iterations, firstIndex));
    firstIndex += iterations;
  }
}
const medians = [...samples.values()].map(times => times.sort((a, b) => a - b)[3]);
console.log(`Node ${process.version}, BITCORE_ECDSA_BACKEND=${process.env.BITCORE_ECDSA_BACKEND ?? 'auto'}`);
console.log(`XRP private key derivation, median μs/op over 7 rounds of ${iterations} calls per case`);
console.log(`legacy ${medians[0].toFixed(1)} | direct ${medians[1].toFixed(1)} | ${(medians[0] / medians[1]).toFixed(2)}x`);
