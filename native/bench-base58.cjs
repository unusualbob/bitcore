/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone CommonJS benchmark. */
'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { createHash } = require('node:crypto');
const { writeSync } = require('node:fs');
const { cpus } = require('node:os');
const { performance } = require('node:perf_hooks');

// First run node native/build-node.cjs and npm run build -w @bitpay-labs/crypto-wallet-core.
// BENCH_DIRECT=1 measures raw addon exports to assess dispatch cutoffs.
// BENCH_SOL_KIT=1 compares the SOL helper against Solana Kit's codec.
const rounds = Number(process.env.BENCH_ROUNDS || 5);
const sampleMs = Number(process.env.BENCH_MS || 120);
const filter = new RegExp(process.env.BENCH_FILTER || '');
assert(Number.isInteger(rounds) && rounds > 0);
assert(Number.isFinite(sampleMs) && sampleMs > 0);

if (!process.argv[2]) {
  const results = {};
  for (const backend of ['js', 'native']) {
    const run = spawnSync(process.execPath, [__filename, backend], {
      env: { ...process.env, BITCORE_ECDSA_BACKEND: backend },
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'inherit']
    });
    if (run.error) throw run.error;
    assert.equal(run.status, 0);
    results[backend] = JSON.parse(run.stdout);
  }
  console.log(`${process.version} / ${cpus()[0]?.model} / median ops/sec (${rounds} × ${sampleMs} ms)`);
  console.table(Object.fromEntries(Object.entries(results.js).map(([name, js]) => {
    const native = results.native[name];
    return [name, { js, native, speedup: (native / js).toFixed(2) + 'x' }];
  })));
} else {
  const { encoding: { Base58, Base58Check } } = require('../packages/bitcore-lib');
  const { encodeBase58, decodeBase58 } = require('../packages/crypto-wallet-core/ts_build/src/base58');
  const SolKit = require('@solana/kit');
  const addon = require('../packages/bitcore-lib/lib/crypto/ecdsa-native').native;
  const useNative = process.argv[2] === 'native';
  const direct = useNative && process.env.BENCH_DIRECT === '1';
  if (useNative) assert.equal(typeof addon?.base58DecodeChecked, 'function', 'Rebuild the addon first');
  const fixtures = Array.from({ length: 512 }, (_, i) => {
    return createHash('shake256', { outputLength: 82 }).update('base58 benchmark ' + i).digest();
  });
  const operations = [];
  function add(name, fn, inputs) {
    if (filter.test(name)) operations.push({ name, fn, inputs, samples: [] });
  }
  function addCodec(name, inputs, reference, codec) {
    const strings = inputs.map(value => reference.encode(value));
    for (const [i, value] of inputs.entries()) {
      assert.equal(codec.encode(value), strings[i]);
      assert.deepEqual(Buffer.from(codec.decode(strings[i])), Buffer.from(value));
    }
    add(name + ' encode', codec.encode, inputs);
    add(name + ' decode', codec.decode, strings);
  }

  for (const size of [25, 32, 38, 64, 82]) {
    addCodec('Base58 ' + size + 'B', fixtures.map(data => data.subarray(0, size)), Base58,
      direct ? { encode: addon.base58Encode, decode: addon.base58Decode } : Base58);
  }
  for (const [name, size, version] of [['address', 21, 0], ['WIF', 34, 128], ['extended key', 78, 4]]) {
    const inputs = fixtures.map(data => {
      const payload = Buffer.from(data.subarray(0, size));
      payload[0] = version;
      if (name === 'WIF') payload[33] = 1;
      return payload;
    });
    addCodec('Base58Check ' + name, inputs, Base58Check,
      direct ? { encode: addon.base58CheckEncode, decode: value => addon.base58DecodeChecked(value).slice(0, -4) } :
        Base58Check);
  }
  const solKit = {
    encode: bytes => SolKit.getBase58Decoder().decode(bytes),
    decode: value => SolKit.getBase58Encoder().encode(value)
  };
  const solCodec = !useNative && process.env.BENCH_SOL_KIT === '1' ? solKit :
    { encode: encodeBase58, decode: decodeBase58 };
  for (const size of [32, 64]) {
    addCodec('SOL ' + size + 'B', fixtures.map(data => Uint8Array.from(data.subarray(0, size))), solKit,
      direct ? { encode: addon.base58Encode, decode: addon.base58Decode } : solCodec);
  }

  let sink;
  function measure({ fn, inputs }, duration) {
    let count = 0;
    const start = performance.now();
    let elapsed;
    do {
      for (const input of inputs) sink = fn(input);
      count += inputs.length;
      elapsed = performance.now() - start;
    } while (elapsed < duration);
    assert.notEqual(sink, undefined);
    return count * 1000 / elapsed;
  }

  assert(operations.length, 'BENCH_FILTER did not match any operation');
  for (const operation of operations) measure(operation, 100);
  for (let round = 0; round < rounds; round++) {
    const order = round % 2 ? operations.slice().reverse() : operations;
    for (const operation of order) operation.samples.push(measure(operation, sampleMs));
  }
  writeSync(1, JSON.stringify(Object.fromEntries(operations.map(({ name, samples }) => {
    samples.sort((a, b) => a - b);
    return [name, Math.round((samples[Math.floor((rounds - 1) / 2)] + samples[Math.floor(rounds / 2)]) / 2)];
  }))));
}
