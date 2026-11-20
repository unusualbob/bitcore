/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone CommonJS benchmark. */
'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const Module = require('node:module');
const os = require('node:os');
const { isMainThread, parentPort, Worker, workerData } = require('node:worker_threads');
const dogeFixture = require('../packages/bitcore-lib-doge/test/data/blk160775-testnet');
const litecoinFixture = require('../packages/bitcore-lib-ltc/test/data/blk1856255-testnet');
const vectors = require('../packages/bitcore-mnemonic/test/data/bip39-vectors.json');

function load(mode) {
  process.env.BITCORE_ECDSA_BACKEND = mode === 'rust' ? 'native' : 'js';
  assert.equal(crypto.getFips(), 0);
  assert.equal(typeof crypto.pbkdf2Sync, 'function');
  assert.equal(typeof crypto.scryptSync, 'function');
  const bitcoin = require('../packages/bitcore-lib/lib/crypto/ecdsa-native').native;
  const dogecoin = require('../packages/bitcore-lib-doge/lib/crypto/ecdsa-native').native;
  const ltc = require('../packages/bitcore-lib-ltc/lib/crypto/ecdsa-native').native;
  if (mode === 'rust') {
    assert.equal(typeof bitcoin?.bip39Seed, 'function');
    assert.equal(typeof dogecoin?.scryptProofOfWork, 'function');
    assert.equal(typeof ltc?.scryptProofOfWork, 'function');
  } else {
    assert.deepEqual([bitcoin, dogecoin, ltc], [undefined, undefined, undefined]);
  }
  const pbkdf2Path = require.resolve('../packages/bitcore-mnemonic/lib/pbkdf2');
  const powPaths = new Set([
    require.resolve('../packages/bitcore-lib-doge/lib/crypto/hash'),
    require.resolve('../packages/bitcore-lib-ltc/lib/crypto/hash')
  ]);
  const legacyMnemonic = { ...crypto, pbkdf2Sync: undefined };
  const legacyPow = { ...crypto, scryptSync: undefined };
  // Expose the legacy paths without disabling Node PBKDF2 inside scryptsy.
  const originalLoad = Module._load;
  Module._load = function(request, parent, ...args) {
    if (mode === 'legacy' && request === 'crypto') {
      if (parent?.filename === pbkdf2Path) {
        return legacyMnemonic;
      }
      if (powPaths.has(parent?.filename)) {
        return legacyPow;
      }
    }
    return originalLoad.call(this, request, parent, ...args);
  };
  try {
    return {
      Mnemonic: require('../packages/bitcore-mnemonic'),
      doge: require('../packages/bitcore-lib-doge'),
      litecoin: require('../packages/bitcore-lib-ltc'),
      dispatch: {
        rust: [
          [bitcoin, 'bip39Seed'], [dogecoin, 'scryptProofOfWork'], [ltc, 'scryptProofOfWork']
        ],
        node: [
          [crypto, 'pbkdf2Sync', args => args[2] === 2048 && args[4] === 'sha512'],
          [crypto, 'scryptSync'], [crypto, 'scryptSync']
        ],
        legacy: [
          [legacyMnemonic, 'createHmac', args => args[0] === 'sha512'],
          [crypto, 'pbkdf2Sync', args => args[2] === 1 && args[4] === 'sha256'],
          [crypto, 'pbkdf2Sync', args => args[2] === 1 && args[4] === 'sha256']
        ]
      }[mode]
    };
  } finally {
    Module._load = originalLoad;
  }
}

function measure(operation, fixtures, milliseconds) {
  let count = 0;
  const start = performance.now();
  let elapsed;
  do {
    for (const input of fixtures) operation(input);
    count += fixtures.length;
    elapsed = performance.now() - start;
  } while (elapsed < milliseconds);
  return count * 1000 / elapsed;
}

function proofOfWork(chain, fixture) {
  const { header } = chain.Block.fromString(fixture.blockhex);
  const invalid = chain.Block.fromString(fixture.blockhex).header;
  invalid.nonce = 0;
  assert.equal(header.validProofOfWork(), true);
  assert.equal(invalid.validProofOfWork(), false);
  return [header, invalid];
}

function sample(mode) {
  const { Mnemonic, doge, litecoin, dispatch } = load(mode);
  const phrases = vectors.english.slice(0, 8).map(([, phrase, seed]) => {
    const mnemonic = new Mnemonic(phrase);
    assert.equal(mnemonic.toSeed('TREZOR').toString('hex'), seed);
    return mnemonic;
  });
  const operations = [
    ['Mnemonic.toSeed', m => m.toSeed('TREZOR'), phrases],
    ['Dogecoin BlockHeader.validProofOfWork', h => h.validProofOfWork(), proofOfWork(doge, dogeFixture)],
    ['Litecoin BlockHeader.validProofOfWork', h => h.validProofOfWork(), proofOfWork(litecoin, litecoinFixture)]
  ];
  for (const [index, [operation, run, fixtures]] of operations.entries()) {
    const [backend, method, matches = () => true] = dispatch[index];
    const original = backend[method];
    let called = false;
    backend[method] = (...args) => {
      const result = original(...args);
      called ||= matches(args);
      return result;
    };
    try {
      run(fixtures[0]);
      assert.ok(called, `${operation} did not reach ${method} in ${mode} mode`);
    } finally {
      backend[method] = original;
    }
  }
  const rates = {};
  for (const [name, fn, inputs] of operations) {
    measure(fn, inputs, 150);
    rates[name] = measure(fn, inputs, 350);
  }
  return rates;
}

function workerSample(mode) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(__filename, { workerData: mode });
    worker.once('message', resolve);
    worker.once('error', reject);
    worker.once('exit', code => reject(new Error(`${mode} benchmark exited with status ${code}`)));
  });
}

async function main() {
  if (!isMainThread) {
    parentPort.postMessage(sample(workerData));
    return;
  }
  if (process.argv[2] === '--sample') {
    process.stdout.write(JSON.stringify(sample(process.argv[3])));
    return;
  }
  const modes = ['legacy', 'node', 'rust'];
  const samples = { legacy: [], node: [], rust: [] };
  for (let round = 0; round < 5; round++) {
    const order = modes.slice(round % modes.length).concat(modes.slice(0, round % modes.length));
    for (const mode of order) {
      samples[mode].push(await workerSample(mode));
    }
  }
  const medians = {};
  for (const operation of Object.keys(samples.node[0])) {
    medians[operation] = Object.fromEntries(modes.map(mode => {
      const orderedRates = samples[mode].map(result => result[operation]).sort((a, b) => a - b);
      return [mode, orderedRates[Math.floor(orderedRates.length / 2)]];
    }));
  }
  console.log(JSON.stringify({ node: process.version, openssl: process.versions.openssl,
    cpu: os.cpus()[0].model, platform: process.platform, arch: process.arch, medians, samples }, null, 2));
}

main().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
