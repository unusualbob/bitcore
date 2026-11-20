/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone CommonJS script. */
'use strict';

const assert = require('node:assert/strict');
const { performance } = require('node:perf_hooks');
const { Worker, isMainThread, parentPort, workerData } = require('node:worker_threads');

const packages = ['bitcore-lib', 'bitcore-lib-cash', 'bitcore-lib-ltc', 'bitcore-lib-doge'];
const modes = ['js', 'previous', 'native'];

if (!isMainThread) {
  const mode = workerData;
  const signers = [];
  const dispatches = [];
  for (const name of packages) {
    const bitcore = require(`../packages/${name}`);
    const { native } = require(`../packages/${name}/lib/crypto/ecdsa-native`);
    const key = new bitcore.PrivateKey('01'.padStart(64, '0'));
    key.toPublicKey();
    let calls = 0;
    if (mode === 'previous') {
      assert.ok(native);
      native.signWithNonce = undefined;
    } else if (mode === 'native') {
      const signWithNonce = native.signWithNonce;
      assert.equal(typeof signWithNonce, 'function');
      native.signWithNonce = (...args) => {
        calls++;
        return signWithNonce(...args);
      };
    }
    const digest = Buffer.alloc(32, 7);
    signers.push([`${name} ECDSA.sign(randomK)`, () => bitcore.crypto.ECDSA.sign(digest, key, { randomK: true })]);
    if (bitcore.Message) {
      const message = new bitcore.Message('Random nonce benchmark');
      signers.push([`${name} Message.sign`, () => message.sign(key)]);
      const cwc = require('../packages/crypto-wallet-core').Message;
      for (const chain of ['btc', 'bch', 'ltc', 'doge']) {
        const args = { chain, message: 'Random nonce benchmark', privateKey: key.toString() };
        signers.push([`CWC ${chain} signMessage`, () => cwc.signMessage(args)]);
      }
    }
    dispatches.push(() => calls);
  }

  function run(fn, ms) {
    let iterations = 0;
    const start = performance.now();
    let elapsed;
    do {
      fn();
      iterations++;
      elapsed = performance.now() - start;
    } while (elapsed < ms);
    return iterations * 1000 / elapsed;
  }

  const nativeCalls = () => dispatches.reduce((total, count) => total + count(), 0);
  const rates = {};
  for (const [name, sign] of signers) {
    const before = nativeCalls();
    assert.ok(sign());
    if (mode === 'native') assert.equal(nativeCalls() - before, 1, name);
    run(sign, 75);
    rates[name] = run(sign, 200);
  }
  parentPort.postMessage(rates);
} else {
  main().catch(error => {
    console.error(error);
    process.exitCode = 1;
  });
}

async function main() {
  const selected = process.env.BITCORE_RANDOM_NONCE_BASELINE ? modes.slice(0, 2) : modes;
  const samples = {};
  for (let round = 0; round < 5; round++) {
    for (const mode of round % 2 ? [...selected].reverse() : selected) {
      const backend = mode === 'js' ? 'js' : 'native';
      const env = {
        ...process.env,
        BITCORE_ECDSA_BACKEND: backend,
        BITCORE_BCH_BACKEND: backend,
        BITCORE_LTC_BACKEND: backend,
        BITCORE_DOGE_BACKEND: backend
      };
      const rates = await new Promise((resolve, reject) => {
        const worker = new Worker(__filename, { env, workerData: mode });
        worker.once('message', resolve);
        worker.once('error', reject);
        worker.once('exit', code => {
          if (code !== 0) reject(new Error(`Benchmark worker exited with status ${code}`));
        });
      });
      for (const [name, rate] of Object.entries(rates)) {
        samples[name] ??= {};
        (samples[name][mode] ??= []).push(rate);
      }
    }
  }
  for (const [name, rates] of Object.entries(samples)) {
    const median = mode => Math.round(rates[mode].sort((a, b) => a - b)[2]);
    console.log(name, Object.fromEntries(selected.map(mode => [mode, median(mode)])));
  }
}
