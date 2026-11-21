/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone offline benchmark. */
'use strict';

const assert = require('node:assert/strict');
const { createRequire } = require('node:module');
const { resolve } = require('node:path');
const { performance } = require('node:perf_hooks');

const walletRequire = createRequire(resolve(__dirname, '../packages/bitcore-wallet-client/package.json'));
const { BitcoreLib } = walletRequire('@bitpay-labs/crypto-wallet-core');
const { Key } = walletRequire('./ts_build/src/lib/key');
const { HDPrivateKey, Script } = BitcoreLib;
const rootPath = "m/44'/0'/0'";
const root = HDPrivateKey.fromSeed(Buffer.alloc(32, 19));
const account = root.deriveChild(rootPath);
const key = new Key({ seedType: 'extendedPrivateKey', seedData: root.toString() });
const toAddress = account.deriveChild('m/0/400').privateKey.toAddress().toString();

function makeProposal(size, distinct) {
  const inputs = Array.from({ length: size }, (_, i) => {
    const path = `m/0/${distinct ? i : 0}`;
    const address = account.deriveChild(path).privateKey.toAddress().toString();
    return {
      path,
      address,
      txId: (i + 1).toString(16).padStart(64, '0'),
      outputIndex: 0,
      script: Script.buildPublicKeyHashOut(address).toHex(),
      satoshis: 20000
    };
  });
  return {
    chain: 'BTC', version: 3, addressType: 'P2PKH', inputs, signingMethod: 'ecdsa',
    toAddress, sendMax: true, amount: 20000 * size - 5000, fee: 5000
  };
}

const scalar = HDPrivateKey.prototype.deriveChild;
const branches = new WeakMap();
function deriveWithBranchReuse(path, ...args) {
  if (typeof path !== 'string' || !/^m\/0\/\d+$/.test(path)) return scalar.call(this, path, ...args);
  let branch = branches.get(this);
  if (!branch) {
    branch = scalar.call(this, 'm/0');
    branches.set(this, branch);
  }
  return scalar.call(branch, 'm/' + path.slice(4), ...args);
}

async function measure(txp, duration) {
  const start = performance.now();
  let count = 0;
  do {
    await key.sign(rootPath, txp);
    count++;
  } while (performance.now() - start < duration);
  return (performance.now() - start) / count;
}

(async () => {
  try {
    for (const [size, distinct] of [[8, false], [8, true], [32, false], [32, true], [100, true]]) {
      HDPrivateKey.prototype.deriveChild = scalar;
      const txp = makeProposal(size, distinct);
      const expected = await key.sign(rootPath, txp);
      assert.equal(expected.length, size);
      HDPrivateKey.prototype.deriveChild = deriveWithBranchReuse;
      assert.deepEqual(await key.sign(rootPath, txp), expected);

      const samples = [[], []];
      for (let round = 0; round < 5; round++) {
        for (const mode of [round % 2, 1 - round % 2]) {
          HDPrivateKey.prototype.deriveChild = mode ? deriveWithBranchReuse : scalar;
          await measure(txp, 100);
          samples[mode].push(await measure(txp, 225));
        }
      }
      const [existing, reused] = samples.map(values => values.sort((a, b) => a - b)[2].toFixed(3));
      console.log(`${size} inputs, ${distinct ? size : 1} distinct keys: ${existing} → ${reused} ms/proposal`);
    }
  } finally {
    HDPrivateKey.prototype.deriveChild = scalar;
  }
})().catch(err => {
  console.error(err);
  process.exitCode = 1;
});
