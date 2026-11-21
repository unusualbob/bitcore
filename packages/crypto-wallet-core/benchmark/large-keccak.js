/* eslint @typescript-eslint/no-require-imports: "off" -- CommonJS benchmark harness. */
'use strict';

const assert = require('node:assert/strict');
const benchmark = require('../../bitcore-lib/benchmark/backends');

benchmark(__filename, ({ Transactions, ethers }) => {
  const operations = {};
  const fixtures = [{}];
  for (const size of [4096, 4097, 65536, 1048576]) {
    const tx = '0x' + 'ab'.repeat(size);
    const run = () => Transactions.getSighash({ chain: 'ETH', tx });
    assert.equal(run(), ethers.keccak256(tx).slice(2));
    operations['sighash' + size] = run;
  }
  if (process.env.BITCORE_ECDSA_BACKEND === 'native') {
    const { native } = require('../../bitcore-lib/lib/crypto/ecdsa-native');
    const hash = native.cwcKeccak256Large;
    let called = false;
    native.cwcKeccak256Large = bytes => { called = true; return hash(bytes); };
    try {
      operations.sighash4097();
      assert(called);
    } finally {
      native.cwcKeccak256Large = hash;
    }
  }
  return { fixtures, operations };
}, { load: () => require('..'), warmupMs: 80, sampleMs: 250 });
