/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone CommonJS test. */
'use strict';

const assert = require('node:assert/strict');
const { native } = require('../packages/bitcore-lib/lib/crypto/ecdsa-native');
const { Transactions, ethers } = require('../packages/crypto-wallet-core');

const getHash = tx => Transactions.getSighash({ chain: 'ETH', tx });
const original = native.cwcKeccak256Large;
assert.equal(typeof original, 'function');
let calls = 0;
native.cwcKeccak256Large = bytes => { calls++; return original(bytes); };
try {
  for (const length of [0, 4095, 4096, 4097, 65536, 1048576]) {
    const bytes = Buffer.alloc(length + 7, 0xab).subarray(7);
    for (const input of [bytes, '0X' + bytes.toString('hex').toUpperCase()]) {
      const expected = ethers.keccak256(input).slice(2);
      const before = calls;
      assert.equal(getHash(input), expected);
      assert.equal(calls - before, Number(length > 4096));
    }
  }
  for (const suffix of ['x1', '0', '\n', '00\n\n']) {
    const malformed = '0x' + '01'.repeat(4097) + suffix;
    assert.throws(() => getHash(malformed), { code: 'INVALID_ARGUMENT' });
  }
  assert.throws(() => original(new Uint8Array(new SharedArrayBuffer(8192))));
  assert.throws(() => original(new Uint16Array(8192)));
  native.cwcKeccak256Large = undefined;
  const large = '0x' + '09'.repeat(8192);
  assert.equal(getHash(large), ethers.keccak256(large).slice(2));
} finally {
  native.cwcKeccak256Large = original;
}
console.log('Large wallet Keccak inputs, legacy addon, dispatch and error parity passed.');
