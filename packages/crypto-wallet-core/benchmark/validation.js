/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone CommonJS benchmark. */
'use strict';

const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const benchmark = require('../../bitcore-lib/benchmark/backends');

benchmark(__filename, ({ Constants, Validation, Utils, ethers, Web3 }) => {
  const fixtures = Array.from({ length: 12 }, (_, i) => {
    const lower = createHash('sha256').update('address fixture ' + i).digest('hex').slice(0, 40);
    const mixed = ethers.getAddress(lower);
    const tampered = mixed.replace(/[A-F]/, c => c.toLowerCase());
    const chain = Constants.EVM_CHAINS[i % Constants.EVM_CHAINS.length];
    assert.equal(Utils.toChecksumAddress(lower), mixed);
    for (const address of [mixed, lower, tampered, mixed.slice(2), mixed.toUpperCase(),
      mixed.replace('0x', '0X'), lower + '0', 'é' + lower.slice(1), Buffer.from(lower, 'hex')]) {
      assert.equal(Validation.validateAddress(chain, 'mainnet', address), Web3.utils.isAddress(address));
    }
    return { mixed, lower, chain };
  });
  if (process.env.BITCORE_ECDSA_BACKEND === 'native') {
    const { native } = require('@bitpay-labs/bitcore-lib/lib/crypto/ecdsa-native');
    const original = native.cwcEvmValidAddress;
    let used = false;
    native.cwcEvmValidAddress = arg => { used = true; return original(arg); };
    try {
      Validation.validateAddress('ETH', 'mainnet', fixtures[0].mixed);
      assert(used, 'Checksummed address skipped the native validator');
    } finally {
      native.cwcEvmValidAddress = original;
    }
  }
  return { fixtures, operations: {
    evmChecksummedAddress: f => Validation.validateAddress(f.chain, 'mainnet', f.mixed),
    evmFormatAddress: f => Utils.toChecksumAddress(f.lower),
    evmLowercaseAddress: f => Validation.validateAddress(f.chain, 'mainnet', f.lower)
  } };
}, { load: () => require('..'), warmupMs: 100, sampleMs: 400 });
