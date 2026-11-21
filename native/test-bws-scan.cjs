/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone CommonJS parity test. */
'use strict';

const assert = require('node:assert/strict');
const { Address } = require('../packages/bitcore-wallet-service/ts_build/src/lib/model/address');
const { Wallet } = require('../packages/bitcore-wallet-service/ts_build/src/lib/model/wallet');
const { makeScan } = require('./bench-bws-scan.cjs');

const withoutTimestamps = scan => scan.stored.map(batch => ({
  ...batch, addresses: batch.addresses.map(address => ({ ...address, createdOn: 0 }))
}));

async function checkScan(fixture) {
  const startIdx = 5;
  const active = [[false, 104], [false, 204], [true, 104]];
  const baseline = makeScan({ ...fixture, active, startingStep: 100, scalar: true });
  const candidate = makeScan({ ...fixture, active, startingStep: 100 });
  await baseline.run({ startIdx });
  await candidate.run({ startIdx });
  assert.deepEqual(withoutTimestamps(candidate), withoutTimestamps(baseline));
  assert.deepEqual(candidate.statuses, ['running', 'success']);
  assert.equal(candidate.wallet.addressManager.receiveAddressIndex, 205);
  assert.equal(candidate.wallet.addressManager.changeAddressIndex, 105);
  assert.deepEqual(candidate.wallet.addressManager.skippedPaths, []);
  assert.equal(candidate.stored[0].addresses.length, 200);
  assert.equal(candidate.stored[1].addresses.length, 100);
  const branch = candidate.wallet.addressManager.getBaseAddressPath(false).slice(0, -1);
  assert.deepEqual(candidate.stored[0].addresses.slice(0, 5).map(address => address.path),
    [104, 204, 203, 202, 201].map(index => branch + index));
  assert.ok(candidate.stored.every(batch => batch.reprocess && batch.replace));
  assert.equal(baseline.scalarCalls, 301);
}

async function main() {
  assert.equal(Wallet.prototype.getSkippedAddress.length, 0);
  assert.equal(Address.derive.length, 9);
  assert.equal(Address._deriveAddress.length, 10);
  const duckWallet = { getSkippedAddress: () => 'legacy reader' };
  assert.equal(Wallet.createSkippedAddressReader(duckWallet)(), 'legacy reader');

  for (const fixture of [
    {},
    { addressType: 'P2WSH', m: 2, n: 3 },
    { addressType: 'P2SH', m: 2, n: 2, derivationStrategy: 'BIP45' },
    { chain: 'bch' },
    { chain: 'ltc' },
    { chain: 'doge' }
  ]) {
    await checkScan(fixture);
  }

  const error = new Error('explorer offline');
  const failing = makeScan({ activityError: error, startingStep: 100 });
  await assert.rejects(failing.run(), err => err === error);
  assert.deepEqual(failing.statuses, ['running', 'error']);
  assert.equal(failing.wallet.addressManager.receiveAddressIndex, 0);
  assert.equal(failing.wallet.addressManager.changeAddressIndex, 0);
  assert.deepEqual(failing.wallet.addressManager.skippedPaths, []);
  assert.deepEqual(failing.stored, []);

  const invalid = { isChange: false, path: 'm/2147483648/0/7' };
  const pending = [{ isChange: false, path: 'm/0/6' }, invalid, { isChange: true, path: 'm/1/8' }];
  const baseline = makeScan().wallet;
  const candidate = makeScan().wallet;
  baseline.addressManager.skippedPaths = [...pending];
  candidate.addressManager.skippedPaths = [...pending];
  const skipped = Wallet.createSkippedAddressReader(candidate);
  assert.equal(skipped().path, baseline.getSkippedAddress().path);
  const errorOf = operation => {
    try {
      operation();
    } catch (error) {
      return [error.name, error.message];
    }
    assert.fail('expected a derivation error');
  };
  assert.deepEqual(errorOf(skipped), errorOf(() => baseline.getSkippedAddress()));
  assert.deepEqual(candidate.addressManager.skippedPaths, [pending[0]]);

  const fixture = makeScan({ startingStep: 10 });
  const hdPrototype = Address.Bitcore.btc.HDPublicKey.prototype;
  const originalDeriveChild = hdPrototype.deriveChild;
  const observedPaths = [];
  hdPrototype.deriveChild = function(path, ...args) {
    observedPaths.push(path);
    return originalDeriveChild.call(this, path, ...args);
  };
  try {
    await fixture.run();
    assert.ok(observedPaths.includes('m/0/8'));
    assert.ok(observedPaths.every(path => /^m\/[01]\/\d+$/.test(path)));
  } finally {
    hdPrototype.deriveChild = originalDeriveChild;
  }

  console.log('BWS scan records, LIFO ordering, rewind, errors, and overrides matched.');
}

main().catch(error => { console.error(error); process.exitCode = 1; });
