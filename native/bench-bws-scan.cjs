/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone CommonJS benchmark. */
'use strict';

const assert = require('node:assert/strict');
const { performance } = require('node:perf_hooks');
const { logger } = require('../packages/bitcore-wallet-service/ts_build/src/lib/logger');
const { Address } = require('../packages/bitcore-wallet-service/ts_build/src/lib/model/address');
const { Wallet } = require('../packages/bitcore-wallet-service/ts_build/src/lib/model/wallet');
const { WalletService } = require('../packages/bitcore-wallet-service/ts_build/src/lib/server');

logger.debug = () => {};

function makeScan({ chain = 'btc', addressType = 'P2PKH', n = 1, m = 1,
  network = 'livenet', derivationStrategy = 'BIP44', startingStep = 1000,
  active = [[false, startingStep - 1]], activityError, scalar = false } = {}) {
  const wallet = Wallet.create({
    id: 'scan-benchmark', chain, coin: chain, network, m, n, addressType, derivationStrategy, nativeCashAddr: true
  });
  const { HDPrivateKey } = Address.Bitcore[chain];
  wallet.status = 'complete';
  wallet.publicKeyRing = Array.from({ length: n }, (_, i) => ({
    xPubKey: HDPrivateKey.fromSeed(Buffer.alloc(32, i + 1), network).hdPublicKey.toString()
  }));
  let scalarCalls = 0;
  if (scalar) {
    const getSkippedAddress = wallet.getSkippedAddress;
    wallet.getSkippedAddress = function() {
      assert.equal(arguments.length, 0);
      scalarCalls++;
      return getSkippedAddress.call(this);
    };
  }
  const addresses = new Set(active.map(([isChange, index]) => {
    const basePath = wallet.addressManager.getBaseAddressPath(isChange);
    const path = basePath.slice(0, -1) + index;
    return Address.derive(wallet.id, addressType, wallet.publicKeyRing, path, m, chain, network, isChange, chain).address;
  }));
  const result = { wallet, stored: [], statuses: [] };
  const service = Object.create(WalletService.prototype);
  Object.assign(service, {
    walletId: wallet.id,
    getWallet(_options, callback) { callback(null, wallet); },
    _runLocked(callback, run) { run(callback); },
    _getBlockchainExplorer() {
      return {
        getAddressActivity(address, callback) {
          setImmediate(callback, activityError, addresses.has(address));
        }
      };
    },
    logd() {},
    _store(_wallet, found, callback, reprocess, replace) {
      result.stored.push({ addresses: found, reprocess, replace });
      callback();
    },
    storage: {
      clearWalletCache(_id, callback) { callback(); },
      storeWallet(stored, callback) {
        result.statuses.push(stored.scanStatus);
        callback();
      },
      fetchWallet(_id, callback) { callback(null, wallet); }
    }
  });
  return {
    ...result,
    get scalarCalls() { return scalarCalls; },
    run(options = {}) {
      return new Promise((resolve, reject) => service.scan({ startingStep, ...options }, error => {
        if (error) reject(error);
        else resolve();
      }));
    }
  };
}

async function measure() {
  const samples = {};
  for (const fixture of [{ addressType: 'P2PKH' }, { addressType: 'P2WSH', m: 2, n: 3 }]) {
    const elapsedByMode = { scalar: [], branch: [] };
    for (let i = 0; i < 7; i++) {
      for (const mode of i % 2 ? ['scalar', 'branch'] : ['branch', 'scalar']) {
        const scan = makeScan({ ...fixture, scalar: mode === 'scalar' });
        const start = performance.now();
        await scan.run();
        const elapsed = performance.now() - start;
        assert.deepEqual(scan.statuses, ['running', 'success']);
        assert.equal(scan.stored.flatMap(batch => batch.addresses).length, 1000);
        assert.equal(scan.wallet.addressManager.receiveAddressIndex, 1000);
        assert.equal(scan.wallet.addressManager.changeAddressIndex, 0);
        if (i >= 2) elapsedByMode[mode].push(elapsed);
      }
    }
    samples[fixture.addressType] = Object.fromEntries(Object.entries(elapsedByMode).map(([mode, elapsed]) =>
      [mode, elapsed.sort((a, b) => a - b)[2]]
    ));
  }
  console.log(process.version, process.env.BITCORE_ECDSA_BACKEND, 'median ms', JSON.stringify(samples));
}

if (require.main === module) measure().catch(error => { console.error(error); process.exitCode = 1; });

module.exports = { makeScan };
