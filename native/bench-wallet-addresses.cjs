/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone offline check and benchmark. */
'use strict';

const assert = require('node:assert/strict');
const { createRequire } = require('node:module');
const { resolve } = require('node:path');
const { performance } = require('node:perf_hooks');

const clientRequire = createRequire(resolve(__dirname, '../packages/bitcore-client/package.json'));
const coreRequire = createRequire(clientRequire.resolve('@bitpay-labs/crypto-wallet-core'));
const loader = coreRequire.resolve('@bitpay-labs/bitcore-lib/lib/crypto/ecdsa-native');
const addonPath = process.argv.slice(2).find(arg => arg !== '--bench');
let addon = require(loader).native;
if (addonPath) {
  addon = require(resolve(addonPath));
  require.cache[loader].exports = { native: addon };
}
const { BitcoreLib, BitcoreLibCash, BitcoreLibDoge, BitcoreLibLtc, Deriver } = clientRequire('@bitpay-labs/crypto-wallet-core');
const forkLibs = { BCH: BitcoreLibCash, DOGE: BitcoreLibDoge, LTC: BitcoreLibLtc };
const addons = {
  BTC: addon,
  BCH: coreRequire('@bitpay-labs/bitcore-lib-cash/lib/crypto/ecdsa-native').native,
  DOGE: coreRequire('@bitpay-labs/bitcore-lib-doge/lib/crypto/ecdsa-native').native,
  LTC: coreRequire('@bitpay-labs/bitcore-lib-ltc/lib/crypto/ecdsa-native').native
};
const dogeCache = coreRequire('@bitpay-labs/bitcore-lib-doge/lib/hdkeycache');
// syncAddresses is usable on a locked watch-only wallet. Fail if this
// fixture unexpectedly reaches bcrypt, whose binary may be absent locally.
const bcryptPath = clientRequire.resolve('bcrypt');
function unexpectedBcrypt() {
  throw new Error('Unexpected bcrypt call in address benchmark');
}
require.cache[bcryptPath] = { exports: { hashSync: unexpectedBcrypt, compare: unexpectedBcrypt } };
const { Wallet } = clientRequire('./ts_build/src/wallet');
delete require.cache[bcryptPath];
const { Client } = clientRequire('./ts_build/src/client');
const { utils } = clientRequire('./ts_build/src/utils');
const batch = addon?.derivePublicChildren;
const originalRange = Deriver.deriveAddressRange;
const chains = ['BTC', 'BCH', 'LTC', 'DOGE', 'ETH', 'MATIC', 'ARB', 'BASE', 'OP', 'ARC', 'XRP'];
const xpub = BitcoreLib.HDPrivateKey.fromSeed(Buffer.alloc(32, 42)).deriveChild("m/44'/0'/0'").hdPublicKey;

function fixture(chain, network = 'livenet') {
  const lib = forkLibs[chain] || BitcoreLib;
  const xPubKey = lib.HDPrivateKey.fromSeed(Buffer.alloc(32, 17), network).deriveChild("m/44'/0'/0'").hdPublicKey.toString();
  return { chain, network, xPubKey };
}

function makeWallet(settings) {
  const wallet = Object.assign(Object.create(Wallet.prototype), {
    chain: 'BTC',
    network: 'livenet',
    xPubKey: xpub.toString(),
    addressIndex: 50,
    authPubKey: 'local-fixture',
    ...settings
  });
  const client = new Client({
    apiUrl: `https://example.test/api/${wallet.chain}/${wallet.network}`,
    authKey: new BitcoreLib.PrivateKey(Buffer.alloc(32, 1))
  });
  wallet.client = client;
  return wallet;
}

async function capture(wallet, withChange) {
  const requests = [];
  wallet.client._request = async request => { requests.push(request); };
  await wallet.syncAddresses(withChange);
  return requests;
}

function checkBinding() {
  const key = xpub.publicKey.toBuffer();
  const chainCode = Buffer.from(xpub.toObject().chainCode, 'hex');
  const last = 0x7fffffff;
  assert.deepEqual(batch(key, chainCode, last, 1), xpub.derive(last).publicKey.toBuffer());
  assert.equal(batch(Buffer.alloc(33), chainCode, 0, 2), null);
  for (const [index, count] of [[0, 0], [0, 257], [last, 2], [-1, 1], [NaN, 1], [0.5, 1], [0, 1.5]]) {
    assert.throws(() => batch(key, chainCode, index, count), /Invalid native HD child range/);
  }
  assert.throws(() => batch(key, chainCode.subarray(1), 0, 2));
  assert.throws(() => batch(new Uint8Array(new SharedArrayBuffer(33)), chainCode, 0, 2));
}

async function checkWallet() {
  const cases = [
    [{ addressIndex: 0 }, true, 0],
    [{ addressIndex: 1, addressZero: 'saved-zero' }, true, 0],
    [{ addressIndex: 2, addressZero: 'saved-zero' }, true, 2],
    [{ addressIndex: 2.5 }, true, 0],
    [{ addressIndex: 259 }, false, 2],
    [{ addressIndex: 258, addressZero: 'saved-zero' }, true, 4],
    [{ ...fixture('BTC', 'testnet'), addressType: 'witnesspubkeyhash' }, true, 2],
    [{ addressType: 'taproot' }, false, 1],
    [{ ...fixture('LTC', 'testnet'), addressType: 'witnesspubkeyhash' }, true, 2],
    [{ ...fixture('ETH'), chain: 'eth', addressIndex: 3 }, true, 2],
    ...chains.flatMap(chain => [
      [{ ...fixture(chain), addressIndex: 63 }, true, 2],
      [{ ...fixture(chain, 'testnet'), addressIndex: 3 }, false, 1]
    ])
  ];

  const dispatches = new Map();
  for (const implementation of new Set(Object.values(addons))) {
    const derive = implementation?.derivePublicChildren;
    if (typeof derive !== 'function') continue;
    const calls = { count: 0, derive };
    dispatches.set(implementation, calls);
    implementation.derivePublicChildren = function (...args) {
      calls.count++;
      return derive.apply(this, args);
    };
  }
  for (const [settings, withChange, calls] of cases) {
    const wallet = makeWallet(settings);
    Deriver.deriveAddressRange = undefined;
    const expected = await capture(wallet, withChange);
    Deriver.deriveAddressRange = originalRange;
    const before = Array.from(dispatches, ([implementation, counter]) => [implementation, counter.count]);
    assert.deepEqual(await capture(wallet, withChange), expected);
    const selected = addons[wallet.chain] ?? (wallet.chain in forkLibs ? undefined : addon);
    for (const [implementation, count] of before) {
      assert.equal(dispatches.get(implementation).count - count,
        wallet.chain !== 'DOGE' && selected === implementation ? calls : 0, wallet.chain);
    }
    if (settings.addressZero && withChange) {
      assert.deepEqual(expected[0].body.slice(0, 2), [{ address: 'saved-zero' }, { address: 'saved-zero' }]);
    }
  }
  for (const [implementation, { derive }] of dispatches) implementation.derivePublicChildren = derive;

  const overridden = makeWallet({ addressIndex: 2, deriveAddress: (i, change) => `${i}:${change}` });
  const [request] = await capture(overridden, true);
  assert.deepEqual(request.body.map(item => item.address), ['0:false', '0:true', '1:false', '1:true']);

  await checkOverrides();
  await checkDogeCache();

  let sent = 0;
  for (const invalid of [{ xPubKey: 'invalid xpub' }, { addressType: 'invalid type' }]) {
    const wallet = makeWallet(invalid);
    wallet.client._request = () => { sent++; };
    await assert.rejects(wallet.syncAddresses(true));
  }
  assert.equal(sent, 0);

  const sol = makeWallet({ chain: 'SOL', addressIndex: 2 });
  await assert.rejects(capture(sol, true), /Cannot derive Solana addresses/);
  const xprivWallet = makeWallet({
    xPubKey: BitcoreLib.HDPrivateKey.fromSeed(Buffer.alloc(32, 42)).toString(),
    addressIndex: 3
  });
  assert.equal(Deriver.deriveAddressRange('BTC', 'livenet', xprivWallet.xPubKey, 0, 3, true), undefined);

  for (const [chain, exportName] of [['ETH', 'cwcEvmAddress'], ['XRP', 'cwcXrpAddress']]) {
    if (!addon) continue;
    const encoder = addon[exportName];
    const wallet = makeWallet({ ...fixture(chain), addressIndex: 3 });
    addon[exportName] = undefined;
    try {
      Deriver.deriveAddressRange = undefined;
      const expected = await capture(wallet, true);
      Deriver.deriveAddressRange = originalRange;
      assert.deepEqual(await capture(wallet, true), expected);
    } finally {
      addon[exportName] = encoder;
      Deriver.deriveAddressRange = originalRange;
    }
  }

  for (const chain of ['BTC', 'BCH', 'LTC']) {
    const implementation = addons[chain];
    const derive = implementation?.derivePublicChildren;
    if (!derive) continue;
    const wallet = makeWallet({ ...fixture(chain), addressIndex: 3 });
    Deriver.deriveAddressRange = undefined;
    const expected = await capture(wallet, true);
    Deriver.deriveAddressRange = originalRange;
    implementation.derivePublicChildren = undefined;
    assert.deepEqual(await capture(wallet, true), expected);
    implementation.derivePublicChildren = () => null;
    assert.deepEqual(await capture(wallet, true), expected);
    implementation.derivePublicChildren = () => Buffer.alloc(3);
    wallet.client._request = () => { sent++; };
    await assert.rejects(wallet.syncAddresses(true), /Invalid native HD child keys/);
    assert.equal(sent, 0);
    implementation.derivePublicChildren = derive;
  }
  console.log(`Signed address import parity passed for ${chains.length} BIP32 chains.`);
}

async function checkOverrides() {
  const wallet = makeWallet({ addressIndex: 3 });
  const check = async (owner, method, replacement, expected) => {
    const original = owner[method];
    owner[method] = replacement;
    try {
      const [request] = await capture(wallet, false);
      assert.deepEqual(request.body.map(item => item.address), expected);
    } finally {
      owner[method] = original;
    }
  };
  await check(Deriver, 'deriveAddress', (_chain, _network, _key, i) => `sdk-${i}`, ['sdk-0', 'sdk-1', 'sdk-2']);
  await check(Deriver, 'get', () => ({ deriveAddress: (_network, _key, i) => `registry-${i}` }),
    ['registry-0', 'registry-1', 'registry-2']);
  await check(Deriver.get('BTC'), 'deriveAddressWithPath', (_network, _key, path) => path, ['m/0/0', 'm/0/1', 'm/0/2']);
  await check(Deriver.get('BTC'), 'getAddress', (_network, key) => {
    assert.ok(key instanceof BitcoreLib.PublicKey);
    return 'formatter';
  }, ['formatter', 'formatter', 'formatter']);
  const paths = [];
  const derive = BitcoreLib.HDPublicKey.prototype.derive;
  const expected = (await capture(wallet, false))[0].body.map(item => item.address);
  await check(BitcoreLib.HDPublicKey.prototype, 'derive', function (path) {
    paths.push(path);
    return derive.call(this, path);
  }, expected);
  assert.deepEqual(paths, ['m/0/0', 'm/0/1', 'm/0/2']);
}

function resetDogeCache() {
  Object.assign(dogeCache, { _cache: {}, _count: 0, _eraseIndex: 0, _usedList: {}, _usedIndex: {} });
}

async function checkDogeCache() {
  const wallet = makeWallet({ ...fixture('DOGE'), addressIndex: 57, addressZero: 'saved-zero' });
  const originalGet = dogeCache.get;
  const originalSet = dogeCache.set;
  const originalSize = dogeCache._CACHE_SIZE;
  let trace = [];
  dogeCache.get = function (parent, index, hardened) {
    const found = originalGet.call(this, parent, index, hardened);
    trace.push(['get', parent, index, !!found]);
    return found;
  };
  dogeCache.set = function (parent, index, hardened, child) {
    trace.push(['set', parent, index, child.xpubkey]);
    return originalSet.call(this, parent, index, hardened, child);
  };
  try {
    for (const size of [originalSize, 25]) {
      dogeCache._CACHE_SIZE = size;
      resetDogeCache();
      trace = [];
      Deriver.deriveAddressRange = undefined;
      const expected = [await capture(wallet, true), await capture(wallet, true)];
      const scalarTrace = trace;
      resetDogeCache();
      trace = [];
      Deriver.deriveAddressRange = originalRange;
      assert.deepEqual([await capture(wallet, true), await capture(wallet, true)], expected);
      assert.deepEqual(trace, scalarTrace);
    }
  } finally {
    Deriver.deriveAddressRange = originalRange;
    dogeCache.get = originalGet;
    dogeCache.set = originalSet;
    dogeCache._CACHE_SIZE = originalSize;
    resetDogeCache();
  }
}

async function benchmark() {
  const modes = [undefined, originalRange];
  console.log(`Node ${process.version}, ${process.platform}/${process.arch}. Backends: ` +
    Object.entries(addons).map(([chain, value]) => `${chain} ${value?.abiVersion ?? 'JS'}`).join(', '));
  try {
    for (const [chain, addressIndex, withChange, addressType, cold] of [
      ...chains.map(chain => [chain, 50, true]),
      ['DOGE', 50, true, undefined, true],
      ...(batch ? [
        ['BTC', 10, false, 'pubkeyhash'], ['BTC', 50, true, 'witnesspubkeyhash'],
        ['BTC', 50, true, 'taproot'], ['BTC', 512, true, 'pubkeyhash']
      ] : [])
    ]) {
      const wallet = makeWallet({ ...fixture(chain), addressIndex, addressType });
      wallet.client._request = async () => {};
      const sync = () => {
        if (cold) resetDogeCache();
        return wallet.syncAddresses(withChange);
      };
      const samples = modes.map(() => []);
      for (let round = 0; round < 5; round++) {
        for (let step = 0; step < modes.length; step++) {
          const i = (step + round) % modes.length;
          Deriver.deriveAddressRange = modes[i];
          const warmup = performance.now() + 100;
          do { await sync(); } while (performance.now() < warmup);
          const start = performance.now();
          let count = 0;
          do {
            await sync();
            count++;
          } while (performance.now() - start < 175);
          samples[i].push((performance.now() - start) / count);
        }
      }
      const [scalar, range] = samples.map(values => values.sort((a, b) => a - b)[2]);
      console.log(`${chain}${cold ? ' cold' : ''} ${addressIndex * (withChange ? 2 : 1)} ${addressType ?? 'default'} addresses: ` +
        `${scalar.toFixed(3)} → ${range.toFixed(3)} ms/import (${(scalar / range).toFixed(2)}×)`);
    }
  } finally {
    Deriver.deriveAddressRange = originalRange;
  }
}

(async () => {
  // Keep actual request signing and pagination. Suppress progress output and the
  // built-in cooldown, since this script never sends a request.
  const log = console.log;
  console.log = (...args) => {
    if (!args[0]?.startsWith('Importing addresses ')) log(...args);
  };
  utils.sleep = async () => {};
  if (batch) checkBinding();
  await checkWallet();
  if (process.argv.includes('--bench')) await benchmark();
})().catch(err => {
  console.error(err);
  process.exitCode = 1;
});
