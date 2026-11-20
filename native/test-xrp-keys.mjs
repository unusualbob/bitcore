import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createRequire, registerHooks } from 'node:module';
import { resolve } from 'node:path';
import { performance } from 'node:perf_hooks';
import { pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';

// Run with Node 24: node native/test-xrp-keys.mjs [--bench] [--no-derivation] [addon.node]
// With two release binaries from before and after the change, use --no-derivation
// for the first run to keep native transaction signing enabled in both runs.
const { values, positionals } = parseArgs({ allowPositionals: true, options: {
  bench: { type: 'boolean' }, 'no-derivation': { type: 'boolean' }
} });
assert.ok(positionals.length <= 1, 'Expected at most one addon path');

const require = createRequire(import.meta.url);
const cwc = '@bitpay-labs/crypto-wallet-core';
const cwcRequire = createRequire(require.resolve(cwc));
const rpcModule = '../packages/crypto-rpc/lib/xrp/XrpRpc.js';
const rpcRequire = createRequire(new URL(rpcModule, import.meta.url));
assert.equal(rpcRequire.resolve(cwc), require.resolve(cwc));
const loader = cwcRequire.resolve('@bitpay-labs/bitcore-lib/lib/crypto/ecdsa-native');
const loaderUrl = pathToFileURL(loader).href;
const xrplRequire = createRequire(cwcRequire.resolve('xrpl'));
const keypairs = xrplRequire('ripple-keypairs');
const { codec } = xrplRequire('ripple-address-codec');
assert.equal(cwcRequire('xrpl/package.json').version, '2.13.0');
assert.equal(xrplRequire('ripple-keypairs/package.json').version, '1.3.1');

// Redirect only the loader's binary lookup for this test process, leaving SDK
// exports, addon exports and installed binaries untouched.
const hook = positionals.length ? registerHooks({
  resolve(specifier, context, nextResolve) {
    return nextResolve(context.parentURL === loaderUrl && specifier === '../native/bitcore_ecdsa.node'
      ? resolve(positionals[0]) : specifier, context);
  }
}) : undefined;
const { xrpl } = require(cwc);
const { nativeCrypto } = await import('../packages/crypto-rpc/lib/native.js');
const { XrpRpc } = await import(rpcModule);
const { walletFromSeed } = await import('../packages/crypto-rpc/lib/xrp/wallet.js');
hook?.deregister();

const derive = nativeCrypto?.xrpDeriveKeypair;
assert.equal(typeof derive, values['no-derivation'] ? 'undefined' : 'function');

const algorithms = ['secp256k1', 'ed25519'];
const entropy = [Buffer.alloc(16), Buffer.alloc(16, 255), ...Array.from({ length: 126 }, (_, index) =>
  createHash('sha256').update(`synthetic XRP seed ${index}`).digest().subarray(0, 16))];
const seeds = algorithms.map(type => entropy.map(bytes => xrpl.encodeSeed(bytes, type)));
const wallets = seeds.map(seedsForAlgorithm => seedsForAlgorithm.map(seed => xrpl.Wallet.fromSeed(seed)));

function walletFields(wallet) {
  assert.ok(wallet instanceof xrpl.Wallet);
  return [wallet.publicKey, wallet.privateKey, wallet.classicAddress, wallet.address, wallet.seed];
}

function outcome(fn) {
  try {
    return walletFields(fn());
  } catch (err) {
    return [err.name, err.message, err.code];
  }
}

function compareWallet(seed, options) {
  assert.deepEqual(outcome(() => walletFromSeed(seed, options)), outcome(() => xrpl.Wallet.fromSeed(seed, options)));
}

let keypairVectors = 0;
for (const [index, seedsForAlgorithm] of seeds.entries()) {
  const ed25519 = index === 1;
  for (const [i, seed] of seedsForAlgorithm.entries()) {
    assert.deepEqual(walletFields(walletFromSeed(seed)), walletFields(wallets[index][i]));
    compareWallet(seed, { algorithm: algorithms[1 - index], accountIndex: i + 1, validator: true });
    if (!derive) continue;
    const options = i < 32 ? [undefined, { validator: true, accountIndex: Symbol() },
      ...[0, 1, -1, 0x80000000, 0xffffffff, 0x100000001, -3.75, 3.75, NaN, Infinity]
        .map(accountIndex => ({ accountIndex }))] : [undefined];
    for (const opts of options) {
      const expected = keypairs.deriveKeypair(seed, opts);
      const result = derive(entropy[i], ed25519, opts?.accountIndex || 0, Boolean(opts?.validator));
      assert.ok(Buffer.isBuffer(result));
      assert.equal(result.toString('hex').toUpperCase(), expected.privateKey + expected.publicKey);
      result.fill(0);
      keypairVectors++;
    }
  }
}

const masterAddress = wallets[0][0].address;
const regularWalletOptions = [undefined, null, {}, { algorithm: null }, { algorithm: 'unknown' },
  { masterAddress }, { masterAddress: '' },
  { masterAddress: xrpl.classicAddressToXAddress(masterAddress, false, false) },
  { masterAddress: xrpl.classicAddressToXAddress(masterAddress, 42, true) },
  { get algorithm() { throw new Error('algorithm getter'); } }];
for (const [seed] of seeds) {
  for (const options of regularWalletOptions) compareWallet(seed, options);
}
const invalid = [undefined, null, 42, false, {}, Buffer.from(seeds[0][0]), '', '0', '*****', 'r',
  ' ' + seeds[0][0], seeds[1][0] + ' ', masterAddress,
  codec.encode(Buffer.alloc(15), { versions: [0x21] }),
  codec.encode(Buffer.alloc(16), { versions: [0x22] }),
  ...seeds.map(([seed]) => seed.slice(0, -1) + 'z')];
for (const seed of invalid) compareWallet(seed);
if (derive) {
  assert.throws(() => derive(Buffer.alloc(15), false, 0, false));
  assert.throws(() => derive(Buffer.alloc(17), true, 0, false));
  assert.throws(() => derive(Buffer.alloc(16), null, 0, false));
  assert.throws(() => derive(Buffer.alloc(16), false, 'bad index', false));
  assert.throws(() => derive(Buffer.alloc(16), false, 0, null));
}

const rpc = Object.create(XrpRpc.prototype);
const prepare = tx => ({ ...tx, Fee: '12', Sequence: 7, LastLedgerSequence: 500, SourceTag: null });
const payments = wallets.map((walletsForAlgorithm, index) => walletsForAlgorithm.slice(0, 32).map((wallet, i) => ({
  secret: wallet.seed,
  address: wallets[1 - index][i].address,
  amount: '0.000042',
  tag: i + 1,
  invoiceID: 'AB'.repeat(32),
})));
const signed = new Map();
for (const [index, batch] of payments.entries()) {
  for (const [i, payment] of batch.entries()) {
    const wallet = wallets[index][i];
    const { tx_blob: blob, hash } = wallet.sign(prepare({
      TransactionType: 'Payment', Account: wallet.address, Amount: '42', Destination: payment.address,
      DestinationTag: payment.tag, InvoiceID: payment.invoiceID
    }));
    assert.ok(wallet.verifyTransaction(blob));
    signed.set(blob, hash);
    payment.expectedHash = hash;
  }
}
rpc.asyncCall = async (method, arg) => {
  if (method === 'autofill') return prepare(arg);
  assert.equal(method, 'submit');
  assert.ok(signed.has(arg), 'RPC submitted different signed bytes from the SDK');
  return { result: { accepted: true, tx_json: { hash: signed.get(arg) } } };
};
for (const payment of payments.flat()) {
  assert.equal(await rpc.sendToAddress(payment), payment.expectedHash);
}
const [name, message] = outcome(() => xrpl.Wallet.fromSeed('bad seed'));
await assert.rejects(rpc.sendToAddress({ ...payments[0][0], secret: 'bad seed' }), { name, message });

console.log(`${seeds.flat().length} seeds, ${keypairVectors} native/SDK keypair comparisons, ` +
  `${invalid.length} invalid seeds, ${signed.size} byte-identical offline sends`);

async function sample(run, asyncRun) {
  let count = 0;
  const warmup = performance.now() + 120;
  while (performance.now() < warmup) {
    if (asyncRun) await run(count++);
    else run(count++);
  }
  const start = performance.now();
  count = 0;
  while (performance.now() - start < 400) {
    if (asyncRun) await run(count++);
    else run(count++);
  }
  return count * 1000 / (performance.now() - start);
}

async function medianRates(jobs) {
  const rates = jobs.map(() => []);
  for (let round = 0; round < 3; round++) {
    const ordered = jobs.map((_, i) => i);
    if (round % 2) ordered.reverse();
    for (const i of ordered) rates[i].push(await sample(...jobs[i]));
  }
  return rates.map(rate => Math.round(rate.sort((a, b) => a - b)[1]));
}

if (values.bench) {
  console.log(`Node ${process.version}, median ops/s, ${derive ? 'native' : 'SDK'} seed derivation, ` +
    `transaction signing exports present: secp256k1=${typeof nativeCrypto?.cwcXrpSign === 'function'}, ` +
    `Ed25519=${typeof nativeCrypto?.ed25519Sign === 'function'}`);
  for (const [i, batch] of payments.entries()) {
    const seedAt = index => seeds[i][index % seeds[i].length];
    const [sdk, helper, send] = await medianRates([
      [index => xrpl.Wallet.fromSeed(seedAt(index)), false],
      [index => walletFromSeed(seedAt(index)), false],
      [index => rpc.sendToAddress(batch[index % batch.length]), true]
    ]);
    console.log(`${algorithms[i]} Wallet.fromSeed ${sdk}, helper ${helper}, offline sendToAddress ${send}`);
  }
}
