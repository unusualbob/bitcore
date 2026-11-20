/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone CommonJS benchmark. */
'use strict';

const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { createRequire } = require('node:module');
const os = require('node:os');
const path = require('node:path');
const { Readable } = require('node:stream');
const { parseArgs } = require('node:util');
const sinon = require('sinon');
const btcBlock = require('../packages/bitcore-lib/benchmark/block-357238.json');
const dogeBlock = require('../packages/bitcore-lib-doge/test/data/blk160775-testnet');
const ltcBlock = require('../packages/bitcore-lib-ltc/test/data/blk1856255-testnet');

const repo = path.resolve(__dirname, '..');
const fixtures = [
  { name: 'BTC 357238', chain: 'BTC', network: 'mainnet', raw: btcBlock },
  { name: 'BTC expanded', chain: 'BTC', network: 'mainnet', raw: btcBlock, count: 2001 },
  { name: 'LTC witness', chain: 'LTC', network: 'testnet', raw: ltcBlock.blockhex, count: 1201 },
  { name: 'BCH CashTokens', chain: 'BCH', network: 'testnet', count: 1201,
    raw: readFileSync(path.join(repo, 'packages/bitcore-lib-cash/test/data/chipnet-121957.dat')).toString('hex') },
  { name: 'DOGE expanded', chain: 'DOGE', network: 'testnet', raw: dogeBlock.blockhex, count: 1201 }
];

function loadModels(build, sandbox, guardedClients) {
  const load = createRequire(path.join(build, 'src/models/block.js'));
  const { MongoClient } = load('mongodb');
  if (!guardedClients.has(MongoClient)) {
    const rejectConnection = () => assert.fail('This benchmark cannot open a MongoDB connection');
    sandbox.stub(MongoClient, 'connect').callsFake(rejectConnection);
    sandbox.stub(MongoClient.prototype, 'connect').callsFake(rejectConnection);
    guardedClients.add(MongoClient);
  }

  const { Libs } = load('../providers/libs');
  const { BitcoinBlockStorage: blockModel } = load('./block');
  const { TransactionStorage: txModel } = load('./transaction');
  const { CoinStorage } = load('./coin');
  const { WalletAddressStorage } = load('./walletAddress');
  Libs.register('BCH', '@bitpay-labs/bitcore-lib-cash', '@bitpay-labs/bitcore-p2p-cash');
  Libs.register('LTC', '@bitpay-labs/bitcore-lib-ltc', '@bitpay-labs/bitcore-p2p');
  Libs.register('DOGE', '@bitpay-labs/bitcore-lib-doge', '@bitpay-labs/bitcore-p2p-doge');

  const cursor = { project: () => cursor, toArray: async () => [] };
  const collection = {
    find: () => cursor,
    findOne: async () => null,
    bulkWrite: async () => {},
    updateOne: async () => {}
  };
  for (const model of [blockModel, txModel, CoinStorage, WalletAddressStorage]) {
    sandbox.stub(model, 'collection').get(() => collection);
  }
  return { Libs, blockModel, txModel };
}

function parseBlock(lib, raw, count) {
  const block = lib.Block.fromString(raw);
  if (!count) return block;

  // Expand existing non-coinbase transactions while keeping their wire formats.
  const originals = block.transactions.slice(1).map(tx => tx.toBuffer());
  assert.ok(originals.length);
  block.transactions = [block.transactions[0]];
  for (let index = 1; index < count; index++) {
    const tx = lib.Transaction().fromBuffer(originals[(index - 1) % originals.length]);
    tx.nLockTime = index;
    block.transactions.push(tx);
  }
  return block;
}

function makeRun({ Libs, blockModel, txModel }, { chain, network, raw, count }) {
  const block = parseBlock(Libs.get(chain).lib, raw, count);
  const height = 900000;
  const blockParams = { block, chain, network, initialSyncComplete: false, initialHeight: height };
  const txParams = { ...blockParams, txs: block.transactions, height };
  const stream = () => new Readable({ objectMode: true, read() {} });

  return {
    transactions: block.transactions.length,
    bytes: block.toBuffer().length,
    operations: {
      getBlockOp: () => blockModel.getBlockOp(blockParams),
      batchImport: () => txModel.batchImport(txParams),
      processBlock: () => blockModel.processBlock(blockParams),
      ...(chain === 'BTC' && !count ? {
        streamMintOps: () => txModel.streamMintOps({ ...txParams, mintStream: stream() }),
        streamTxOps: () => txModel.streamTxOps({ ...txParams, txStream: stream() })
      } : {})
    }
  };
}

function median(samples) {
  return samples.slice().sort((a, b) => a - b)[Math.floor(samples.length / 2)];
}

async function measure(operations, rounds, iterations, smoke) {
  const samples = operations.map(() => []);
  if (!smoke) {
    for (const run of operations) {
      for (let i = 0; i < iterations; i++) await run();
    }
  }
  for (let round = 0; round < rounds; round++) {
    for (let offset = 0; offset < operations.length; offset++) {
      const index = (round + offset) % operations.length;
      global.gc?.();
      const start = performance.now();
      for (let i = 0; i < iterations; i++) await operations[index]();
      samples[index].push((performance.now() - start) / iterations);
    }
  }
  const milliseconds = samples.map(median);
  return { milliseconds, samples, ...(operations.length === 2 ? { speedup: milliseconds[0] / milliseconds[1] } : {}) };
}

async function main() {
  const { positionals, values: { smoke } } = parseArgs({
    options: { smoke: { type: 'boolean', default: false } }, allowPositionals: true
  });
  if (positionals.length > 2) {
    throw new Error('Usage: node [--expose-gc] native/bench-utxo-ingestion.cjs [--smoke] [BUILD [SECOND_BUILD]]');
  }
  const builds = positionals.length ? positionals.map(dir => path.resolve(dir)) : [path.join(repo, 'packages/bitcore-node/build')];
  assert.equal(new Set(builds).size, builds.length, 'Pass distinct compiled build directories');
  process.env.BITCORE_CONFIG_PATH = path.join(repo, 'bitcore-test.config.json');
  process.env.BCN_LOG_LEVEL = 'none';

  const sandbox = sinon.createSandbox();
  try {
    const guardedClients = new Set();
    const models = builds.map(build => loadModels(build, sandbox, guardedClients));
    const rounds = smoke ? 1 : 7;
    const results = [];
    for (const fixture of fixtures) {
      const runs = models.map(model => makeRun(model, fixture));
      const [{ transactions, bytes, operations }] = runs;
      const iterations = smoke ? 1 : fixture.count ? 8 : 20;
      for (const run of runs) {
        assert.equal(run.transactions, transactions);
        assert.equal(run.bytes, bytes);
      }

      const timings = {};
      for (const name of Object.keys(operations)) {
        timings[name] = await measure(runs.map(run => run.operations[name]), rounds, iterations, smoke);
      }
      results.push({ name: fixture.name, chain: fixture.chain, transactions, bytes, iterations, timings });
    }
    console.log(JSON.stringify({ builds, rounds, smoke, mongoDB: 'mocked', gcBetweenSamples: typeof global.gc === 'function',
      node: process.version, cpu: os.cpus()[0].model, results }, null, 2));
  } finally {
    sandbox.restore();
  }
}

main().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
