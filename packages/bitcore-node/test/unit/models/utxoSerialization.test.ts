/* eslint-disable @typescript-eslint/no-require-imports */
import assert from 'assert/strict';
import { readFileSync } from 'fs';
import { dirname, join } from 'path';
import { Readable } from 'stream';
import * as sinon from 'sinon';
import { BitcoinBlockStorage } from '../../../src/models/block';
import { CoinStorage } from '../../../src/models/coin';
import { EventStorage } from '../../../src/models/events';
import { MintOp, SpendOp, TransactionStorage, TxOp } from '../../../src/models/transaction';
import { WalletAddressStorage } from '../../../src/models/walletAddress';
import { Libs } from '../../../src/providers/libs';
import { SpentHeightIndicators } from '../../../src/types/Coin';

function fixture(packageName: string, path: string) {
  return join(dirname(require.resolve(`@bitpay-labs/${packageName}/package.json`)), path);
}

describe('UTXO model serialization', function() {
  let sandbox: sinon.SinonSandbox;

  before(() => {
    Libs.register('BCH', '@bitpay-labs/bitcore-lib-cash', '@bitpay-labs/bitcore-p2p-cash');
    Libs.register('LTC', '@bitpay-labs/bitcore-lib-ltc', '@bitpay-labs/bitcore-p2p');
    Libs.register('DOGE', '@bitpay-labs/bitcore-lib-doge', '@bitpay-labs/bitcore-p2p-doge');
  });

  beforeEach(() => {
    sandbox = sinon.createSandbox();
  });
  afterEach(() => sandbox.restore());

  function mockWrites() {
    const cursor = { project: () => cursor, toArray: async () => [] };
    const coinWrites = sandbox.stub().resolves();
    const txWrites = sandbox.stub().resolves();
    const blockWrites = sandbox.stub().resolves();
    const coinFind = sandbox.stub().returns(cursor);
    const txFind = sandbox.stub().returns(cursor);
    sandbox.stub(CoinStorage, 'collection').get(() => ({ find: coinFind, bulkWrite: coinWrites }));
    sandbox.stub(WalletAddressStorage, 'collection').get(() => ({ find: () => cursor }));
    sandbox.stub(TransactionStorage, 'collection').get(() => ({ find: txFind, bulkWrite: txWrites }));
    sandbox.stub(BitcoinBlockStorage, 'collection').get(() => ({
      bulkWrite: blockWrites,
      findOne: async () => null,
      updateOne: async () => {}
    }));
    return { coinFind, coinWrites, txWrites, blockWrites, txFind };
  }

  for (const chain of ['BTC', 'BCH', 'LTC', 'DOGE']) {
    it(`writes canonical txids and sizes on ${chain}`, async () => {
      const lib = Libs.get(chain).lib;
      const network = chain === 'BTC' ? 'mainnet' : 'testnet';
      let block;
      switch (chain) {
        case 'BTC':
          block = lib.Block.fromString(require(fixture('bitcore-lib', 'benchmark/block-357238.json')));
          assert.equal(block.transactions.length, 369);
          break;
        case 'BCH':
          block = lib.Block.fromBuffer(readFileSync(fixture('bitcore-lib-cash', 'test/data/chipnet-121957.dat')));
          assert(block.transactions.some(tx => tx.outputs.some(output => output.tokenData)));
          break;
        case 'LTC':
          block = lib.Block.fromString(require(fixture('bitcore-lib-ltc', 'test/data/blk1856255-testnet.js')).blockhex);
          assert(block.transactions.some(tx => tx.hash !== tx.witnessHash));
          break;
        case 'DOGE': {
          const raw = Buffer.from(require(fixture('bitcore-lib-doge', 'test/data/blk160775-testnet.js')).blockhex, 'hex');
          const original = lib.Block.fromBuffer(raw);
          const header = Buffer.from(raw.subarray(0, 80));
          header.writeInt32LE(header.readInt32LE(0) + 0x100, 0);
          // Build an AuxPow wire header from the fixture's coinbase and parent header.
          block = lib.Block.fromBuffer(Buffer.concat([
            header, original.transactions[0].toBuffer(), Buffer.alloc(32),
            Buffer.alloc(10), raw.subarray(0, 80), raw.subarray(80)
          ]));
          assert(block.header.toBuffer().length > 80);
          break;
        }
      }

      const params = { block, chain, network, initialSyncComplete: false, initialHeight: 900000 };
      const expectedBlockSize = block.toBuffer().length;
      const txs = block.transactions.map(tx => ({
        txid: tx.hash, size: tx.toBuffer().length, coinbase: tx.isCoinbase(), outputs: tx.outputs.length
      }));
      const { blockWrites, coinWrites, txWrites } = mockWrites();
      const standaloneOp = await BitcoinBlockStorage.getBlockOp(params);
      assert.equal(standaloneOp.updateOne.update.$set.size, expectedBlockSize);
      const serialize = sandbox.spy(lib.Transaction.prototype, 'toBufferWriter');
      await BitcoinBlockStorage.processBlock(params);

      if (chain !== 'DOGE') {
        assert.equal(serialize.callCount, txs.length);
      }
      assert.equal(blockWrites.firstCall.args[0][0].updateOne.update.$set.size, expectedBlockSize);
      const writtenTxs: TxOp[] = txWrites.args.flatMap(([ops]) => ops);
      assert.deepEqual(writtenTxs.map(({ updateOne: { filter, update: { $set } } }) => ({
        txid: filter.txid, size: $set.size, coinbase: $set.coinbase, outputs: $set.outputCount
      })), txs);
      const coinOps: (MintOp | SpendOp)[] = coinWrites.args.flatMap(([ops]) => ops);
      const mintedIds = coinOps
        .filter(op => 'mintHeight' in op.updateOne.update.$set)
        .map(op => op.updateOne.filter.mintTxid);
      assert.deepEqual(mintedIds, txs.flatMap(tx => Array<string>(tx.outputs).fill(tx.txid)));
      const spentIds = new Set(coinOps
        .filter(op => 'spentTxid' in op.updateOne.update.$set)
        .map(op => op.updateOne.update.$set.spentTxid));
      assert.deepEqual(spentIds, new Set(txs.filter(tx => !tx.coinbase).map(tx => tx.txid)));
    });
  }

  it('recomputes metadata when a parsed transaction is changed and imported again', async () => {
    const lib = Libs.get('BTC').lib;
    const raw = require(fixture('bitcore-lib-ltc', 'test/data/blk1856255-testnet.js')).blockhex;
    const tx = lib.Block.fromString(raw).transactions[1];
    const originalTxid = tx.hash;
    const originalSize = tx.toBuffer().length;
    const { txWrites } = mockWrites();
    const params = { txs: [tx], chain: 'BTC', network: 'testnet', height: 2, initialSyncComplete: false };

    await TransactionStorage.batchImport(params);
    tx.inputs[0].setWitnesses([Buffer.alloc(253, 1)]);
    await TransactionStorage.batchImport(params);
    const size = tx.toBuffer().length;
    assert.notEqual(size, originalSize);
    tx.nLockTime++;
    await TransactionStorage.batchImport(params);
    const txid = tx.hash;
    assert.notEqual(txid, originalTxid);
    assert.deepEqual(txWrites.args.map(([ops]) => [
      ops[0].updateOne.filter.txid, ops[0].updateOne.update.$set.size
    ]), [[originalTxid, originalSize], [originalTxid, size], [txid, size]]);
  });

  it('keeps caller-provided hashes on standalone methods and supports custom serializers', async () => {
    const lib = Libs.get('BTC').lib;
    const raw = require(fixture('bitcore-lib', 'benchmark/block-357238.json'));
    const tx = lib.Block.fromString(raw).transactions[1];
    const providedHash = 'a'.repeat(64);
    const params = { txs: [tx], chain: 'BTC', network: 'mainnet', height: 2, initialSyncComplete: false };
    const { txWrites } = mockWrites();

    tx._hash = providedHash;
    const spentStream = new Readable({ objectMode: true, read() {} });
    TransactionStorage.streamSpendOps({ ...params, spentStream });
    const spends: SpendOp[] = spentStream.read();
    assert(spends.every(({ updateOne }) => updateOne.update.$set.spentTxid === providedHash));
    const txStream = new Readable({ objectMode: true, read() {} });
    await TransactionStorage.streamTxOps({ ...params, txStream });
    assert.equal(txStream.read()[0].updateOne.filter.txid, providedHash);

    const customHash = 'b'.repeat(64);
    Object.defineProperty(tx, 'hash', { value: customHash });
    tx.toBuffer = () => Buffer.alloc(321);
    await TransactionStorage.batchImport(params);
    const [{ updateOne }] = txWrites.firstCall.args[0];
    assert.equal(updateOne.filter.txid, customHash);
    assert.equal(updateOne.update.$set.size, 321);
  });

  it('uses the same canonical ID in the mempool spend query and upserts', async () => {
    const { coinFind, txWrites } = mockWrites();
    sandbox.stub(TransactionStorage, 'pruneMempool').resolves();
    sandbox.stub(EventStorage, 'signalAddressCoins').resolves();
    sandbox.stub(EventStorage, 'signalTxs').resolves();
    const lib = Libs.get('BTC').lib;
    const raw = require(fixture('bitcore-lib-ltc', 'test/data/blk1856255-testnet.js')).blockhex;
    const tx = lib.Block.fromString(raw).transactions[1];
    const txid = tx.hash;
    tx._hash = tx.witnessHash;
    assert.notEqual(tx._hash, txid);
    const height = SpentHeightIndicators.pending;
    const mempoolTime = new Date();
    await TransactionStorage.batchImport({
      txs: [tx], chain: 'BTC', network: 'testnet', height, mempoolTime, initialSyncComplete: true
    });

    assert.deepEqual(coinFind.lastCall.args[0].spentTxid, { $in: [txid] });
    const [{ updateOne }] = txWrites.firstCall.args[0];
    assert.equal(updateOne.filter.txid, txid);
    assert.equal(updateOne.update.$setOnInsert.size, tx.toBuffer().length);
    assert.equal(updateOne.update.$setOnInsert.mempoolTime, mempoolTime);
  });

  it('copies parent transaction metadata and finishes pre-fork imports', async () => {
    const { coinWrites, txWrites, txFind } = mockWrites();
    const txid = 'a'.repeat(64);
    const parent = { txid, size: 100, coinbase: true, fee: 0, locktime: 0, inputCount: 1, outputCount: 1, value: 1 };
    txFind.returns({ toArray: async () => [parent] });
    await TransactionStorage.batchImport({
      txs: [], height: 1, chain: 'BCH', network: 'mainnet', parentChain: 'BTC', forkHeight: 2, initialSyncComplete: false
    });
    assert.equal(coinWrites.callCount, 0);
    const [{ updateOne }] = txWrites.firstCall.args[0];
    assert.equal(updateOne.filter.txid, parent.txid);
    assert.equal(updateOne.update.$set.size, parent.size);
  });
});
