/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone CommonJS benchmark and parity checks. */
'use strict';

const assert = require('node:assert/strict');
const os = require('node:os');
const { btc, bch, Escrow, without, header, proof, transaction, keys } = require('./test-utxo-validation.cjs');

let sink;
function rate(run, ms) {
  const start = performance.now();
  let count = 0;
  do {
    for (let i = 0; i < 16; i++) sink = run();
    count += 16;
  } while (performance.now() - start < ms);
  assert.notEqual(sink, undefined);
  return count * 1000 / (performance.now() - start);
}

const operations = [];
function add(name, run, before) {
  operations.push({ name, run, before, samples: [[], []] });
}

for (const [count, stride] of [[1001, 999], [1001, 8], [129, 1]]) {
  const { block, matched } = proof(btc.chain, count, stride);
  const off = run => without(btc, ['partialMerkle'], run);
  const description = `${count} txs, ${block.hashes.length} proof hashes`;
  add(`BTC verify partial root (${description})`, () => block.validMerkleTree(), off);
  add(`BTC extract partial matches (${description})`, () => block.filterdTxsHash(), off);
  add(`BTC find partial match (${description})`, () => block.hasTransaction(matched.at(-1)), off);
}

const signed = transaction(btc.chain).toBuffer();
const full = new btc.chain.Block({ header: header(), transactions: Array.from({ length: 1001 }, (_, index) => {
  const tx = new btc.chain.Transaction(signed);
  tx.nLockTime = index;
  return tx;
}) });
full.header.merkleRoot = full.getMerkleTree().at(-1);
add('BTC validate full block (1001 txs)', () => full.validMerkleRoot(), run => without(btc, ['merkleRoot'], run));

const publicKeys = keys(64);
for (const count of [4, 16, 64]) {
  const input = publicKeys.slice(0, count);
  add(`BCH build escrow redeem script (${count} keys)`, () => bch.chain.Script.buildEscrowOut(input, publicKeys[0]),
    run => without(bch, ['escrowKeyRoot', 'escrowMerkleRoot'], run));
}
const leaves = publicKeys.map(key => bch.chain.crypto.Hash.sha256ripemd160(key.toBuffer())).slice(0, 33);
add('BCH get escrow root (33 prehashed leaves)', () => Escrow.getMerkleRoot(leaves),
  run => without(bch, ['escrowMerkleRoot'], run));

const pow = btc.chain.BlockHeader.fromObject(header());
add('BTC validate proof of work (cold header ID)', () => {
  pow._id = undefined;
  return pow.validProofOfWork();
}, run => without(btc, ['hash256'], run));
add('BTC parse transaction and compute txid', () => new btc.chain.Transaction(signed).id,
  run => without(btc, ['hash256'], run));
const manyInputs = transaction(btc.chain, 32).toBuffer();
add('BTC parse transaction and compute txid (32 inputs)', () => new btc.chain.Transaction(manyInputs).id,
  run => without(btc, ['hash256'], run));
add('BCH public key to address', () => publicKeys[0].toAddress(),
  run => without(bch, ['hash160'], run));
const spending = new btc.chain.Transaction(signed);
const { Sighash } = btc.chain.Transaction;
for (const size of [25, 128, 512, 2048, 8192]) {
  const script = btc.chain.Script.fromBuffer(Buffer.alloc(size, 0x51));
  add(`BTC legacy sighash (${size} script bytes)`, () =>
    Sighash.sighash(spending, btc.chain.crypto.Signature.SIGHASH_ALL, 0, script),
  run => without(btc, ['hash256'], run));
  const redeem = bch.chain.Script.fromBuffer(Buffer.alloc(size, 0x51));
  add(`BCH create script hash output (${size} script bytes)`, () => bch.chain.Script.buildScriptHashOut(redeem),
    run => without(bch, ['hash160'], run));
}

const filter = new RegExp(process.env.BENCH_FILTER ?? '', 'i');
const selected = operations.filter(op => filter.test(op.name));
assert.ok(selected.length);
for (const { run, before } of selected) {
  before(() => rate(run, 100));
  rate(run, 100);
}
for (let round = 0; round < 5; round++) {
  for (const { run, before, samples } of selected) {
    for (const mode of round % 2 ? [1, 0] : [0, 1]) {
      samples[mode].push(mode ? rate(run, 180) : before(() => rate(run, 180)));
    }
  }
}
const results = selected.map(({ name, samples }) => {
  const [before, after] = samples.map(values => Math.round(values.slice().sort((a, b) => a - b)[2]));
  return { name, before, after, speedup: +(after / before).toFixed(2) };
});
console.log(JSON.stringify({ node: process.version, cpu: os.cpus()[0].model, results }, null, 2));
