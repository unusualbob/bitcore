'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { createHash } = crypto;
const { cpus } = require('node:os');
const { resolve } = require('node:path');
const { performance } = require('node:perf_hooks');

// Run from either revision with the same Node binary and installed dependencies.
// An optional argument selects a different checkout to benchmark.
const root = resolve(process.argv[2] || resolve(__dirname, '..'));
const rounds = Number(process.env.BENCH_ROUNDS || 5);
const sampleMs = Number(process.env.BENCH_MS || 200);
// Disable one-shot hashing before importing Bitcore for an isolated comparison.
if (process.env.BENCH_STREAMING_SHA256 === '1') crypto.hash = undefined;
assert(Number.isInteger(rounds) && rounds > 0);
assert(Number.isFinite(sampleMs) && sampleMs > 0);
const filter = new RegExp(process.env.BENCH_FILTER || '');
const fixtures = Array.from({ length: 1024 }, (_, index) => {
  const digest = createHash('sha256').update('address benchmark ' + index).digest();
  const pubkey = Buffer.concat([Buffer.from([2 + (index & 1)]), digest]);
  return {
    digest,
    hash: digest.subarray(0, 20),
    nonceData: Buffer.concat([digest, Buffer.from([0]), digest, digest]),
    childData: Buffer.concat([pubkey, Buffer.alloc(4)])
  };
});

const operations = [];
function add(name, operation, prepare) {
  if (filter.test(name)) operations.push({ name, operation, prepare, samples: [] });
}

for (const [chain, suffix] of [['BTC', ''], ['BCH', '-cash'], ['LTC', '-ltc'], ['DOGE', '-doge']]) {
  const { Address, Transaction, crypto: { Hash }, encoding: { Base58, Base58Check } } =
    require(resolve(root, 'packages', 'bitcore-lib' + suffix));
  const addressTypes = [Address.PayToPublicKeyHash, Address.PayToWitnessPublicKeyHash, Address.PayToTaproot];
  const labels = [chain === 'BCH' ? 'CashAddr' : 'P2PKH', 'SegWit v0', 'Taproot'];
  addressTypes.forEach((type, index) => {
    if (!type) return;
    const addresses = fixtures.map(({ digest, hash }) =>
      new Address(index === 2 ? digest : hash, 'livenet', type));
    const strings = addresses.map(address => address.toString());
    const label = chain + ' ' + labels[index];
    assert.deepEqual(Address.fromString(strings[0]).hashBuffer, addresses[0].hashBuffer);
    add(label + ' encode', i => addresses[i].toString());
    add(label + ' decode', i => Address.fromString(strings[i]));
    if (chain === 'BCH') {
      const legacy = addresses.map(address => address.toLegacyAddress());
      add('BCH legacy encode', i => addresses[i].toLegacyAddress());
      add('BCH legacy decode', i => Address.fromString(legacy[i]));
    }
  });
  // The four packages expose the same codecs and HMAC code, measured directly on BTC.
  if (chain === 'BTC') {
    const payloads = fixtures.map(({ hash }) => Buffer.concat([Buffer.from([0]), hash]));
    const checked = payloads.map(payload => Base58Check.encode(payload));
    const raw = checked.map(address => Base58.decode(address));
    add('Base58 encode 25 bytes', i => Base58.encode(raw[i]));
    add('Base58 decode 25 bytes', i => Base58.decode(checked[i]));
    add('Base58Check encode 21 bytes', i => Base58Check.encode(payloads[i]));
    add('Base58Check decode 21 bytes', i => Base58Check.decode(checked[i]));
    const extended = fixtures.map(({ digest, childData }) => Buffer.concat([digest, childData, digest.subarray(0, 9)]));
    const extendedStrings = extended.map(payload => Base58Check.encode(payload));
    add('Base58Check encode 78 bytes', i => Base58Check.encode(extended[i]));
    add('Base58Check decode 78 bytes', i => Base58Check.decode(extendedStrings[i]));
    add('HMAC SHA256 RFC6979-sized', i => Hash.sha256hmac(fixtures[i].nonceData, fixtures[i].digest));
    add('HMAC SHA512 BIP32-sized', i => Hash.sha512hmac(fixtures[i].childData, fixtures[i].digest));
    const headers = fixtures.map(({ digest }) => Buffer.concat([digest, digest, digest.subarray(0, 16)]));
    add('BTC SHA256 header 80 bytes', i => Hash.sha256(headers[i]));
    add('BTC SHA256d header 80 bytes', i => Hash.sha256sha256(headers[i]));
    const transactionBytes = fixtures.map(({ digest }, i) => new Transaction()
      .from({ txId: digest.toString('hex'), outputIndex: 0,
        script: '76a914' + fixtures[i].hash.toString('hex') + '88ac', satoshis: 100000 })
      .to(checked[i], 75000)
      .to(checked[(i + 1) % fixtures.length], 24000)
      .toBuffer());
    const expectedId = createHash('sha256').update(createHash('sha256').update(transactionBytes[0]).digest())
      .digest().reverse().toString('hex');
    assert.equal(new Transaction(transactionBytes[0]).id, expectedId);
    add('BTC SHA256d unsigned transaction', i => Hash.sha256sha256(transactionBytes[i]));
    add('BTC cold txid', (i, batch) => batch[i].id,
      () => transactionBytes.map(bytes => new Transaction(bytes)));
    add('BTC parse transaction and txid', i => new Transaction(transactionBytes[i]).id);
  }
}

const BloomFilter = require(resolve(root, 'packages/bitcore-p2p/lib/bloomfilter'));
const bloom = BloomFilter.create(fixtures.length, 0.001, 0x12345678);
for (const { hash } of fixtures) bloom.insert(hash);
assert(bloom.contains(fixtures[0].hash));
const misses = fixtures.map(({ digest }) => digest.subarray(12));
add('P2P bloom insert 20 bytes', i => bloom.insert(fixtures[i].hash));
add('P2P bloom hit 20 bytes', i => bloom.contains(fixtures[i].hash));
add('P2P bloom miss 20 bytes', i => bloom.contains(misses[i]));

let sink;
function measure({ operation, prepare }, duration) {
  let count = 0;
  let elapsed = 0;
  do {
    const batch = prepare?.();
    const start = performance.now();
    for (let index = 0; index < fixtures.length; index++) sink = operation(index, batch);
    elapsed += performance.now() - start;
    count += fixtures.length;
  } while (elapsed < duration);
  assert.notEqual(sink, undefined);
  return Math.round(count * 1000 / elapsed);
}

assert(operations.length, 'BENCH_FILTER did not match any operation');
for (const operation of operations) measure(operation, 100);
for (let round = 0; round < rounds; round++) {
  const order = round % 2 ? operations.slice().reverse() : operations;
  for (const operation of order) operation.samples.push(measure(operation, sampleMs));
}
const results = operations.map(({ name, samples }) => {
  const sorted = samples.slice().sort((a, b) => a - b);
  const median = (sorted[Math.floor((rounds - 1) / 2)] + sorted[Math.floor(rounds / 2)]) / 2;
  return { name, median, samples };
});
console.log(JSON.stringify({
  node: process.version,
  openssl: process.versions.openssl,
  oneShotHashAvailable: typeof crypto.hash === 'function',
  cpu: cpus()[0]?.model,
  rounds,
  sampleMs,
  results
}, null, 2));
