/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone CommonJS benchmark and parity checks. */
/* eslint-disable no-bitwise -- Transaction flags and compact block difficulty are bit fields. */
'use strict';

const assert = require('node:assert/strict');
const os = require('node:os');
const { isMainThread, parentPort, Worker, workerData } = require('node:worker_threads');

const packages = ['bitcore-lib', 'bitcore-lib-cash', 'bitcore-lib-doge', 'bitcore-lib-ltc'];
const inputCount = 32;

function libraries() {
  process.env.BITCORE_ECDSA_BACKEND = 'native';
  return packages.map(name => {
    const chain = require(`../packages/${name}`);
    const { native } = require(`../packages/${name}/lib/crypto/ecdsa-native`);
    assert.equal(typeof native.merkleParents, 'function', 'Build the addon to run this benchmark');
    return { chain, native };
  });
}

function withoutBatching({ chain, native }, run) {
  const hash = chain.crypto.Hash.sha256sha256;
  const merkle = native.merkleParents;
  try {
    // Preserve the real hashing implementation while making the guarded paths
    // defer to their original code. The same curve backend is used in both modes.
    chain.crypto.Hash.sha256sha256 = data => hash(data);
    native.merkleParents = undefined;
    return run();
  } finally {
    chain.crypto.Hash.sha256sha256 = hash;
    native.merkleParents = merkle;
  }
}

function makeTransaction(chain, type, count) {
  const key = new chain.PrivateKey(chain.crypto.BN.fromBuffer(Buffer.alloc(32, 1)));
  const address = chain.Address.fromPublicKey(key.publicKey, undefined, type);
  const receivingAddress = new chain.PrivateKey(chain.crypto.BN.fromBuffer(Buffer.alloc(32, 2))).toAddress();
  const script = chain.Script.fromAddress(address).toHex();
  const utxos = Array.from({ length: count }, (_, index) => ({
    txId: chain.crypto.Hash.sha256(Buffer.from(`utxo benchmark ${type} ${index}`)).toString('hex'),
    outputIndex: index % 3,
    script,
    satoshis: 100000 + index
  }));
  const make = () => new chain.Transaction().from(utxos).to(receivingAddress, 50000)
    .to(receivingAddress, 25000).to(receivingAddress, 10000);
  return { key, make };
}

function fixtures(libs) {
  const [bitcoin, cash, dogecoin, litecoin] = libs;
  return [
    ['BTC 32 legacy inputs', bitcoin, bitcoin.chain.Address.PayToPublicKeyHash],
    ['BTC 32 SegWit inputs', bitcoin, bitcoin.chain.Address.PayToWitnessPublicKeyHash],
    ['BTC 32 Taproot inputs', bitcoin, bitcoin.chain.Address.PayToTaproot],
    ['BCH 32 fork-ID inputs', cash, cash.chain.Address.PayToPublicKeyHash],
    ['DOGE 32 legacy inputs', dogecoin, dogecoin.chain.Address.PayToPublicKeyHash],
    ['LTC 32 SegWit inputs', litecoin, litecoin.chain.Address.PayToWitnessPublicKeyHash]
  ].map(([name, lib, type]) => ({ name, lib, type, ...makeTransaction(lib.chain, type, inputCount) }));
}

function makeBlock(chain, size) {
  const fixture = makeTransaction(chain, chain.Address.PayToPublicKeyHash, 2);
  const signed = fixture.make().sign(fixture.key).toBuffer();
  const transactions = Array.from({ length: size }, (_, index) => {
    const tx = new chain.Transaction(signed);
    tx.nLockTime = index;
    return tx;
  });
  return new chain.Block({
    header: { version: 1, prevHash: Buffer.alloc(32), merkleRoot: Buffer.alloc(32), time: 1700000000, bits: 0x1d00ffff, nonce: 0 },
    transactions
  });
}

function originalTarget(chain, header, bits) {
  const { BN } = chain.crypto;
  bits = bits || header.bits;
  let target = new BN(bits & 0xffffff);
  let shift = 8 * ((bits >>> 24) - 3);
  while (shift-- > 0) target = target.mul(new BN(2));
  return target;
}

function check(libs) {
  const CashInterpreter = require('../packages/bitcore-lib-cash/lib/script/interpreter');

  const [bitcoin, cash, , litecoin] = libs;
  const validSignature = (tx, sig) => tx.inputs[sig.inputIndex].isValidSignature(tx, sig);
  const ltcLegacy = litecoin.chain.Address.PayToPublicKeyHash;
  const cases = fixtures(libs).concat({ lib: litecoin, type: ltcLegacy, ...makeTransaction(litecoin.chain, ltcLegacy, inputCount) });
  for (const { lib, type, make, key } of cases) {
    const { chain } = lib;
    const tx = make();
    const sig = chain.crypto.Signature;
    const taproot = chain.Address.PayToTaproot && type === chain.Address.PayToTaproot;
    const forkId = chain === cash.chain ? sig.SIGHASH_FORKID : 0;
    const flags = [sig.SIGHASH_ALL, sig.SIGHASH_NONE, sig.SIGHASH_SINGLE, sig.SIGHASH_ANYONECANPAY | sig.SIGHASH_ALL];
    if (taproot) flags.push(sig.SIGHASH_DEFAULT);
    for (const flag of flags) {
      const sigtype = flag | forkId;
      const original = withoutBatching(lib, () => tx.getSignatures(key, sigtype));
      const batched = tx.getSignatures(key, sigtype);
      assert.ok(original.length > 0);
      assert.deepEqual(batched.map(s => s.inputIndex), original.map(s => s.inputIndex));
      if (taproot) {
        for (const signature of batched) {
          assert.ok(withoutBatching(lib, () => validSignature(tx, signature)));
        }
      } else {
        assert.deepEqual(batched.map(s => s.toObject()), original.map(s => s.toObject()));
      }
    }
    if (forkId) {
      const original = withoutBatching(lib, () => tx.getSignatures(key, sig.SIGHASH_ALL));
      assert.deepEqual(tx.getSignatures(key, sig.SIGHASH_ALL).map(s => s.toObject()), original.map(s => s.toObject()));
      const { Sighash } = chain.Transaction;
      const { script, _satoshisBN } = tx.inputs[0].output;
      const replay = CashInterpreter.SCRIPT_ENABLE_SIGHASH_FORKID | CashInterpreter.SCRIPT_ENABLE_REPLAY_PROTECTION;
      const signature = Sighash.sign(tx, key, sig.SIGHASH_ALL | forkId, 0, script, _satoshisBN, replay);
      assert.ok(Sighash.verify(tx, signature, key.publicKey, 0, script, _satoshisBN, replay));
      assert.ok(!Sighash.verify(tx, signature, key.publicKey, 0, script, _satoshisBN));
    }
    const signed = make().sign(key);
    assert.ok(signed.inputs.every(input => input.isFullySigned()));
    if (!taproot) {
      assert.deepEqual(signed.toBuffer(), withoutBatching(lib, () => make().sign(key).toBuffer()));
    }
    const prior = tx.getSignatures(key);
    assert.equal(prior.length, inputCount);
    tx.inputs[inputCount - 1].sequenceNumber--;
    tx.inputs[0].prevTxId[0] ^= 1;
    tx.outputs[0].satoshis++;
    const next = tx.getSignatures(key);
    for (const signature of next) assert.ok(withoutBatching(lib, () => validSignature(tx, signature)));
    assert.ok(!validSignature(tx, prior[0]));

    const mutating = make();
    const second = mutating.inputs[1];
    const getSignatures = second.getSignatures;
    second.getSignatures = function(...args) {
      mutating.outputs[0].satoshis++;
      return getSignatures.apply(this, args);
    };
    const signatures = mutating.getSignatures(key);
    assert.equal(signatures.length, inputCount);
    assert.ok(validSignature(mutating, signatures[1]));
    assert.ok(!validSignature(mutating, signatures[0]));
  }

  const { chain } = bitcoin;
  const segwit = makeTransaction(chain, chain.Address.PayToWitnessPublicKeyHash, 4);
  const taproot = makeTransaction(chain, chain.Address.PayToTaproot, 4);
  const mixed = taproot.make();
  mixed.inputs.unshift(...segwit.make().inputs);
  const mixedSignatures = mixed.getSignatures(taproot.key);
  assert.equal(mixedSignatures.length, 8);
  assert.ok(mixedSignatures.every(sig => withoutBatching(bitcoin, () => validSignature(mixed, sig))));
  for (const signature of mixedSignatures) mixed.applySignature(signature);
  assert.ok(mixed.isFullySigned());

  const key2 = new chain.PrivateKey(chain.crypto.BN.fromBuffer(Buffer.alloc(32, 3)));
  const pubkeys = [segwit.key.publicKey, key2.publicKey];
  const redeem = chain.Script.buildMultisigOut(pubkeys, 2);
  for (const redeemScript of [redeem, chain.Script.buildWitnessMultisigOutFromScript(redeem)]) {
    const script = chain.Script.buildScriptHashOut(redeemScript).toHex();
    const make = () => new chain.Transaction().from(Array.from({ length: 4 }, (_, index) => ({
      txId: Buffer.alloc(32, index + 1).toString('hex'), outputIndex: 0, satoshis: 100000, script
    })), pubkeys, 2).to(segwit.key.toAddress(), 350000);
    const signed = make().sign([segwit.key, key2]);
    assert.ok(signed.isFullySigned());
    assert.deepEqual(signed.toBuffer(), withoutBatching(bitcoin, () => make().sign([segwit.key, key2]).toBuffer()));
  }

  for (const lib of libs) {
    const { header } = makeBlock(lib.chain, 0);
    for (const bits of [0, 0x190, 0x0199ffff, 0x0200ffff, 0x0300ffff, 0x1d00ffff, 0xff00ffff]) {
      assert.equal(header.getTargetDifficulty(bits).toString(16), originalTarget(lib.chain, header, bits).toString(16));
    }
    for (const size of [0, 1, 7, 8, 9, 64, 65]) {
      const block = makeBlock(lib.chain, size);
      const expected = withoutBatching(lib, () => block.getMerkleTree());
      assert.deepEqual(block.getMerkleTree(), expected);
      const root = expected[expected.length - 1];
      block.header.merkleRoot = root;
      assert.ok(block.validMerkleRoot());
      if (size > 0) {
        block.transactions[0].nLockTime++;
        assert.ok(!block.validMerkleRoot());
      }
    }
  }
  const { native } = libs[0];
  const maxLeaves = 65_536;
  const full = native.merkleParents(Buffer.alloc(maxLeaves * 32), maxLeaves);
  let root = Buffer.alloc(32);
  for (let depth = 0; depth < 16; depth++) root = bitcoin.chain.crypto.Hash.sha256sha256(Buffer.concat([root, root]));
  assert.equal(full.length, (maxLeaves - 1) * 32);
  assert.deepEqual(full.subarray(-32), root);
  const shared = new Uint8Array(new SharedArrayBuffer(64));
  for (const [leaves, count] of [[shared, 2], [Buffer.alloc(64), 3], [Buffer.alloc(64), 65537], [Buffer.alloc(64), NaN]]) {
    assert.throws(() => native.merkleParents(leaves, count));
  }
}

function rate(run) {
  function sample(ms) {
    const start = performance.now();
    let count = 0;
    do {
      run();
      count++;
    } while (performance.now() - start < ms);
    return count * 1000 / (performance.now() - start);
  }
  sample(150);
  return sample(350);
}

function sample(before) {
  const libs = libraries();
  const measure = (lib, run) => before ? withoutBatching(lib, () => rate(run)) : rate(run);
  const result = {};
  for (const { name, lib, make, key } of fixtures(libs)) {
    result[name] = measure(lib, () => make().sign(key));
  }
  const [bitcoin] = libs;
  const block = makeBlock(bitcoin.chain, 1001);
  block.header.merkleRoot = withoutBatching(bitcoin, () => block.getMerkleRoot());
  result['BTC validate Merkle root with 1001 transactions'] = measure(bitcoin, () => assert.ok(block.validMerkleRoot()));
  const difficulties = Array.from({ length: 512 }, (_, index) => 0x17000000 + 67377 + index);
  const target = before ? bits => originalTarget(bitcoin.chain, block.header, bits) : bits => block.header.getTargetDifficulty(bits);
  let totalBits = 0;
  result['BTC decode compact targets'] = difficulties.length * rate(() => {
    for (const bits of difficulties) totalBits += target(bits).bitLength();
  });
  assert.ok(totalBits > 0);
  return result;
}

function workerSample(before) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(__filename, { workerData: before });
    worker.once('message', resolve);
    worker.once('error', reject);
    worker.once('exit', code => reject(new Error(`UTXO sample worker exited with status ${code}`)));
  });
}

async function main() {
  if (!isMainThread) {
    parentPort.postMessage(sample(workerData));
    return;
  }
  check(libraries());
  if (process.argv.includes('--test')) {
    console.log('UTXO signing and Merkle parity checks passed.');
    return;
  }
  const samples = { before: [], after: [] };
  for (let round = 0; round < 5; round++) {
    for (const mode of round % 2 ? ['after', 'before'] : ['before', 'after']) {
      samples[mode].push(await workerSample(mode === 'before'));
    }
  }
  const results = Object.fromEntries(Object.keys(samples.before[0]).map(name => {
    const median = mode => samples[mode].map(sample => sample[name]).sort((a, b) => a - b)[2];
    const before = median('before');
    const after = median('after');
    return [name, { before, after, speedup: after / before }];
  }));
  console.log(JSON.stringify({ node: process.version, cpu: os.cpus()[0].model, results, samples }, null, 2));
}

main().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
