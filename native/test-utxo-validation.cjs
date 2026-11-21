/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone CommonJS parity checks. */
/* eslint-disable no-bitwise -- Proof flags and compact targets are bit fields. */
'use strict';

process.env.BITCORE_ECDSA_BACKEND = 'native';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const Escrow = require('../packages/bitcore-lib-cash/lib/script/escrow');

const packages = ['bitcore-lib', 'bitcore-lib-cash', 'bitcore-lib-doge', 'bitcore-lib-ltc'];
const libs = packages.map(name => ({
  chain: require(`../packages/${name}`),
  native: require(`../packages/${name}/lib/crypto/ecdsa-native`).native
}));
const [btc, bch] = libs;

function without(lib, names, run) {
  const originals = names.map(name => lib.native[name]);
  try {
    for (const name of names) lib.native[name] = undefined;
    return run();
  } finally {
    for (const [index, name] of names.entries()) lib.native[name] = originals[index];
  }
}

function header() {
  return {
    version: 1, prevHash: Buffer.alloc(32), merkleRoot: Buffer.alloc(32),
    time: 1700000000, bits: 0x1d00ffff, nonce: 0
  };
}

function proof(chain, count, stride) {
  const { sha256sha256, sha256 } = chain.crypto.Hash;
  const leaves = Array.from({ length: count }, (_, index) => sha256(Buffer.from(String(index))));
  const matches = leaves.map((_, i) => i % stride === 0);
  const levels = [leaves];
  while (levels.at(-1).length > 1) {
    const level = levels.at(-1);
    levels.push(Array.from({ length: Math.ceil(level.length / 2) }, (_, i) =>
      sha256sha256(Buffer.concat([level[i * 2], level[i * 2 + 1] ?? level[i * 2]]))));
  }
  const hashes = [];
  const flags = [];
  let bits = 0;
  function visit(height, pos) {
    const width = 2 ** height;
    const matched = matches.slice(pos * width, (pos + 1) * width).some(Boolean);
    const byte = bits >> 3;
    flags[byte] = (flags[byte] ?? 0) | (Number(matched) << (bits++ & 7));
    if (!height || !matched) {
      hashes.push(mixedHex(levels[height][pos]));
      return;
    }
    visit(height - 1, pos * 2);
    if (pos * 2 + 1 < levels[height - 1].length) visit(height - 1, pos * 2 + 1);
  }
  visit(levels.length - 1, 0);
  return {
    block: new chain.MerkleBlock({ header: { ...header(), merkleRoot: levels.at(-1)[0] },
      numTransactions: count, hashes, flags }),
    matched: leaves.filter((_, i) => matches[i]).map(mixedHex)
  };
}

function mixedHex(hash) {
  const hex = hash.toString('hex');
  return hex.slice(0, 32).toUpperCase() + hex.slice(32);
}

function transaction(chain, count = 2) {
  const key = new chain.PrivateKey(chain.crypto.BN.fromBuffer(Buffer.alloc(32, 1)));
  const address = key.toAddress();
  const script = chain.Script.fromAddress(address).toHex();
  return new chain.Transaction().from(Array.from({ length: count }, (_, index) => ({
    txId: chain.crypto.Hash.sha256(Buffer.from(String(index))).toString('hex'),
    outputIndex: 0, satoshis: 100000, script
  }))).to(address, 1000).sign(key);
}

function keys(count) {
  const { PrivateKey, PublicKey, crypto } = bch.chain;
  return Array.from({ length: count }, (_, index) => {
    const key = new PrivateKey(new crypto.BN(index + 1)).publicKey;
    return index % 2 === 0 ? key : new PublicKey(key.point, { compressed: false });
  }).reverse();
}

function outcome(run) {
  try {
    return { result: run() };
  } catch (err) {
    return { name: err.name, message: err.message };
  }
}

function checkPartial(lib) {
  const { chain, native } = lib;
  const disabled = ['partialMerkle'];
  const compare = (block, match) => {
    for (const run of [() => block.validMerkleTree(), () => block.hasTransaction(match),
      ...(block.filterdTxsHash ? [() => block.filterdTxsHash()] : [])]) {
      assert.deepEqual(outcome(run), without(lib, disabled, () => outcome(run)));
    }
  };

  for (const [count, stride] of [[1, 1], [7, 1], [8, 1], [17, 1], [45, 7], [129, 4], [2001, 999]]) {
    const { block, matched } = proof(chain, count, stride);
    if (count === 8) {
      block.hashes = block.hashes.map(hash => hash.toUpperCase());
      for (let i = 0; i < matched.length; i++) matched[i] = matched[i].toUpperCase();
    }
    assert.ok(block.validMerkleTree());
    assert.ok(block.hasTransaction(matched.at(-1)));
    assert.ok(!block.hasTransaction(matched.at(-1).toLowerCase()));
    if (block.filterdTxsHash && count > 1 && block.hashes.length > 1) {
      assert.deepEqual(block.filterdTxsHash(), matched);
    }
    compare(block, matched.at(-1));
  }
  const { block, matched } = proof(chain, 45, 2);
  block.header.merkleRoot = Buffer.alloc(32);
  assert.equal(block.validMerkleTree(), false);
  for (const change of [
    obj => obj.flags.pop(),
    obj => obj.flags.fill(0),
    obj => obj.hashes.pop(),
    obj => { obj.hashes[2] = 42; },
    obj => { obj.hashes[2] = 'x'.repeat(64); },
    obj => { delete obj.flags[0]; },
    obj => { obj.flags = null; },
    obj => { obj.hashes = 'invalid'; }
  ]) {
    const invalid = new chain.MerkleBlock({ ...block, hashes: [...block.hashes], flags: [...block.flags] });
    change(invalid);
    compare(invalid, matched[0]);
  }
  const real = native.partialMerkle;
  let calls = 0;
  native.partialMerkle = (...args) => {
    calls++;
    return real(...args);
  };
  try {
    compare(block, matched[0]);
    assert.equal(calls, block.filterdTxsHash ? 3 : 2);
    calls = 0;

    // Both malformed proofs pass the JavaScript size prechecks and enter Rust.
    const unusedHash = proof(chain, 65, 8);
    unusedHash.block.hashes.push('ab'.repeat(32));
    const exhausted = proof(chain, 45, 1);
    exhausted.block.flags.length = Math.ceil(exhausted.block.hashes.length / 8);
    for (const { block: invalid, matched: [first] } of [unusedHash, exhausted]) {
      const packed = Buffer.from(invalid.hashes.join(''), 'hex');
      assert.equal(real(packed, Buffer.from(invalid.flags), invalid.numTransactions, true), null);
      assert.equal(real(packed, Buffer.from(invalid.flags), invalid.numTransactions, false), null);
      compare(invalid, first);
    }
    assert.equal(calls, block.filterdTxsHash ? 6 : 4);
    calls = 0;

    const { Hash } = chain.crypto;
    const original = Hash.sha256;
    Hash.sha256 = value => original(value);
    try {
      compare(block, matched[0]);
      assert.equal(calls, 0);
    } finally {
      Hash.sha256 = original;
    }
    const originalWidth = block._calcTreeWidth;
    block._calcTreeWidth = function(height) { return originalWidth.call(this, height); };
    compare(block, matched[0]);
    assert.equal(calls, 0);
    delete block._calcTreeWidth;
    const flag = block.flags[0];
    Object.defineProperty(block.flags, 0, { get: () => flag });
    compare(block, matched[0]);
    assert.equal(calls, 0);
  } finally {
    native.partialMerkle = real;
  }
}

function checkRoot(lib) {
  const { chain, native } = lib;
  const tx = transaction(chain);
  for (const size of [0, 1, 7, 8, 9, 65]) {
    const block = new chain.Block({ header: header(), transactions: Array(size).fill(tx) });
    const tree = block.getMerkleTree();
    const original = native.merkleRoot;
    let calls = 0;
    native.merkleRoot = (...args) => {
      calls++;
      return original(...args);
    };
    try {
      const jsRoot = without(lib, ['merkleRoot', 'merkleParents', 'hash256'], () => block.getMerkleRoot());
      assert.deepEqual(block.getMerkleRoot(), jsRoot);
      assert.deepEqual(jsRoot, tree.at(-1));
      block.header.merkleRoot = jsRoot;
      assert.ok(block.validMerkleRoot());
      assert.equal(calls, size >= 8 ? 2 : 0);
      const override = Buffer.alloc(32, 1);
      block.getMerkleTree = () => [override];
      block.getMerkleTree.call = undefined;
      assert.equal(block.getMerkleRoot(), override);
      assert.equal(calls, size >= 8 ? 2 : 0);
    } finally {
      native.merkleRoot = original;
    }
  }
}

function checkEscrow() {
  const disabled = ['escrowMerkleRoot', 'escrowKeyRoot', 'hash160'];
  const { Hash } = bch.chain.crypto;
  const input = keys(17);
  for (const size of [1, 7, 8, 9, 17]) {
    const hashes = input.slice(0, size).map(key => Hash.sha256ripemd160(key.toBuffer()));
    const root = () => Escrow.getMerkleRoot(hashes);
    const script = () => bch.chain.Script.buildEscrowOut(input.slice(0, size), input[0]).toBuffer();
    const roots = bch.native.escrowMerkleRoot;
    const keys = bch.native.escrowKeyRoot;
    let rootCalls = 0;
    let keyCalls = 0;
    bch.native.escrowMerkleRoot = (...args) => {
      rootCalls++;
      return roots(...args);
    };
    bch.native.escrowKeyRoot = (...args) => {
      keyCalls++;
      return keys(...args);
    };
    try {
      assert.deepEqual(root(), without(bch, disabled, root));
      assert.deepEqual(script(), without(bch, disabled, script));
      assert.equal(rootCalls, size >= 7 ? 1 : 0);
      assert.equal(keyCalls, size >= 8 ? 1 : 0);
    } finally {
      bch.native.escrowMerkleRoot = roots;
      bch.native.escrowKeyRoot = keys;
    }
  }
  const root = Escrow.getMerkleRoot;
  const hash = Hash.ripemd160;
  const sparse = input.slice();
  delete sparse[4];
  const sparseRoot = () => Escrow.generateMerkleRootFromPublicKeys(sparse);
  assert.deepEqual(outcome(sparseRoot), without(bch, disabled, () => outcome(sparseRoot)));
  try {
    Hash.ripemd160 = () => Buffer.alloc(20, 7);
    assert.deepEqual(Escrow.generateMerkleRootFromPublicKeys(input), Buffer.alloc(20, 7));
    Escrow.getMerkleRoot = leaves => leaves[0];
    assert.deepEqual(Escrow.generateMerkleRootFromPublicKeys(input), Buffer.alloc(20, 7));
  } finally {
    Escrow.getMerkleRoot = root;
    Hash.ripemd160 = hash;
  }
  try {
    Escrow.getMerkleRoot = () => Buffer.alloc(20, 8);
    assert.deepEqual(Escrow.generateMerkleRootFromPublicKeys(input), Buffer.alloc(20, 8));
  } finally {
    Escrow.getMerkleRoot = root;
  }
  let reads = 0;
  Object.defineProperty(Escrow, 'getMerkleRoot', {
    configurable: true,
    get() {
      reads++;
      return () => Buffer.alloc(20, 9);
    }
  });
  try {
    assert.deepEqual(Escrow.generateMerkleRootFromPublicKeys(input), Buffer.alloc(20, 9));
    assert.equal(reads, 1);
  } finally {
    Object.defineProperty(Escrow, 'getMerkleRoot', { value: root, writable: true, configurable: true });
  }
}

function checkHashes(lib) {
  const { Hash } = lib.chain.crypto;
  const shared = Buffer.from(new SharedArrayBuffer(40));
  const bytes = Buffer.from('0123456789abcdef1234567890');
  for (const [name, method] of [['hash256', 'sha256sha256'], ['hash160', 'sha256ripemd160']]) {
    const limit = name === 'hash256' ? 512 : 128;
    const run = name === 'hash256'
      ? data => lib.chain.BlockHeader.prototype._getHash.call({ toBuffer: () => data })
      : data => Hash[method](data);
    const original = lib.native[name];
    let calls = 0;
    lib.native[name] = data => {
      calls++;
      return original(data);
    };
    try {
      for (const data of [bytes, bytes.subarray(5), Buffer.alloc(limit), Buffer.alloc(limit + 1),
        Buffer.alloc(0), new Uint8Array(bytes), shared]) {
        const sha = crypto.createHash('sha256').update(data).digest();
        const expected = crypto.createHash(name === 'hash256' ? 'sha256' : 'ripemd160').update(sha).digest();
        assert.deepEqual(run(data), expected);
      }
      assert.equal(calls, 3);
      if (name === 'hash256') {
        assert.deepEqual(Hash[method](bytes), run(bytes));
        assert.equal(calls, 4);
        assert.deepEqual(transaction(lib.chain)._getHash(), without(lib, [name], () => transaction(lib.chain)._getHash()));
        assert.equal(calls, 5);
      }
      const expectedCalls = calls;
      const sha256 = Hash.sha256;
      Hash.sha256 = () => Buffer.alloc(32, 1);
      try {
        const expected = name === 'hash256' ? Buffer.alloc(32, 1) : Hash.ripemd160(Buffer.alloc(32, 1));
        assert.deepEqual(run(bytes), expected);
        assert.equal(calls, expectedCalls);
      } finally {
        Hash.sha256 = sha256;
      }
      const getFips = crypto.getFips;
      crypto.getFips = () => 1;
      try {
        assert.deepEqual(run(bytes), without(lib, [name], () => run(bytes)));
        assert.equal(calls, expectedCalls);
      } finally {
        crypto.getFips = getFips;
      }
    } finally {
      lib.native[name] = original;
    }
  }
}

function check() {
  for (const lib of libs) {
    for (const name of ['merkleRoot', 'partialMerkle', 'escrowMerkleRoot', 'escrowKeyRoot', 'hash256', 'hash160']) {
      assert.equal(typeof lib.native[name], 'function', 'Build the addon to run these tests');
    }
    checkPartial(lib);
    checkRoot(lib);
    checkHashes(lib);
  }
  checkEscrow();
  console.log('UTXO validation and escrow parity checks passed.');
}

if (require.main === module) check();

module.exports = { btc, bch, Escrow, without, header, proof, transaction, keys };
