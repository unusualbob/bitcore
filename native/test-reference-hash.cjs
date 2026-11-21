/* eslint @typescript-eslint/no-require-imports: "off" -- Isolated two-backend corpus. */
'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const bs58 = require('bs58');

const backend = process.env.BITCORE_ECDSA_BACKEND || 'native';
assert.ok(['native', 'js'].includes(backend));
process.env.BITCORE_ECDSA_BACKEND = backend;
for (const fork of ['BCH', 'DOGE', 'LTC']) process.env['BITCORE_' + fork + '_BACKEND'] = backend;
const names = ['bitcore-lib', 'bitcore-lib-cash', 'bitcore-lib-doge', 'bitcore-lib-ltc'];
const counters = new Map();
// Base58 captures the addon entry points at require time. Install counters first.
for (const name of names) {
  const addon = require('../packages/' + name + '/lib/crypto/ecdsa-native').native;
  assert.equal(Boolean(addon), backend === 'native');
  if (!addon) continue;
  const methods = ['base58Encode', 'base58Decode', 'base58CheckEncode', 'base58DecodeChecked',
    'merkleParents', 'merkleRoot', 'partialMerkle', 'hash256', 'hash160'];
  if (name === 'bitcore-lib') methods.push('bip39Seed', 'bitcoinCoreWalletKey');
  if (name.endsWith('cash')) methods.push('escrowKeyRoot', 'escrowMerkleRoot');
  if (name.endsWith('doge') || name.endsWith('ltc')) methods.push('scryptProofOfWork');
  for (const method of methods) {
    const id = name + '.' + method;
    const original = addon[method];
    assert.equal(typeof original, 'function', id);
    counters.set(id, 0);
    addon[method] = (...args) => {
      const result = original(...args);
      if (result != null) counters.set(id, counters.get(id) + 1);
      return result;
    };
  }
}

// Load application modules only after installing the dispatch counters.
function loadApplicationModules() {
  const { bitcoinCoreDecrypt } = require('../packages/bitcore-client/ts_build/src/encryption');
  const escrow = require('../packages/bitcore-lib-cash/lib/script/escrow');
  const pbkdf2 = require('../packages/bitcore-mnemonic/lib/pbkdf2');
  const { header, proof, keys } = require('./test-utxo-validation.cjs');

  return { bitcoinCoreDecrypt, escrow, pbkdf2, header, proof, keys };
}
const { bitcoinCoreDecrypt, escrow, pbkdf2, header, proof, keys } = loadApplicationModules();

const digest = (algorithm, input) => crypto.createHash(algorithm).update(input).digest();
const sha256d = input => digest('sha256', digest('sha256', input));
const hash160 = input => digest('ripemd160', digest('sha256', input));

function withCryptoFunction(name, replacement, run) {
  const original = crypto[name];
  try {
    crypto[name] = replacement;
    return run();
  } finally {
    crypto[name] = original;
  }
}

function checkBlock(chain) {
  for (const count of [0, 1, 7, 8, 9, 32]) {
    const leaves = Array.from({ length: count }, (_, i) => digest('sha256', Buffer.from([i])));
    const block = new chain.Block({ header: header(), transactions: [] });
    block.transactions = leaves.map(hash => ({ _getHash: () => hash }));
    let level = count ? leaves : [Buffer.alloc(32)];
    const expected = [...level];
    while (level.length > 1) {
      level = Array.from({ length: Math.ceil(level.length / 2) }, (_, i) =>
        sha256d(Buffer.concat([level[2 * i], level[2 * i + 1] ?? level[2 * i]])));
      expected.push(...level);
    }
    assert.deepEqual(block.getMerkleTree(), expected);
    assert.deepEqual(block.getMerkleRoot(), expected.at(-1));
  }

  for (const [count, stride] of [[1, 1], [9, 1], [45, 7]]) {
    const { block, matched } = proof(chain, count, stride);
    assert.equal(block.validMerkleTree(), true);
    assert.equal(block.hasTransaction(matched[0]), true);
    assert.equal(block.hasTransaction(new chain.Transaction()), false);
    assert.throws(() => block.hasTransaction(null));
    if (block.filterdTxsHash) assert.deepEqual(block.filterdTxsHash(), count === 1 ? [] : matched);
    assert.deepEqual(block._traverseMerkleTree(0, 0), Buffer.from(block.hashes[0], 'hex'));
    assert.equal(block._traverseMerkleTree(0, 0, { flagBitsUsed: block.flags.length * 8 + 1 }), null);
    assert.equal(block._traverseMerkleTree(0, 0, { hashesUsed: block.hashes.length }), null);
  }
  for (const mutate of [b => b.numTransactions = 1, b => b.flags.length = 0,
    b => b.hashes.push('aa'.repeat(32))]) {
    const { block } = proof(chain, 65, 8);
    mutate(block);
    assert.equal(block.validMerkleTree(), false);
    if (block.filterdTxsHash) assert.throws(() => block.filterdTxsHash());
  }
}

function checkEncoding(chain) {
  const { Base58, Base58Check } = chain.encoding;
  for (const length of [0, 1, 2, 3, 20, 32, 47, 64, 124, 128, 129]) {
    const input = Buffer.alloc(length, 0xbd);
    if (length >= 3) input[0] = 0;
    const encoded = bs58.encode(input);
    assert.equal(Base58.encode(input), encoded);
    assert.deepEqual(Base58.decode(encoded), input);
    const checked = bs58.encode(Buffer.concat([input, sha256d(input).subarray(0, 4)]));
    assert.equal(Base58Check.encode(input), checked);
    assert.deepEqual(Base58Check.decode(checked), input);
  }
  for (const codec of [Base58, Base58Check]) {
    assert.throws(() => codec.encode('invalid'), /buffer/);
    assert.throws(() => codec.decode(null), /string/);
    assert.throws(() => codec.decode('z'.repeat(63) + '0'), /Non-base58/);
  }
  assert.throws(() => Base58Check.decode('11'), /too short/);
  assert.throws(() => Base58Check.decode('zzzzzz'), /Checksum mismatch/);
}

for (const name of names) {
  const chain = require('../packages/' + name);
  checkEncoding(chain);
  checkBlock(chain);
  const data = Buffer.alloc(80, 12);
  const { Hash } = chain.crypto;
  assert.deepEqual(chain.BlockHeader.prototype._getHash.call({ toBuffer: () => data }), sha256d(data));
  assert.deepEqual(Hash.sha256ripemd160(data), hash160(data));
  withCryptoFunction('getFips', () => 1, () => assert.deepEqual(Hash.sha256(data), digest('sha256', data)));
  if (Hash.scrypt) {
    const expected = crypto.scryptSync(data, data, 32, { N: 1024, r: 1, p: 1 }).reverse();
    assert.deepEqual(withCryptoFunction('scryptSync', undefined, () => Hash.scrypt(data)), expected);
    assert.throws(() => Hash.scrypt(null));
  }
}

for (const count of [1, 8, 9]) {
  const publicKeys = keys(count);
  const leaves = publicKeys.map(key => key.toBuffer()).sort(Buffer.compare).map(hash160);
  function root(hashes) {
    let level = hashes;
    while (level.length > 1) level = Array.from({ length: Math.ceil(level.length / 2) }, (_, i) =>
      hash160(Buffer.concat(level.slice(2 * i, 2 * i + 2))));
    return level[0];
  }
  assert.deepEqual(escrow.getMerkleRoot(leaves), root(leaves));
  while (leaves.length < 2 ** Math.ceil(Math.log2(count))) leaves.push(hash160(Buffer.alloc(0)));
  assert.deepEqual(escrow.generateMerkleRootFromPublicKeys(publicKeys), root(leaves));
}

for (const [key, salt, rounds, length] of [
  ['pass', 'salt', 2048, 64], [Buffer.alloc(129, 0x61), Buffer.from('salt'), 2048, 64],
  [Buffer.alloc(0), 'salt', 3, 129], ['password', Buffer.alloc(0), 1, 65]
]) {
  const expected = crypto.pbkdf2Sync(key, salt, rounds, length, 'sha512');
  // Disabling just this provider forces the original HMAC loop on the JS run.
  const unsupported = () => { throw Object.assign(new Error(), { code: 'ERR_OSSL_EVP_UNSUPPORTED' }); };
  assert.deepEqual(withCryptoFunction('pbkdf2Sync', unsupported, () => pbkdf2(key, salt, rounds, length)), expected);
}
assert.throws(() => pbkdf2('pass', 'salt', 1, 2 ** 38), /too long/);
assert.throws(() => pbkdf2(1, 'salt', 1, 32), /key must/);
assert.throws(() => pbkdf2('pass', 2, 1, 32), /salt must/);

for (const rounds of [undefined, 1, 3]) {
  const password = 'fixture';
  const salt = Buffer.from('salt');
  let material = Buffer.concat([Buffer.from(password), salt]);
  for (let i = 0; i < (rounds ?? 1); i++) material = digest('sha512', material);
  const master = Buffer.alloc(32, 6);
  const cipher = crypto.createCipheriv('aes-256-cbc', material.subarray(0, 32), material.subarray(32, 48));
  const cipherText = Buffer.concat([cipher.update(master), cipher.final()]).toString('hex');
  const result = bitcoinCoreDecrypt([{ cipherText, rounds, derivationMethod: 'SHA512',
    salt: rounds === 1 ? salt.toString('hex') : salt }], password);
  assert.equal(result.master, master.toString('hex'));
}

for (const [name, count] of counters) assert.ok(count > 0, name + ' never returned a native result');
console.log('Hash, encoding, KDF and Merkle reference cases passed (' + backend + ').');
