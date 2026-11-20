/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone parity test. */
'use strict';

const assert = require('node:assert/strict');
const { createPublicKey, verify } = require('node:crypto');
const { execFileSync } = require('node:child_process');

async function sample() {
  const { SolDeriver } = require('../packages/crypto-wallet-core/ts_build/src/derivation/sol');
  const { BitcoreLib, Deriver, SolKit, SolanaProgram, Transactions } = require('../packages/crypto-wallet-core');
  const { native } = require('../packages/bitcore-lib/lib/crypto/ecdsa-native');
  const calls = new Map();
  if (native) {
    for (const name of ['slip10DeriveEd25519', 'ed25519PublicKey', 'ed25519Sign', 'solAssociatedTokenAddress']) {
      const operation = native[name];
      assert.equal(typeof operation, 'function');
      native[name] = (...args) => {
        calls.set(name, (calls.get(name) || 0) + 1);
        return operation(...args);
      };
    }
  }

  const xpriv = BitcoreLib.HDPrivateKey.fromSeed(Buffer.alloc(32, 7));
  const deriver = new SolDeriver();
  const parent = { key: xpriv._buffers.privateKey, chainCode: xpriv._buffers.chainCode };
  assert.strictEqual(deriver.deriveChild(parent, 'm'), parent);
  assert.deepEqual(deriver.deriveChild(parent, "ignored/01suffix/2'"), deriver.deriveChild(parent, 'm/1/2'));
  const { CKDPriv } = require('ed25519-hd-key');
  assert.deepEqual(deriver.deriveChild(parent, 'm/-2147483648/2147483647'), CKDPriv(CKDPriv(parent, 0), 0xffffffff));
  assert.throws(() => deriver.deriveChild(parent, 'm/2147483648'), RangeError);
  for (const depth of [255, 256]) {
    const deriveCalls = calls.get('slip10DeriveEd25519') || 0;
    let expected = parent;
    for (let step = 0; step < depth; step++) expected = CKDPriv(expected, 0x80000001);
    assert.deepEqual(deriver.deriveChild(parent, 'm' + "/1'".repeat(depth)), expected);
    if (native) assert.equal(calls.get('slip10DeriveEd25519'), deriveCalls + Number(depth <= 255));
  }

  const keys = [0, 1, 2, 3].map(index => Deriver.derivePrivateKey('SOL', 'livenet', xpriv.xprivkey, index, false));
  const [key, recipient, mint, other] = keys;
  const seed = Deriver.privateKeyToBuffer('SOL', key.privKey);
  assert.equal(Deriver.getPublicKey('SOL', 'livenet', seed), key.pubKey);
  assert.throws(() => Deriver.getPublicKey('SOL', 'livenet', Buffer.alloc(31)), /seed size/);

  const provider = Transactions.get({ chain: 'SOL' });
  const results = [key, recipient];
  const Token = SolanaProgram.Token;
  for (const owner of keys) {
    for (const config of [undefined, { programAddress: other.address }]) {
      const seeds = { owner: owner.address, mint: mint.address, tokenProgram: Token.TOKEN_PROGRAM_ADDRESS };
      const ata = await Token.findAssociatedTokenPda(seeds, config);
      const encoder = SolKit.getAddressEncoder();
      const reference = await SolKit.getProgramDerivedAddress({
        programAddress: config?.programAddress ?? Token.ASSOCIATED_TOKEN_PROGRAM_ADDRESS,
        seeds: [seeds.owner, seeds.tokenProgram, seeds.mint].map(address => encoder.encode(address))
      });
      assert.deepEqual(ata, reference);
      results.push(ata);
    }
  }
  const xZero = Buffer.alloc(32);
  xZero[0] = 1;
  const noncanonicalY = Buffer.alloc(32, 0xff);
  noncanonicalY[0] = 0xee;
  noncanonicalY[31] = 0x7f; // p + 1 reduces modulo p to y = 1.
  const negativeZeroX = Buffer.from(xZero);
  negativeZeroX[31] = 0x80;
  const noncanonicalNegative = Buffer.from(noncanonicalY);
  noncanonicalNegative[31] = 0xff;
  const originalDigest = globalThis.crypto.subtle.digest;
  try {
    for (const [candidate, onCurve] of [[xZero, true], [noncanonicalY, true],
      [negativeZeroX, false], [noncanonicalNegative, false]]) {
      let round = 0;
      globalThis.crypto.subtle.digest = async () => Uint8Array.from(round++ === 0 ? candidate : negativeZeroX).buffer;
      const pda = await SolKit.getProgramDerivedAddress({ programAddress: Token.ASSOCIATED_TOKEN_PROGRAM_ADDRESS, seeds: [] });
      assert.equal(pda[1], onCurve ? 254 : 255);
    }
  } finally {
    globalThis.crypto.subtle.digest = originalDigest;
  }
  const txParams = {
    from: key.address, blockHash: mint.address, blockHeight: 13,
    recipients: [{ address: recipient.address, amount: '50' }]
  };
  const nodePublicKey = createPublicKey({
    key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(key.pubKey, 'hex')]),
    format: 'der', type: 'spki'
  });
  for (const len of [0, 200, 1296]) {
    const messageBytes = Buffer.alloc(len, 11);
    const encoded = await provider.signMessage({ key, messageBytes });
    assert(verify(null, messageBytes, nodePublicKey, SolKit.getBase58Encoder().encode(encoded)));
    assert.deepEqual(messageBytes, Buffer.alloc(len, 11));
    results.push(encoded);
  }

  for (const [chain, params] of [
    ['SOL', txParams],
    ['SOLSPL', { ...txParams, fromAta: other.address, tokenAddress: mint.address, decimals: 6 }]
  ]) {
    const tx = Transactions.create({ chain, ...params });
    const signed = await Transactions.sign({ chain, tx, key });
    const decoded = provider.decodeRawTransaction({ rawTx: signed, decodeTransactionMessage: false });
    assert(verify(null, decoded.messageBytes, nodePublicKey, decoded.signatures[key.address]));
    assert.equal(await provider.signPartially({ tx: signed, key }), signed);
    await assert.rejects(provider.sign({ tx, key: other }), /not a signer/i);
    results.push(signed);
  }

  const payer = { address: key.address, signTransactions: async () => [] };
  const newAccount = { address: recipient.address, signTransactions: async () => [] };
  const unsigned = provider.create({ ...txParams, category: 'createAccount', fromKeyPair: payer,
    recipients: [{ ...txParams.recipients[0], addressKeyPair: newAccount }] });
  await assert.rejects(provider.sign({ tx: unsigned, key }), /missing.*signatures/i);
  const partial = await provider.signPartially({ tx: unsigned, key });
  const completed = await provider.sign({ tx: partial, key: recipient });
  const decoded = provider.decodeRawTransaction({ rawTx: completed, decodeTransactionMessage: false });
  assert.deepEqual(Object.keys(decoded.signatures), [key.address, recipient.address]);
  assert(verify(null, decoded.messageBytes, nodePublicKey, decoded.signatures[key.address]));
  const wire = Buffer.from(completed, 'base64');
  const partialWire = Buffer.from(partial, 'base64');
  assert.equal(wire[0], 2);
  assert.deepEqual(wire.subarray(1, 65), Buffer.from(decoded.signatures[key.address]));
  assert.deepEqual(wire.subarray(65, 129), Buffer.from(decoded.signatures[recipient.address]));
  assert.deepEqual(partialWire.subarray(0, 65), wire.subarray(0, 65));
  assert.deepEqual(partialWire.subarray(65, 129), Buffer.alloc(64));
  assert.deepEqual(partialWire.subarray(129), wire.subarray(129));
  results.push(completed);

  if (native) assert.equal(calls.size, 4);
  console.log(JSON.stringify(results));
}

if (process.argv[2] === '--sample') {
  sample().catch(error => { console.error(error); process.exitCode = 1; });
} else {
  const run = backend => execFileSync(process.execPath, [__filename, '--sample'], {
    env: { ...process.env, BITCORE_ECDSA_BACKEND: backend }, encoding: 'utf8'
  });
  assert.equal(run('js'), run('native'));
  console.log('SLIP-0010, Ed25519 and SOL/SPL wire signature parity passed');
}
