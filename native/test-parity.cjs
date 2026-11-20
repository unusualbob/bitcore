/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone CommonJS script. */
'use strict';

// Run the same public API workload in fresh processes so module caching cannot
// accidentally make both sides of the comparison use the same backend.
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');

function corpus() {
  const { PrivateKey, Script, Transaction, crypto: { BN, ECDSA, Hash, Point, Signature } } =
    require('../packages/bitcore-lib');
  const order = Point.getN();
  const hashes = [Buffer.alloc(32), order.toBuffer(), Buffer.alloc(32, 255)];
  for (let i = 0; i < 256; i++) hashes.push(Hash.sha256(Buffer.from('parity-' + i)));
  const rows = [];
  for (const [i, digest] of hashes.entries()) {
    const scalar = Hash.sha256(Buffer.from('fixture-key-' + i));
    const key = new PrivateKey(i % 2 ? scalar : BN.fromBuffer(scalar));
    const pub = key.publicKey;
    for (const endian of ['big', 'little']) {
      const hash = Uint8Array.from(digest);
      const sig = ECDSA.sign(hash, key, { endian });
      assert(sig instanceof Signature);
      assert.deepEqual(Buffer.from(hash), digest);
      assert(ECDSA.verify(hash, sig, pub.toBuffer(), { endian }));
      const high = new Signature(sig.r, order.sub(sig.s));
      assert(ECDSA.verify(hash, high, pub, { endian }));
      const recoveryHash = endian === 'little' ? Buffer.from(digest).reverse() : digest;
      assert.equal(ECDSA.calci(recoveryHash, sig, pub), sig);
      assert.deepEqual(ECDSA.recoverPublicKey(recoveryHash, sig).toBuffer(), pub.toBuffer());
      if (i === 0) {
        const missingFlag = new Signature(sig.r, sig.s);
        missingFlag.i = sig.i;
        assert.equal(ECDSA.recoverPublicKey(recoveryHash, missingFlag).compressed, true);
      }
      rows.push([sig.toString(), sig.i, sig.compressed,
        ECDSA.verificationError(hash, new Signature(sig.r, BN.Zero), pub),
        ECDSA.verificationError(Buffer.alloc(31), sig, pub),
        ECDSA.verificationError(hash, new Signature(sig.r, sig.s.addn(1)), pub, { endian })]);
    }
  }
  const key = new PrivateKey(BN.One);
  const infinity = new Signature(BN.One, BN.One);
  const negativeOne = order.subn(1).toBuffer({ size: 32 });
  assert.equal(ECDSA.verificationError(negativeOne, infinity, key.publicKey), 'p is infinity');
  assert.equal(ECDSA.verify(negativeOne, infinity, key.publicKey), false);
  // r = 2 admits the rare recovery branch with x = r + curve order.
  const shortDigest = Buffer.alloc(32);
  shortDigest[31] = 3;
  for (const recoveryId of [2, 3]) {
    const sig = new Signature(new BN(2), BN.One);
    sig.i = recoveryId;
    const recovered = ECDSA.recoverPublicKey(shortDigest, sig);
    assert(ECDSA.verify(shortDigest, sig, recovered));
    assert.equal(ECDSA.calci(shortDigest, sig, recovered).i, recoveryId);
    rows.push(recovered.toString());
  }
  const address = key.toAddress();
  const transaction = new Transaction().from({ txId: '11'.repeat(32), outputIndex: 2,
    script: Script.buildPublicKeyHashOut(address).toHex(), satoshis: 100000 })
    .to(address, 99000).sign(key);
  assert(transaction.isFullySigned());
  rows.push(transaction.toString());
  return rows;
}

if (process.argv[2] === '--corpus') {
  process.stdout.write(JSON.stringify(corpus()));
} else {
  function run(backend) {
    return execFileSync(process.execPath, [__filename, '--corpus'], {
      env: { ...process.env, BITCORE_ECDSA_BACKEND: backend }, encoding: 'utf8'
    });
  }
  const reference = run('js');
  assert.deepEqual(JSON.parse(run('native')), JSON.parse(reference));
  console.log('Matched ' + JSON.parse(reference).length + ' public ECDSA cases across both backends.');
}
