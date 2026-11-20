import assert from 'assert/strict';
import { BitcoreLib } from '@bitpay-labs/crypto-wallet-core';
import secp256k1 from 'secp256k1';
import { verifyRequestSignature } from '../../../src/utils/auth';

describe('verifyRequestSignature', function() {
  const key = new BitcoreLib.PrivateKey('00'.repeat(31) + '01');
  const message = 'GET|/api/BTC/mainnet/wallet/test|{}';
  const digest = BitcoreLib.crypto.Hash.sha256sha256(Buffer.from(message));
  const compact = Buffer.from(secp256k1.ecdsaSign(digest, key.toBuffer()).signature);
  const payload = { message, pubKey: key.toPublicKey().toString(), signature: compact.toString('hex') };

  it('verifies the signed message and rejects a different message or public key', function() {
    const otherKey = new BitcoreLib.PrivateKey('00'.repeat(31) + '02');
    assert.equal(verifyRequestSignature(payload), true);
    assert.equal(verifyRequestSignature({ ...payload, message: message + 'changed' }), false);
    assert.equal(verifyRequestSignature({ ...payload, pubKey: otherKey.toPublicKey().toString() }), false);
  });

  it('rejects a high-S encoding of an otherwise valid signature', function() {
    const order = BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141');
    const lowS = BigInt('0x' + compact.subarray(32).toString('hex'));
    const highS = (order - lowS).toString(16).padStart(64, '0');
    assert.equal(verifyRequestSignature({ ...payload, signature: payload.signature.slice(0, 64) + highS }), false);
  });

  it('preserves errors for absent and malformed compact signatures', function() {
    assert.throws(() => verifyRequestSignature({ ...payload, signature: undefined }), /Signature must exist/);
    assert.throws(() => verifyRequestSignature({ ...payload, signature: 'bad' }));
  });
});
