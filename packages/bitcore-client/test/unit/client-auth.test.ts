import assert from 'assert/strict';
import { BitcoreLib } from '@bitpay-labs/crypto-wallet-core';
import * as secp256k1 from 'secp256k1';
import sinon from 'sinon';
import { Client } from '../../src/client';

describe('Client request signing', function() {
  const authKey = new BitcoreLib.PrivateKey('00'.repeat(31) + '01');
  const params = {
    method: 'POST',
    url: 'https://example.test/api/BTC/mainnet/wallet?example=1',
    payload: [{ address: '1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH' }]
  };
  const message = 'POST|/api/BTC/mainnet/wallet?example=1|[{"address":"1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"}]';
  const client = new Client({ apiUrl: 'https://example.test', authKey });
  const legacySignature = (digest: Buffer) => secp256k1.sign(digest, authKey.toBuffer()).signature.toString('hex');

  afterEach(function() {
    sinon.restore();
  });

  it('preserves the signed message and deterministic compact signature', function() {
    const digest = BitcoreLib.crypto.Hash.sha256sha256(Buffer.from(message));
    assert.equal(client.getMessage(params), message);
    assert.equal(client.sign(params), legacySignature(digest));
    assert.equal(client.sign(params), client.sign(params));
    assert.equal(secp256k1.verify(digest, Buffer.from(client.sign(params), 'hex'), authKey.toPublicKey().toBuffer()), true);
    assert.notEqual(client.sign({ ...params, payload: [] }), client.sign(params));
  });

  it('uses the legacy signature for digests at and above the curve order', function() {
    const order = Buffer.from('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141', 'hex');
    const hash = sinon.stub(BitcoreLib.crypto.Hash, 'sha256sha256');
    for (const digest of [order, Buffer.alloc(32, 0xff)]) {
      hash.returns(digest);
      assert.equal(client.sign(params), legacySignature(digest));
    }
  });
});
