import assert from 'assert/strict';
import crypto from 'crypto';
import sinon from 'sinon';
import { bitcoinCoreDecrypt } from '../../src/encryption';
import { native } from '../../src/native';

describe('Bitcoin Core encrypted key import', function() {
  // Synthetic wallet dump. The master ciphertext uses 25,000 rounds of SHA-512
  // over the UTF-8 passphrase and eight salt bytes. The key ciphertext uses
  // the first 16 bytes of the compressed public key's double-SHA256 as its IV.
  const passphrase = 'synthetic-é-🏳️';
  const salt = '0123456789abcdef';
  const rounds = 25_000;
  const pubKey = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
  const address = '1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH';
  const rows = (saltBytes: Buffer) => [
    {
      cipherText: '0760d8fe939351eada71b8fe0636b1b85caadad12db741bd773cbf627e6a9af28077ca8bbe6a895286dc84a74e51dc93',
      derivationMethod: 'SHA512',
      salt: saltBytes,
      rounds
    },
    {
      cipherText: '3171d8efaa522b29ae039606e75fe4b13ea4ad5e73cbb3cf9c633f6df613cd3a09e11624751a2be9441178ffb18a9fb0',
      pubKey,
      address: `addr:${address}`
    }
  ];
  const expected = {
    master: '37'.repeat(32),
    jsonlDecrypted: [{ privKey: '00'.repeat(31) + '01', pubKey, address }]
  };

  const sandbox = sinon.createSandbox();
  afterEach(() => sandbox.restore());

  it('decrypts a master key and private key with the selected backend', function() {
    const derive = typeof native?.bitcoinCoreWalletKey === 'function'
      ? sandbox.spy(native, 'bitcoinCoreWalletKey')
      : undefined;
    const saltBytes = Buffer.from(salt, 'hex');
    assert.deepEqual(bitcoinCoreDecrypt(rows(saltBytes), passphrase), expected);
    assert.equal(saltBytes.toString('hex'), salt);
    if (derive && !crypto.getFips()) {
      assert.equal(derive.callCount, 1);
      assert.equal(derive.firstCall.args[1], rounds);
    }
  });

  it('decodes the same dump with the legacy repeated SHA-512 path and a hex salt', function() {
    if (typeof native?.bitcoinCoreWalletKey === 'function') {
      sandbox.stub(native, 'bitcoinCoreWalletKey').value(undefined);
    }
    assert.deepEqual(bitcoinCoreDecrypt(rows(salt as unknown as Buffer), passphrase), expected);
  });
});
