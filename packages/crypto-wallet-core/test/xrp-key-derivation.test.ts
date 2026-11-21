import assert from 'node:assert/strict';
import BitcoreLib from '@bitpay-labs/bitcore-lib';
import { XrpDeriver } from '../src/derivation/xrp';

describe('XRP key derivation', () => {
  it('preserves leading zero bytes, uppercase keys and the address from the public path', () => {
    const deriver = new XrpDeriver();
    const root = BitcoreLib.HDPrivateKey.fromSeed(Buffer.alloc(32, 13));
    const path = 'm/0/6';
    const key = deriver.derivePrivateKeyWithPath('livenet', root.toString(), path);
    const legacyPublicKey = root.derive(path).hdPublicKey.toObject().publicKey.toUpperCase();
    assert.equal(key.privKey, '0091123C825706615D1E0D2D981F04B6E638851939E80EE5C87FAFFB64376173');
    assert.equal(key.pubKey, legacyPublicKey);
    assert.equal(key.path, path);
    assert.equal(key.address, deriver.deriveAddressWithPath('livenet', root.hdPublicKey.toString(), path));
  });
});
