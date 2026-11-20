'use strict';

const benchmark = require('./backends');

benchmark(__filename, bitcore => {
  const { ECDSA, Hash, BN } = bitcore.crypto;
  const fixtures = Array.from({ length: 16 }, (_, index) => {
    const key = new bitcore.PrivateKey(BN.fromBuffer(Hash.sha256(Buffer.from('benchmark key ' + index))));
    const hash = Hash.sha256(Buffer.from('bitcore benchmark ' + index));
    const pub = key.publicKey;
    const encoded = pub.toBuffer();
    const sig = ECDSA.sign(hash, key);
    ECDSA.calci(hash, sig, pub);
    if (!ECDSA.verify(hash, sig, encoded)) throw new Error('Invalid signing fixture');
    const otherHash = Hash.sha256(hash);
    if (ECDSA.verify(otherHash, sig, pub)) throw new Error('Invalid rejection fixture');
    const address = key.toAddress();
    const utxo = { txId: hash.toString('hex'), outputIndex: 0,
      script: bitcore.Script.buildPublicKeyHashOut(address).toHex(), satoshis: 100000 };
    return { key, hash, otherHash, pub, encoded, sig, utxo, address };
  });
  const operations = {
    sign: f => ECDSA.sign(f.hash, f.key),
    verify: f => ECDSA.verify(f.hash, f.sig, f.pub),
    verifyInvalid: f => ECDSA.verify(f.otherHash, f.sig, f.pub),
    verifySerialized: f => ECDSA.verify(f.hash, f.sig, f.encoded),
    recover: f => ECDSA.recoverPublicKey(f.hash, f.sig),
    recoveryFactor: f => ECDSA.calci(f.hash, f.sig, f.pub),
    signP2PKHTransaction: f => new bitcore.Transaction().from(f.utxo).to(f.address, 99000).sign(f.key)
  };
  return { fixtures, operations };
});
