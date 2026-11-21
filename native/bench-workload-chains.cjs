/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone offline benchmark. */
'use strict';

const assert = require('node:assert/strict');
const { createPublicKey, verify } = require('node:crypto');
const { createRequire } = require('node:module');
const path = require('node:path');

module.exports = function makeChainWorkloads(root) {
  const pkg = name => path.resolve(root, 'packages', name);
  const { BitcoreLib, Deriver, SolKit, Transactions } = require(pkg('crypto-wallet-core'));
  const eciesRequire = createRequire(path.join(pkg('bitcore-tss'), 'package.json'));
  const ECIES = eciesRequire('./ecies/ecies');
  assert.equal(BitcoreLib.PrivateKey, require(pkg('bitcore-lib')).PrivateKey, 'Wallet core loaded another checkout');
  assert.equal(eciesRequire('@bitpay-labs/bitcore-lib').PrivateKey, BitcoreLib.PrivateKey, 'TSS loaded another checkout');

  const xpriv = BitcoreLib.HDPrivateKey.fromSeed(Buffer.alloc(32, 7)).xprivkey;
  const [key, recipient, mint, sourceAta] = [0, 1, 2, 3].map(index =>
    Deriver.derivePrivateKey('SOL', 'livenet', xpriv, index, false));
  const transfer = { from: key.address, blockHash: mint.address, blockHeight: 13,
    recipients: [{ address: recipient.address, amount: '50' }] };
  const addressBytes = SolKit.getBase58Encoder().encode(key.address);
  const publicKey = createPublicKey({
    key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), addressBytes]),
    format: 'der', type: 'spki'
  });

  function signingWorkload(chain, options) {
    const tx = Transactions.create({ chain, ...transfer, ...options });
    const decoder = SolKit.getTransactionDecoder();
    const { messageBytes } = decoder.decode(Buffer.from(tx, 'base64'));
    return {
      run: () => Transactions.sign({ chain, tx, key }),
      check(signed) {
        const decoded = decoder.decode(Buffer.from(signed, 'base64'));
        assert.deepEqual(decoded.messageBytes, messageBytes);
        assert.ok(verify(null, messageBytes, publicKey, decoded.signatures[key.address]));
        return signed;
      }
    };
  }

  const sender = BitcoreLib.PrivateKey.fromBuffer(Buffer.alloc(32, 11));
  const receiver = BitcoreLib.PrivateKey.fromBuffer(Buffer.alloc(32, 12));
  const message = Buffer.alloc(256, 19);
  // Both checkouts must produce an identical ciphertext for this fixture.
  const encryption = { privateKey: sender, publicKey: receiver.publicKey, message, ivbuf: Buffer.alloc(16, 7) };
  const payload = ECIES.encrypt(encryption);
  const decryption = { privateKey: receiver, payload };

  return {
    solTransfer: signingWorkload('SOL', {}),
    splTransfer: signingWorkload('SOLSPL', { fromAta: sourceAta.address, tokenAddress: mint.address, decimals: 6 }),
    eciesEncrypt256: {
      run: () => ECIES.encrypt(encryption),
      check(result) {
        assert.deepEqual(ECIES.decrypt({ privateKey: receiver, payload: result }), message);
        return result.toString('hex');
      }
    },
    eciesDecrypt256: {
      run: () => ECIES.decrypt(decryption),
      check(result) {
        assert.deepEqual(result, message);
        return result.toString('hex');
      }
    }
  };
};
