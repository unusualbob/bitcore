/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone offline benchmark. */
'use strict';

const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const { existsSync } = require('node:fs');
const path = require('node:path');

function sample(root, upstream) {
  const pkg = name => path.resolve(root, 'packages', name);
  const { BitcoreLib, Transactions, Deriver, xrpl } = require(pkg('crypto-wallet-core'));
  assert.equal(BitcoreLib.HDPrivateKey, require(pkg('bitcore-lib')).HDPrivateKey, 'Wallet core resolved a different checkout');
  for (const suffix of ['', '-cash', '-ltc', '-doge']) {
    const loader = pkg('bitcore-lib' + suffix) + '/lib/crypto/ecdsa-native.js';
    if (upstream) assert.ok(!existsSync(loader), 'Expected a checkout before the Bitcore Rust addon');
    else assert.ok(require(loader).native);
  }
  const xpriv = BitcoreLib.HDPrivateKey.fromSeed(Buffer.alloc(32, 7)).xprivkey;
  const payload = Buffer.from(xpriv);
  const codec = BitcoreLib.encoding.Base58Check;
  const extended = codec.decode(xpriv);
  const small = '0x' + 'ab'.repeat(4096);
  const large = small + 'ab';
  const wallet = xrpl.Wallet.fromEntropy(new Uint8Array(16).fill(7));
  const destination = xrpl.Wallet.fromEntropy(new Uint8Array(16).fill(9)).classicAddress;
  const payment = amount => ({
    chain: 'XRP', key: { pubKey: wallet.publicKey, privKey: wallet.privateKey },
    tx: xrpl.encode({ TransactionType: 'Payment', Account: wallet.classicAddress,
      Destination: destination, Amount: amount, Fee: '12', Sequence: 1 })
  });
  const drops = payment('1000');
  const issued = payment({ currency: 'USD', issuer: destination, value: '1.23' });
  const key = BitcoreLib.PrivateKey.fromBuffer(Buffer.alloc(32, 11));
  const recipient = BitcoreLib.PrivateKey.fromBuffer(Buffer.alloc(32, 12)).publicKey;
  const digest = BitcoreLib.crypto.Hash.sha256(payload);
  const sig = BitcoreLib.crypto.ECDSA.sign(digest, key);
  const cash = require(pkg('bitcore-lib-cash'));
  const cashKey = cash.PrivateKey.fromBuffer(Buffer.alloc(32, 11));
  const doge = require(pkg('bitcore-lib-doge'));
  const ltc = require(pkg('bitcore-lib-ltc'));
  const header = Buffer.alloc(80, 29);
  const ECIES = require(pkg('bitcore-tss') + '/ecies/ecies');
  const Mnemonic = require(pkg('bitcore-mnemonic'));
  const mnemonic = new Mnemonic(Array(11).fill('abandon').concat('about').join(' '));
  const eth = { chain: 'ETH', key: { privKey: key.toString(), pubKey: key.publicKey.toString() },
    tx: Transactions.create({ chain: 'ETH', network: 'mainnet', nonce: 1, gasLimit: 21000,
      maxGasFee: 2e9, priorityGasFee: 1, recipients: [{ address: '0x' + '33'.repeat(20), amount: '1000' }] }) };
  const operations = {
    btcSign: () => BitcoreLib.crypto.ECDSA.sign(digest, key).toDER(),
    btcVerify: () => BitcoreLib.crypto.ECDSA.verify(digest, sig, key.publicKey),
    cashSchnorr: () => cash.crypto.Schnorr.sign(digest, cashKey).toBuffer(),
    dogeScrypt: () => doge.crypto.Hash.scrypt(header),
    ltcScrypt: () => ltc.crypto.Hash.scrypt(header),
    mnemonicSeed: () => mnemonic.toSeed('TREZOR'),
    tssEciesKeys: () => ECIES.KDF(key, recipient),
    ethType2Sign: () => Transactions.sign(eth),
    sha256: () => BitcoreLib.crypto.Hash.sha256(payload).toString('hex'),
    extendedKeyEncode: () => codec.encode(extended),
    extendedKeyDecode: () => codec.decode(xpriv),
    ethSighash4096: () => Transactions.getSighash({ chain: 'ETH', tx: small }),
    ethSighash4097: () => Transactions.getSighash({ chain: 'ETH', tx: large }),
    solReceiveKey: () => Deriver.derivePrivateKey('SOL', 'livenet', xpriv, 0, false),
    xrpDropsEd25519: () => Transactions.sign(drops),
    xrpIssuedEd25519: () => Transactions.sign(issued)
  };
  const results = {};
  for (const [name, run] of Object.entries(operations)) {
    const measure = ms => {
      const start = performance.now();
      let count = 0;
      do { run(); count++; } while (performance.now() - start < ms);
      return 1000 * count / (performance.now() - start);
    };
    measure(100);
    results[name] = { rate: measure(300), output: run() };
  }
  return results;
}

if (process.argv[2] === '--sample') {
  console.log(JSON.stringify(sample(process.argv[3], process.argv[4] === '--upstream')));
} else {
  const [previous, current] = process.argv.slice(2);
  assert.ok(previous && current, 'Pass the previous and current compiled checkout roots');
  const env = { ...process.env };
  for (const name of ['ECDSA', 'BCH', 'LTC', 'DOGE']) env['BITCORE_' + name + '_BACKEND'] = 'native';
  const rounds = [[], []];
  for (let i = 0; i < 5; i++) {
    for (const side of [i % 2, 1 - i % 2]) {
      const args = [__filename, '--sample', [previous, current][side]];
      if (side === 0 && process.argv.includes('--upstream')) args.push('--upstream');
      const output = execFileSync(process.execPath, args, { env });
      rounds[side].push(JSON.parse(output));
    }
  }
  for (const name of Object.keys(rounds[0][0])) {
    const median = rounds.map(samples => {
      for (const row of samples) assert.deepEqual(row[name].output, rounds[0][0][name].output, name);
      return samples.map(row => row[name].rate).sort((a, b) => a - b)[2];
    });
    console.log(name, ...median.map(Math.round), (median[1] / median[0]).toFixed(2) + 'x');
  }
}
