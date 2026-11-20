/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone CommonJS benchmark. */
'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');

async function sample() {
  const { BitcoreLib, Deriver, SolKit, SolanaProgram, Transactions } = require('..');
  const { SolDeriver } = require('../ts_build/src/derivation/sol');
  const { native } = require('@bitpay-labs/bitcore-lib/lib/crypto/ecdsa-native');
  const provider = Transactions.get({ chain: 'SOL' });
  const Token = SolanaProgram.Token;
  const deriver = new SolDeriver();
  const xpriv = BitcoreLib.HDPrivateKey.fromSeed(Buffer.alloc(32, 7));
  const parent = { key: xpriv._buffers.privateKey, chainCode: xpriv._buffers.chainCode };
  const keys = [0, 1, 2, 3].map(index => Deriver.derivePrivateKey('SOL', 'livenet', xpriv.xprivkey, index, false));
  const [key, recipient, mint, other] = keys;
  const txParams = { from: key.address, blockHash: mint.address, blockHeight: 13,
    recipients: [{ address: recipient.address, amount: '50' }] };
  const sol = Transactions.create({ chain: 'SOL', ...txParams });
  const spl = Transactions.create({ chain: 'SOLSPL', ...txParams, fromAta: other.address, tokenAddress: mint.address, decimals: 6 });
  const seed = Deriver.privateKeyToBuffer('SOL', key.privKey);
  const messageBytes = Buffer.alloc(200, 19);
  const pkcs8 = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]);
  const importKey = () => crypto.createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
  const publicKeyObject = crypto.createPublicKey(importKey());
  const expected = await provider.signMessage({ key, messageBytes });
  const signature = SolKit.getBase58Encoder().encode(expected);
  assert.deepEqual(crypto.sign(null, messageBytes, importKey()), Buffer.from(signature));
  const webKey = await SolKit.createKeyPairFromPrivateKeyBytes(seed);
  const operations = {
    slip10ChildPath: () => deriver.deriveChild(parent, "m/44'/501'/0'/0'"),
    ed25519PublicKey: () => Deriver.getPublicKey('SOL', 'livenet', seed),
    receiveKey: () => Deriver.derivePrivateKey('SOL', 'livenet', xpriv.xprivkey, 0, false),
    signMessage: () => provider.signMessage({ key, messageBytes }),
    signSol: () => Transactions.sign({ chain: 'SOL', tx: sol, key }),
    signSpl: () => Transactions.sign({ chain: 'SOLSPL', tx: spl, key }),
    ata: () => Token.findAssociatedTokenPda({ owner: key.address, tokenProgram: Token.TOKEN_PROGRAM_ADDRESS, mint: mint.address })
  };
  if (process.env.BITCORE_ECDSA_BACKEND === 'native') {
    for (const [name, run] of Object.entries({ slip10DeriveEd25519: operations.slip10ChildPath,
      ed25519PublicKey: operations.ed25519PublicKey, ed25519Sign: operations.signSol, solAssociatedTokenAddress: operations.ata })) {
      const original = native?.[name];
      assert.equal(typeof original, 'function', `Rebuild the addon to benchmark ${name}`);
      let used = false;
      native[name] = (...args) => { used = true; return original(...args); };
      try {
        await run();
        assert(used, `${name} did not dispatch to Rust`);
      } finally {
        native[name] = original;
      }
    }
  } else {
    operations.openSslPublicKey = () => crypto.createPublicKey(importKey()).export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex');
    operations.openSslSignMessage = () => SolKit.getBase58Decoder().decode(crypto.sign(null, messageBytes, importKey()));
    operations.openSslVerify = () => crypto.verify(null, messageBytes, publicKeyObject, signature);
    operations.webCryptoVerify = () => SolKit.verifySignature(webKey.publicKey, signature, messageBytes);
  }

  const measure = async (operation, ms) => {
    let count = 0;
    const start = performance.now();
    let elapsed;
    do {
      await operation();
      count++;
      elapsed = performance.now() - start;
    } while (elapsed < ms);
    return count * 1000 / elapsed;
  };
  const results = {};
  for (const [name, operation] of Object.entries(operations)) {
    await measure(operation, 150);
    results[name] = await measure(operation, 500);
  }
  return results;
}

function compare() {
  const samples = { js: [], native: [] };
  for (let i = 0; i < 5; i++) {
    for (const backend of i % 2 ? ['native', 'js'] : ['js', 'native']) {
      const output = execFileSync(process.execPath, [__filename, '--sample'], {
        env: { ...process.env, BITCORE_ECDSA_BACKEND: backend }, encoding: 'utf8'
      });
      samples[backend].push(JSON.parse(output));
    }
  }
  const medians = {};
  for (const [backend, rounds] of Object.entries(samples)) {
    medians[backend] = Object.fromEntries(Object.keys(rounds[0]).map(name => [name, rounds.map(round => round[name]).sort((a, b) => a - b)[2]]));
  }
  console.log(JSON.stringify({ node: process.version, cpu: require('node:os').cpus()[0].model, medians, samples }, null, 2));
}

if (process.argv[2] === '--sample') {
  sample().then(results => console.log(JSON.stringify(results))).catch(error => { console.error(error); process.exitCode = 1; });
} else {
  compare();
}
