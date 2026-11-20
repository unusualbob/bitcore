/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone CommonJS test. */
'use strict';

const assert = require('node:assert/strict');
const { Worker, isMainThread, parentPort } = require('node:worker_threads');

// Exercise the exported chain registry so a newly supported chain enters the
// differential suite even if it shares its provider with an existing chain.
function corpus() {
  const wallet = require('@bitpay-labs/crypto-wallet-core');
  const { BitcoreLib, Constants, Deriver, Message, Validation } = wallet;
  const libs = { bch: wallet.BitcoreLibCash, ltc: wallet.BitcoreLibLtc, doge: wallet.BitcoreLibDoge };
  const seed = Buffer.from('0123456789abcdef'.repeat(4), 'hex');
  const messageKey = BitcoreLib.HDPrivateKey.fromSeed(seed).privateKey;
  const rows = {};
  for (const chain of Constants.CHAINS) {
    const lib = libs[chain] || BitcoreLib;
    rows[chain] = [];
    for (const network of ['livenet', 'testnet']) {
      const master = lib.HDPrivateKey.fromSeed(seed, network);
      for (const change of [false, true]) {
        const key = Deriver.derivePrivateKey(chain, network, master.toString(), 7, change);
        const secret = Deriver.privateKeyToBuffer(chain, key.privKey);
        try {
          const pub = Deriver.getPublicKey(chain, network, secret);
          assert.equal(pub.toLowerCase(), key.pubKey.toLowerCase(), chain + ' key import');
          const address = Deriver.getAddress(chain, network, pub);
          rows[chain].push({ key, pub, address, valid: Validation.validateAddress(chain, network, address) });
          if (chain !== 'sol') {
            rows[chain].push(Deriver.deriveAddress(chain, network, master.hdPublicKey.toString(), 7, change));
          }
        } finally {
          secret.fill(0);
        }
      }
    }
    const message = 'Bitcore parity — 🪙';
    const args = { chain, message, privateKey: messageKey, encoding: 'hex' };
    const signed = Message.signMessage(args);
    rows[chain].push(Message.getMessageHash(args), signed.publicKey);
    if (Constants.UTXO_CHAINS.includes(chain)) {
      // These public methods use a randomized nonce.
      assert(new BitcoreLib.Message(message).verify(messageKey.toAddress(),
        Buffer.from(signed.signature, 'hex').toString('base64')), chain + ' message signature');
    } else {
      rows[chain].push(signed.signature);
    }
  }
  return rows;
}

function run(backend) {
  return new Promise((resolve, reject) => {
    const env = { ...process.env, BITCORE_ECDSA_BACKEND: backend };
    for (const fork of ['BCH', 'LTC', 'DOGE']) env['BITCORE_' + fork + '_BACKEND'] = backend;
    const worker = new Worker(__filename, { env });
    let result;
    worker.on('message', rows => { result = rows; });
    worker.on('error', reject);
    worker.on('exit', status => {
      if (status || !result) reject(new Error('Chain coverage worker exited with status ' + status));
      else resolve(result);
    });
  });
}

if (isMainThread) {
  Promise.all([run('js'), run('native')]).then(([js, native]) => {
    assert.deepEqual(native, js);
    console.log('Public wallet API parity passed for ' + Object.keys(js).join(', '));
  }).catch(error => { console.error(error); process.exitCode = 1; });
} else {
  parentPort.postMessage(corpus());
}
