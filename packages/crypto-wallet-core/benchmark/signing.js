/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone CommonJS benchmark. */
'use strict';

const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { BitcoreLib, Deriver, Transactions } = require('..');

async function main() {
  const xpriv = BitcoreLib.HDPrivateKey.fromSeed(Buffer.alloc(32, 13)).toString();
  const results = {};
  for (const chain of ['ETH', 'XRP', 'SOL']) {
    const key = Deriver.derivePrivateKey(chain, 'livenet', xpriv, 0, false);
    const recipient = Deriver.derivePrivateKey(chain, 'livenet', xpriv, 1, false);
    const tx = Transactions.create({
      chain, network: 'livenet', category: 'transfer', from: key.address,
      recipients: [{ address: recipient.address, amount: 1000 }],
      nonce: chain === 'SOL' ? undefined : 1, fee: 12, gasPrice: 1000000000, gasLimit: 21000,
      blockHash: 'GtV1Hb3FvP3HURHAsj8mGwEqCumvP3pv3i6CVCzYNj3d', blockHeight: 531575
    });
    const sign = () => Transactions.sign({ chain, key, tx });
    const signed = await sign();
    assert.equal(typeof signed, 'string');
    assert(signed.length > 0 && signed !== tx);
    const measure = async ms => {
      let count = 0;
      const start = performance.now();
      let elapsed;
      do {
        assert.equal(await sign(), signed);
        count++;
        elapsed = performance.now() - start;
      } while (elapsed < ms);
      return count * 1000 / elapsed;
    };
    await measure(250);
    const samples = [];
    for (let i = 0; i < 5; i++) samples.push(await measure(1000));
    results[chain] = {
      medianOpsPerSecond: [...samples].sort((a, b) => a - b)[2], samples,
      signedFixtureHash: createHash('sha256').update(signed).digest('hex')
    };
  }
  console.log(JSON.stringify({ backend: process.env.BITCORE_ECDSA_BACKEND || 'auto', results }, null, 2));
}

main().catch(err => { console.error(err); process.exitCode = 1; });
