'use strict';

const { execFileSync } = require('node:child_process');
const os = require('node:os');

function measure() {
  const loadStart = performance.now();
  const bitcore = require('..');
  const requireMilliseconds = performance.now() - loadStart;
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
  const results = {};
  for (const [name, operation] of Object.entries(operations)) {
    const run = duration => {
      let count = 0;
      const start = performance.now();
      let elapsed;
      do {
        for (const fixture of fixtures) operation(fixture);
        count += fixtures.length;
        elapsed = performance.now() - start;
      } while (elapsed < duration);
      return count * 1000 / elapsed;
    };
    run(250);
    results[name] = run(1000);
  }
  return { requireMilliseconds, operationsPerSecond: results };
}

if (process.argv[2] === '--sample') {
  process.stdout.write(JSON.stringify(measure()));
} else {
  const samples = { js: [], native: [] };
  for (let round = 0; round < 5; round++) {
    for (const backend of round % 2 ? ['native', 'js'] : ['js', 'native']) {
      const result = execFileSync(process.execPath, [__filename, '--sample'], {
        env: { ...process.env, BITCORE_ECDSA_BACKEND: backend }, encoding: 'utf8'
      });
      samples[backend].push(JSON.parse(result));
    }
  }
  const summary = {};
  for (const name of Object.keys(samples.js[0].operationsPerSecond)) {
    const median = backend => {
      const rates = samples[backend].map(sample => sample.operationsPerSecond[name]);
      return rates.sort((a, b) => a - b)[Math.floor(rates.length / 2)];
    };
    const js = median('js');
    const native = median('native');
    summary[name] = { js, native, speedup: native / js };
  }
  console.log(JSON.stringify({ node: process.version, cpu: os.cpus()[0].model,
    platform: process.platform, arch: process.arch, summary, samples }, null, 2));
}
