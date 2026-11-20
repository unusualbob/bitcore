/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone CommonJS benchmark. */
'use strict';

// cargo build --locked --release --manifest-path native/Cargo.toml -p bitcore-kdfs --example wallet_kdfs
// node native/bench-wallet-kdfs.cjs [samples] [rust-example-path]
const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');
const crypto = require('node:crypto');
const { createRequire } = require('node:module');
const os = require('node:os');
const path = require('node:path');
const { performance } = require('node:perf_hooks');
const { promisify } = require('node:util');
const sjcl = require('sjcl');

const samples = Number(process.argv[2] ?? 7);
assert.ok(Number.isSafeInteger(samples) && samples >= 3, 'Use at least three samples');
assert.equal(crypto.getFips(), 0, 'The benchmark needs the default OpenSSL provider');
const executable = process.argv[3] ?? path.join(__dirname, 'target', 'release', 'examples',
  process.platform === 'win32' ? 'wallet_kdfs.exe' : 'wallet_kdfs');
const scryptsy = createRequire(require.resolve('bip38'))('scryptsy');
const runExample = promisify(execFile);
const password = 'synthetic-pässphrase-🏳️';
const walletSalt = '0123456789abcdef';
const importSalt = '01234567';
const bip38Salt = 'abcd';

function timed(run) {
  return () => {
    const start = performance.now();
    const output = run();
    return { elapsed: performance.now() - start, hex: Buffer.from(output).toString('hex') };
  };
}

function rust(method, salt, rounds, length) {
  return async () => {
    const { stdout } = await runExample(executable, [method, password, salt, String(rounds), String(length)]);
    const [elapsed, hex] = stdout.trim().split(' ');
    return { elapsed: Number(elapsed), hex };
  };
}

async function compare(name, implementations) {
  const entries = Object.entries(implementations);
  const results = entries.map(() => []);
  const expected = (await entries[0][1]()).hex;
  for (const [, run] of entries.slice(1)) assert.equal((await run()).hex, expected);
  for (let sample = 0; sample < samples; sample++) {
    for (let step = 0; step < entries.length; step++) {
      const index = (sample + step) % entries.length;
      const { elapsed, hex } = await entries[index][1]();
      assert.equal(hex, expected);
      assert.ok(Number.isFinite(elapsed) && elapsed > 0);
      results[index].push(elapsed);
    }
  }
  console.log(name);
  for (const [index, [label]] of entries.entries()) {
    const values = results[index].sort((a, b) => a - b);
    const median = (values[Math.floor((samples - 1) / 2)] + values[Math.floor(samples / 2)]) / 2;
    console.log(`  ${label.padEnd(15)} ${median.toFixed(2)} ms median [${values[0].toFixed(2)}, ${values.at(-1).toFixed(2)}]`);
  }
}

async function main() {
  console.log(`Node ${process.version}, OpenSSL ${process.versions.openssl}, ${process.arch}, ${os.cpus()[0]?.model}`);
  console.log(`${samples} samples per implementation. Rust timings exclude subprocess startup.`);

  for (const rounds of [600_000, 800_000]) {
    await compare(`Wallet PBKDF2-HMAC-SHA256, ${rounds} iterations, 32 bytes`, {
      'Node/OpenSSL': timed(() => crypto.pbkdf2Sync(password, walletSalt, rounds, 32, 'sha256')),
      'Rust release': rust('pbkdf2', walletSalt, rounds, 32),
    });
  }

  const importRounds = 200_000;
  await compare(`Bitcoin Core import SHA-512, ${importRounds} rounds`, {
    'Node/OpenSSL': timed(() => {
      let bytes = Buffer.from(password + importSalt);
      for (let i = 0; i < importRounds; i++) bytes = crypto.createHash('sha512').update(bytes).digest();
      return bytes;
    }),
    'Rust release': rust('sha512', importSalt, importRounds, 64),
  });

  await compare('BIP38 scrypt, N=16384, r=8, p=8, 64 bytes', {
    'Legacy scryptsy': timed(() => scryptsy(Buffer.from(password), Buffer.from(bip38Salt), 16384, 8, 8, 64)),
    'Node/OpenSSL': timed(() => crypto.scryptSync(password, bip38Salt, 64, { N: 16384, r: 8, p: 8 })),
    'Rust release': rust('scrypt', bip38Salt, 0, 64),
  });

  await compare('Legacy SJCL PBKDF2-HMAC-SHA256, 10,000 iterations, 16 bytes', {
    'Node/OpenSSL': timed(() => crypto.pbkdf2Sync(password, walletSalt, 10_000, 16, 'sha256')),
    'SJCL': timed(() => Buffer.from(sjcl.codec.hex.fromBits(
      sjcl.misc.pbkdf2(password, sjcl.codec.utf8String.toBits(walletSalt), 10_000, 128)
    ), 'hex')),
  });
}

main().catch(err => {
  console.error(err);
  process.exitCode = 1;
});
