/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone CommonJS test runner. */
'use strict';

const { execFileSync } = require('node:child_process');
const { readdirSync } = require('node:fs');
const path = require('node:path');

// Separate processes isolate the backend selector, addon mocks and shared BN
// prototypes. This runner exercises every checked-in native parity corpus.
const env = { ...process.env, BITCORE_ECDSA_BACKEND: 'native' };
for (const coin of ['BCH', 'LTC', 'DOGE']) delete env[`BITCORE_${coin}_BACKEND`];
// Compile only the workspace packages used by the parity fixtures, in dependency order.
for (const name of ['bitcore-logging', 'crypto-wallet-core', 'bitcore-wallet-service', 'bitcore-wallet-client', 'bitcore-client']) {
  execFileSync(process.execPath, [require.resolve('typescript/bin/tsc'), '-p', path.join(__dirname, '../packages', name)], {
    stdio: 'inherit'
  });
}
for (const file of readdirSync(__dirname).filter(name => /^test-.*\.[cm]js$/.test(name)).sort()) {
  execFileSync(process.execPath, [path.join(__dirname, file)], { stdio: 'inherit', env });
}
const jsEnv = { ...env, BITCORE_ECDSA_BACKEND: 'js' };
for (const file of ['test-random-nonce.cjs', 'test-bws-scan.cjs', 'test-wallet-signatures.cjs', 'bench-wallet-addresses.cjs']) {
  execFileSync(process.execPath, [path.join(__dirname, file)], { stdio: 'inherit', env: jsEnv });
}
execFileSync(process.execPath, [path.join(__dirname, 'bench-utxo.cjs'), '--test'], { stdio: 'inherit', env });
execFileSync(process.execPath, [path.join(__dirname, 'bench-rpc.mjs'), '--test'], { stdio: 'inherit', env });
execFileSync(process.execPath, [path.join(__dirname, 'bench-wallet-addresses.cjs')], { stdio: 'inherit', env });
