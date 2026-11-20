/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone CommonJS test runner. */
'use strict';

const { execFileSync } = require('node:child_process');
const { readdirSync } = require('node:fs');
const path = require('node:path');

// Separate processes isolate the backend selector, addon mocks and shared BN
// prototypes. This runner exercises every checked-in native parity corpus.
const env = { ...process.env, BITCORE_ECDSA_BACKEND: 'native' };
for (const coin of ['BCH', 'LTC', 'DOGE']) delete env[`BITCORE_${coin}_BACKEND`];
for (const file of readdirSync(__dirname).filter(name => /^test-.*\.[cm]js$/.test(name)).sort()) {
  execFileSync(process.execPath, [path.join(__dirname, file)], { stdio: 'inherit', env });
}
execFileSync(process.execPath, [path.join(__dirname, 'test-random-nonce.cjs')], {
  stdio: 'inherit', env: { ...env, BITCORE_ECDSA_BACKEND: 'js' }
});
execFileSync(process.execPath, [path.join(__dirname, 'bench-utxo.cjs'), '--test'], { stdio: 'inherit', env });
