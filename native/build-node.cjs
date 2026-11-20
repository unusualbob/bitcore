/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone CommonJS script. */
'use strict';

// Explicit developer build. npm consumers can use the JS backend without Cargo.
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const output = execFileSync('cargo', [
  'build', '--locked', '--release', '-p', 'bitcore-node-addon', '--message-format=json'
], { cwd: __dirname, encoding: 'utf8', maxBuffer: 8 * 1024 * 1024, stdio: ['ignore', 'pipe', 'inherit'] });
const records = output.trim().split('\n').map(line => JSON.parse(line));
const artifact = records.find(record => record.reason === 'compiler-artifact' &&
  record.target.name === 'bitcore_node_addon' && record.target.kind.includes('cdylib'));
if (!artifact) throw new Error('Cargo did not produce the bitcore Node addon');
const binary = artifact.filenames.find(file => /\.(so|dylib|dll)$/.test(file));
if (!binary) throw new Error('Missing native library in Cargo output');
const dest = path.join(__dirname, '../packages/bitcore-lib/lib/native/bitcore_ecdsa.node');
fs.mkdirSync(path.dirname(dest), { recursive: true });
// Replace atomically so a process using the previous binary can finish safely.
const temporary = path.join(path.dirname(dest), 'bitcore_ecdsa.' + process.pid + '.tmp.node');
try {
  fs.copyFileSync(binary, temporary);
  fs.renameSync(temporary, dest);
} finally {
  fs.rmSync(temporary, { force: true });
}
console.log(dest);
