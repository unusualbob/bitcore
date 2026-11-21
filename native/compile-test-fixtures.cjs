/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone CommonJS test runner. */
'use strict';

const { execFileSync } = require('node:child_process');
const path = require('node:path');

module.exports = function compileFixtures() {
  const projects = ['bitcore-logging', 'crypto-wallet-core', 'bitcore-wallet-service', 'bitcore-wallet-client', 'bitcore-client'];
  for (const project of projects) {
    execFileSync(process.execPath, [require.resolve('typescript/bin/tsc'), '-p', path.join(__dirname, '../packages', project)], {
      stdio: 'inherit'
    });
  }
};
