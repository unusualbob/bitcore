/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone CommonJS packaging test. */
'use strict';

const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

// Exercise Docker's own ignore rules without sending the checkout or running
// an image. A source marker ensures COPY still includes every coin package.
const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'bitcore-docker-context-'));
const context = path.join(temporary, 'context');
const coins = ['bitcore-lib', 'bitcore-lib-cash', 'bitcore-lib-doge', 'bitcore-lib-ltc'];
try {
  fs.mkdirSync(context);
  fs.copyFileSync(path.join(__dirname, '../.dockerignore'), path.join(context, '.dockerignore'));
  fs.writeFileSync(path.join(context, 'Dockerfile'), 'FROM scratch\nCOPY packages /packages\n');
  for (const coin of coins) {
    const dir = path.join(context, 'packages', coin, 'lib/native');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'source.js'), coin);
  }
  for (const mode of ['clean', 'after-host-build']) {
    const out = path.join(temporary, mode);
    if (mode === 'after-host-build') {
      for (const coin of coins) {
        const dir = path.join(context, 'packages', coin, 'lib/native');
        fs.writeFileSync(path.join(dir, 'bitcore_ecdsa.node'), 'local release binary');
        fs.writeFileSync(path.join(dir, 'bitcore_ecdsa.123.tmp.node'), 'interrupted build');
      }
    }
    execFileSync('docker', ['buildx', 'build', '--network=none', '--output', 'type=local,dest=' + out, context], {
      stdio: 'inherit'
    });
    for (const coin of coins) {
      const dir = path.join(out, 'packages', coin, 'lib/native');
      assert.deepEqual(fs.readdirSync(dir), ['source.js'], coin + ' (' + mode + ')');
      assert.equal(fs.readFileSync(path.join(dir, 'source.js'), 'utf8'), coin);
    }
  }
} finally {
  fs.rmSync(temporary, { recursive: true, force: true });
}
