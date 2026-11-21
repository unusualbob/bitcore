/* eslint @typescript-eslint/no-require-imports: "off" -- Offline differential tests. */
'use strict';

const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const compileFixtures = require('./compile-test-fixtures.cjs');
const report = require('./reference-coverage.cjs');

const repo = path.resolve(__dirname, '..');
const mocha = require.resolve('mocha/bin/mocha');
const suites = ['bitcore-lib', 'bitcore-lib-cash', 'bitcore-lib-doge', 'bitcore-lib-ltc', 'bitcore-mnemonic',
  'crypto-wallet-core'].map(pkg => ({ cwd: path.join(repo, 'packages', pkg), name: pkg, mocha: true,
  args: [mocha, '--recursive', pkg === 'crypto-wallet-core' ? 'ts_build/test' : 'test'] }));
suites.push({ name: 'client', mocha: true, args: [mocha, 'packages/bitcore-client/ts_build/test/unit/client-auth.test.js',
  'packages/bitcore-client/ts_build/test/unit/encryption.test.js'] });

const corpora = {
  'test-parity.cjs': '--corpus', 'test-forks.cjs': '--corpus', 'test-hdkeys.cjs': '--corpus',
  'test-point-api.cjs': '--corpus', 'test-sol.cjs': '--sample', 'test-taproot.cjs': '--sample',
  'test-cwc-ledgers.cjs': '--corpus', 'test-curve-boundaries.cjs': '--selected'
};
for (const [name, arg] of Object.entries(corpora)) {
  suites.push({ name, args: [path.join(__dirname, name), arg], compareOutput: true });
}
for (const name of ['test-base58.cjs', 'test-encoding.cjs', 'test-random-nonce.cjs', 'test-wallet-signatures.cjs',
  'bench-wallet-addresses.cjs', 'bench-rpc.mjs', 'test-xrp-keys.mjs', 'test-ecies.cjs',
  'test-large-keccak.cjs', 'test-reference-hash.cjs']) {
  suites.push({ name, args: [path.join(__dirname, name), ...(name === 'bench-rpc.mjs' ? ['--test'] : [])] });
}

function run(suite, dir, mode) {
  const args = suite.args.slice();
  if (suite.mocha) args.push('--exit', '--timeout', '30000', '--reporter', 'json');
  if (suite.name === 'test-xrp-keys.mjs' && mode === 'js') args.push('--no-derivation');
  const env = { ...process.env };
  for (const coin of ['ECDSA', 'BCH', 'LTC', 'DOGE']) env['BITCORE_' + coin + '_BACKEND'] = mode;
  env.NODE_V8_COVERAGE = path.join(dir, mode + '-profiles');
  env.BITCORE_REFERENCE_DISPATCH = path.join(dir, mode + '-dispatch');
  fs.mkdirSync(env.BITCORE_REFERENCE_DISPATCH, { recursive: true });
  args.unshift('--require', path.join(__dirname, 'reference-dispatch.cjs'));
  const log = path.join(dir, mode + '-' + suite.name + '.log');
  const fd = fs.openSync(log, 'w', 0o600);
  try {
    execFileSync(process.execPath, args, { env, cwd: suite.cwd || repo, stdio: ['ignore', fd, 'inherit'] });
  } finally {
    fs.closeSync(fd);
  }
  if (suite.mocha) {
    const results = JSON.parse(fs.readFileSync(log, 'utf8'));
    assert.ok(results.passes.length > 0 && results.failures.length === 0, suite.name);
    const titles = tests => tests.map(test => test.fullTitle).sort();
    return { passed: titles(results.passes), pending: titles(results.pending) };
  }
  return suite.compareOutput ? fs.readFileSync(log, 'utf8') : undefined;
}

async function main() {
  compileFixtures();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bitcore-reference-'));
  console.log('Reference profiles and test logs: ' + dir);
  let passed = 0;
  let pending = 0;
  for (const suite of suites) {
    console.log('Testing both backends: ' + suite.name);
    const reference = run(suite, dir, 'js');
    assert.deepEqual(run(suite, dir, 'native'), reference, suite.name);
    if (suite.mocha) {
      passed += reference.passed.length;
      pending += reference.pending.length;
    }
  }
  console.log('Mocha results per backend: ' + passed + ' passed, ' + pending + ' pending.');
  const calls = mode => fs.readdirSync(path.join(dir, mode + '-dispatch')).map(file =>
    JSON.parse(fs.readFileSync(path.join(dir, mode + '-dispatch', file))));
  const js = calls('js');
  const observed = calls('native');
  assert.ok(js.length >= suites.length && observed.length >= suites.length, 'Missing dispatch records');
  assert.deepEqual(js.flatMap(entry => entry.exports), [], 'Forced-JS cases loaded the addon');
  const addon = require('../packages/bitcore-lib/lib/native/bitcore_ecdsa.node');
  const expected = new Set(Object.keys(addon).filter(name => typeof addon[name] === 'function'));
  const reached = new Set(observed.flatMap(entry => entry.calls));
  assert.deepEqual(reached, expected, 'Missing public dispatch for native exports');
  console.log('Successful public dispatch for ' + reached.size + ' native exports.');
  const manifests = ['reference-curve.json', 'reference-chains.json', 'reference-hash.json'];
  console.log('Forced-JavaScript reference coverage:');
  const jsPassed = await report([path.join(dir, 'js-profiles')], manifests, true);
  console.log('Reference coverage including JavaScript fallbacks in native mode:');
  const combinedPassed = await report(['js', 'native'].map(mode => path.join(dir, mode + '-profiles')), manifests);
  return jsPassed && combinedPassed;
}

// check-crypto already runs its own parity suites. Run the coverage gate explicitly.
if (require.main === module) main().then(ok => { process.exitCode = ok ? 0 : 1; })
  .catch(err => { console.error(err); process.exitCode = 1; });
