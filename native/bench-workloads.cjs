/* eslint @typescript-eslint/no-require-imports: "off" -- Offline two-checkout benchmark. */
'use strict';

const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const { existsSync } = require('node:fs');
const { cpus } = require('node:os');
const { resolve } = require('node:path');

const groups = ['utxo', 'wallet', 'chains', 'ledger'];
const rounds = 10;

async function measure(run, duration) {
  let result;
  let count = 0;
  const start = performance.now();
  do {
    result = await run();
    count++;
  } while (performance.now() - start < duration);
  return { ms: (performance.now() - start) / count, result };
}

async function sample(root, side, group) {
  const pkg = name => resolve(root, 'packages', name);
  const wallet = require(pkg('crypto-wallet-core'));
  for (const [suffix, exported] of [['', 'BitcoreLib'], ['-cash', 'BitcoreLibCash'],
    ['-doge', 'BitcoreLibDoge'], ['-ltc', 'BitcoreLibLtc']]) {
    const coin = pkg('bitcore-lib' + suffix);
    assert.equal(wallet[exported].PrivateKey, require(coin).PrivateKey, 'Coin library resolved outside the checkout');
    const loader = resolve(coin, 'lib/crypto/ecdsa-native.js');
    if (side === 'master') assert.ok(!existsSync(loader), 'Expected upstream without the Rust addon');
    else assert.ok(require(loader).native, 'Expected compiled branch addon');
  }
  const fixtures = await require('./bench-workload-' + group + '.cjs')(root);
  const rows = {};
  for (const [name, { run, check }] of Object.entries(fixtures)) {
    await measure(run, 100);
    const { ms, result } = await measure(run, 300);
    rows[name] = { ms, output: await check(result) };
    assert.notEqual(rows[name].output, undefined);
  }
  return rows;
}

function median(values) {
  const sorted = values.slice().sort((a, b) => a - b);
  return (sorted[rounds / 2 - 1] + sorted[rounds / 2]) / 2;
}

function compare(masterRoot, branchRoot, group) {
  const env = { ...process.env };
  for (const coin of ['ECDSA', 'BCH', 'LTC', 'DOGE']) env['BITCORE_' + coin + '_BACKEND'] = 'native';
  const pairs = [];
  for (let round = 0; round < rounds; round++) {
    const pair = {};
    for (const side of round % 2 ? ['branch', 'master'] : ['master', 'branch']) {
      const args = [__filename, '--sample', side === 'branch' ? branchRoot : masterRoot, side, group];
      pair[side] = JSON.parse(execFileSync(process.execPath, args, { env, encoding: 'utf8' }));
    }
    assert.deepEqual(Object.keys(pair.master), Object.keys(pair.branch));
    for (const name of Object.keys(pair.master)) {
      assert.deepEqual(pair.master[name].output, pair.branch[name].output, name);
      if (round) assert.deepEqual(pair.master[name].output, pairs[0].master[name].output, name);
    }
    pairs.push(pair);
    console.error(group + ': completed pair ' + (round + 1) + '/' + rounds);
  }
  return Object.fromEntries(Object.keys(pairs[0].master).map(name => {
    const samples = pairs.map(p => [p.master[name].ms, p.branch[name].ms]);
    const masterMs = median(samples.map(p => p[0]));
    const branchMs = median(samples.map(p => p[1]));
    const changes = samples.map(([a, b]) => 100 * (a / b - 1));
    return [name, { masterMs, branchMs, speedup: masterMs / branchMs,
      low: Math.min(...changes), high: Math.max(...changes),
      average: changes.reduce((a, b) => a + b) / rounds, samples }];
  }));
}

async function main() {
  const [first, second, ...selected] = process.argv.slice(2);
  if (first === '--sample') {
    const [side, group] = selected;
    assert.ok(['master', 'branch'].includes(side) && groups.includes(group));
    return sample(second, side, group);
  }
  assert.ok(first && second && selected.every(group => groups.includes(group)),
    'Usage: node native/bench-workloads.cjs <master-root> <branch-root> [workload groups...]');
  const rows = {};
  for (const group of selected.length ? selected : groups) Object.assign(rows, compare(first, second, group));
  return { node: process.version, cpu: cpus()[0]?.model, rounds, rows };
}

main().then(result => console.log(JSON.stringify(result, null, 2))).catch(err => {
  console.error(err);
  process.exitCode = 1;
});
