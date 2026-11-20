'use strict';

const { execFileSync } = require('node:child_process');
const os = require('node:os');

function measure(createSuite, { load, warmupMs, sampleMs }) {
  const loadStart = performance.now();
  const bitcore = load();
  const requireMilliseconds = performance.now() - loadStart;
  const { fixtures, operations } = createSuite(bitcore);
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
    run(warmupMs);
    results[name] = run(sampleMs);
  }
  return { requireMilliseconds, operationsPerSecond: results };
}

module.exports = function benchmark(file, createSuite, {
  load = () => require('..'), warmupMs = 250, sampleMs = 1000
} = {}) {
  if (process.argv[2] === '--sample') {
    process.stdout.write(JSON.stringify(measure(createSuite, { load, warmupMs, sampleMs })));
    return;
  }
  const samples = { js: [], native: [] };
  for (let round = 0; round < 5; round++) {
    for (const backend of round % 2 ? ['native', 'js'] : ['js', 'native']) {
      const result = execFileSync(process.execPath, [file, '--sample'], {
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
};
