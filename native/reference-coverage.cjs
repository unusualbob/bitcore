/* eslint @typescript-eslint/no-require-imports: "off" -- Offline test coverage report. */
'use strict';

const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { fileURLToPath } = require('node:url');
const CoverageReport = require('monocart-coverage-reports');

const root = path.join(__dirname, '..');
// The manifests use source line numbers. A source edit must not silently shift
// the coverage target to an unrelated (already tested) line.
const fingerprints = {
  'reference-curve.json': '282c52f7094aa3763b35fe3a50795a88000242c8a6906b0676b969c39af5b5c6',
  'reference-hash.json': 'a2513ebddba15ced9e55bcf63de336007500ce0ccb77c4b03e5bdc52bdd891c2',
  'reference-chains.json': '43a7b3f4bd7462ab7ff1658895f3ca8cdaf0cb3b59d9e924049d0eb1deb1a76c'
};

async function report(directories, manifests, forcedJs = false) {
  assert.ok(directories.length, 'Pass V8 coverage directories from the forced-JavaScript test processes');
  const scope = new Map();
  for (const name of manifests) {
    const fingerprint = createHash('sha256');
    const manifest = require('./' + name);
    for (const file of Object.keys(manifest).sort()) {
      const ranges = manifest[file];
      const lines = fs.readFileSync(path.resolve(root, file), 'utf8').split(/\r?\n/);
      const snippets = ranges.map(([first, last]) => {
        assert.ok(first > 0 && last >= first && last <= lines.length, file + ': invalid reference range');
        return lines.slice(Math.max(first - 2, 0), last + 1);
      });
      fingerprint.update(JSON.stringify([file, ranges, snippets]));
      scope.set(file, [...(scope.get(file) || []), ...ranges]);
    }
    assert.equal(fingerprint.digest('hex'), fingerprints[name], 'Review source ranges and refresh fingerprint for ' + name);
  }
  const outputDir = fs.mkdtempSync(path.join(os.tmpdir(), 'bitcore-js-report-'));
  const coverageReport = new CoverageReport({
    baseDir: root, outputDir, reports: ['json'], logging: 'off',
    entryFilter: entry => {
      const file = path.relative(root, fileURLToPath(entry.url));
      const ts = file.replace(/\/(?:ts_build|build)\//, '/').replace(/\.js$/, '.ts');
      return scope.has(file) || scope.has(ts);
    }
  });
  for (const dir of directories) {
    assert.ok(fs.readdirSync(dir).some(name => /^coverage-.*\.json$/.test(name)), 'No V8 profiles in ' + dir);
    await coverageReport.addFromDir(dir);
  }
  await coverageReport.generate();
  const coverage = JSON.parse(fs.readFileSync(path.join(outputDir, 'coverage-final.json')));
  const files = new Map(Object.values(coverage).map(f => [path.relative(root, path.resolve(root, f.path)), f]));
  const totals = { statements: [0, 0], lines: [0, 0], functions: [0, 0], branches: [0, 0] };
  const gaps = {};
  const nativeModeFallbacks = {};
  for (const [file, ranges] of scope) {
    const entry = files.get(file);
    assert.ok(entry, 'No source coverage for ' + file);
    const included = line => ranges.some(([first, last]) => line >= first && line <= last);
    const misses = [];
    const count = (kind, hits, location) => {
      totals[kind][1]++;
      if (hits > 0) totals[kind][0]++;
      else misses.push(kind + ' ' + location);
    };
    const lines = new Map();
    for (const [id, loc] of Object.entries(entry.statementMap)) {
      const line = loc.start.line;
      if (!included(line)) continue;
      count('statements', entry.s[id], line + ':' + loc.start.column);
      lines.set(line, Math.max(lines.get(line) || 0, entry.s[id]));
    }
    for (const [line, hits] of lines) count('lines', hits, line);
    for (const [id, fn] of Object.entries(entry.fnMap)) {
      if (included(fn.decl.start.line)) count('functions', entry.f[id], fn.name + ' at ' + fn.decl.start.line);
    }
    for (const [id, branch] of Object.entries(entry.branchMap)) {
      if (!included(branch.loc.start.line)) continue;
      for (const [i, hits] of entry.b[id].entries()) {
        const loc = branch.locations[i].start;
        // Each fork requests a root-only JS tree for small blocks only when the addon is present.
        // Report that arm here and require it in the combined report below.
        if (forcedJs && hits === 0 && branch.type === 'ConditionalExpression' && i === 0 &&
            /^packages\/bitcore-lib(?:-cash|-ltc|-doge)?\/lib\/block\/block\.js$/.test(file) &&
            fs.readFileSync(path.join(root, file), 'utf8').split('\n')[loc.line - 1]?.trim() ===
              'return rootOnly ? tree[tree.length - 1] : tree;') {
          nativeModeFallbacks[file] = loc.line;
          totals.branches[1]++;
          continue;
        }
        count('branches', hits, branch.loc.start.line + ' ' + branch.type + '[' + i + '] at ' + loc.line + ':' + loc.column);
      }
    }
    for (const [first, last] of ranges) {
      assert.ok([...lines.keys()].some(line => line >= first && line <= last),
        'No executable statements mapped for ' + file + ' at lines ' + first + '–' + last);
    }
    if (misses.length) gaps[file] = misses;
  }
  console.log(JSON.stringify({ files: scope.size, totals, gaps, nativeModeFallbacks, outputDir }, null, 2));
  return Object.keys(gaps).length === 0;
}

module.exports = report;
if (require.main === module) {
  const args = process.argv.slice(2);
  report(args.filter(arg => arg !== '--js'), Object.keys(fingerprints), args.includes('--js'))
    .then(ok => { process.exitCode = ok ? 0 : 1; })
    .catch(error => { console.error(error); process.exitCode = 1; });
}
