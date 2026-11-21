/* eslint @typescript-eslint/no-require-imports: "off" -- Preload only in the paired coverage tests. */
'use strict';

const fs = require('node:fs');
const Module = require('node:module');
const path = require('node:path');
const { threadId } = require('node:worker_threads');

const load = Module._extensions['.node'];
const packages = path.resolve(__dirname, '../packages') + path.sep;
const calls = new Set();
const exportsSeen = new Set();
Module._extensions['.node'] = function loadAddon(module, filename) {
  load(module, filename);
  if (!filename.startsWith(packages) || path.basename(filename) !== 'bitcore_ecdsa.node') return;
  for (const [name, operation] of Object.entries(module.exports)) {
    if (typeof operation !== 'function') continue;
    exportsSeen.add(name);
    module.exports[name] = function observed(...args) {
      const result = operation(...args);
      if (result != null && result !== false && !calls.has(name)) {
        // A direct binding test alone does not establish public dispatch.
        const trace = {};
        Error.captureStackTrace(trace, observed);
        if (trace.stack.split('\n').slice(1).some(frame => frame.includes(packages) &&
            /[/\\](lib|src|ecies)[/\\]/.test(frame) && !frame.includes('node_modules'))) calls.add(name);
      }
      return result;
    };
  }
};
process.on('exit', () => {
  const file = path.join(process.env.BITCORE_REFERENCE_DISPATCH, process.pid + '-' + threadId + '.json');
  fs.writeFileSync(file, JSON.stringify({ exports: [...exportsSeen], calls: [...calls] }));
});
