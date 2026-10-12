'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { createCanaryMonitor } = require('../../src/core/canaryMonitor');

module.exports = (async () => {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'npa-monitor-unit-'));
  const reports = [];
  const errors = [];
  const monitors = [];
  const calls = [];
  const originals = [];
  function prohibit(module, name) {
    if (typeof module[name] !== 'function') return;
    originals.push([module, name, module[name]]);
    module[name] = () => { calls.push(name); throw new Error('Monitor must not execute commands or request network'); };
  }
  const watch = fs.watch;
  try {
    for (const name of ['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork']) prohibit(require('child_process'), name);
    for (const module of [require('http'), require('https')]) for (const name of ['get', 'request']) prohibit(module, name);
    prohibit(require('net'), 'connect'); prohibit(require('net').Socket.prototype, 'connect'); prohibit(require('tls'), 'connect'); prohibit(globalThis, 'fetch');
    // Simulate unavailable notifications to prove the real periodic scan works.
    fs.watch = () => { throw Object.assign(new Error('Watch unavailable in this test'), { code: 'TEST_WATCH_UNAVAILABLE' }); };
    const monitor = createCanaryMonitor({ roots: [parent], intervalMs: 200, onReport: report => reports.push(report), onError: error => errors.push(error) });
    monitors.push(monitor);
    assert.strictEqual(reports[0].monitor.watchErrors[0].error, 'TEST_WATCH_UNAVAILABLE');
    assert.strictEqual(reports[0].complete, false);
    fs.writeFileSync(path.join(parent, 'canary.js'), '// inert periodic-check fixture\n');
    const deadline = Date.now() + 4000;
    while (fs.existsSync(path.join(parent, 'canary.js')) && Date.now() < deadline) await new Promise(resolve => setTimeout(resolve, 25));
    assert.ok(!fs.existsSync(path.join(parent, 'canary.js')), 'Periodic check must quarantine a new file without watch notifications');
    assert.ok(reports.some(report => report.quarantine.actions.some(action => action.status === 'quarantined')));
    monitor.close();
    const stoppedCount = reports.length;
    fs.writeFileSync(path.join(parent, 'canary.js'), '// after close; must remain\n');
    await new Promise(resolve => setTimeout(resolve, 250));
    assert.ok(fs.existsSync(path.join(parent, 'canary.js')));
    assert.strictEqual(reports.length, stoppedCount);
    const readOnly = createCanaryMonitor({ roots: [parent], readOnly: true, intervalMs: 200, onReport: report => reports.push(report) });
    monitors.push(readOnly);
    assert.ok(fs.existsSync(path.join(parent, 'canary.js')));
    assert.strictEqual(reports.at(-1).monitor.mode, 'read-only');
    assert.deepStrictEqual(calls, []);
    assert.deepStrictEqual(errors, []);
    console.log('  canary monitor: automatic periodic fallback, incomplete watch coverage, read-only mode, shutdown and zero subprocess/network calls passed');
  } finally {
    for (const monitor of monitors) monitor.close();
    fs.watch = watch;
    for (const [module, name, original] of originals.reverse()) module[name] = original;
    fs.rmSync(parent, { recursive: true, force: true });
  }
})();
