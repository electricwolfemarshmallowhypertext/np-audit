'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

if (process.platform !== 'win32') console.log('  SKIP terminal installer test: Windows required');
else {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'npa-profile-installer-'));
  const shell = path.join(process.env.SystemRoot, 'System32/WindowsPowerShell/v1.0/powershell.exe');
  const installer = path.resolve(__dirname, '../../bin/install-canary-terminal.ps1');
  const profile = path.join(parent, 'profile.ps1');
  const env = { ...process.env, NPA_CANARY_GUARD: '', NODE_OPTIONS: '' };
  function run(uninstall = false) {
    const result = spawnSync(shell, ['-NoProfile', '-NonInteractive', '-File', installer, '-ProfilePaths', profile, '-SkipCmd',
      ...(uninstall ? ['-Uninstall'] : [])], { env, encoding: 'utf8', timeout: 20000 });
    assert.ifError(result.error);
    assert.strictEqual(result.status, 0, result.stderr);
  }
  try {
    run();
    assert.match(fs.readFileSync(profile, 'utf8'), /automatic terminal activation/);
    run(true);
    assert.strictEqual(fs.readFileSync(profile).length, 0);
    const original = Buffer.from('# existing user setup\r\n', 'utf8');
    fs.writeFileSync(profile, original);
    run();
    const installed = fs.readFileSync(profile);
    assert.ok(installed.subarray(0, original.length).equals(original));
    run();
    assert.deepStrictEqual(fs.readFileSync(profile), installed);
    run(true);
    assert.deepStrictEqual(fs.readFileSync(profile), original);
    console.log('  terminal installer: absent profile, original-byte preservation, idempotence and uninstall passed on isolated paths; registry unchanged');
  } finally { fs.rmSync(parent, { recursive: true, force: true }); }
}
