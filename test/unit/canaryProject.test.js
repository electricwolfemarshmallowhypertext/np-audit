'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { projectRoots } = require('../../src/utils/canaryProject');
const { automaticEnvironment } = require('../../src/utils/canaryStartup');

const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'npa-auto-project-'));
try {
  const project = path.join(parent, 'project');
  const nested = path.join(project, 'nested');
  fs.mkdirSync(nested, { recursive: true });
  fs.writeFileSync(path.join(project, 'package.json'), '{}');
  assert.deepStrictEqual(projectRoots(nested), [project]);
  assert.deepStrictEqual(projectRoots(parent), []);
  assert.deepStrictEqual(projectRoots(parent, path.join(project, 'app.js')), [project]);
  const loose = path.join(parent, 'loose');
  fs.mkdirSync(loose);
  assert.deepStrictEqual(projectRoots(parent, path.join(loose, 'canary.js')), [loose]);
  fs.writeFileSync(path.join(loose, 'canary.js'), '// inert');
  assert.deepStrictEqual(projectRoots(loose), [loose]);
  const env = automaticEnvironment({ NODE_OPTIONS: '--trace-warnings' });
  assert.deepStrictEqual(JSON.parse(env.NPA_CANARY_GUARD), { autoProject: true });
  assert.match(env.NODE_OPTIONS, /^--require /);
  assert.ok(env.NODE_OPTIONS.endsWith('--trace-warnings'));
  assert.strictEqual(automaticEnvironment(env).NODE_OPTIONS, env.NODE_OPTIONS);
  const prior = automaticEnvironment({ BASH_ENV: path.join(parent, 'original.sh') });
  assert.strictEqual(prior.NPA_CANARY_ORIGINAL_BASH_ENV, path.join(parent, 'original.sh'));
  assert.ok(prior.BASH_ENV.endsWith('/bin/canary-bash-guard.sh'));
  assert.strictEqual(automaticEnvironment(prior).NPA_CANARY_ORIGINAL_BASH_ENV, prior.NPA_CANARY_ORIGINAL_BASH_ENV);
  console.log('  automatic roots: nearest project, loose canary, entry path, no project and idempotent environment passed');
} finally { fs.rmSync(parent, { recursive: true, force: true }); }
