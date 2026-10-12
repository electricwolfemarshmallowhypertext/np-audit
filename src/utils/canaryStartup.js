'use strict';

const path = require('path');
const ACTIVE = Symbol.for('np-audit.canary-startup');
const activeStartup = () => globalThis[ACTIVE] || null;

function startupEnvironment(env, base, config = {}, roots = null) {
  const selected = roots || [base, ...(config.canaryRoots || []).map(root => path.resolve(base, root)), ...(activeStartup()?.roots || [])];
  const settings = JSON.stringify({ roots: [...new Set(selected.map(root => path.resolve(root)))], base: path.resolve(base) });
  if (Buffer.byteLength(settings, 'utf8') > 65536) throw new Error('Node startup guard root configuration exceeds 64 KiB');
  const preload = path.resolve(__dirname, '../core/canaryPreload.js').split(path.sep).join('/');
  return { ...env, NPA_CANARY_GUARD: settings,
    NODE_OPTIONS: `--require ${JSON.stringify(preload)}${env.NODE_OPTIONS ? ' ' + env.NODE_OPTIONS : ''}` };
}

function shellSetup(env) {
  const quote = value => process.platform === 'win32' ? "'" + value.replace(/'/g, "''") + "'" : "'" + value.replace(/'/g, "'\\''") + "'";
  return ['NPA_CANARY_GUARD', 'NODE_OPTIONS'].map(name => process.platform === 'win32'
    ? `$env:${name} = ${quote(env[name])}` : `export ${name}=${quote(env[name])}`);
}

module.exports = { startupEnvironment, shellSetup, activeStartup, ACTIVE };
