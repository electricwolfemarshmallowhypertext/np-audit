'use strict';

const path = require('path');
const fs = require('fs');
const { protectRepository } = require('./canaryProtection');
const { inside } = require('./canaryQuarantine');
const { startupTrustedFiles } = require('./canaryTrust');
const { ACTIVE } = require('../utils/canaryStartup');

try {
  const value = process.env.NPA_CANARY_GUARD;
  if (!value || Buffer.byteLength(value, 'utf8') > 65536) throw new Error('Node startup protection requires explicit NPA_CANARY_GUARD roots');
  const settings = JSON.parse(value);
  if (!Array.isArray(settings.roots) || !settings.roots.length || settings.roots.some(root => typeof root !== 'string' || !path.isAbsolute(root)) ||
      typeof settings.base !== 'string' || !path.isAbsolute(settings.base) || !settings.roots.some(root => inside(root, settings.base))) throw new Error('Invalid Node startup guard root configuration');
  const inline = process.execArgv.some(arg => /^-[ep]+$|^--(?:eval|print)(?:=|$)/.test(arg));
  const entry = !inline && process.argv[1] ? path.resolve(process.argv[1]) : null;
  if (entry && path.basename(entry) === 'canary.js' && !settings.roots.some(root => inside(root, entry))) {
    throw new Error('Canary entrypoint lies outside selected protection roots; startup blocked');
  }
  const report = protectRepository({ roots: settings.roots, trustedFiles: startupTrustedFiles(settings.base), trustBase: settings.base });
  if (!report.protection.allowed) {
    throw new Error('Protection failed: ' + JSON.stringify(report.protection.failures.slice(0, 20)));
  }
  if (entry && path.basename(entry) === 'canary.js' && !fs.existsSync(entry)) throw new Error('Canary entrypoint is quarantined or missing; startup blocked');
  globalThis[ACTIVE] = settings;
  if (report.quarantine.actions.length || report.repairs.actions.length) {
    process.stderr.write(`Canary startup protection: ${report.quarantine.actions.length} files quarantined; ${report.repairs.actions.length} references repaired\n`);
  }
} catch (err) {
  process.stderr.write('Canary startup blocked: ' + JSON.stringify(err.message) + '\n');
  process.exit(2);
}
