'use strict';

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const { protectRepository } = require('../core/canaryProtection');
const { checkPath, inside } = require('../core/canaryQuarantine');
const { startupEnvironment, automaticEnvironment, activeStartup } = require('../utils/canaryStartup');
const { projectRoots } = require('../utils/canaryProject');

module.exports = {
  name: 'canary-run',
  aliases: [],
  description: 'Protect selected roots before launching a command',
  help() {
    return `
  npa canary-run <root> [root...] -- <program> [arguments...]
  npa canary-run --auto -- <program> [arguments...]
  npa canary-run --auto --check
  npa canary-run --check  (check inherited startup roots without launching)

  Repairs references, quarantines untrusted canaries and updates ignore rules
  before launching the explicitly supplied command. Failed protection blocks
  launch. The working directory must be within a selected root.
  --auto selects the current project on each launch; outside a project it
  forwards the command with automatic Node startup protection inherited.
  Child Node processes inherit the startup guard. Program arguments after --
  are forwarded unchanged; np-audit does not evaluate them as shell text.
  PowerShell session setup also routes cmd, PowerShell, Bash and sh launchers
  through this check when those executables are available.
`;
  },
  run({ rawArgs, cwd }) {
    if (rawArgs.length === 1 && ['--help', '-h'].includes(rawArgs[0])) {
      process.stdout.write(this.help());
      return;
    }
    try {
      const sessionCheck = rawArgs.length === 1 && rawArgs[0] === '--check';
      const inherited = sessionCheck ? activeStartup() : null;
      if (sessionCheck && !inherited) throw new Error('Inherited startup protection is required for --check');
      const separator = rawArgs.findIndex(arg => arg === '--' || arg === '--encoded-argv' || arg === '--check');
      if (separator < (sessionCheck ? 0 : 1)) throw new Error('canary-run requires explicit roots and -- followed by a command');
      const automatic = separator === 1 && rawArgs[0] === '--auto';
      const roots = sessionCheck ? inherited.roots : automatic ? projectRoots(cwd) : [...new Set(rawArgs.slice(0, separator).map(root => {
        if (root.startsWith('-')) throw new Error('Unsupported canary-run option');
        const target = path.resolve(cwd, root);
        checkPath(target);
        if (!fs.lstatSync(target).isDirectory()) throw new Error('canary-run roots must be directories');
        return target;
      }))];
      if (!automatic && !sessionCheck && !roots.some(root => inside(root, cwd))) throw new Error('Command working directory must be within selected protection roots');
      let argv = rawArgs.slice(separator + 1);
      const checkOnly = rawArgs[separator] === '--check';
      if (checkOnly && argv.length) throw new Error('--check does not accept a command');
      if (rawArgs[separator] === '--encoded-argv') {
        if (argv.length !== 1 || argv[0].length > 65536 || !/^[A-Za-z\d+/]*={0,2}$/.test(argv[0])) throw new Error('Invalid encoded command arguments');
        argv = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.from(argv[0], 'base64')));
      }
      if (!checkOnly && (!Array.isArray(argv) || !argv.length || argv.some(arg => typeof arg !== 'string' || arg.includes('\0')) || !argv[0])) throw new Error('canary-run requires a program and string arguments');
      const report = roots.length ? protectRepository({ roots }) : null;
      if (report && !report.protection.allowed) {
        process.stderr.write('Canary command blocked: ' + JSON.stringify(report.protection.failures.slice(0, 20)) + '\n');
        process.exitCode = 2;
        return;
      }
      if (report && (report.quarantine.actions.length || report.repairs.actions.length)) {
        process.stderr.write(`Canary command protection: ${report.quarantine.actions.length} files quarantined; ${report.repairs.actions.length} references repaired\n`);
      }
      if (checkOnly) return;
      const result = spawnSync(argv[0], argv.slice(1), { cwd, stdio: 'inherit', shell: false,
        env: automatic ? automaticEnvironment(process.env) : startupEnvironment(process.env, roots[0], {}, roots) });
      if (result.error) process.stderr.write('Canary command launch failed: ' + result.error.message + '\n');
      process.exitCode = Number.isInteger(result.status) ? result.status : 1;
    } catch (err) {
      process.stderr.write('Canary command blocked: ' + JSON.stringify(err.message) + '\n');
      process.exitCode = 2;
    }
  },
};
