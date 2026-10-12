'use strict';

const { loadConfig, DEFAULT_CONFIG } = require('./utils/config');
const { checkForUpdate } = require('./utils/updateChecker');
const commands = require('./commands');
const output = require('./utils/output');

const VERSION = require('../package.json').version;
const NAME    = require('../package.json').name;

function buildMainHelp() {
  const cmdList = commands.list();
  const lines = cmdList.map(cmd => {
    const aliases = cmd.aliases.length ? ` (alias: ${cmd.aliases.join(', ')})` : '';
    return `    npa ${cmd.name.padEnd(20)} ${cmd.description}${aliases}`;
  });

  return `
  npa — npm package auditor ${VERSION}
  Static security analysis for npm packages.

  Usage:
${lines.join('\n')}

  Flags:
    --review, -r   Interactive mode: choose which scripts to allow
    --json        Machine-readable JSON output
    --no-dev      Skip devDependencies
    --verbose     Show extra detail
    --skip        Skip auditing for this install or ci command
    --protect-canary  Quarantine canary files and repair calls before commands
    --version     Print version
    --help, -h    Print this help (use <command> -h for command help)

  Config keys (stored in ~/.npmauditor.json):
    blockScore       Score threshold for hard block (default: ${DEFAULT_CONFIG.blockScore})
    warnScore        Score threshold for warning (default: ${DEFAULT_CONFIG.warnScore})
    registry         npm registry URL (default: ${DEFAULT_CONFIG.registry})
    timeout          HTTP timeout in ms (default: ${DEFAULT_CONFIG.timeout})
    parallelFetches  Concurrent downloads (default: ${DEFAULT_CONFIG.parallelFetches})
    skipScopes       Array of @scopes to skip
    skipPackages     Array of package names to skip
    maxTarballSize   Max unpacked tarball size (default: ${DEFAULT_CONFIG.maxTarballSize})
`;
}

function parseArgs(argv) {
  const args  = argv.slice(2);
  const flags = {
    review:  false,
    json:    false,
    noDev:   false,
    verbose: false,
    skip:    false,
    version: false,
    help:    false,
    protectCanary: false,
  };
  const positionals = [];
  const npaFlagIndexes = new Set();

  for (const [index, arg] of args.entries()) {
    switch (arg) {
      case '--review':
      case '-r':         flags.review  = true; npaFlagIndexes.add(index); break;
      case '--json':     flags.json    = true; npaFlagIndexes.add(index); break;
      case '--no-dev':   flags.noDev   = true; npaFlagIndexes.add(index); break;
      case '--verbose':  flags.verbose = true; npaFlagIndexes.add(index); break;
      case '--skip':     flags.skip    = true; npaFlagIndexes.add(index); break;
      case '--protect-canary': flags.protectCanary = true; npaFlagIndexes.add(index); break;
      case '--version':
      case '-v':         flags.version = true; npaFlagIndexes.add(index); break;
      case '--help':
      case '-h':         flags.help    = true; npaFlagIndexes.add(index); break;
      default:
        if (!arg.startsWith('-')) positionals.push(arg);
    }
  }

  const command = positionals[0] || null;
  const cmdArgs = positionals.slice(1);
  const commandIndex = args.indexOf(command);
  // Preserve npm options on either side of a recognised command. This is
  // important for npm's global options, e.g. `npm -g install foo` when npa
  // is used as an npm proxy. Only npa's own flags are consumed here.
  const rawArgs = args.filter((_, index) => index !== commandIndex && !npaFlagIndexes.has(index));
  return { command, args: cmdArgs, rawArgs, flags };
}

async function main() {
  const parsed = parseArgs(process.argv);
  const { command, args, rawArgs, flags } = parsed;
  const cwd    = process.cwd();
  const config = ['canary-killer', 'canary-monitor', 'canary-guard'].includes(command) ? DEFAULT_CONFIG : loadConfig(cwd);
  if (flags.protectCanary && !['canary-killer', 'canary-monitor', 'canary-guard'].includes(command)) config.canaryProtection = true;

  if (flags.version) {
    process.stdout.write(`npa ${VERSION} (${NAME})\n`);
    return;
  }

  if (flags.help && command) {
    const cmd = commands.get(command);
    if (cmd) {
      process.stdout.write(cmd.help() + '\n');
      return;
    }
  }

  if (flags.help || !command) {
    output.printLogo(VERSION);
    process.stdout.write(buildMainHelp() + '\n');
    return;
  }

  const cmd = commands.get(command);
  let protection = null;
  if (config.canaryProtection && (!cmd || ['scan', 'install', 'ci'].includes(cmd.name))) {
    const { protectionForCommand, commandScopeError } = require('./core/canaryProtection');
    const scopeError = commandScopeError(rawArgs);
    protection = scopeError ? null : protectionForCommand(cwd, config);
    if (scopeError || !protection.protection.allowed) {
      const error = scopeError || 'Canary protection failed; command was not started';
      if (flags.json) process.stdout.write(JSON.stringify({ error, protection }, null, 2) + '\n');
      else { output.error(error); if (protection) for (const failure of protection.protection.failures) output.error(JSON.stringify(failure)); }
      process.exitCode = 2;
      return;
    }
    if (!flags.json && (protection.quarantine.actions.length || protection.repairs.actions.length)) output.info(`Canary protection: ${protection.quarantine.actions.length} files quarantined; ${protection.repairs.actions.length} references repaired`);
  }
  if (!cmd) {
    // Forward unknown commands to npm (allows `alias npm='npa'`)
    const { spawnNpm } = require('./utils/npm');
    const result = spawnNpm(process.argv.slice(2).filter(arg => arg !== '--protect-canary'), {
      stdio: 'inherit',
      cwd,
    }, config.canaryProtection, config);
    if (config.canaryProtection && result.error) output.error(result.error.message);
    process.exit(config.canaryProtection ? (Number.isInteger(result.status) ? result.status : 1) : result.status || 0);
    return;
  }

  // Deprecation notice for old shell hook
  if (process.env.NPA_RUNNING && !flags.json && !config.silent) {
    output.warn('Deprecated: The old npa shell hook is no longer needed.');
    output.log(output.dim('  Run: npa alias --install   to upgrade to the simpler alias.'));
    output.log('');
  }

  // Fire update check only for scan/install/ci commands (non-blocking)
  const UPDATE_COMMANDS = ['scan', 's', 'install', 'i', 'ci'];
  const updatePromise = (UPDATE_COMMANDS.includes(command) && !flags.json && !config.silent)
    ? checkForUpdate(config, VERSION)
    : Promise.resolve(null);

  await cmd.run({ args, rawArgs, flags, config, cwd, protection });

  // Print update notice after command output
  const latestVersion = await updatePromise;
  if (latestVersion) {
    output.log('');
    output.log(output.dim(`  Update available: ${VERSION} → ${latestVersion} — run "npm i -g np-audit" to update`));
  }
}

main().catch(err => {
  output.error(err.message);
  if (process.env.NPA_DEBUG) console.error(err);
  process.exit(1);
});
