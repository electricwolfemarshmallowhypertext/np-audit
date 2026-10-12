'use strict';

const fs = require('fs');
const { parseOptions } = require('./canary-killer');
const { checkPath } = require('../core/canaryQuarantine');
const { startupEnvironment, shellSetup } = require('../utils/canaryStartup');

module.exports = {
  name: 'canary-guard',
  aliases: [],
  description: 'Print session settings for canary protection before Node startup',
  help() {
    return `
  npa canary-guard — Node startup protection for selected folders

  Usage: npa canary-guard <root> [root...] [--json]

  Prints current-session environment settings; apply them in your terminal.
  Configured Node processes check selected roots before their entrypoint runs.
  Child Node processes inherit the check unless their environment is replaced.
  Trusted path/hash exceptions are preserved. Failed checks stop startup.
  Does not install a service, change profiles or intercept non-Node programs.
  Native protected npm commands receive this startup guard automatically.
  PowerShell Node/shell setup: & ./bin/enable-canary-guard.ps1 -Roots <root>
`;
  },
  run({ rawArgs, flags, cwd }) {
    if (flags.skip || flags.noDev || flags.review || flags.verbose || flags.protectCanary) throw new Error('Unsupported canary-guard flag');
    const options = parseOptions(rawArgs, cwd);
    if (options.quarantine || options.excludes.length) throw new Error('canary-guard accepts explicit directory roots and --json');
    for (const root of options.roots) {
      checkPath(root);
      if (!fs.lstatSync(root).isDirectory()) throw new Error('Node startup guard roots must be directories');
    }
    const env = startupEnvironment(process.env, options.roots[0], {}, options.roots);
    const setup = shellSetup(env);
    if (flags.json) process.stdout.write(JSON.stringify({ env: { NPA_CANARY_GUARD: env.NPA_CANARY_GUARD, NODE_OPTIONS: env.NODE_OPTIONS }, setup }, null, 2) + '\n');
    else process.stdout.write(setup.join('\n') + '\n');
  },
};
