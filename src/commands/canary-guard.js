'use strict';

const fs = require('fs');
const path = require('path');
const { parseOptions } = require('./canary-killer');
const { checkPath } = require('../core/canaryQuarantine');
const { startupEnvironment, automaticEnvironment, shellSetup } = require('../utils/canaryStartup');

module.exports = {
  name: 'canary-guard',
  aliases: [],
  description: 'Print session settings for canary protection before Node startup',
  help() {
    return `
  npa canary-guard — Node startup protection for selected folders

  Usage: npa canary-guard <root> [root...] [--json]
         npa canary-guard --auto

  Prints current-session environment settings; apply them in your terminal.
  Configured Node processes check selected roots before their entrypoint runs.
  Child Node processes inherit the check unless their environment is replaced.
  Trusted path/hash exceptions are preserved. Failed checks stop startup.
  Does not install a service, change profiles or intercept non-Node programs.
  Native protected npm commands receive this startup guard automatically.
  PowerShell Node/shell setup: & ./bin/enable-canary-guard.ps1 -Roots <root>
  Automatic Windows startup: & ./bin/install-canary-terminal.ps1
  The installer preserves existing current-user profiles and CMD AutoRun.
`;
  },
  run({ rawArgs, flags, cwd }) {
    if (flags.skip || flags.noDev || flags.review || flags.verbose || flags.protectCanary) throw new Error('Unsupported canary-guard flag');
    if (rawArgs[0] === '--auto') {
      const env = automaticEnvironment(process.env);
      if (rawArgs.length === 3 && rawArgs[1] === '--cmd-env-file') {
        const values = ['NODE_OPTIONS', 'BASH_ENV', 'NPA_CANARY_NODE', 'NPA_CANARY_CLI', 'NPA_CANARY_ORIGINAL_BASH_ENV'].map(name => env[name]);
        const content = values.join('\n') + '\n';
        if (values.some(value => /[\r\n\0]/.test(value)) || Buffer.byteLength(content) > 65536) throw new Error('Unsupported CMD guard environment data');
        const target = path.resolve(cwd, rawArgs[2]);
        const created = [];
        try {
          for (const [index, name] of ['NODE_OPTIONS', 'BASH_ENV', 'NPA_CANARY_NODE', 'NPA_CANARY_CLI', 'NPA_CANARY_ORIGINAL_BASH_ENV'].entries()) {
            const file = index ? target + '.' + name : target;
            fs.writeFileSync(file, values[index] + '\n', { flag: 'wx' });
            created.push(file);
          }
        } catch (err) {
          for (const file of created) fs.unlinkSync(file);
          throw err;
        }
      } else if (rawArgs.length === 1) {
        process.stdout.write(JSON.stringify({ env: guardSettings(env) }) + '\n');
      } else throw new Error('Unsupported automatic guard setup option');
      return;
    }
    const options = parseOptions(rawArgs, cwd);
    if (options.quarantine || options.excludes.length) throw new Error('canary-guard accepts explicit directory roots and --json');
    for (const root of options.roots) {
      checkPath(root);
      if (!fs.lstatSync(root).isDirectory()) throw new Error('Node startup guard roots must be directories');
    }
    const env = startupEnvironment(process.env, options.roots[0], {}, options.roots);
    const setup = shellSetup(env);
    if (flags.json) process.stdout.write(JSON.stringify({ env: guardSettings(env), setup }, null, 2) + '\n');
    else process.stdout.write(setup.join('\n') + '\n');
  },
};

function guardSettings(env) {
  return Object.fromEntries(['NPA_CANARY_GUARD', 'NODE_OPTIONS', 'BASH_ENV', 'NPA_CANARY_NODE', 'NPA_CANARY_CLI', 'NPA_CANARY_ORIGINAL_BASH_ENV'].map(name => [name, env[name]]));
}
