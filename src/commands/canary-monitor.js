'use strict';

const { parseOptions, printReport } = require('./canary-killer');
const { createCanaryMonitor } = require('../core/canaryMonitor');
const output = require('../utils/output');

module.exports = {
  name: 'canary-monitor',
  aliases: [],
  description: 'Watch selected folders and run canary protection automatically',
  help() {
    return `
  npa canary-monitor — Foreground canary protection for selected folders

  Usage: npa canary-monitor <root> [root...] [--exclude <path>] [--json]
                           [--read-only] [--interval <milliseconds>]

  Runs protection at startup and after changes; rechecks every 5000ms.
  Exact trusted path/SHA-256 matches preserve files and their resolved calls.
  --read-only reports findings without repairs, quarantine or ignore changes.
  --json emits one JSON record per changed report or error.
  Ctrl+C stops monitoring. No service, shell interception or script execution.
  Notifications can arrive after a file has run; monitoring is not an
  execution barrier. Watch failures and incomplete coverage are reported.
`;
  },
  async run({ rawArgs, flags, cwd }) {
    if (flags.skip || flags.noDev || flags.review || flags.verbose || flags.protectCanary) throw new Error('Unsupported canary-monitor flag');
    const args = [];
    let readOnly = false;
    let intervalMs = 5000;
    let positionalOnly = false;
    for (let index = 0; index < rawArgs.length; index++) {
      const arg = rawArgs[index];
      if (arg === '--' && !positionalOnly) { positionalOnly = true; args.push(arg); }
      else if (!positionalOnly && arg === '--read-only') readOnly = true;
      else if (!positionalOnly && arg === '--interval') {
        if (!rawArgs[index + 1]) throw new Error('--interval requires milliseconds');
        intervalMs = Number(rawArgs[++index]);
      } else args.push(arg);
    }
    const options = parseOptions(args, cwd);
    if (options.quarantine) throw new Error('canary-monitor already applies protection; use --read-only to disable actions');
    await new Promise(resolve => {
      const monitor = createCanaryMonitor({ ...options, readOnly, intervalMs,
        onReport(report) {
          if (flags.json) process.stdout.write(JSON.stringify({ event: 'scan', report }) + '\n');
          else printReport(report);
        },
        onError(error) {
          if (flags.json) process.stdout.write(JSON.stringify({ event: 'error', ...error }) + '\n');
          else output.error(error.error);
        },
      });
      const stop = () => {
        monitor.close();
        process.removeListener('SIGINT', stop);
        process.removeListener('SIGTERM', stop);
        resolve();
      };
      process.once('SIGINT', stop);
      process.once('SIGTERM', stop);
    });
  },
};
