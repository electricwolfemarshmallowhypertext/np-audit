'use strict';

const path = require('path');
const { protectRepository, scanCanaries } = require('../core/canaryProtection');
const output = require('../utils/output');

function parseOptions(args, cwd) {
  const roots = [];
  const excludes = [];
  let quarantine = false;
  let positionalOnly = false;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (!positionalOnly && arg === '--') { positionalOnly = true; continue; }
    if (!positionalOnly && arg === '--quarantine') {
      quarantine = true;
    } else if (!positionalOnly && arg === '--exclude') {
      if (!args[i + 1] || args[i + 1].startsWith('-')) throw new Error('--exclude requires a path');
      excludes.push(path.resolve(cwd, args[++i]));
    } else if (!positionalOnly && arg.startsWith('-')) {
      throw new Error(`Unsupported Canary Killer option: ${arg}`);
    } else roots.push(path.resolve(cwd, arg));
  }
  if (!roots.length) throw new Error('Canary Killer requires explicit scan roots: npa canary-killer <root> [root...]');
  return { roots, excludes, quarantine };
}

function printReport(report) {
  const log = text => output.log(String(text).replace(/[\x00-\x1f\x7f-\x9f]/g,
    char => '\\u' + char.charCodeAt(0).toString(16).padStart(4, '0')));
  output.printScanHeader();
  log(`Canary Killer: ${report.summary.status}; ${report.summary.files} text files inspected; ${report.summary.findings} findings`);
  for (const root of report.roots) log(`Root: ${root}`);
  if (report.trust) for (const item of report.trust.files) log(`${item.path} [${item.status}] explicit SHA-256 exception${item.error ? ': ' + item.error : ''}`);
  if (report.quarantine) {
    log(`Before quarantine coverage: ${report.quarantine.before.summary.status}`);
    for (const action of report.quarantine.actions) {
      log(`${action.path} [${action.status}] ${action.target || action.error}`);
      if (action.ignore) log(`Git ignore: ${action.ignore.path} [${action.ignore.status}]`);
    }
    for (const evidence of report.quarantine.evidence) {
      log(`${evidence.path}:${evidence.line} [before quarantine] ${evidence.name}: ${evidence.detail}`);
      log(`  ${evidence.evidence}${evidence.evidenceTruncated ? ' [evidence truncated]' : ''}`);
    }
    for (const kind of ['unreadable', 'exclusions']) {
      for (const item of report.quarantine.before[kind]) log(`${item.path} [before quarantine ${kind}] ${item.reason}`);
    }
    for (const failure of report.quarantine.ignoreFailures || []) log(`${failure.path} [ignore failed] ${failure.error}`);
  }
  if (report.repairs) {
    for (const action of report.repairs.actions) {
      log(`${action.path}:${action.line} [reference repaired] ${action.script || 'hook'}: ${action.after || '(removed)'}`);
    }
    for (const failure of report.repairs.failures) log(`${failure.path} [repair failed] ${failure.error}`);
    log(`Canary protection: ${report.protection.allowed ? 'policy satisfied' : 'blocked'}`);
  }
  for (const finding of report.findings) {
    log(`${finding.path}:${finding.line} [${finding.severity}] ${finding.name}: ${finding.detail}`);
    log(`  ${finding.evidence}${finding.evidenceTruncated ? ' [evidence truncated]' : ''}`);
  }
  for (const ref of report.references) {
    log(`${ref.path}:${ref.line} [${ref.status}] ${ref.reference} -> ${ref.target || '(unresolved)'}`);
    log(`  ${ref.evidence}${ref.evidenceTruncated ? ' [evidence truncated]' : ''}`);
  }
  for (const kind of ['unresolved', 'unreadable', 'exclusions']) {
    for (const item of report[kind]) {
      log(`${item.path}${item.line ? ':' + item.line : ''} [${kind}] ${item.reason}`);
      if (item.evidence !== undefined) log(`  ${item.evidence}${item.evidenceTruncated ? ' [evidence truncated]' : ''}`);
    }
  }
  for (const item of report.coverage.hookDirectories) log(`Hooks: ${item.path} (${item.configuredBy})`);
  for (const file of report.coverage.files) log(`Inspected: ${file}`);
  for (const text of report.limitations) log(text);
  if (!report.findings.length) log('No indicators matched in inspected text; this is not a host-integrity verdict.');
  if (!report.complete) output.warn('Coverage is incomplete. Review unreadable paths, unresolved references and exclusions.');
}

module.exports = {
  name: 'canary-killer',
  aliases: [],
  description: 'Repository scan; opt-in canary quarantine (explicit roots)',
  help() {
    return `
  npa canary-killer — Static repository scan; optional quarantine

  Usage: npa canary-killer <root> [root...] [--exclude <path>] [--json] [--quarantine]

  Supply explicit roots; roots and exclusions resolve from the current directory.
  Every package.json script and local Git config/hook is inspected as text.
  No npm, Git, scripts, hooks or downloaded content are executed.
  Default: read-only. --quarantine moves exact canary.js files into
  .np-audit-quarantine/ and appends canary.js/storage ignore rules.
  Direct canary calls are removed from scripts/hooks; remaining && commands
  are preserved. Ambiguous canary commands are reported as blocked.
  This filename policy is explicit; it does not classify matches as malware.
  Quarantine requires directory roots. Git index/history are not rewritten.
  Exact path/SHA-256 exceptions use canaryTrustedFiles in each root's
  .npmauditor.json. Matched files and their resolved calls are preserved.
  Exit codes: 0 = complete/no review findings; 1 = review findings;
              2 = incomplete coverage or invalid arguments (takes precedence).
  canary.js is only an indicator; package.jsonl is not an npm manifest.

  Examples:
    npa canary-killer . --json
    npa canary-killer /srv/app /dev/shm /tmp
    npa canary-killer ./checkout --exclude ./checkout/node_modules
    npa canary-killer ./checkout --quarantine --json
`;
  },
  async run({ rawArgs, flags, cwd }) {
    let report;
    try {
      if (flags.skip || flags.noDev || flags.review || flags.verbose) throw new Error('Canary Killer supports only --json, --exclude, --quarantine and explicit roots');
      const options = parseOptions(rawArgs, cwd);
      if (flags.protectCanary) options.quarantine = true;
      report = options.quarantine ? protectRepository({ ...options, protectionOnly: false }) : scanCanaries(options);
    }
    catch (err) {
      if (flags.json) process.stdout.write(JSON.stringify({ scan: 'canary-killer', complete: false, error: err.message }) + '\n');
      else output.error(err.message);
      process.exitCode = 2;
      return;
    }
    if (flags.json) process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    else printReport(report);
    process.exitCode = !report.complete ? 2 : report.findings.some(f => f.severity === 'review') ? 1 : 0;
  },
  parseOptions,
  printReport,
};
