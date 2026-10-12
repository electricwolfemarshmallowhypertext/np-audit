'use strict';

const path = require('path');
const fs = require('fs');
const { scanRepository } = require('./repositoryScanner');
const { quarantineCanaries, DIRECTORY, inside, checkPath } = require('./canaryQuarantine');
const { repairCanaryReferences, isHook } = require('./canaryRepair');

function coverageFailures(scan) {
  const critical = target => ['package.json', '.git'].includes(path.basename(target)) || isHook(target, scan) ||
    scan.coverage.gitConfigs.some(config => config.path === target) || /(?:^|[\\/])\.git(?:[\\/])/.test(target);
  const failures = scan.unreadable.filter(item => critical(item.path) || !/encoded data was not valid/.test(item.reason));
  for (const item of scan.exclusions) {
    if (item.reason.startsWith('Git metadata other than') || item.reason === 'Quarantine storage is not analyzed' ||
        (item.reason === 'Explicit path exclusion' && path.basename(item.path) === DIRECTORY)) continue;
    if (!critical(item.path) && path.basename(item.path) !== 'canary.js' && item.reason.startsWith('Symbolic link/reparse point')) {
      try {
        const target = path.resolve(path.dirname(item.path), fs.readlinkSync(item.path));
        checkPath(target);
        if (scan.roots.some(root => inside(root, target))) continue;
      } catch {}
    }
    if (critical(item.path) || !/^(?:Binary content|Per-file size limit)/.test(item.reason)) failures.push(item);
  }
  for (const item of scan.unresolved) {
    if (/record limit|nesting limit|Git directory pointer|Conditional or expanded Git include|Unsupported Git configuration|Unterminated Git configuration|Unsupported hooksPath/.test(item.reason) ||
        (item.reason === 'Outside supplied scan roots' && scan.coverage.hookDirectories.some(dir => inside(dir.path, item.path)))) failures.push(item);
    if (item.reference && path.basename(item.reference.replace(/\\/g, '/')) === 'canary.js') failures.push(item);
    if (/Inline JavaScript|Dynamic inline|Runtime option|Dynamic working directory/.test(item.reason) && /canary\.js/.test(item.evidence || item.command || '')) failures.push(item);
  }
  return failures;
}

function protectRepository(options) {
  const scanOptions = { ...options, excludeQuarantine: true, protectionOnly: options.protectionOnly !== false };
  const initial = scanRepository(scanOptions);
  const repairs = repairCanaryReferences(initial);
  const quarantine = quarantineCanaries(initial, { ignoreRoots: repairs.ignoreRoots });
  quarantine.before = { summary: initial.summary, unreadable: initial.unreadable,
    exclusions: initial.exclusions, unresolved: initial.unresolved };
  const targets = new Set(quarantine.actions.map(action => action.path));
  quarantine.evidence = initial.findings.filter(finding => targets.has(finding.path));
  const report = scanRepository(scanOptions);
  const remaining = report.references.filter(ref => path.basename((ref.reference || '').replace(/\\/g, '/')) === 'canary.js');
  const failures = [...coverageFailures(initial).filter(item => !item.reference), ...coverageFailures(report),
    ...repairs.failures, ...quarantine.ignoreFailures, ...quarantine.actions.filter(action => action.status !== 'quarantined'),
    ...report.coverage.canaryFiles, ...remaining];
  report.repairs = repairs;
  report.quarantine = quarantine;
  report.protection = { allowed: !failures.length && repairs.actionsComplete && quarantine.actionsComplete, failures };
  if (!initial.complete || !report.protection.allowed) {
    report.complete = false;
    report.summary.status = 'incomplete';
  }
  return report;
}

function protectionForCommand(cwd, config = {}) {
  if (!config.canaryProtection) return null;
  const roots = [cwd, ...(config.canaryRoots || []).map(root => path.resolve(cwd, root))];
  return protectRepository({ roots: [...new Set(roots)] });
}

function commandScopeError(args = []) {
  for (const arg of args) {
    if (arg === '--') break;
    if (/^(?:-g|--global(?:=.*)?|--prefix(?:=.*)?|-C(?:=.*)?|--location=global)$/.test(arg)) {
      return 'Canary protection requires the current project directory; global/prefix target options are unsupported';
    }
  }
  return null;
}

module.exports = { protectRepository, protectionForCommand, coverageFailures, commandScopeError };
