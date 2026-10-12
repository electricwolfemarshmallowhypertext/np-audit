'use strict';

const fs = require('fs');
const path = require('path');
const { protectRepository, scanCanaries } = require('./canaryProtection');
const { checkPath, DIRECTORY } = require('./canaryQuarantine');

function createCanaryMonitor({ roots, excludes = [], readOnly = false, intervalMs = 5000, onReport = () => {}, onError = () => {} }) {
  if (!Array.isArray(roots) || !roots.length) throw new Error('Canary monitor requires explicit directory roots');
  if (!Number.isInteger(intervalMs) || intervalMs < 200 || intervalMs > 300000) throw new Error('Monitor interval must be 200 to 300000 milliseconds');
  const selected = [...new Set(roots.map(root => path.resolve(root)))];
  for (const root of selected) {
    checkPath(root);
    if (!fs.lstatSync(root).isDirectory()) throw new Error('Canary monitor roots must be directories');
  }
  const watchers = [];
  const watchErrors = [];
  let stopped = false;
  let pending = null;
  let last = null;
  function scan() {
    if (stopped) return;
    if (pending) { clearTimeout(pending); pending = null; }
    try {
      const options = { roots: selected, excludes, protectionOnly: true, excludeQuarantine: true };
      const report = readOnly ? scanCanaries(options) : protectRepository(options);
      report.monitor = { mode: readOnly ? 'read-only' : 'protect', intervalMs,
        watchedRoots: watchers.filter(item => !item.failed).map(item => item.root), watchErrors: [...watchErrors],
        limitation: 'Arrival monitoring does not intercept execution; a file may run before a notification or periodic check is handled.' };
      if (watchErrors.length) { report.complete = false; report.summary.status = 'incomplete'; }
      const signature = JSON.stringify({ summary: report.summary, findings: report.findings, references: report.references,
        unreadable: report.unreadable, unresolved: report.unresolved, exclusions: report.exclusions,
        trust: report.trust, protection: report.protection, actions: report.quarantine?.actions, monitor: report.monitor });
      if (signature !== last) { last = signature; onReport(report); }
    } catch (err) {
      const signature = 'error:' + err.message;
      if (signature !== last) { last = signature; onError({ complete: false, error: err.message }); }
    }
  }
  function schedule() {
    if (stopped) return;
    if (pending) clearTimeout(pending);
    pending = setTimeout(scan, 200);
  }
  for (const root of selected) {
    try {
      const watcher = fs.watch(root, { recursive: true }, (_, filename) => {
        if (filename && String(filename).split(/[\\/]/).includes(DIRECTORY)) return;
        schedule();
      });
      const item = { root, watcher, failed: false };
      watchers.push(item);
      watcher.on('error', err => {
        if (item.failed || stopped) return;
        item.failed = true;
        watchErrors.push({ path: root, error: err.code || err.message });
        watcher.close();
        schedule();
      });
    } catch (err) { watchErrors.push({ path: root, error: err.code || err.message }); }
  }
  const timer = setInterval(scan, intervalMs);
  scan();
  return {
    close() {
      stopped = true;
      clearInterval(timer);
      if (pending) clearTimeout(pending);
      for (const item of watchers) item.watcher.close();
    },
  };
}

module.exports = { createCanaryMonitor };
