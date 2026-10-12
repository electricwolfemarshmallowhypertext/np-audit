'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');
const { LIMITS } = require('./repositoryScanner');
const { inside, checkPath } = require('./canaryQuarantine');

const key = target => process.platform === 'win32' ? path.resolve(target).toLowerCase() : path.resolve(target);

function readBounded(target, limit, budget) {
  checkPath(target);
  const before = fs.lstatSync(target);
  if (!before.isFile() || before.size > limit || budget.bytes + before.size > LIMITS.totalBytes) throw new Error('Trusted-file read limit/type failure');
  const fd = fs.openSync(target, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  try {
    const buffer = Buffer.alloc(before.size + 1);
    let length = 0;
    while (length < buffer.length) {
      const count = fs.readSync(fd, buffer, length, buffer.length - length, null);
      if (!count) break;
      length += count;
    }
    const after = fs.fstatSync(fd);
    if (length !== before.size || after.dev !== before.dev || after.ino !== before.ino || after.size !== before.size || after.mtimeMs !== before.mtimeMs) throw new Error('Trusted file changed during verification');
    budget.bytes += length;
    return buffer.subarray(0, length);
  } finally { fs.closeSync(fd); }
}

function loadTrustedFiles(roots, excludes = [], additional = [], base = process.cwd()) {
  const entries = [];
  const budget = { bytes: 0 };
  function append(files, directory, configuredBy, references = false) {
    if (!Array.isArray(files) || files.length > 128) throw new Error('canaryTrustedFiles must be an array with at most 128 entries');
    for (const entry of files) {
      if (!entry || typeof entry.path !== 'string' || !entry.path || typeof entry.sha256 !== 'string' || !/^[a-f\d]{64}$/i.test(entry.sha256)) throw new Error('Each canaryTrustedFiles entry requires an exact path and a SHA-256 hash');
      const item = { path: path.resolve(directory, entry.path), sha256: entry.sha256.toLowerCase(), configuredBy, references };
      if (!entries.some(existing => key(existing.path) === key(item.path) && existing.sha256 === item.sha256)) entries.push(item);
      if (entries.length > 128) throw new Error('canaryTrustedFiles supports at most 128 distinct entries');
    }
  }
  for (const root of new Set(roots.map(target => path.resolve(target)))) {
    let info;
    try { info = fs.lstatSync(root); } catch (err) { if (err.code === 'ENOENT') continue; throw err; }
    if (!info.isDirectory() || info.isSymbolicLink()) continue;
    const config = path.join(root, '.npmauditor.json');
    if (excludes.some(exclusion => inside(path.resolve(exclusion), config))) continue;
    let buffer;
    try { buffer = readBounded(config, 128 * 1024, budget); } catch (err) { if (err.code === 'ENOENT') continue; throw err; }
    const settings = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(buffer).replace(/^\uFEFF/, ''));
    append(settings.canaryTrustedFiles || [], root, config);
    append(settings.canaryTrustedReferenceFiles || [], root, config, true);
  }
  append(additional, base, 'np-audit configuration');
  return entries;
}

function verifyTrustedFiles(scan, entries) {
  const files = [];
  const trustedPaths = new Set();
  const trustedReferencePaths = new Set();
  const declared = new Map();
  const budget = { bytes: 0 };
  for (const entry of entries) {
    const target = path.resolve(entry.path);
    if (!scan.roots.some(root => inside(root, target)) || (!entry.references && path.basename(target) !== 'canary.js')) throw new Error('Trusted canary paths must name canary.js inside selected roots');
    if (entry.references && path.basename(target) !== 'package.json' && !require('./canaryRepair').isHook(target, scan)) throw new Error('Trusted reference files must be manifests or hooks');
    if (declared.has(key(target))) {
      if (declared.get(key(target)) !== entry.sha256) throw new Error('Conflicting trusted hashes for the same canary path');
      continue;
    }
    declared.set(key(target), entry.sha256);
    const item = { path: target, expectedSha256: entry.sha256, configuredBy: entry.configuredBy, references: !!entry.references };
    const scanned = entry.references ? scan.coverage.files.some(file => key(file) === key(target)) : scan.coverage.canaryFiles.some(candidate => key(candidate.path) === key(target));
    if (!scanned) {
      item.status = scan.exclusions.some(exclusion => inside(exclusion.path, target)) ? 'unscanned' : 'missing';
    } else {
      try {
        item.actualSha256 = crypto.createHash('sha256').update(readBounded(target, LIMITS.fileBytes, budget)).digest('hex');
        item.status = item.actualSha256 === entry.sha256 ? 'trusted' : 'changed';
        if (item.status === 'trusted') (entry.references ? trustedReferencePaths : trustedPaths).add(key(target));
      } catch (err) { item.status = 'unverified'; item.error = err.code || err.message; }
    }
    files.push(item);
  }
  return { files, trustedPaths, trustedReferencePaths, basis: 'Explicit path and SHA-256 exceptions; neither filenames nor trust entries establish a malware or safety verdict. Reference exceptions preserve reviewed test-data calls without hiding their scan findings.' };
}

function startupTrustedFiles(base) {
  const budget = { bytes: 0 };
  let files = [];
  for (const config of new Set([path.join(os.homedir(), '.npmauditor.json'), path.join(base, '.npmauditor.json')])) {
    let buffer;
    try { buffer = readBounded(config, 128 * 1024, budget); } catch (err) { if (err.code === 'ENOENT') continue; throw err; }
    const settings = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(buffer).replace(/^\uFEFF/, ''));
    if (Object.prototype.hasOwnProperty.call(settings, 'canaryTrustedFiles')) files = settings.canaryTrustedFiles;
  }
  return files;
}

module.exports = { loadTrustedFiles, verifyTrustedFiles, startupTrustedFiles, key };
