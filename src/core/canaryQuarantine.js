'use strict';

const fs = require('fs');
const path = require('path');
const { LIMITS } = require('./repositoryScanner');

const DIRECTORY = '.np-audit-quarantine';
const IGNORE_BLOCK = '# np-audit Canary Killer quarantine\ncanary.js\n.np-audit-quarantine/\n';
const MAX_IGNORE_BYTES = 128 * 1024;

function inside(root, target) {
  const rel = path.relative(root, target);
  return rel === '' || (rel !== '..' && !rel.startsWith('..' + path.sep) && !path.isAbsolute(rel));
}

function checkPath(target) {
  let current = target;
  while (true) {
    try {
      if (fs.lstatSync(current).isSymbolicLink()) throw new Error(`Refusing symbolic link/reparse point: ${current}`);
    } catch (err) { if (err.code !== 'ENOENT') throw err; }
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }
}

function quarantineCanaries(scan, { ignoreRoots = [] } = {}) {
  const roots = scan.roots.map(root => path.resolve(root));
  const excluded = scan.exclusions.filter(item => item.reason === 'Explicit path exclusion').map(item => path.resolve(item.path));
  const actions = [];
  const exclusions = new Set();
  const ignoreUpdates = new Map();
  const ignoreFailures = [];
  let ignoreBytes = 0;
  function inScope(target) {
    if (!roots.some(root => inside(root, target))) throw new Error('Quarantine writes must stay inside supplied scan roots');
    if (excluded.some(root => inside(root, target))) throw new Error(`Refusing write to explicitly excluded path: ${target}`);
    checkPath(target);
  }
  function updateIgnore(root) {
    if (ignoreUpdates.has(root)) return ignoreUpdates.get(root);
    const target = path.join(root, '.gitignore');
    inScope(target);
    let original = Buffer.alloc(0);
    let info = null;
    try {
      info = fs.lstatSync(target);
      if (!info.isFile()) throw new Error('.gitignore is not a regular file');
      if (info.size > MAX_IGNORE_BYTES || ignoreBytes + info.size > LIMITS.totalBytes) throw new Error('.gitignore read limit reached');
      const fd = fs.openSync(target, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
      try {
        original = Buffer.alloc(info.size + 1);
        let length = 0;
        while (length < original.length) {
          const count = fs.readSync(fd, original, length, original.length - length, null);
          if (!count) break;
          length += count;
        }
        if (length !== info.size) throw new Error('.gitignore changed while being read');
        original = original.subarray(0, length);
        ignoreBytes += length;
      } finally { fs.closeSync(fd); }
    } catch (err) { if (err.code !== 'ENOENT') throw err; }
    if (original.includes(0)) throw new Error('Binary .gitignore is unsupported');
    const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(original);
    if (text.replace(/\r\n/g, '\n').endsWith(IGNORE_BLOCK)) {
      const result = { path: target, status: 'already-present' };
      ignoreUpdates.set(root, result);
      return result;
    }
    const newline = text.includes('\r\n') ? '\r\n' : '\n';
    const block = IGNORE_BLOCK.replace(/\n/g, newline);
    const suffix = (original.length && !text.endsWith('\n') ? newline : '') + block;
    const temporary = path.join(root, `.npa-ignore-${require('crypto').randomUUID()}.tmp`);
    inScope(temporary);
    try {
      fs.writeFileSync(temporary, Buffer.concat([original, Buffer.from(suffix)]), { flag: 'wx', mode: info ? info.mode & 0o777 : 0o644 });
      inScope(target);
      if (info) {
        const latest = fs.lstatSync(target);
        if (latest.dev !== info.dev || latest.ino !== info.ino || latest.size !== info.size || latest.mtimeMs !== info.mtimeMs) throw new Error('.gitignore changed before update');
      } else if (fs.existsSync(target)) throw new Error('.gitignore appeared before update');
      fs.renameSync(temporary, target);
    } finally { if (fs.existsSync(temporary)) fs.unlinkSync(temporary); }
    const result = { path: target, status: 'updated' };
    ignoreUpdates.set(root, result);
    return result;
  }
  for (const root of new Set(ignoreRoots)) {
    try {
      inScope(root);
      if (!fs.lstatSync(root).isDirectory()) throw new Error('Ignore root is not a directory');
      updateIgnore(root);
    } catch (err) { ignoreFailures.push({ path: root, error: err.code || err.message }); }
  }
  for (const candidate of scan.coverage.canaryFiles) {
    const action = { path: candidate.path, status: 'failed' };
    let entry;
    let moved = false;
    try {
      const source = path.resolve(candidate.path);
      if (path.basename(source) !== 'canary.js') throw new Error('Only exact canary.js filenames can be quarantined');
      inScope(source);
      const info = fs.lstatSync(source);
      if (!info.isFile()) throw new Error('Quarantine target is not a regular file');
      const directoryRoots = roots.filter(root => inside(root, source) && fs.lstatSync(root).isDirectory());
      if (!directoryRoots.length) throw new Error('Quarantine requires a supplied directory root containing the file');
      const repositories = scan.coverage.repositories.map(repo => repo.path)
        .filter(repo => inside(repo, source) && directoryRoots.some(root => inside(root, repo)));
      const root = (repositories.length ? repositories : directoryRoots).sort((a, b) => b.length - a.length)[0];
      const storage = path.join(root, DIRECTORY);
      inScope(storage);
      const existing = fs.existsSync(storage) ? fs.lstatSync(storage) : null;
      if (existing && !existing.isDirectory()) throw new Error('Quarantine storage is not a directory');
      action.ignore = updateIgnore(root);
      fs.mkdirSync(storage, { recursive: true, mode: 0o700 });
      inScope(storage);
      entry = fs.mkdtempSync(path.join(storage, 'entry-'));
      inScope(entry);
      const destination = path.join(entry, 'payload.quarantined');
      const metadata = { originalPath: source, quarantinedPath: destination, size: info.size,
        originalMode: info.mode & 0o777, quarantinedAt: new Date().toISOString() };
      fs.writeFileSync(path.join(entry, 'metadata.json'), JSON.stringify(metadata, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
      inScope(source);
      const latest = fs.lstatSync(source);
      if (!latest.isFile() || latest.dev !== info.dev || latest.ino !== info.ino || latest.size !== info.size || latest.mtimeMs !== info.mtimeMs) throw new Error('Canary file changed before quarantine');
      fs.renameSync(source, destination);
      moved = true;
      exclusions.add(storage);
      action.status = 'quarantined';
      action.target = destination;
      action.metadata = path.join(entry, 'metadata.json');
    } catch (err) {
      action.error = err.code || err.message;
    } finally {
      if (entry && !moved) {
        try {
          fs.unlinkSync(path.join(entry, 'metadata.json'));
          fs.rmdirSync(entry);
        } catch (err) { action.cleanupError = err.code || err.message; }
      }
    }
    actions.push(action);
  }
  return { actionsComplete: !ignoreFailures.length && actions.every(action => action.status === 'quarantined'), actions,
    excludedStorage: [...exclusions], ignoreUpdates: [...ignoreUpdates.values()], ignoreFailures };
}

module.exports = { quarantineCanaries, DIRECTORY, inside, checkPath };
