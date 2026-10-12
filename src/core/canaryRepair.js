'use strict';

const fs = require('fs');
const path = require('path');
const { randomUUID } = require('crypto');
const { parseCommand, tokenize } = require('../utils/command');
const { scriptLocations, location, LIMITS } = require('./repositoryScanner');
const { inside, checkPath } = require('./canaryQuarantine');

function isHook(target, scan) {
  return scan.coverage.hookDirectories.some(dir => inside(dir.path, target)) ||
    /(?:^|[\\/])(?:\.husky|\.githooks)(?:[\\/])/.test(target);
}

function hookBase(target, scan) {
  const hook = scan.coverage.hookDirectories.find(dir => inside(dir.path, target));
  if (hook) {
    const repo = scan.coverage.repositories.filter(root => inside(root.path, target) ||
      (hook.configuredBy !== 'default' && inside(root.path, hook.configuredBy)))
      .sort((a, b) => b.path.length - a.path.length)[0];
    if (repo) return repo.path;
  }
  const versioned = target.match(/(?:^|[\\/])(?:\.husky|\.githooks)(?:[\\/])/);
  return versioned ? target.slice(0, versioned.index) : path.dirname(target);
}

function cleanCommand(command, base, roots) {
  const segments = [];
  let quote = null;
  let start = 0;
  let unsafe = false;
  for (let i = 0; i < command.length; i++) {
    const char = command[i];
    if (char === '\\' && command[i + 1] && quote !== "'") { i++; continue; }
    if (quote) { if (char === quote) quote = null; continue; }
    if (char === '"' || char === "'" || char === '`') { quote = char; continue; }
    if (char === '&' && command[i + 1] === '&') {
      segments.push(command.slice(start, i).trim()); start = ++i + 1;
    } else if (';|&<>\r\n(){}'.includes(char)) unsafe = true;
  }
  segments.push(command.slice(start).trim());
  if (quote) unsafe = true;
  const kept = [];
  const targets = [];
  for (const segment of segments) {
    const normalized = process.platform === 'win32' ? segment.replace(/\\(?=[\w.\/\\-])/g, '/') : segment;
    const tokens = tokenize(normalized);
    const refs = parseCommand(normalized);
    const canary = refs.filter(ref => ref.kind === 'file' && path.basename(ref.path.replace(/\\/g, '/')) === 'canary.js');
    if (!canary.length) { kept.push(segment); continue; }
    const interpreter = (tokens[0] || '').split('/').pop();
    if (!['node', 'nodejs', 'canary.js'].includes(interpreter) ||
        (interpreter !== 'canary.js' && tokens[1] !== canary[0].path && tokens[1] !== './' + canary[0].path) ||
        /[$`]/.test(normalized)) unsafe = true;
    const target = path.resolve(base, canary[0].path);
    if (!roots.some(root => inside(root, target))) unsafe = true;
    targets.push(target);
  }
  // Nested shell syntax is never rewritten from a guessed command structure.
  const unquoted = command.replace(/(['"`])(?:\\.|[^\\])*?\1/g, value => {
    const text = value.slice(1, -1);
    return /^(?:[^\s]*[\/\\])?canary\.js$/.test(text) ? text : ' '.repeat(value.length);
  });
  if (!targets.length && /\b(?:node|nodejs)\s+(?:[^\s;|]*[\/\\])?canary\.js\b/.test(unquoted)) unsafe = true;
  if ((targets.length || unsafe) && /\b(?:if|then|for|while|case|function|cd|exec)\b/.test(command)) unsafe = true;
  return { changed: targets.length > 0 && !unsafe, blocked: unsafe && (targets.length > 0 || /\bcanary\.js\b/.test(command)),
    value: kept.filter(Boolean).join(' && '), targets };
}

function repairCanaryReferences(scan) {
  const actions = [];
  const failures = [];
  const ignoreRoots = new Set();
  let bytes = 0;
  function requireScope(target) {
    if (!scan.roots.some(root => inside(root, target))) throw new Error('Reference repair must stay inside supplied roots');
    if (scan.exclusions.some(item => item.reason === 'Explicit path exclusion' && inside(item.path, target))) throw new Error('Reference repair path is explicitly excluded');
    checkPath(target);
  }
  function chooseIgnoreRoot(target) {
    const roots = scan.roots.filter(root => inside(root, target) && fs.lstatSync(root).isDirectory());
    const repos = scan.coverage.repositories.map(repo => repo.path).filter(repo => inside(repo, target) && roots.some(root => inside(root, repo)));
    return (repos.length ? repos : roots).sort((a, b) => b.length - a.length)[0];
  }
  for (const target of scan.coverage.files) {
    if (path.basename(target) !== 'package.json' && !isHook(target, scan)) continue;
    if (path.basename(target) === 'canary.js') continue;
    try {
      requireScope(target);
      const info = fs.lstatSync(target);
      if (!info.isFile() || info.size > LIMITS.fileBytes || bytes + info.size > LIMITS.totalBytes) throw new Error('Reference repair read limit/type failure');
      const fd = fs.openSync(target, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
      let buffer;
      try {
        buffer = Buffer.alloc(info.size + 1);
        let length = 0;
        while (length < buffer.length) {
          const count = fs.readSync(fd, buffer, length, buffer.length - length, null);
          if (!count) break;
          length += count;
        }
        if (length !== info.size) throw new Error('Reference file changed while being read');
        buffer = buffer.subarray(0, length);
      } finally { fs.closeSync(fd); }
      bytes += buffer.length;
      const original = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(buffer);
      let updated = original;
      const edits = [];
      if (path.basename(target) === 'package.json') {
        const manifest = JSON.parse(original.replace(/^\uFEFF/, ''));
        const scripts = scriptLocations(original);
        for (const script of [...scripts].reverse()) {
          const clean = cleanCommand(script.command, path.dirname(target), scan.roots);
          if (clean.blocked) throw new Error(`Cannot safely repair script ${script.script}: ${script.command.slice(0, 160)}`);
          if (!clean.changed) continue;
          if (scripts.filter(item => item.script === script.script).length !== 1 || manifest.scripts?.[script.script] !== script.command) throw new Error('Duplicate/ambiguous script keys cannot be safely repaired');
          const current = scriptLocations(updated).find(item => item.script === script.script);
          if (clean.value) updated = updated.slice(0, current.offset) + JSON.stringify(clean.value) + updated.slice(current.end);
          else {
            let end = current.end;
            while (/\s/.test(updated[end] || '') && end < updated.length) end++;
            if (updated[end] === ',') updated = updated.slice(0, current.keyOffset) + updated.slice(end + 1);
            else {
              let start = current.keyOffset - 1;
              while (start >= 0 && /\s/.test(updated[start])) start--;
              updated = updated.slice(0, updated[start] === ',' ? start : current.keyOffset) + updated.slice(current.end);
            }
          }
          edits.push({ path: target, ...location(original, script.offset), script: script.script, before: script.command,
            after: clean.value || null, targets: clean.targets });
        }
        JSON.parse(updated.replace(/^\uFEFF/, ''));
      } else {
        const lines = original.match(/[^\n]*\n|[^\n]+$/g) || [];
        let offset = 0;
        let continuation = false;
        updated = lines.map(line => {
          const newline = line.endsWith('\r\n') ? '\r\n' : line.endsWith('\n') ? '\n' : '';
          const text = line.slice(0, line.length - newline.length);
          const clean = /^\s*#/.test(text) ? { changed: false, blocked: false } : cleanCommand(text, hookBase(target, scan), scan.roots);
          if (clean.blocked || (clean.changed && (continuation || /\\\s*$/.test(text)))) throw new Error(`Cannot safely repair hook line ${location(original, offset).line}`);
          continuation = /\\\s*$/.test(text);
          const beforeOffset = offset;
          offset += line.length;
          if (!clean.changed) return line;
          edits.push({ path: target, ...location(original, beforeOffset), before: text, after: clean.value || null, targets: clean.targets });
          return clean.value ? (text.match(/^\s*/)[0] + clean.value + newline) : '';
        }).join('');
      }
      if (!edits.length) continue;
      const temporary = path.join(path.dirname(target), `.npa-repair-${randomUUID()}.tmp`);
      requireScope(temporary);
      try {
        fs.writeFileSync(temporary, updated, { flag: 'wx', mode: info.mode & 0o777 });
        requireScope(target);
        const latest = fs.lstatSync(target);
        if (latest.dev !== info.dev || latest.ino !== info.ino || latest.size !== info.size || latest.mtimeMs !== info.mtimeMs) throw new Error('Reference file changed before repair');
        fs.renameSync(temporary, target);
      } finally { if (fs.existsSync(temporary)) fs.unlinkSync(temporary); }
      actions.push(...edits);
      for (const edit of edits) for (const canary of edit.targets) {
        const root = chooseIgnoreRoot(canary);
        if (root) ignoreRoots.add(root);
      }
    } catch (err) { failures.push({ path: target, error: err.code || err.message }); }
  }
  return { actionsComplete: !failures.length, actions, failures, ignoreRoots: [...ignoreRoots] };
}

module.exports = { repairCanaryReferences, cleanCommand, isHook };
