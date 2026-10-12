'use strict';

const fs = require('fs');
const path = require('path');
const { parseCommand, splitOnShellSeparators, tokenize } = require('../utils/command');
const { extractRequires } = require('./requireWalker');
const networkCalls = require('../marshallers/networkCalls');
const processEnv = require('../marshallers/processEnv');
const filesystemManipulation = require('../marshallers/filesystemManipulation');

const LIMITS = Object.freeze({ files: 10000, entries: 20000, fileBytes: 1024 * 1024,
  totalBytes: 32 * 1024 * 1024, records: 2000, depth: 100 });
const LIMITATIONS = [
  'Static text heuristics can match comments, strings and legitimate tools; matches are not malware verdicts.',
  'No scripts, hooks, Git commands, downloads or repository-configured external commands are executed.',
  'Only supplied local roots are inspected, including untracked files present there. A GitHub checkout cannot inspect other machines or their local .git/hooks.',
  'System/global Git configuration and environment overrides are not inferred. Conditional includes and dynamic commands remain unresolved.',
  'This scan cannot establish host integrity, recover deleted contents, attribute an incident or reconstruct a previously executed payload.',
];

function inside(root, target) {
  const rel = path.relative(root, target);
  return rel === '' || (!rel.startsWith('..' + path.sep) && rel !== '..' && !path.isAbsolute(rel));
}

function location(code, offset) {
  const lineStart = code.lastIndexOf('\n', offset - 1) + 1;
  const lineEnd = code.indexOf('\n', offset);
  const evidence = code.slice(lineStart, lineEnd < 0 ? code.length : lineEnd).replace(/\r$/, '');
  return { line: code.slice(0, offset).split('\n').length,
    evidence: evidence.slice(0, 240), evidenceTruncated: evidence.length > 240 };
}

function gitValue(raw) {
  let quoted = false;
  let end = raw.length;
  for (let i = 0; i < raw.length; i++) {
    if (raw[i] === '\\') { i++; continue; }
    if (raw[i] === '"') quoted = !quoted;
    if (!quoted && (raw[i] === '#' || raw[i] === ';')) { end = i; break; }
  }
  if (quoted) throw new Error('Unterminated Git configuration quote');
  const value = raw.slice(0, end).trim();
  return value.startsWith('"') && value.endsWith('"') ? value.slice(1, -1) : value;
}

// JSON is validated first. Walk its tokens to retain the exact source location
// of script values, including escaped keys and repeated values elsewhere.
function scriptLocations(code) {
  const token = /\s*("(?:[^"\\]|\\.)*"|[{}\[\],:]|true|false|null|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/gy;
  const values = [];
  function next() {
    const m = token.exec(code);
    if (!m) throw new Error('Unable to locate JSON token');
    return { text: m[1], offset: token.lastIndex - m[1].length };
  }
  function visit(keys, depth, keyOffset = 0) {
    if (depth > LIMITS.depth) throw new Error('JSON nesting limit reached');
    const t = next();
    if (t.text === '{') {
      let key = next();
      if (key.text === '}') return;
      while (true) {
        next(); // colon
        visit([...keys, JSON.parse(key.text)], depth + 1, key.offset);
        if (next().text === '}') break;
        key = next();
      }
    } else if (t.text === '[') {
      const saved = token.lastIndex;
      if (next().text === ']') return;
      token.lastIndex = saved;
      while (true) {
        visit([...keys, null], depth + 1);
        if (next().text === ']') break;
      }
    } else if (keys.length === 2 && keys[0] === 'scripts' && t.text.startsWith('"')) {
      values.push({ script: keys[1], command: JSON.parse(t.text), offset: t.offset, end: token.lastIndex, keyOffset });
    }
  }
  visit([], 0);
  return values;
}

function scanRepository({ roots, excludes = [], limits = {}, excludeQuarantine = false, protectionOnly = false }) {
  if (!Array.isArray(roots) || !roots.length) throw new Error('Supply at least one explicit scan root');
  const caps = { ...LIMITS, ...limits };
  const scanRoots = [...new Set(roots.map(p => path.resolve(p)))];
  const excluded = excludes.map(p => path.resolve(p));
  const report = { scan: 'canary-killer', roots: scanRoots, complete: true,
    findings: [], references: [], unreadable: [], exclusions: [], unresolved: [],
    coverage: { files: [], canaryFiles: [], repositories: [], entries: 0, bytes: 0, gitConfigs: [], hookDirectories: [] },
    limits: caps, limitations: LIMITATIONS };
  const seen = new Set();
  const contents = new Map();
  const filenameOnly = new Set();
  const shellSources = new Set();
  const findingsSeen = new Set();
  const missingPaths = new Set();
  const configs = new Set();
  const hooks = new Map();
  let records = 0;
  let stopped = false;
  function record(list, item) {
    if (records >= caps.records) {
      if (!stopped) report.unresolved.push({ path: item.path, reason: 'Report record limit reached; remaining coverage is incomplete' });
      stopped = true;
      report.complete = false;
      return;
    }
    (Array.isArray(list) ? list : report[list]).push(item);
    records++;
  }
  function gap(list, target, reason, extra = {}) {
    report.complete = false;
    record(list, { path: target, reason, ...extra });
  }
  function finding(target, code, offset, name, detail, severity = 'review') {
    const key = `${target}\0${offset}\0${name}`;
    if (findingsSeen.has(key)) return;
    findingsSeen.add(key);
    record('findings', { path: target, ...location(code, offset), name, severity, detail });
  }
  function allowed(target) {
    if (!scanRoots.some(root => inside(root, target))) {
      gap('unresolved', target, 'Outside supplied scan roots');
      return false;
    }
    if (excluded.some(root => inside(root, target))) {
      gap('exclusions', target, 'Explicit path exclusion');
      return false;
    }
    return true;
  }
  function stat(target, optional = false) {
    if (!allowed(target)) return null;
    try {
      // Check ancestors too: a configured hooksPath must not escape via a link.
      let current = target;
      while (true) {
        const s = fs.lstatSync(current);
        if (s.isSymbolicLink()) {
          gap('exclusions', target, `Symbolic link/reparse point is not followed: ${current}`);
          return null;
        }
        const parent = path.dirname(current);
        if (parent === current) break;
        current = parent;
      }
      return fs.lstatSync(target);
    } catch (err) {
      if (err.code === 'ENOENT') missingPaths.add(target);
      if (!(optional && err.code === 'ENOENT')) gap('unreadable', target, err.code || err.message);
      return null;
    }
  }
  function read(target, s) {
    const limit = report.coverage.files.length >= caps.files ? `Text file count limit reached (${caps.files})` :
      s.size > caps.fileBytes ? `Per-file size limit reached (${s.size} > ${caps.fileBytes} bytes)` :
      report.coverage.bytes + s.size > caps.totalBytes ? `Total byte limit reached (${caps.totalBytes} bytes)` : null;
    if (limit) {
      gap('exclusions', target, limit);
      return null;
    }
    let fd;
    try {
      fd = fs.openSync(target, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_NONBLOCK || 0));
      const actual = fs.fstatSync(fd);
      if (!actual.isFile()) { gap('exclusions', target, 'Not a regular file'); return null; }
      const buf = Buffer.alloc(Math.min(caps.fileBytes, caps.totalBytes - report.coverage.bytes) + 1);
      let length = 0;
      while (length < buf.length) {
        const count = fs.readSync(fd, buf, length, buf.length - length, null);
        if (!count) break;
        length += count;
      }
      report.coverage.bytes += length;
      if (length === buf.length) { gap('exclusions', target, 'Read size limit reached'); return null; }
      const data = buf.subarray(0, length);
      if (data.includes(0)) { gap('exclusions', target, 'Binary content is not analyzed'); return null; }
      const code = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(data);
      report.coverage.files.push(target);
      contents.set(target, code);
      return code;
    } catch (err) {
      gap('unreadable', target, err.code || err.message);
      return null;
    } finally { if (fd !== undefined) fs.closeSync(fd); }
  }
  function behavior(target, code) {
    function matches(regex, name, detail, severity) {
      for (const m of code.matchAll(regex)) {
        finding(target, code, m.index, name, detail, severity);
        if (stopped) break;
      }
    }
    matches(/\bcanary\.js\b/gi, 'canary-indicator', 'Text references canary.js; the name alone does not establish malicious behavior.', 'indicator');
    if (path.basename(target).toLowerCase() === 'canary.js' && !/\bcanary\.js\b/i.test(code)) {
      finding(target, code, 0, 'canary-indicator', 'File is named canary.js; inspect behavior independently of its name.', 'indicator');
    }
    matches(/\b(?:curl|wget)\b(?:[^\r\n;]|\\\r?\n){0,1000}\|\s*(?:sudo\s+)?(?:\/(?:[\w.-]+\/)*)?(?:ba|da|z)?sh\b/g,
      'remote-to-shell', 'Download command, possibly continued across lines, is piped to a shell; fetched content is not retrieved or verified.');
    matches(/\b(?:ba|da|z)?sh\s+(?:-[a-z]*c\s+)?["']?\s*(?:\$\(|`|<\()\s*(?:curl|wget)\b/g,
      'remote-to-shell', 'Shell consumes a download through command/process substitution.');
    matches(/\b(?:ba|da|z)?sh\s+-[a-z]*c\s+["']\s*(?:\\?["'])?\s*\$\(\s*(?:curl|wget)\b/g,
      'remote-to-shell', 'Shell command string contains a substituted download; verify its quoting and execution behavior.');
    matches(/\b(?:curl|wget)\b[^\r\n;]{0,500}(?:-o|-O|--output(?:-document)?[= ])\s*([\w./-]+)[\s\S]{0,500}?\b(?:ba|da|z)?sh\s+\1\b/g,
      'remote-to-shell', 'Download is saved to a named file subsequently supplied to a shell.');
    const collection = /process\.env\b|\b(?:hostname|userInfo)\s*\(|\b(?:hostname|whoami|printenv|env)\b/g;
    const outbound = networkCalls.check(code) || /\b(?:curl|wget)\b/.test(code) ||
      /\b(?:https?|dns)\.(?:get|request|lookup|resolve)\s*\(/.test(code) ||
      /\bimport\s+[^;\n]{0,300}\sfrom\s*['"](?:node:)?(?:https?|dns|net|tls|dgram|http2)['"]/.test(code);
    if (outbound && (processEnv.check(code) || collection.test(code))) {
      collection.lastIndex = 0;
      matches(collection, 'outbound-collection', 'Host/user/environment collection and a network primitive occur in this file. Static co-occurrence does not prove transmitted data or intent.');
    }
    if (outbound) {
      matches(/\b(?:exec(?:Sync)?|spawn(?:Sync)?)\s*\([^\r\n]{0,300}(?:['"](?:\/bin\/)?(?:ba|da|z)?sh['"]|shell\s*:\s*(?:true|['"][^'"]+['"]))/g,
        'remote-shell-primitives', 'Network and shell execution primitives co-occur in this file; downloaded-content flow and runtime effects are unverified.');
    }
    matches(/\b(?:curl|wget|cp|install|tee|touch|printf|echo|cat)\b[^\r\n]{0,500}[\s\S]{0,500}?\bchmod\s+(?:\+[xX]|[0-7]*[1357][0-7]{2})\s+[^\r\n;&]+/g,
      'executable-recreation', 'File creation/download and executable permission assignment occur together; verify target and purpose.');
    matches(/\b(?:echo|printf|cat)\b[^\r\n]{0,500}>\s*[^\s;&]+\.(?:[cm]?js|sh|py)\b/g,
      'executable-recreation', 'Command writes a script file that could recreate an executable target.');
    if (filesystemManipulation.check(code) || /\b(?:writeFile(?:Sync)?|appendFile(?:Sync)?|createWriteStream)\s*\(/.test(code)) {
      matches(/\b(?:fs\.)?(?:writeFile(?:Sync)?|appendFile(?:Sync)?|createWriteStream)\s*\([^\r\n]{0,300}(?:\.(?:[cm]?js|sh|py)["']|0o[0-7]*[1357][0-7]{2})/g,
        'executable-recreation', 'Filesystem write targets a script or an executable mode; verify whether it recreates a target.');
      matches(/\b(?:writeFile(?:Sync)?|appendFile(?:Sync)?|createWriteStream)\s*\([\s\S]{0,1000}?\bchmod(?:Sync)?\s*\([^\r\n]{0,300}0o[0-7]*[1357][0-7]{2}/g,
        'executable-recreation', 'Filesystem write and executable chmod occur together; target identity and runtime recreation are unverified.');
    }
  }
  function references(target, code, command, offset, base, depth = 0) {
    if (stopped) return;
    if (process.platform === 'win32') command = command.replace(/\\(?=[\w.\/\\-])/g, '/');
    if (depth > 8) { gap('unresolved', target, 'Inline command nesting limit', location(code, offset)); return; }
    if (/\bcd\s/.test(command) && /\|\||;/.test(command)) {
      gap('unresolved', target, 'Working directory depends on shell control flow', location(code, offset));
      return;
    }
    let commandBase = base;
    for (const segment of splitOnShellSeparators(command)) {
      if (stopped) break;
      const tokens = tokenize(segment);
      if (tokens[0] === 'cd') {
        if (tokens.length === 2 && !/[$`*?~]/.test(tokens[1])) commandBase = path.resolve(commandBase, tokens[1]);
        else { gap('unresolved', target, 'Dynamic working directory', location(code, offset)); return; }
        continue;
      }
      // Reuse the parser after removing recognizable environment wrappers.
      let unwrapped = segment.replace(/^(?:env\s+)?(?:[A-Za-z_]\w*=[^\s]+\s+)+/, '').replace(/^env\s+/, '');
      if ((tokens[0] === '.' || tokens[0] === 'source') && tokens[1]) unwrapped = `sh "${tokens[1]}"`;
      if (/\bnode(?:js)?\s+[^;&]*\s(?:-r|--require|--loader|--import)\b|\bnode(?:js)?\s+(?:-r|--require|--loader|--import)\b|\b(?:bun|deno)\s+run\b/.test(unwrapped)) {
        gap('unresolved', target, 'Runtime option/subcommand target resolution is unsupported', location(code, offset));
        continue;
      }
      const parsedRefs = parseCommand(unwrapped);
      if (parsedRefs.length === 1 && parsedRefs[0].kind === 'inline' && /^(?:\.\.?[\/\\]|\/)/.test(tokens[0] || '')) {
        parsedRefs[0] = { kind: 'file', path: tokens[0], interpreter: 'auto' };
      }
      for (const ref of parsedRefs) {
        if (ref.kind === 'inline') {
          if (ref.interpreter === 'sh' && ref.code !== unwrapped) references(target, code, ref.code, offset, commandBase, depth + 1);
          else if (ref.interpreter === 'node' && extractRequires(ref.code).staticTargets.some(p => /^(?:\.\.?\/|\/)/.test(p))) {
            gap('unresolved', target, 'Inline JavaScript local imports are not resolved', location(code, offset));
          } else if (ref.interpreter === 'node' && extractRequires(ref.code).dynamicHints.length) {
            gap('unresolved', target, 'Dynamic inline JavaScript imports', location(code, offset));
          } else if (/^(?:node(?:js)?|(?:ba|da|z)?sh)\s*(?:-\s*)?$/.test(unwrapped)) {
            gap('unresolved', target, 'Interpreter stdin/interactive input is unavailable', location(code, offset));
          } else if (ref.interpreter === 'shell' && !/^(?:echo|printf|curl|wget|chmod|exit|true|false|#)\b/.test(ref.code)) {
            gap('unresolved', target, 'Command entry point is not statically resolved', { ...location(code, offset), command: ref.code.slice(0, 240) });
          }
          continue;
        }
        const item = { path: target, ...location(code, offset), reference: ref.path };
        if (/[$`*?~<>]|^https?:/.test(ref.path)) {
          item.status = 'unresolved';
          gap('unresolved', target, 'Dynamic or remote script target', item);
        } else {
          item.target = path.resolve(commandBase, ref.path);
          const s = stat(item.target, true);
          if (s && s.isFile()) item.status = 'exists';
          else {
            item.status = 'unresolved';
            if (missingPaths.has(item.target)) item.status = 'missing';
            gap('unresolved', target, item.status === 'missing' ? 'Referenced script target is missing' : 'Script target could not be inspected', item);
          }
        }
        record('references', item);
      }
    }
  }
  function gitConfig(target, code, repo, depth) {
    if (configs.has(target)) return;
    configs.add(target);
    record(report.coverage.gitConfigs, { path: target });
    let section = '';
    let offset = 0;
    for (const line of code.split('\n')) {
      if (stopped) break;
      const header = line.match(/^\s*\[([^\]]+)\]/);
      if (header) section = header[1].toLowerCase();
      const setting = line.match(/^\s*([\w.-]+)\s*=\s*(.*?)\s*$/);
      if (setting) {
        const key = setting[1].toLowerCase();
        let value;
        try { value = gitValue(setting[2]); }
        catch (err) { gap('unresolved', target, err.message, location(code, offset)); offset += line.length + 1; continue; }
        if (section === 'core' && key === 'hookspath') {
          if (/[$~\\]/.test(value)) gap('unresolved', target, 'Unsupported hooksPath expansion/escape', location(code, offset));
          else {
            const dir = path.resolve(repo, value);
            hooks.set(dir, repo);
            record(report.coverage.hookDirectories, { path: dir, configuredBy: target, ...location(code, offset) });
            visit(dir, depth + 1, repo);
          }
        } else if ((section === 'include' || section.startsWith('includeif ')) && key === 'path') {
          if (section !== 'include' || /[$~\\]/.test(value)) gap('unresolved', target, 'Conditional or expanded Git include is not resolved', location(code, offset));
          else visit(path.resolve(path.dirname(target), value), depth + 1, repo, true);
        }
      } else if (line.trim() && !header && !/^\s*[#;]/.test(line)) {
        gap('unresolved', target, 'Unsupported Git configuration syntax', location(code, offset));
      }
      offset += line.length + 1;
    }
  }
  function file(target, s, depth, repo, isConfig) {
    if (path.basename(target) === 'canary.js') record(report.coverage.canaryFiles, { path: target });
    if (protectionOnly && !isConfig && !['package.json', 'canary.js'].includes(path.basename(target)) &&
        ![...hooks.keys()].some(dir => inside(dir, target)) && !/(?:^|[\\/])(?:\.husky|\.githooks)(?:[\\/])/.test(target)) {
      filenameOnly.add(target);
      return;
    }
    filenameOnly.delete(target);
    const code = read(target, s);
    if (code === null) return;
    behavior(target, code);
    if (isConfig) gitConfig(target, code, repo, depth);
    if (path.basename(target) === 'package.jsonl') {
      finding(target, code, 0, 'nonstandard-manifest', 'package.jsonl is a nonstandard text file, not an npm manifest.', 'indicator');
    }
    if (path.basename(target) === 'package.json') {
      try {
        const manifest = JSON.parse(code.replace(/^\uFEFF/, ''));
        if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) throw new Error('Manifest must be an object');
        if (manifest.scripts !== undefined && (!manifest.scripts || typeof manifest.scripts !== 'object' || Array.isArray(manifest.scripts))) throw new Error('scripts must be an object');
        for (const [key, value] of Object.entries(manifest.scripts || {})) {
          if (typeof value !== 'string') gap('unresolved', target, `Script ${key} is not a string`);
        }
        for (const script of scriptLocations(code)) references(target, code, script.command, script.offset, path.dirname(target));
      } catch (err) { gap('unreadable', target, `Invalid/unsupported package.json: ${err.message}`); }
    } else if (/\.(?:[cm]?js|[cm]?ts)$/.test(target)) {
      const imports = extractRequires(code);
      for (const ref of imports.staticTargets.filter(p => /^(?:\.\.?\/|\/)/.test(p))) {
        if (stopped) break;
        const base = path.resolve(path.dirname(target), ref);
        const candidates = [base, ...['.js', '.mjs', '.cjs', '.json', '/index.js', '/index.mjs', '/index.cjs'].map(ext => base + ext)];
        const found = candidates.find(p => { const info = stat(p, true); return info && info.isFile(); });
        const status = found ? 'exists' : candidates.every(p => missingPaths.has(p)) ? 'missing' : 'unresolved';
        const item = { path: target, ...location(code, code.indexOf(ref)), reference: ref, target: found || base, status };
        record('references', item);
        if (!found) gap('unresolved', target, 'Local import target could not be resolved', item);
      }
      for (const match of code.matchAll(/\b(require|import)\s*\(\s*([^)]*?)\s*\)/g)) {
        if (stopped) break;
        const arg = match[2].trim();
        const hint = match[1] === 'import' ? `import(${arg.slice(0, 100)})` : arg.slice(0, 120);
        if (imports.dynamicHints.includes(hint)) gap('unresolved', target, 'Dynamic JavaScript import/require', { ...location(code, match.index), reference: hint });
      }
    }
    const hook = [...hooks].find(([dir]) => inside(dir, target));
    const versionedHook = target.match(/(?:^|[\\/])(?:\.husky|\.githooks)(?:[\\/])/);
    if (/\.(?:sh|bash)$/.test(target) || /^#![^\n]*\b(?:ba|da|z)?sh\b/.test(code) ||
        (!/\.(?:[cm]?js|[cm]?ts|json)$/.test(target) && (hook || /(?:^|[\\/])(?:\.husky|\.githooks)(?:[\\/])/.test(target)))) {
      shellReferences(target, code, hook ? hook[1] : repo || (versionedHook ? target.slice(0, versionedHook.index) : path.dirname(target)));
    }
  }
  function shellReferences(target, code, base) {
    const key = `${target}\0${base}`;
    if (shellSources.has(key)) return;
    shellSources.add(key);
      let offset = 0;
      for (const line of code.split('\n')) {
        if (line.trim() && !/^\s*#/.test(line)) references(target, code, line, offset, base);
        offset += line.length + 1;
      }
  }
  function gitDirectory(dir, repo, depth) {
    if (gitDirs.has(dir)) return;
    gitDirs.add(dir);
    if (depth > caps.depth) { gap('unresolved', dir, 'Git metadata nesting limit'); return; }
    const info = stat(dir);
    if (!info) return;
    if (!info.isDirectory()) { gap('unresolved', dir, 'Git directory is not a directory'); return; }
    hooks.set(path.join(dir, 'hooks'), repo);
    record(report.coverage.hookDirectories, { path: path.join(dir, 'hooks'), configuredBy: 'default' });
    for (const name of ['config', 'config.worktree', 'hooks', 'commondir']) {
      if (stopped) break;
      const target = path.join(dir, name);
      const s = stat(target, true);
      if (!s) continue;
      if (name === 'commondir' && s.isFile()) {
        const text = read(target, s);
        if (text !== null) gitPointer(target, text, text.trim(), path.resolve(dir, text.trim()), repo, depth + 1);
      } else visit(target, depth + 1, repo, name.startsWith('config'));
    }
    gap('exclusions', dir, 'Git metadata other than config, config.worktree, commondir and hooks is not analyzed');
  }
  function gitPointer(source, code, ref, target, repo, depth) {
    const info = stat(target, true);
    const item = { path: source, ...location(code, 0), reference: ref, target,
      status: info && info.isDirectory() ? 'exists' : missingPaths.has(target) ? 'missing' : 'unresolved' };
    record('references', item);
    if (item.status !== 'exists') gap('unresolved', source, 'Git directory pointer could not be resolved', item);
    else gitDirectory(target, repo, depth);
  }
  const gitDirs = new Set();
  function visit(target, depth = 0, repo = null, isConfig = false) {
    if (stopped) return;
    if (excludeQuarantine && path.basename(target) === '.np-audit-quarantine') {
      gap('exclusions', target, 'Quarantine storage is not analyzed');
      return;
    }
    if (seen.has(target)) {
      if (isConfig && filenameOnly.has(target)) {
        const info = stat(target);
        if (info && info.isFile()) file(target, info, depth, repo, true);
        return;
      }
      if (isConfig && contents.has(target)) gitConfig(target, contents.get(target), repo, depth);
      return;
    }
    if (depth > caps.depth) { gap('exclusions', target, 'Directory nesting limit reached'); return; }
    if (++report.coverage.entries > caps.entries) { gap('exclusions', target, 'Traversal entry limit reached'); stopped = true; return; }
    const s = stat(target);
    if (!s) return;
    seen.add(target);
    if (path.basename(target) === '.git') {
      const root = path.dirname(target);
      record(report.coverage.repositories, { path: root });
      if (s.isDirectory()) { gitDirectory(target, root, depth); return; }
      if (s.isFile()) {
        const code = read(target, s);
        const m = code && code.match(/^gitdir:\s*(.+)\s*$/);
        if (m) gitPointer(target, code, m[1].trim(), path.resolve(root, m[1].trim()), root, depth);
        else gap('unresolved', target, 'Unrecognized .git pointer');
        return;
      }
    }
    if (s.isFile()) { file(target, s, depth, repo, isConfig); return; }
    if (!s.isDirectory()) { gap('exclusions', target, 'Not a regular file/directory'); return; }
    const localGit = path.join(target, '.git');
    if (stat(localGit, true)) {
      repo = target;
      visit(localGit, depth + 1, repo);
    }
    let dir;
    try {
      dir = fs.opendirSync(target);
      let entry;
      while (!stopped && (entry = dir.readSync())) visit(path.join(target, entry.name), depth + 1, repo);
    } catch (err) { gap('unreadable', target, err.code || err.message); }
    finally { if (dir) dir.closeSync(); }
  }
  for (const root of scanRoots) visit(root);
  // A separately supplied hook root may have been visited before its config.
  for (const [dir, repo] of hooks) {
    if (stopped) break;
    for (const target of [...filenameOnly]) {
      if (stopped) break;
      if (inside(dir, target)) { const info = stat(target); if (info && info.isFile()) file(target, info, 0, repo, false); }
    }
    for (const [target, code] of contents) {
      if (stopped) break;
      if (inside(dir, target) && (!/\.(?:[cm]?js|[cm]?ts|json)$/.test(target) || /^#![^\n]*\b(?:ba|da|z)?sh\b/.test(code))) shellReferences(target, code, repo);
    }
  }
  for (const target of excluded) if (!report.exclusions.some(item => item.path === target)) gap('exclusions', target, 'Explicit path exclusion');
  if (protectionOnly) {
    report.coverage.filenameOnlyFiles = [...filenameOnly];
    report.limitations = [...LIMITATIONS, 'Protection checks all discovered filenames; content inspection is limited to manifests, Git config/hooks and canary.js. Filename-only paths are listed separately.'];
  }
  report.summary = { status: report.complete ? 'complete' : 'incomplete', files: report.coverage.files.length,
    findings: report.findings.length, unresolved: report.unresolved.length,
    unreadable: report.unreadable.length, exclusions: report.exclusions.length };
  return report;
}

module.exports = { scanRepository, scriptLocations, location, LIMITS };
