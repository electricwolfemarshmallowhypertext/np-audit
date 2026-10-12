'use strict';

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

function spawnNpm(args, options, protection = false) {
  if (process.platform === 'win32' && protection) {
    // Node cannot spawn a .cmd file directly. Run npm's JavaScript entry point
    // with argv intact instead of passing user arguments through cmd.exe.
    const directories = [...new Set([path.dirname(process.execPath), ...(process.env.PATH || '').split(path.delimiter)])];
    for (const directory of directories) {
      if (!directory) continue;
      const entry = path.join(directory, 'node_modules', 'npm', 'bin', 'npm-cli.js');
      try {
        if (fs.statSync(entry).isFile()) return spawnSync(process.execPath, [entry, ...args], options);
      } catch (err) { if (!['ENOENT', 'ENOTDIR'].includes(err.code)) throw err; }
    }
    throw new Error('Protected npm launch requires a discoverable npm-cli.js beside Node or on PATH');
  }
  return spawnSync(process.platform === 'win32' ? 'npm.cmd' : 'npm', args, options);
}

module.exports = { spawnNpm };
