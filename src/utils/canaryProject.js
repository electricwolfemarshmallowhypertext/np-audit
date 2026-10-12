'use strict';

const fs = require('fs');
const path = require('path');
const { checkPath } = require('../core/canaryQuarantine');

function projectRoots(cwd, entry = null) {
  function find(start) {
    let directory = path.resolve(start);
    while (true) {
      if (['package.json', '.git'].some(name => fs.existsSync(path.join(directory, name)))) {
        checkPath(directory);
        return directory;
      }
      const parent = path.dirname(directory);
      if (parent === directory) return null;
      directory = parent;
    }
  }
  const roots = [];
  const project = find(cwd);
  if (project) roots.push(project);
  else if (fs.existsSync(path.join(cwd, 'canary.js'))) roots.push(path.resolve(cwd));
  if (entry && (!project || path.basename(entry) === 'canary.js')) {
    const directory = path.dirname(path.resolve(entry));
    const entryProject = find(directory);
    if (entryProject || path.basename(entry) === 'canary.js') roots.push(entryProject || directory);
  }
  return [...new Set(roots)];
}

module.exports = { projectRoots };
