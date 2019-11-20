/*!
 * require.js - custom require for bmocha
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bmocha
 */

'use strict';

const path = require('path');
const imports = require('./imports');

const {
  basename,
  dirname,
  isAbsolute,
  join,
  resolve
} = path;

/*
 * Constants
 */

const extensions = require.extensions || {};

/*
 * Imports
 */

async function _imports(request, root = '.') {
  if (!imports.supported) {
    if (isBuiltin(request))
      return _require(request, root);

    return { 'default': _require(request, root) };
  }

  return imports(_imports.resolveURL(request, root));
}

_imports.resolve = function resolve(request, root = '.') {
  if (!imports.supported)
    return _require.resolve(request, root);

  const undo1 = injectPaths(root);
  const undo2 = injectExtensions();

  try {
    return require.resolve(tryResolve(root, request));
  } finally {
    undo2();
    undo1();
  }
};

_imports.resolveURL = function resolveURL(request, root = '.') {
  const path = _imports.resolve(request, root);

  if (isAbsolute(path))
    return imports.pathToFileURL(path);

  return path;
};

/*
 * Require
 */

function _require(request, root = '.') {
  const undo = injectPaths(root);
  try {
    return require(tryResolve(root, request));
  } finally {
    undo();
  }
}

_require.cache = require.cache;

_require.extensions = require.extensions;

_require.imports = _imports;

_require.main = require.main;

_require.resolve = function resolve(request, root = '.') {
  const undo = injectPaths(root);
  try {
    return require.resolve(tryResolve(root, request));
  } finally {
    undo();
  }
};

_require.resolve.paths = function paths(request, root = '.') {
  const undo = injectPaths(root);
  try {
    return require.resolve.paths(tryResolve(root, request));
  } finally {
    undo();
  }
};

/*
 * Helpers
 */

function nodeModulePaths(root) {
  if (typeof root !== 'string')
    throw new TypeError('"root" must be a string.');

  const paths = [];

  let dir = resolve(root);

  for (;;) {
    if (basename(dir) !== 'node_modules')
      paths.push(join(dir, 'node_modules'));

    const next = dirname(dir);

    if (next === dir)
      break;

    dir = next;
  }

  if (process.platform === 'win32') {
    const {APPDATA} = process.env;
    if (APPDATA)
      paths.push(resolve(APPDATA, 'npm', 'node_modules'));
  } else {
    const PREFIX = resolve(process.execPath, '..', '..');
    paths.push(join(PREFIX, 'lib', 'node_modules'));
  }

  return paths;
}

function injectPaths(root) {
  const paths = nodeModulePaths(root);
  const save = module.paths.slice();

  module.paths.length = 0;
  module.paths.push(...paths);

  return () => {
    module.paths.length = 0;
    module.paths.push(...save);
  };
}

function injectExtensions() {
  const js = extensions['.js'];
  const mjs = extensions['.mjs'];
  const cjs = extensions['.cjs'];

  if (!mjs)
    extensions['.mjs'] = js;

  if (!cjs)
    extensions['.cjs'] = js;

  return () => {
    if (!mjs)
      delete extensions['.mjs'];

    if (!cjs)
      delete extensions['.cjs'];
  };
}

function tryResolve(root, request) {
  if (typeof root !== 'string')
    throw new TypeError('"root" must be a string.');

  if (typeof request !== 'string')
    return request;

  if (request === '.'
      || request.startsWith('./')
      || request.startsWith('../')
      || request.startsWith('.\\')
      || request.startsWith('..\\')) {
    return resolve(root, request);
  }

  return request;
}

function isBuiltin(request) {
  try {
    request = require.resolve(request);
  } catch (e) {
    return false;
  }
  return !isAbsolute(request);
}

/*
 * Expose
 */

module.exports = _require;
