/*!
 * loady.js - dynamic loader for node.js
 * Copyright (c) 2019-2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/loady
 */

'use strict';

const fs = require('fs');
const path = require('path');

/*
 * Constants
 */

const types = [
  'Debug',
  'Release',
  'MinSizeRel',
  'RelWithDebInfo'
];

/**
 * Resolve
 */

function resolve(name, root) {
  if (typeof name !== 'string')
    throw new TypeError('"name" must be a string.');

  if (typeof root !== 'string')
    throw new TypeError('"root" must be a string.');

  if (!fs.existsSync)
    throw moduleError(name);

  if (path.extname(name) !== '.node')
    name += '.node';

  root = ensurePath(root);

  const key = `${name}\0${root}`;

  if (resolve.cache[key])
    return resolve.cache[key];

  if (process.pkg && !isPath(name))
    name = path.resolve(process.execPath, '..', name);

  if (isPath(name)) {
    const file = path.resolve(root, name);

    if (!fs.existsSync(file))
      throw moduleError(file);

    const real = realpath(file);

    resolve.cache[key] = real;

    return real;
  }

  for (;;) {
    const build = path.join(root, 'build');

    if (fs.existsSync(build)) {
      const files = [path.join(build, name)];

      for (const type of types)
        files.push(path.join(build, type, name));

      for (const file of files) {
        if (fs.existsSync(file)) {
          const real = realpath(file);
          resolve.cache[key] = real;
          return real;
        }
      }
    }

    const next = path.dirname(root);

    if (next === root)
      break;

    root = next;
  }

  throw moduleError(name);
}

resolve.cache = Object.create(null);

/**
 * Load
 */

function load(name, root) {
  const file = resolve(name, root);

  if (load.cache[file])
    return load.cache[file];

  if (!process.dlopen)
    throw new Error(`${name}: cannot open shared object file`);

  const module = { exports: {} };

  process.dlopen(module, file);

  load.cache[file] = module.exports;

  return module.exports;
}

load.cache = Object.create(null);

/*
 * Helpers
 */

function isPath(str) {
  if (process.platform === 'win32')
    str = str.replace('\\', '/');

  return str[0] === '/'
      || str.startsWith('./')
      || str.startsWith('../');
}

function ensurePath(str) {
  if (str.indexOf('file:') === 0) {
    const url = require('url');

    if (!url.fileURLToPath)
      throw new Error('File URLs are unsupported on this platform.');

    // Assume this is an import.meta.url.
    return path.resolve(url.fileURLToPath(str), '..');
  }

  return path.resolve(str);
}

function realpath(file) {
  try {
    return fs.realpathSync(file);
  } catch (e) {
    return path.resolve(file);
  }
}

function moduleError(name) {
  const err = new Error(`Cannot find module '${name}'`);
  err.code = 'MODULE_NOT_FOUND';
  throw err;
}

/*
 * Expose
 */

load.load = load;
load.resolve = resolve;

module.exports = load;
