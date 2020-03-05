/*!
 * extra.js - extra functions for bfile
 * Copyright (c) 2014-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bfile
 */

'use strict';

const path = require('path');
const error = require('./error');
const fs = require('./backend');
const util = require('./util');
const {dirname, join, resolve} = path;
const {ArgError, FSError} = error;
const {fromPath, fromPaths} = util;
const {EEXIST, EPERM} = FSError;

/*
 * Constants
 */

const ASYNC_ITERATOR = Symbol.asyncIterator || 'asyncIterator';
const PARSED_OPTIONS = Symbol('PARSED_OPTIONS');
const DEFAULT_STRINGIFY_OPTIONS = [null, 2, '\n'];

/*
 * Copy
 */

async function copy(src, dest, options) {
  return _copy(fromPath(src),
               fromPath(dest),
               copyOptions(options),
               new Set(),
               0);
}

async function _copy(src, dest, options, seen, depth) {
  const sstat = await stats(src, options.stats);
  const dstat = await lstatTry(dest);

  let ret = 0;

  if (!options.overwrite && dstat)
    throw new FSError(EEXIST, 'copy', dest);

  if (dstat && sstat.dev === dstat.dev && sstat.ino === dstat.ino)
    throw new FSError(EPERM, 'cannot copy file into itself', 'copy', dest);

  if (options.filter) {
    if (!await options.filter(src, sstat, depth))
      return ret + 1;
  }

  if (sstat.isDirectory()) {
    if (options.follow) {
      let real = resolve(src);

      try {
        real = await fs.realpath(real);
      } catch (e) {
        if (!isIgnorable(e))
          throw e;
      }

      if (seen.has(real))
        return ret;

      seen.add(real);
    }

    const list = await fs.readdir(src);

    if (dstat) {
      if (!dstat.isDirectory())
        throw new FSError(EEXIST, 'mkdir', dest);
    } else {
      await fs.mkdir(dest, sstat.mode);
    }

    if (options.timestamps)
      await fs.utimes(dest, sstat.atime, sstat.mtime);

    for (const name of list) {
      ret += await _copy(join(src, name),
                         join(dest, name),
                         options,
                         seen,
                         depth + 1);
    }

    return ret;
  }

  if (sstat.isSymbolicLink()) {
    if (dstat) {
      if (!dstat.isFIFO()
          && !dstat.isFile()
          && !dstat.isSocket()
          && !dstat.isSymbolicLink()) {
        throw new FSError(EEXIST, 'symlink', dest);
      }

      await fs.unlink(dest);
    }

    await fs.symlink(await fs.readlink(src), dest);

    if (options.timestamps)
      await fs.utimes(dest, sstat.atime, sstat.mtime);

    return ret;
  }

  if (sstat.isFile()) {
    if (dstat) {
      if (!dstat.isFIFO()
          && !dstat.isFile()
          && !dstat.isSocket()
          && !dstat.isSymbolicLink()) {
        throw new FSError(EEXIST, 'open', dest);
      }

      if (!dstat.isFile())
        await fs.unlink(dest);
    }

    await fs.copyFile(src, dest, options.flags);

    if (options.timestamps)
      await fs.utimes(dest, sstat.atime, sstat.mtime);

    return ret;
  }

  return ret + 1;
}

function copySync(src, dest, options) {
  return _copySync(fromPath(src),
                   fromPath(dest),
                   copyOptions(options),
                   new Set(),
                   0);
}

function _copySync(src, dest, options, seen, depth) {
  const sstat = statsSync(src, options.stats);
  const dstat = lstatTrySync(dest);

  let ret = 0;

  if (!options.overwrite && dstat)
    throw new FSError(EEXIST, 'copy', dest);

  if (dstat && sstat.dev === dstat.dev && sstat.ino === dstat.ino)
    throw new FSError(EPERM, 'cannot copy file into itself', 'copy', dest);

  if (options.filter) {
    if (!options.filter(src, sstat, depth))
      return ret + 1;
  }

  if (sstat.isDirectory()) {
    if (options.follow) {
      let real = resolve(src);

      try {
        real = fs.realpathSync(real);
      } catch (e) {
        if (!isIgnorable(e))
          throw e;
      }

      if (seen.has(real))
        return ret;

      seen.add(real);
    }

    const list = fs.readdirSync(src);

    if (dstat) {
      if (!dstat.isDirectory())
        throw new FSError(EEXIST, 'mkdir', dest);
    } else {
      fs.mkdirSync(dest, sstat.mode);
    }

    if (options.timestamps)
      fs.utimesSync(dest, sstat.atime, sstat.mtime);

    for (const name of list) {
      ret += _copySync(join(src, name),
                       join(dest, name),
                       options,
                       seen,
                       depth + 1);
    }

    return ret;
  }

  if (sstat.isSymbolicLink()) {
    if (dstat) {
      if (!dstat.isFIFO()
          && !dstat.isFile()
          && !dstat.isSocket()
          && !dstat.isSymbolicLink()) {
        throw new FSError(EEXIST, 'symlink', dest);
      }

      fs.unlinkSync(dest);
    }

    fs.symlinkSync(fs.readlinkSync(src), dest);

    if (options.timestamps)
      fs.utimesSync(dest, sstat.atime, sstat.mtime);

    return ret;
  }

  if (sstat.isFile()) {
    if (dstat) {
      if (!dstat.isFIFO()
          && !dstat.isFile()
          && !dstat.isSocket()
          && !dstat.isSymbolicLink()) {
        throw new FSError(EEXIST, 'open', dest);
      }

      if (!dstat.isFile())
        fs.unlinkSync(dest);
    }

    fs.copyFileSync(src, dest, options.flags);

    if (options.timestamps)
      fs.utimesSync(dest, sstat.atime, sstat.mtime);

    return ret;
  }

  return ret + 1;
}

async function empty(path, mode) {
  const dir = fromPath(path);

  let list = null;

  try {
    list = await fs.readdir(dir);
  } catch (e) {
    if (e.code === 'ENOENT')
      return mkdirp(dir, mode);
    throw e;
  }

  for (const name of list)
    await remove(join(dir, name));

  return undefined;
}

function emptySync(path, mode) {
  const dir = fromPath(path);

  let list = null;

  try {
    list = fs.readdirSync(dir);
  } catch (e) {
    if (e.code === 'ENOENT')
      return mkdirpSync(dir, mode);
    throw e;
  }

  for (const name of list)
    removeSync(join(dir, name));

  return undefined;
}

async function exists(file, mode) {
  if (mode == null)
    mode = fs.constants.F_OK;

  try {
    await fs.access(file, mode);
    return true;
  } catch (e) {
    if (isIgnorable(e))
      return false;
    throw e;
  }
}

function existsSync(file, mode) {
  if (mode == null)
    mode = fs.constants.F_OK;

  try {
    fs.accessSync(file, mode);
    return true;
  } catch (e) {
    if (isIgnorable(e))
      return false;
    throw e;
  }
}

async function lstatTry(...args) {
  try {
    return await fs.lstat(...args);
  } catch (e) {
    if (isIgnorable(e))
      return null;
    throw e;
  }
}

function lstatTrySync(...args) {
  try {
    return fs.lstatSync(...args);
  } catch (e) {
    if (isIgnorable(e))
      return null;
    throw e;
  }
}

async function mkdirp(dir, mode) {
  if (mode == null)
    mode = 0o777;

  return fs.mkdir(dir, { mode, recursive: true });
}

function mkdirpSync(dir, mode) {
  if (mode == null)
    mode = 0o777;

  return fs.mkdirSync(dir, { mode, recursive: true });
}

async function move(src, dest) {
  try {
    await fs.rename(src, dest);
    return;
  } catch (e) {
    if (e.code !== 'EXDEV')
      throw e;
  }

  await copy(src, dest, { timestamps: true });
  await remove(src);
}

function moveSync(src, dest) {
  try {
    fs.renameSync(src, dest);
    return;
  } catch (e) {
    if (e.code !== 'EXDEV')
      throw e;
  }

  copySync(src, dest, { timestamps: true });
  removeSync(src);
}

async function outputFile(path, data, options) {
  if (options == null)
    options = {};

  if (typeof options === 'string')
    options = { encoding: options };

  const file = fromPath(path);
  const dir = dirname(file);

  let mode = options.mode;

  if ((mode & 0o777) === mode)
    mode |= (mode & 0o444) >>> 2;

  await mkdirp(dir, mode);
  await fs.writeFile(file, data, options);
}

function outputFileSync(path, data, options) {
  if (options == null)
    options = {};

  if (typeof options === 'string')
    options = { encoding: options };

  const file = fromPath(path);
  const dir = dirname(file);

  let mode = options.mode;

  if ((mode & 0o777) === mode)
    mode |= (mode & 0o444) >>> 2;

  mkdirpSync(dir, mode);
  fs.writeFileSync(file, data, options);
}

async function readJSON(path, options) {
  const [reviver, opt] = readJSONOptions(options);
  const text = await fs.readFile(path, opt);

  return decodeJSON(text, reviver);
}

function readJSONSync(path, options) {
  const [reviver, opt] = readJSONOptions(options);
  const text = fs.readFileSync(path, opt);

  return decodeJSON(text, reviver);
}

async function remove(paths, options) {
  paths = fromPaths(paths);
  options = removeOptions(options);

  let ret = 0;
  let error = null;

  for (const path of paths) {
    let tries = 0;

    for (;;) {
      try {
        ret += await _remove(path, options, 0);
      } catch (e) {
        const retry = e.code === 'EBUSY'
                   || e.code === 'ENOTEMPTY'
                   || e.code === 'EPERM'
                   || e.code === 'EMFILE'
                   || e.code === 'ENFILE';

        if (retry && tries < options.maxRetries) {
          tries += 1;
          await wait(tries * options.retryDelay);
          continue;
        }

        if (!error)
          error = e;
      }

      break;
    }
  }

  if (error)
    throw error;

  return ret;
}

async function _remove(path, options, depth) {
  let ret = 0;
  let stat = null;

  try {
    stat = await safeStat(path);
  } catch (e) {
    if (e.code === 'ENOENT')
      return ret;
    throw e;
  }

  if (options.filter) {
    if (!await options.filter(path, stat, depth))
      return ret + 1;
  }

  if (stat.isDirectory()) {
    let list = null;

    try {
      list = await fs.readdir(path);
    } catch (e) {
      if (e.code === 'ENOENT')
        return ret;
      throw e;
    }

    for (const name of list)
      ret += await _remove(join(path, name), options, depth + 1);

    if (ret === 0) {
      try {
        await fs.rmdir(path);
      } catch (e) {
        if (e.code === 'ENOENT')
          return ret;
        throw e;
      }
    }

    return ret;
  }

  try {
    await fs.unlink(path);
  } catch (e) {
    if (e.code === 'ENOENT')
      return ret;
    throw e;
  }

  return ret;
}

function removeSync(paths, options) {
  paths = fromPaths(paths);
  options = removeOptions(options);

  let ret = 0;
  let error = null;

  for (const path of paths) {
    let tries = 0;

    for (;;) {
      try {
        ret += _removeSync(path, options, 0);
      } catch (e) {
        const retry = e.code === 'EBUSY'
                   || e.code === 'ENOTEMPTY'
                   || e.code === 'EPERM'
                   || e.code === 'EMFILE'
                   || e.code === 'ENFILE';

        if (retry && tries < options.maxRetries) {
          tries += 1;
          continue;
        }

        if (!error)
          error = e;
      }

      break;
    }
  }

  if (error)
    throw error;

  return ret;
}

function _removeSync(path, options, depth) {
  let ret = 0;
  let stat = null;

  try {
    stat = safeStatSync(path);
  } catch (e) {
    if (e.code === 'ENOENT')
      return ret;
    throw e;
  }

  if (options.filter) {
    if (!options.filter(path, stat, depth))
      return ret + 1;
  }

  if (stat.isDirectory()) {
    let list = null;

    try {
      list = fs.readdirSync(path);
    } catch (e) {
      if (e.code === 'ENOENT')
        return ret;
      throw e;
    }

    for (const name of list)
      ret += _removeSync(join(path, name), options, depth + 1);

    if (ret === 0) {
      let tries = 0;

      for (;;) {
        try {
          fs.rmdirSync(path);
        } catch (e) {
          if (e.code === 'ENOENT')
            return ret;

          if (e.code === 'ENOTEMPTY' && process.platform === 'win32') {
            if (tries < options.maxRetries + 1) {
              tries += 1;
              continue;
            }
          }

          throw e;
        }

        break;
      }
    }

    return ret;
  }

  try {
    fs.unlinkSync(path);
  } catch (e) {
    if (e.code === 'ENOENT')
      return ret;
    throw e;
  }

  return ret;
}

async function statTry(...args) {
  try {
    return await fs.stat(...args);
  } catch (e) {
    if (isIgnorable(e))
      return null;
    throw e;
  }
}

function statTrySync(...args) {
  try {
    return fs.statSync(...args);
  } catch (e) {
    if (isIgnorable(e))
      return null;
    throw e;
  }
}

async function stats(file, options) {
  options = statsOptions(options);

  if (options.follow) {
    try {
      return await fs.stat(file, options.stat);
    } catch (e) {
      if (!isIgnorable(e))
        throw e;
    }
  }

  return fs.lstat(file, options.stat);
}

function statsSync(file, options) {
  options = statsOptions(options);

  if (options.follow) {
    try {
      return fs.statSync(file, options.stat);
    } catch (e) {
      if (!isIgnorable(e))
        throw e;
    }
  }

  return fs.lstatSync(file, options.stat);
}

async function statsTry(file, options) {
  try {
    return await stats(file, options);
  } catch (e) {
    if (isIgnorable(e))
      return null;
    throw e;
  }
}

function statsTrySync(file, options) {
  try {
    return statsSync(file, options);
  } catch (e) {
    if (isIgnorable(e))
      return null;
    throw e;
  }
}

/*
 * Traversal
 */

async function traverse(paths, options, cb) {
  if (typeof options === 'function'
      && typeof cb !== 'function') {
    [options, cb] = [cb, options];
  }

  if (typeof cb !== 'function')
    throw new ArgError('callback', cb, 'function');

  const iter = walk(paths, options);

  for (;;) {
    const {value, done} = await iter.next();

    if (done)
      break;

    const [file, stat, depth] = value;

    if ((await cb(file, stat, depth)) === false)
      break;
  }
}

function traverseSync(paths, options, cb) {
  if (typeof options === 'function'
      && typeof cb !== 'function') {
    [options, cb] = [cb, options];
  }

  if (typeof cb !== 'function')
    throw new ArgError('callback', cb, 'function');

  for (const [file, stat, depth] of walkSync(paths, options)) {
    if (cb(file, stat, depth) === false)
      break;
  }
}

function walk(paths, options) {
  paths = fromPaths(paths);
  options = walkOptions(options);

  return new AsyncWalker(paths, options);
}

function* walkSync(paths, options) {
  paths = fromPaths(paths);
  options = walkOptions(options);

  for (const path of paths)
    yield* syncWalker(path, options);
}

async function writeJSON(path, json, options) {
  const [args, opt] = writeJSONOptions(options);
  const text = encodeJSON(json, args);

  return fs.writeFile(path, text, opt);
}

function writeJSONSync(path, json, options) {
  const [args, opt] = writeJSONOptions(options);
  const text = encodeJSON(json, args);

  fs.writeFileSync(path, text, opt);
}

/**
 * AsyncWalker
 */

class AsyncWalker {
  constructor(paths, options) {
    this.stack = [paths.reverse()];
    this.dirs = options.dirs;
    this.files = options.files;
    this.filter = options.filter;
    this.follow = options.follow;
    this.maxDepth = options.maxDepth;
    this.stats = options.stats;
    this.statter = options.throws ? stats : statsTry;
    this.seen = new Set();
    this.depth = 0;
  }

  [ASYNC_ITERATOR]() {
    return this;
  }

  push(items) {
    this.stack.push(items);
    this.depth += 1;
  }

  pop() {
    for (;;) {
      if (this.stack.length === 0)
        return null;

      const items = this.stack[this.stack.length - 1];

      if (items.length === 0) {
        this.stack.pop();
        this.depth -= 1;
        if (this.depth === 0)
          this.seen.clear();
        continue;
      }

      return items.pop();
    }
  }

  async read(path, dir, depth) {
    if (!dir || depth === this.maxDepth)
      return;

    if (this.follow) {
      let real = resolve(path);

      try {
        real = await fs.realpath(real);
      } catch (e) {
        if (!isIgnorable(e))
          throw e;
      }

      if (this.seen.has(real))
        return;

      this.seen.add(real);
    }

    let list = null;

    try {
      list = await fs.readdir(path);
    } catch (e) {
      if (isIgnorable(e))
        return;
      throw e;
    }

    const items = new Array(list.length);

    for (let i = 0; i < list.length; i++)
      items[i] = join(path, list[list.length - 1 - i]);

    this.push(items);
  }

  async next() {
    const path = this.pop();
    const depth = this.depth;

    if (path == null)
      return { value: undefined, done: true };

    const stat = await this.statter(path, this.stats);
    const dir = stat ? stat.isDirectory() : false;

    if (this.filter) {
      if (!await this.filter(path, stat, depth))
        return this.next();
    }

    await this.read(path, dir, depth);

    if (!shouldShow(this, dir))
      return this.next();

    return { value: [path, stat, depth], done: false };
  }
}

/*
 * SyncWalker
 */

function* syncWalker(path, options) {
  const statter = options.throws ? statsSync : statsTrySync;
  const seen = new Set();

  yield* (function* next(path, depth) {
    const stat = statter(path, options.stats);
    const dir = stat ? stat.isDirectory() : false;

    if (options.filter) {
      if (!options.filter(path, stat, depth))
        return;
    }

    if (shouldShow(options, dir))
      yield [path, stat, depth];

    if (!dir || depth === options.maxDepth)
      return;

    if (options.follow) {
      let real = resolve(path);

      try {
        real = fs.realpathSync(real);
      } catch (e) {
        if (!isIgnorable(e))
          throw e;
      }

      if (seen.has(real))
        return;

      seen.add(real);
    }

    let list = null;

    try {
      list = fs.readdirSync(path);
    } catch (e) {
      if (isIgnorable(e))
        return;
      throw e;
    }

    for (const name of list)
      yield* next(join(path, name), depth + 1);
  })(path, 0);
}

/*
 * Options Parsing
 */

function copyOptions(options) {
  if (options == null)
    options = 0;

  if (typeof options === 'function')
    options = { filter: options };
  else if (typeof options === 'boolean')
    options = { follow: options };
  else if (typeof options === 'number')
    options = { flags: options };

  if (typeof options !== 'object') {
    throw new ArgError('options', options, ['null',
                                            'function',
                                            'boolean',
                                            'number',
                                            'object']);
  }

  let {flags, filter, follow, overwrite, timestamps} = options;

  if (flags == null)
    flags = 0;

  if (filter == null)
    filter = null;

  if (follow == null)
    follow = false;

  if (overwrite == null)
    overwrite = (flags & fs.constants.COPYFILE_EXCL) === 0;

  if (timestamps == null)
    timestamps = false;

  if ((flags >>> 0) !== flags)
    throw new ArgError('flags', flags, 'integer');

  if (filter != null && typeof filter !== 'function')
    throw new ArgError('filter', filter, 'function');

  if (typeof follow !== 'boolean')
    throw new ArgError('follow', follow, 'boolean');

  if (typeof overwrite !== 'boolean')
    throw new ArgError('overwrite', overwrite, 'boolean');

  if (typeof timestamps !== 'boolean')
    throw new ArgError('timestamps', timestamps, 'boolean');

  if (overwrite)
    flags &= ~fs.constants.COPYFILE_EXCL;
  else
    flags |= fs.constants.COPYFILE_EXCL;

  return {
    flags,
    filter,
    follow,
    overwrite,
    stats: statsOptions(follow),
    timestamps
  };
}

function readJSONOptions(options) {
  if (options == null)
    return [undefined, 'utf8'];

  if (typeof options === 'string')
    return [undefined, options];

  if (typeof options === 'function')
    return [options, 'utf8'];

  if (typeof options !== 'object') {
    throw new ArgError('options', options, ['null',
                                            'string',
                                            'object']);
  }

  let {reviver} = options;

  if (reviver == null)
    reviver = undefined;

  if (reviver != null && typeof reviver !== 'function')
    throw new ArgError('reviver', reviver, 'function');

  options = prepareOptions(options);

  return [reviver, options];
}

function removeOptions(options) {
  if (options == null)
    options = {};

  if (typeof options === 'function')
    options = { filter: options };

  if (typeof options !== 'object') {
    throw new ArgError('options', options, ['null',
                                            'function',
                                            'object']);
  }

  let {filter, maxRetries, retryDelay} = options;

  if (filter == null)
    filter = null;

  if (maxRetries == null)
    maxRetries = 3;

  if (retryDelay == null)
    retryDelay = 100;

  if (filter != null && typeof filter !== 'function')
    throw new ArgError('filter', filter, 'function');

  if ((maxRetries >>> 0) !== maxRetries)
    throw new ArgError('maxRetries', maxRetries, 'integer');

  if ((retryDelay >>> 0) !== retryDelay)
    throw new ArgError('retryDelay', retryDelay, 'integer');

  return { filter, maxRetries, retryDelay };
}

function statsOptions(options) {
  if (options && options[PARSED_OPTIONS])
    return options;

  if (options == null)
    options = true;

  if (typeof options === 'boolean')
    options = { follow: options };

  if (typeof options !== 'object') {
    throw new ArgError('options', options, ['null',
                                            'boolean',
                                            'object']);
  }

  let {follow, bigint} = options;

  if (follow == null)
    follow = true;

  if (bigint == null)
    bigint = false;

  if (typeof follow !== 'boolean')
    throw new ArgError('follow', follow, 'boolean');

  if (typeof bigint !== 'boolean')
    throw new ArgError('bigint', bigint, 'boolean');

  return {
    [PARSED_OPTIONS]: true,
    follow,
    stat: {
      bigint
    }
  };
}

function walkOptions(options) {
  if (options == null)
    options = true;

  if (typeof options === 'function')
    options = { filter: options };
  else if (typeof options === 'boolean')
    options = { follow: options };
  else if (typeof options === 'number')
    options = { maxDepth: options };

  if (typeof options !== 'object') {
    throw new ArgError('options', options, ['null',
                                            'function',
                                            'boolean',
                                            'number',
                                            'object']);
  }

  let {dirs, files, filter, follow, maxDepth, throws} = options;

  if (options.noDirs != null)
    dirs = !options.noDirs;

  if (options.noFiles != null)
    files = !options.noFiles;

  if (dirs == null)
    dirs = true;

  if (files == null)
    files = true;

  if (filter == null)
    filter = null;

  if (follow == null)
    follow = true;

  if (maxDepth == null)
    maxDepth = -1;

  if (throws == null)
    throws = false;

  if (filter != null && typeof filter !== 'function')
    throw new ArgError('filter', filter, 'function');

  if (typeof dirs !== 'boolean')
    throw new ArgError('dirs', dirs, 'boolean');

  if (typeof files !== 'boolean')
    throw new ArgError('files', files, 'boolean');

  if (typeof follow !== 'boolean')
    throw new ArgError('follow', follow, 'boolean');

  if (maxDepth !== -1 && (maxDepth >>> 0) !== maxDepth)
    throw new ArgError('maxDepth', maxDepth, 'integer');

  if (typeof throws !== 'boolean')
    throw new ArgError('throws', throws, 'boolean');

  if (!dirs && !files)
    throw new Error('`dirs` and `files` cannot both be false.');

  return {
    dirs,
    files,
    filter,
    follow,
    maxDepth,
    stats: statsOptions({
      bigint: options.bigint,
      follow
    }),
    throws
  };
}

function writeJSONOptions(options) {
  const defaults = DEFAULT_STRINGIFY_OPTIONS;

  if (options == null)
    return [defaults, 'utf8'];

  if (typeof options === 'string')
    return [defaults, options];

  if (typeof options === 'function') {
    const [, spaces, eol] = defaults;
    return [[options, spaces, eol], 'utf8'];
  }

  if ((options >>> 0) === options) {
    const [replacer, , eol] = defaults;
    return [[replacer, options, eol], 'utf8'];
  }

  if (typeof options !== 'object') {
    throw new ArgError('options', options, ['null',
                                            'string',
                                            'function',
                                            'integer',
                                            'object']);
  }

  let {replacer, spaces, eol} = options;

  if (replacer == null)
    replacer = defaults[0];

  if (spaces == null)
    spaces = defaults[1];

  if (eol == null)
    eol = defaults[2];

  if (replacer != null && typeof replacer !== 'function')
    throw new ArgError('replacer', replacer, 'function');

  if ((spaces >>> 0) !== spaces)
    throw new ArgError('spaces', spaces, 'integer');

  if (typeof eol !== 'string')
    throw new ArgError('eol', eol, 'string');

  options = prepareOptions(options);

  return [[replacer, spaces, eol], options];
}

/*
 * Helpers
 */

function isIgnorable(err) {
  return err.code === 'ENOENT'
      || err.code === 'EACCES'
      || err.code === 'EPERM'
      || err.code === 'ELOOP';
}

function wait(ms) {
  return new Promise(r => setTimeout(r, ms));
}

async function safeStat(path) {
  try {
    return await fs.lstat(path);
  } catch (e) {
    if (e.code === 'EPERM' && process.platform === 'win32') {
      try {
        await fs.chmod(path, 0o666);
      } catch (e) {
        ;
      }
      return fs.lstat(path);
    }
    throw e;
  }
}

function safeStatSync(path) {
  try {
    return fs.lstatSync(path);
  } catch (e) {
    if (e.code === 'EPERM' && process.platform === 'win32') {
      try {
        fs.chmodSync(path, 0o666);
      } catch (e) {
        ;
      }
      return fs.lstatSync(path);
    }
    throw e;
  }
}

function shouldShow(options, dir) {
  return dir ? options.dirs : options.files;
}

function encodeJSON(json, [replacer, spaces, eol]) {
  let text = JSON.stringify(json, replacer, spaces);

  if (typeof text !== 'string')
    throw new Error(`Cannot stringify JSON of type ${typeof json}.`);

  if (spaces > 0 && eol !== '\n')
    text = text.replace(/\n/g, () => eol);

  return text + eol;
}

function decodeJSON(text, reviver) {
  // UTF-16 BOM (also slices UTF-8 BOM).
  if (text.length > 0 && text.charCodeAt(0) === 0xfeff)
    text = text.substring(1);

  return JSON.parse(text, reviver);
}

function prepareOptions(options) {
  const out = {};

  for (const key of Object.keys(options)) {
    switch (key) {
      case 'replacer':
      case 'reviver':
      case 'spaces':
      case 'eol':
        continue;
    }

    out[key] = options[key];
  }

  if (out.encoding == null)
    out.encoding = 'utf8';

  return out;
}

/*
 * Expose
 */

exports.copy = copy;
exports.copySync = copySync;
exports.empty = empty;
exports.emptySync = emptySync;
exports.exists = exists;
exports.existsSync = existsSync;
exports.lstatTry = lstatTry;
exports.lstatTrySync = lstatTrySync;
exports.mkdirp = mkdirp;
exports.mkdirpSync = mkdirpSync;
exports.move = move;
exports.moveSync = moveSync;
exports.outputFile = outputFile;
exports.outputFileSync = outputFileSync;
exports.readJSON = readJSON;
exports.readJSONSync = readJSONSync;
exports.removeSync = removeSync;
exports.remove = remove;
exports.removeSync = removeSync;
exports.statTry = statTry;
exports.statTrySync = statTrySync;
exports.stats = stats;
exports.statsSync = statsSync;
exports.statsTry = statsTry;
exports.statsTrySync = statsTrySync;
exports.traverse = traverse;
exports.traverseSync = traverseSync;
exports.walk = walk;
exports.walkSync = walkSync;
exports.writeJSON = writeJSON;
exports.writeJSONSync = writeJSONSync;
