/*!
 * compat.js - compat functions for bfile
 * Copyright (c) 2014-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bfile
 */

/* global BigInt */

'use strict';

const fs = require('fs');
const path = require('path');
const {ArgError, FSError} = require('./error');
const util = require('./util');
const {EIO, ENOTDIR} = FSError;

const {
  dirname,
  join,
  normalize
} = path;

const {
  call,
  promisify,
  fromPath,
  toBuffer
} = util;

/*
 * Constants
 */

const COPYFILE_EXCL = 1 << 0;
const COPYFILE_FICLONE = 1 << 1;
const COPYFILE_FICLONE_FORCE = 1 << 2;

/*
 * copyFile()
 */

async function copyFile(src, dest, flags) {
  if (flags == null)
    flags = 0;

  if ((flags >>> 0) !== flags)
    throw new ArgError('flags', flags, 'integer');

  const writer = fs.createWriteStream(dest, {
    flags: (flags & COPYFILE_EXCL) ? 'wx' : 'w',
    mode: (await call(fs.stat, [src])).mode
  });

  const reader = fs.createReadStream(src);

  return new Promise((resolve, reject) => {
    let called = false;
    let onError;
    let onClose;

    const cleanup = () => {
      if (called)
        return false;

      called = true;

      writer.removeListener('error', onError);
      writer.removeListener('close', onClose);

      reader.removeListener('error', onError);

      try {
        writer.destroy();
      } catch (e) {
        ;
      }

      try {
        reader.destroy();
      } catch (e) {
        ;
      }

      return true;
    };

    onError = (err) => {
      if (cleanup())
        reject(err);
    };

    onClose = () => {
      if (cleanup())
        resolve();
    };

    writer.on('error', onError);
    writer.on('close', onClose);

    reader.on('error', onError);

    try {
      reader.pipe(writer);
    } catch (e) {
      reject(e);
    }
  });
}

function copyFileSync(src, dest, flags) {
  if (flags == null)
    flags = 0;

  if ((flags >>> 0) !== flags)
    throw new ArgError('flags', flags, 'integer');

  const flag = (flags & COPYFILE_EXCL) ? 'wx' : 'w';
  const slab = Buffer.allocUnsafe(64 * 1024);

  let rfd = null;
  let stat = null;
  let wfd = null;
  let pos = 0;

  try {
    rfd = fs.openSync(src, 'r');
    stat = fs.fstatSync(rfd);
    wfd = fs.openSync(dest, flag, stat.mode);

    while (pos < stat.size) {
      const length = Math.min(stat.size - pos, slab.length);
      const bytes = fs.readSync(rfd, slab, 0, length, pos);

      if (bytes !== length)
        throw new FSError(EIO, 'read', fromPath(src));

      fs.writeSync(wfd, slab, 0, length, null);
      pos += bytes;
    }
  } finally {
    try {
      if (wfd != null)
        fs.closeSync(wfd);
    } finally {
      if (rfd != null)
        fs.closeSync(rfd);
    }
  }
}

/*
 * mkdir()
 */

function getPaths(path) {
  const paths = [];

  let dir = normalize(fromPath(path));

  for (;;) {
    paths.push(dir);

    const next = dirname(dir);

    if (next === dir)
      break;

    dir = next;
  }

  return paths.reverse();
}

async function mkdirp(dir, mode) {
  if (mode == null)
    mode = 0o777;

  if ((mode >>> 0) !== mode)
    throw new ArgError('mode', mode, 'integer');

  for (const path of getPaths(dir)) {
    try {
      const stat = await call(fs.stat, [path]);
      if (!stat.isDirectory())
        throw new FSError(ENOTDIR, 'mkdir', path);
    } catch (e) {
      if (e.code === 'ENOENT')
        await call(fs.mkdir, [path, mode]);
      else
        throw e;
    }
  }
}

function mkdirpSync(dir, mode) {
  if (mode == null)
    mode = 0o777;

  if ((mode >>> 0) !== mode)
    throw new ArgError('mode', mode, 'integer');

  for (const path of getPaths(dir)) {
    try {
      const stat = fs.statSync(path);
      if (!stat.isDirectory())
        throw new FSError(ENOTDIR, 'mkdir', path);
    } catch (e) {
      if (e.code === 'ENOENT')
        fs.mkdirSync(path, mode);
      else
        throw e;
    }
  }
}

function mkdirArgs(path, options) {
  let mode = null;
  let recursive = false;

  if (options != null) {
    if (typeof options === 'object') {
      if (options.mode != null)
        mode = options.mode;

      if (options.recursive != null)
        recursive = options.recursive;
    } else {
      mode = options;
    }
  }

  if (mode != null && (mode >>> 0) !== mode)
    throw new ArgError('mode', mode, 'integer');

  if (typeof recursive !== 'boolean')
    throw new ArgError('recursive', recursive, 'boolean');

  if (mode != null)
    return [[path, mode], recursive];

  return [[path], recursive];
}

async function mkdir(path, options) {
  const [args, recursive] = mkdirArgs(path, options);

  if (recursive)
    return mkdirp(...args);

  return call(fs.mkdir, args);
}

function mkdirSync(path, options) {
  const [args, recursive] = mkdirArgs(path, options);

  if (recursive)
    return mkdirpSync(...args);

  return fs.mkdirSync(...args);
}

/*
 * open()
 */

async function open(...args) {
  if (args[1] == null)
    args[1] = 'r';

  return call(fs.open, args);
}

function openSync(...args) {
  if (args[1] == null)
    args[1] = 'r';

  return fs.openSync(...args);
}

/*
 * read()
 */

async function read(...args) {
  args[1] = toBuffer(args[1]);
  return call(fs.read, args);
}

function readSync(...args) {
  args[1] = toBuffer(args[1]);
  return fs.readSync(...args);
}

/*
 * readdir()
 */

async function readdir(...args) {
  const [dir, options] = args;
  const withFileTypes = options && options.withFileTypes;
  const list = await call(fs.readdir, args);

  if (!withFileTypes || fs.Dirent)
    return list;

  const out = [];
  const root = fromPath(dir);

  for (const name of list) {
    const file = join(root, fromPath(name));
    const stat = await call(fs.lstat, [file]);

    out.push(new Dirent(name, stat));
  }

  return out;
}

function readdirSync(...args) {
  const [dir, options] = args;
  const withFileTypes = options && options.withFileTypes;
  const list = fs.readdirSync(...args);

  if (!withFileTypes || fs.Dirent)
    return list;

  const out = [];
  const root = fromPath(dir);

  for (const name of list) {
    const file = join(root, fromPath(name));
    const stat = fs.lstatSync(file);

    out.push(new Dirent(name, stat));
  }

  return out;
}

/**
 * Dirent
 */

class Dirent {
  constructor(name, stat) {
    this.name = name;
    this.stat = stat;
  }

  isBlockDevice() {
    return this.stat.isBlockDevice();
  }

  isCharacterDevice() {
    return this.stat.isCharacterDevice();
  }

  isDirectory() {
    return this.stat.isDirectory();
  }

  isFIFO() {
    return this.stat.isFIFO();
  }

  isFile() {
    return this.stat.isFile();
  }

  isSocket() {
    return this.stat.isSocket();
  }

  isSymbolicLink() {
    return this.stat.isSymbolicLink();
  }
}

/*
 * realpath.native()
 */

function realpath(...args) {
  return call(fs.realpath, args);
}

realpath.native = async function(...args) {
  return call(fs.realpath, args);
};

function realpathSync(...args) {
  return fs.realpathSync(...args);
}

realpathSync.native = function(...args) {
  return fs.realpathSync(...args);
};

/*
 * stat()
 */

function wrapStat(statter) {
  return async function stat(file, options) {
    return convertStat(await call(statter, [file]), options);
  };
}

function wrapStatSync(statter) {
  return function statSync(file, options) {
    return convertStat(statter(file), options);
  };
}

function convertStat(stats, options) {
  const bigint = options && options.bigint;

  if (stats.atimeMs == null) {
    stats.atimeMs = stats.atime.getTime();
    stats.mtimeMs = stats.mtime.getTime();
    stats.ctimeMs = stats.ctime.getTime();
    stats.birthtimeMs = stats.birthtime.getTime();
  }

  // eslint-disable-next-line
  if (bigint && typeof stats.atimeMs !== 'bigint') {
    if (typeof BigInt !== 'function')
      throw new Error('Bigint is not supported.');

    stats.dev = BigInt(stats.dev);
    stats.ino = BigInt(stats.ino);
    stats.mode = BigInt(stats.mode);
    stats.nlink = BigInt(stats.nlink);
    stats.uid = BigInt(stats.uid);
    stats.gid = BigInt(stats.gid);
    stats.rdev = BigInt(stats.rdev);
    stats.size = BigInt(stats.size);
    stats.blksize = BigInt(stats.blksize);
    stats.blocks = BigInt(stats.blocks);
    stats.atimeMs = BigInt(Math.floor(stats.atimeMs));
    stats.mtimeMs = BigInt(Math.floor(stats.mtimeMs));
    stats.ctimeMs = BigInt(Math.floor(stats.ctimeMs));
    stats.birthtimeMs = BigInt(Math.floor(stats.birthtimeMs));
  }

  return stats;
}

const fstat = wrapStat(fs.fstat);
const fstatSync = wrapStatSync(fs.fstatSync);
const stat = wrapStat(fs.stat);
const statSync = wrapStatSync(fs.statSync);
const lstat = wrapStat(fs.lstat);
const lstatSync = wrapStatSync(fs.lstatSync);

/*
 * write()
 */

async function write(...args) {
  if (typeof args[1] !== 'string')
    args[1] = toBuffer(args[1]);

  return call(fs.write, args);
}

function writeSync(...args) {
  if (typeof args[1] !== 'string')
    args[1] = toBuffer(args[1]);

  return fs.writeSync(...args);
}

/*
 * writeFile()
 */

async function writeFile(...args) {
  if (typeof args[1] !== 'string')
    args[1] = toBuffer(args[1]);

  return call(fs.writeFile, args);
}

function writeFileSync(...args) {
  if (typeof args[1] !== 'string')
    args[1] = toBuffer(args[1]);

  return fs.writeFileSync(...args);
}

/**
 * FileHandle
 */

class FileHandle {
  constructor(fd) {
    this._fd = fd;
  }

  getAsyncId() {
    return -1;
  }

  get fd() {
    return this._fd;
  }

  appendFile(...args) {
    return call(fs.appendFile, [this._fd, ...args]);
  }

  chmod(...args) {
    return call(fs.fchmod, [this._fd, ...args]);
  }

  chown(...args) {
    return call(fs.fchown, [this._fd, ...args]);
  }

  close() {
    return call(fs.close, [this._fd]);
  }

  datasync() {
    return call(fs.fdatasync, [this._fd]);
  }

  async read(...args) {
    return {
      bytesRead: await read(this._fd, ...args),
      buffer: args[0]
    };
  }

  readFile(...args) {
    return call(fs.readFile, [this._fd, ...args]);
  }

  stat(...args) {
    return fstat(this._fd, ...args);
  }

  sync() {
    return call(fs.fsync, [this._fd]);
  }

  truncate(...args) {
    return call(fs.ftruncate, [this._fd, ...args]);
  }

  utimes(...args) {
    return call(fs.futimes, [this._fd, ...args]);
  }

  async write(...args) {
    return {
      bytesWritten: await write(this._fd, ...args),
      buffer: args[0]
    };
  }

  writeFile(...args) {
    return writeFile(this._fd, ...args);
  }
}

/*
 * Promises
 */

const promises = {
  access: promisify(fs.access),
  appendFile: promisify(fs.appendFile),
  chmod: promisify(fs.chmod),
  chown: promisify(fs.chown),
  copyFile,
  lchmod: promisify(fs.lchmod),
  lchown: promisify(fs.lchown),
  link: promisify(fs.link),
  lstat,
  mkdir,
  mkdtemp: promisify(fs.mkdtemp),
  // eslint-disable-next-line
  open: async function _open(...args) {
    return new FileHandle(await open(...args));
  },
  readdir,
  readFile: promisify(fs.readFile),
  readlink: promisify(fs.readlink),
  realpath,
  rename: promisify(fs.rename),
  rmdir: promisify(fs.rmdir),
  stat,
  symlink: promisify(fs.symlink),
  truncate: promisify(fs.truncate),
  unlink: promisify(fs.unlink),
  utimes: promisify(fs.utimes),
  writeFile
};

/*
 * Promise Patches
 */

function clonePromises(promises) {
  return {
    access: promises.access,
    appendFile: promises.appendFile,
    chmod: promises.chmod,
    chown: promises.chown,
    copyFile: promises.copyFile,
    lchmod: promises.lchmod,
    lchown: promises.lchown,
    link: promises.link,
    lstat: promises.lstat,
    mkdir: promises.mkdir,
    mkdtemp: promises.mkdtemp,
    open: promises.open,
    readdir: promises.readdir,
    readFile: promises.readFile,
    readlink: promises.readlink,
    realpath: promises.realpath,
    rename: promises.rename,
    rmdir: promises.rmdir,
    stat: promises.stat,
    symlink: promises.symlink,
    truncate: promises.truncate,
    unlink: promises.unlink,
    utimes: promises.utimes,
    writeFile: promises.writeFile
  };
}

function patchTypedArray(promises) {
  const {open} = promises;

  // Insanity? Maybe.
  //
  // I don't like changing anything global.
  // May be worth wrapping FileHandle with
  // a new class in order to patch it.
  let inject = (handle) => {
    const FileHandle = handle.constructor;
    const proto = FileHandle.prototype;
    const {read, write, writeFile} = proto;

    if (!FileHandle.__hasPatch) {
      // eslint-disable-next-line
      proto.read = function _read(...args) {
        args[0] = toBuffer(args[0]);
        return read.call(this, ...args);
      };

      // eslint-disable-next-line
      proto.write = function _write(...args) {
        if (typeof args[0] !== 'string')
          args[0] = toBuffer(args[0]);

        return write.call(this, ...args);
      };

      // eslint-disable-next-line
      proto.writeFile = function _writeFile(...args) {
        if (typeof args[0] !== 'string')
          args[0] = toBuffer(args[0]);

        return writeFile.call(this, ...args);
      };

      FileHandle.__hasPatch = true;
    }

    inject = x => x;

    return handle;
  };

  // eslint-disable-next-line
  promises.open = async function _open(...args) {
    return inject(await open(...args));
  };
}

function patchOpenFlags(promises) {
  const {open} = promises;

  // eslint-disable-next-line
  promises.open = async function _open(...args) {
    if (args[1] == null)
      args[1] = 'r';
    return open(...args);
  };
}

/*
 * Expose
 */

exports.COPYFILE_EXCL = COPYFILE_EXCL;
exports.COPYFILE_FICLONE = COPYFILE_FICLONE;
exports.COPYFILE_FICLONE_FORCE = COPYFILE_FICLONE_FORCE;
exports.copyFile = copyFile;
exports.copyFileSync = copyFileSync;
exports.mkdir = mkdir;
exports.mkdirSync = mkdirSync;
exports.open = open;
exports.openSync = openSync;
exports.read = read;
exports.readSync = readSync;
exports.readdir = readdir;
exports.readdirSync = readdirSync;
exports.Dirent = Dirent;
exports.realpath = realpath;
exports.realpathSync = realpathSync;
exports.fstat = fstat;
exports.fstatSync = fstatSync;
exports.stat = stat;
exports.statSync = statSync;
exports.lstat = lstat;
exports.lstatSync = lstatSync;
exports.write = write;
exports.writeSync = writeSync;
exports.writeFile = writeFile;
exports.writeFileSync = writeFileSync;
exports.promises = promises;
exports.clonePromises = clonePromises;
exports.patchTypedArray = patchTypedArray;
exports.patchOpenFlags = patchOpenFlags;
