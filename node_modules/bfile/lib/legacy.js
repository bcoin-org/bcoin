/*!
 * legacy.js - legacy backend for bfile
 * Copyright (c) 2014-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bfile
 */

'use strict';

const compat = require('./compat');
const features = require('./features');
const fs = require('./modern');

/*
 * Helpers
 */

let cloned = false;

// Future proofing:
const clone = () => {
  if (!cloned) {
    fs.constants = Object.assign(Object.create(null), fs.constants);
    cloned = true;
  }
};

/*
 * Legacy
 */

if (!features.HAS_STAT_NUMBERS
    || !features.HAS_STAT_BIGINTS
    || !features.HAS_STAT_NANO) {
  fs.fstat = compat.fstat;
  fs.fstatSync = compat.fstatSync;
  fs.stat = compat.stat;
  fs.statSync = compat.statSync;
  fs.lstat = compat.lstat;
  fs.lstatSync = compat.lstatSync;
}

if (!features.HAS_COPY_FILE_IMPL) {
  clone();
  fs.constants.COPYFILE_EXCL = compat.COPYFILE_EXCL;
  fs.constants.COPYFILE_FICLONE = compat.COPYFILE_FICLONE;
  fs.constants.COPYFILE_FICLONE_FORCE = compat.COPYFILE_FICLONE_FORCE;
  fs.copyFile = compat.copyFile;
  fs.copyFileSync = compat.copyFileSync;
}

if (!features.HAS_REALPATH_NATIVE_IMPL) {
  fs.realpath = compat.realpath;
  fs.realpathSync = compat.realpathSync;
}

if (!features.HAS_PROMISES_IMPL) {
  Object.defineProperty(fs, 'promises', {
    configurable: true,
    enumerable: false,
    get() {
      return compat.promises;
    }
  });
}

if (!features.HAS_DIRENT_IMPL) {
  fs.readdir = compat.readdir;
  fs.readdirSync = compat.readdirSync;
  fs.Dirent = compat.Dirent;
}

if (!features.HAS_RW_TYPED_ARRAY) {
  fs.read = compat.read;
  fs.readSync = compat.readSync;
  fs.write = compat.write;
  fs.writeSync = compat.writeSync;
  fs.writeFile = compat.writeFile;
  fs.writeFileSync = compat.writeFileSync;
}

if (!features.HAS_RECURSIVE_MKDIR) {
  fs.mkdir = compat.mkdir;
  fs.mkdirSync = compat.mkdirSync;
}

if (!features.HAS_OPTIONAL_FLAGS) {
  fs.open = compat.open;
  fs.openSync = compat.openSync;
}

if (!features.HAS_WRITEV_IMPL) {
  fs.writev = compat.writev;
  fs.writevSync = compat.writevSync;
}

if (!features.HAS_RECURSIVE_RMDIR) {
  fs.rmdir = compat.rmdir;
  fs.rmdirSync = compat.rmdirSync;
}

if (!features.HAS_OPENDIR_IMPL) {
  fs.opendir = compat.opendir;
  fs.opendirSync = compat.opendirSync;
  fs.Dir = compat.Dir;
}

// A few things still need patching even if we have native promises.
if (features.HAS_PROMISES_IMPL && !features.HAS_OPENDIR_IMPL) {
  const getter = Object.getOwnPropertyDescriptor(fs, 'promises').get;

  const getPromises = () => {
    if (features.HAS_STABLE_PROMISES)
      return getter();

    const emit = process.emitWarning;

    process.emitWarning = () => {};

    try {
      return getter();
    } finally {
      process.emitWarning = emit;
    }
  };

  let promises = null;

  Object.defineProperty(fs, 'promises', {
    configurable: true,
    enumerable: false,
    get() {
      if (promises)
        return promises;

      promises = compat.clonePromises(getPromises());

      if (!features.HAS_STAT_BIGINTS
          || !features.HAS_STAT_NANO) {
        promises.stat = compat.promises.stat;
        compat.patchStat(promises);
      }

      if (!features.HAS_DIRENT_IMPL)
        promises.readdir = compat.promises.readdir;

      if (!features.HAS_RW_TYPED_ARRAY) {
        promises.writeFile = compat.promises.writeFile;
        compat.patchTypedArray(promises);
      }

      if (!features.HAS_RECURSIVE_MKDIR)
        promises.mkdir = compat.promises.mkdir;

      if (!features.HAS_OPTIONAL_FLAGS)
        compat.patchOpenFlags(promises);

      if (!features.HAS_WRITEV_IMPL)
        compat.patchWritev(promises);

      if (!features.HAS_RECURSIVE_RMDIR)
        promises.rmdir = compat.promises.rmdir;

      if (!features.HAS_OPENDIR_IMPL)
        promises.opendir = compat.promises.opendir;

      return promises;
    }
  });
}

/*
 * Expose
 */

module.exports = fs;
