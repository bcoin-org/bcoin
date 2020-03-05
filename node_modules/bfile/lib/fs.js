/*!
 * fs.js - promisified fs module for bcoin
 * Copyright (c) 2014-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const fs = require('./backend');
const extra = require('./extra');
const features = require('./features');

/*
 * Extra
 */

fs.copy = extra.copy;
fs.copySync = extra.copySync;
fs.empty = extra.empty;
fs.emptySync = extra.emptySync;
fs.exists = extra.exists;
fs.existsSync = extra.existsSync;
fs.lstatTry = extra.lstatTry;
fs.lstatTrySync = extra.lstatTrySync;
fs.mkdirp = extra.mkdirp;
fs.mkdirpSync = extra.mkdirpSync;
fs.move = extra.move;
fs.moveSync = extra.moveSync;
fs.outputFile = extra.outputFile;
fs.outputFileSync = extra.outputFileSync;
fs.readJSON = extra.readJSON;
fs.readJSONSync = extra.readJSONSync;
fs.remove = extra.remove;
fs.removeSync = extra.removeSync;
fs.rimraf = extra.remove; // Compat.
fs.rimrafSync = extra.removeSync; // Compat.
fs.statTry = extra.statTry;
fs.statTrySync = extra.statTrySync;
fs.stats = extra.stats;
fs.statsSync = extra.statsSync;
fs.statsTry = extra.statsTry;
fs.statsTrySync = extra.statsTrySync;
fs.traverse = extra.traverse;
fs.traverseSync = extra.traverseSync;
fs.walk = extra.walk;
fs.walkSync = extra.walkSync;
fs.writeJSON = extra.writeJSON;
fs.writeJSONSync = extra.writeJSONSync;

/*
 * Promises
 */

if (features.USE_STABLE_PROMISES) {
  const native = fs.realpath.native;

  fs.access = fs.promises.access;
  fs.appendFile = fs.promises.appendFile;
  fs.chmod = fs.promises.chmod;
  fs.chown = fs.promises.chown;
  fs.copyFile = fs.promises.copyFile;
  fs.lchmod = fs.promises.lchmod;
  fs.lchown = fs.promises.lchown;
  fs.link = fs.promises.link;
  fs.lstat = fs.promises.lstat;
  fs.mkdir = fs.promises.mkdir;
  fs.mkdtemp = fs.promises.mkdtemp;
  fs.opendir = fs.promises.opendir;
  fs.handle = fs.promises.open;
  fs.readdir = fs.promises.readdir;
  fs.readFile = fs.promises.readFile;
  fs.readlink = fs.promises.readlink;
  fs.realpath = fs.promises.realpath;
  fs.rename = fs.promises.rename;
  fs.rmdir = fs.promises.rmdir;
  fs.stat = fs.promises.stat;
  fs.symlink = fs.promises.symlink;
  fs.truncate = fs.promises.truncate;
  fs.unlink = fs.promises.unlink;
  fs.utimes = fs.promises.utimes;
  fs.writeFile = fs.promises.writeFile;

  // fs.realpath.native does not
  // currently exist for promises.
  if (!fs.realpath.native) {
    fs.realpath = function realpath(...args) {
      return fs.promises.realpath(...args);
    };
    fs.realpath.native = native;
  }
} else {
  let compat = null;

  Object.defineProperty(fs, 'handle', {
    configurable: true,
    enumerable: false,
    get() {
      if (!compat)
        compat = require('./compat');

      return compat.promises.open;
    }
  });
}

/*
 * Info
 */

fs.features = features;
fs.unsupported = false;

/*
 * Expose
 */

module.exports = fs;
