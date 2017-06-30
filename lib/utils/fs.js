/*!
 * fs.js - promisified fs module for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const fs = require('fs');
const co = require('./co');

exports.access = co.promisify(fs.access);
exports.accessSync = fs.accessSync;
exports.appendFile = co.promisify(fs.appendFile);
exports.appendFileSync = fs.appendFileSync;
exports.chmod = co.promisify(fs.chmod);
exports.chmodSync = fs.chmodSync;
exports.chown = co.promisify(fs.chown);
exports.chownSync = fs.chownSync;
exports.close = co.promisify(fs.close);
exports.closeSync = fs.closeSync;
exports.constants = fs.constants;
exports.createReadStream = fs.createReadStream;
exports.createWriteStream = fs.createWriteStream;
exports.exists = co.promisify(fs.exists);
exports.existsSync = fs.existsSync;
exports.fchmod = co.promisify(fs.fchmod);
exports.fchmodSync = fs.fchmodSync;
exports.fchown = co.promisify(fs.fchown);
exports.fchownSync = fs.fchownSync;
exports.fdatasync = co.promisify(fs.fdatasync);
exports.fdatasyncSync = fs.fdatasyncSync;
exports.fstat = co.promisify(fs.fstat);
exports.fstatSync = fs.fstatSync;
exports.fsync = co.promisify(fs.fsync);
exports.fsyncSync = fs.fsyncSync;
exports.ftruncate = co.promisify(fs.ftruncate);
exports.ftruncateSync = fs.ftruncateSync;
exports.futimes = co.promisify(fs.futimes);
exports.futimesSync = fs.futimesSync;
exports.lchmod = co.promisify(fs.lchmod);
exports.lchmodSync = fs.lchmodSync;
exports.lchown = co.promisify(fs.lchown);
exports.lchownSync = fs.lchownSync;
exports.link = co.promisify(fs.link);
exports.linkSync = fs.linkSync;
exports.lstat = co.promisify(fs.lstat);
exports.lstatSync = fs.lstatSync;
exports.mkdir = co.promisify(fs.mkdir);
exports.mkdirSync = fs.mkdirSync;
exports.mkdtemp = co.promisify(fs.mkdtemp);
exports.mkdtempSync = fs.mkdtempSync;
exports.open = co.promisify(fs.open);
exports.openSync = fs.openSync;
exports.read = co.promisify(fs.read);
exports.readSync = fs.readSync;
exports.readdir = co.promisify(fs.readdir);
exports.readdirSync = fs.readdirSync;
exports.readFile = co.promisify(fs.readFile);
exports.readFileSync = fs.readFileSync;
exports.readlink = co.promisify(fs.readlink);
exports.readlinkSync = fs.readlinkSync;
exports.realpath = co.promisify(fs.realpath);
exports.realpathSync = fs.realpathSync;
exports.rename = co.promisify(fs.rename);
exports.renameSync = fs.renameSync;
exports.rmdir = co.promisify(fs.rmdir);
exports.rmdirSync = fs.rmdirSync;
exports.stat = co.promisify(fs.stat);
exports.statSync = fs.statSync;
exports.symlink = co.promisify(fs.symlink);
exports.symlinkSync = fs.symlinkSync;
exports.truncate = co.promisify(fs.truncate);
exports.truncateSync = fs.truncateSync;
exports.unlink = co.promisify(fs.unlink);
exports.unlinkSync = fs.unlinkSync;
exports.unwatchFile = fs.unwatchFile;
exports.utimes = co.promisify(fs.utimes);
exports.utimesSync = fs.utimesSync;
exports.watch = fs.watch;
exports.watchFile = fs.watchFile;
exports.write = co.promisify(fs.write);
exports.writeSync = fs.writeSync;
exports.writeFile = co.promisify(fs.writeFile);
exports.writeFileSync = fs.writeFileSync;

exports.mkdirpSync = function mkdirpSync(dir, mode) {
  let [path, parts] = getParts(dir);

  if (mode == null)
    mode = 0o750;

  for (let part of parts) {
    path += part;

    try {
      let stat = exports.statSync(path);
      if (!stat.isDirectory())
        throw new Error('Could not create directory.');
    } catch (e) {
      if (e.code === 'ENOENT')
        exports.mkdirSync(path, mode);
      else
        throw e;
    }

    path += '/';
  }
};

exports.mkdirp = async function mkdirp(dir, mode) {
  let [path, parts] = getParts(dir);

  if (mode == null)
    mode = 0o750;

  for (let part of parts) {
    path += part;

    try {
      let stat = await exports.stat(path);
      if (!stat.isDirectory())
        throw new Error('Could not create directory.');
    } catch (e) {
      if (e.code === 'ENOENT')
        await exports.mkdir(path, mode);
      else
        throw e;
    }

    path += '/';
  }
};

function getParts(path) {
  let root = '';
  let parts;

  path = path.replace(/\\/g, '/');
  path = path.replace(/(^|\/)\.\//, '$1');
  path = path.replace(/\/+\.?$/, '');
  parts = path.split(/\/+/);

  if (process.platform === 'win32') {
    if (parts[0].indexOf(':') !== -1)
      root = parts.shift() + '/';
  }

  if (parts.length > 0) {
    if (parts[0].length === 0) {
      parts.shift();
      root = '/';
    }
  }

  return [root, parts];
}
