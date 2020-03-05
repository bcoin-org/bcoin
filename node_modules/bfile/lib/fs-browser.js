/*!
 * fs-browser.js - promisified fs module
 * Copyright (c) 2014-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bfile
 */

'use strict';

const {FSError} = require('./error');
const {ENOENT, EBADF} = FSError;

/*
 * Constants
 */

const constants = {
  UV_FS_SYMLINK_DIR: 1,
  UV_FS_SYMLINK_JUNCTION: 2,
  O_RDONLY: 0,
  O_WRONLY: 1,
  O_RDWR: 2,
  UV_DIRENT_UNKNOWN: 0,
  UV_DIRENT_FILE: 1,
  UV_DIRENT_DIR: 2,
  UV_DIRENT_LINK: 3,
  UV_DIRENT_FIFO: 4,
  UV_DIRENT_SOCKET: 5,
  UV_DIRENT_CHAR: 6,
  UV_DIRENT_BLOCK: 7,
  S_IFMT: 61440,
  S_IFREG: 32768,
  S_IFDIR: 16384,
  S_IFCHR: 8192,
  S_IFBLK: 24576,
  S_IFIFO: 4096,
  S_IFLNK: 40960,
  S_IFSOCK: 49152,
  O_CREAT: 64,
  O_EXCL: 128,
  O_NOCTTY: 256,
  O_TRUNC: 512,
  O_APPEND: 1024,
  O_DIRECTORY: 65536,
  O_NOATIME: 262144,
  O_NOFOLLOW: 131072,
  O_SYNC: 1052672,
  O_DSYNC: 4096,
  O_DIRECT: 16384,
  O_NONBLOCK: 2048,
  S_IRWXU: 448,
  S_IRUSR: 256,
  S_IWUSR: 128,
  S_IXUSR: 64,
  S_IRWXG: 56,
  S_IRGRP: 32,
  S_IWGRP: 16,
  S_IXGRP: 8,
  S_IRWXO: 7,
  S_IROTH: 4,
  S_IWOTH: 2,
  S_IXOTH: 1,
  F_OK: 0,
  R_OK: 4,
  W_OK: 2,
  X_OK: 1,
  UV_FS_COPYFILE_EXCL: 1,
  COPYFILE_EXCL: 1,
  UV_FS_COPYFILE_FICLONE: 2,
  COPYFILE_FICLONE: 2,
  UV_FS_COPYFILE_FICLONE_FORCE: 4,
  COPYFILE_FICLONE_FORCE: 4
};

/*
 * Errors
 */

function enoent(syscall) {
  return async (path) => {
    throw new FSError(ENOENT, syscall, path);
  };
}

function enoentSync(syscall) {
  return (path) => {
    throw new FSError(ENOENT, syscall, path);
  };
}

function ebadf(syscall) {
  return async () => {
    throw new FSError(EBADF, syscall);
  };
}

function ebadfSync(syscall) {
  return () => {
    throw new FSError(EBADF, syscall);
  };
}

function emit(handler, desc, syscall) {
  setTimeout(() => {
    handler(new FSError(desc, syscall));
  }, 1);
}

/*
 * Noop
 */

async function noop() {}

function noopSync() {}

/*
 * Streams
 */

const readStream = {
  emit: noopSync,
  on: (event, handler) => {
    if (event === 'error')
      emit(handler, ENOENT, 'stat');
  },
  once: (event, handler) => {
    if (event === 'error')
      emit(handler, ENOENT, 'stat');
  },
  addListener: (event, handler) => {
    if (event === 'error')
      emit(handler, ENOENT, 'stat');
  },
  off: noopSync,
  removeListener: noopSync,
  removeAllListeners: noopSync,
  listeners: () => [],
  listenerCount: () => 0,
  readable: true,
  writable: false,
  pipe: enoentSync('stat'),
  write: noopSync,
  end: noopSync,
  close: noopSync,
  destroy: noopSync
};

const writeStream = {
  emit: noopSync,
  on: noopSync,
  once: noopSync,
  addListener: noopSync,
  off: noopSync,
  removeListener: noopSync,
  removeAllListeners: noopSync,
  listeners: () => [],
  listenerCount: () => 0,
  readable: false,
  writable: true,
  write: () => true,
  end: () => true,
  close: noopSync,
  destroy: noopSync
};

/*
 * Expose
 */

exports.access = enoent('stat');
exports.accessSync = enoentSync('stat');
exports.appendFile = enoent('open');
exports.appendFileSync = enoentSync('open');
exports.chmod = noop;
exports.chmodSync = noopSync;
exports.chown = noop;
exports.chownSync = noopSync;
exports.close = ebadf('close');
exports.closeSync = ebadfSync('close');
exports.constants = constants;
exports.copyFile = noop;
exports.copyFileSync = noopSync;
exports.createReadStream = () => readStream;
exports.createWriteStream = () => writeStream;
exports.exists = null;
exports.existsSync = null;
exports.fchmod = ebadf('fchmod');
exports.fchmodSync = ebadfSync('fchmod');
exports.fchown = ebadf('fchown');
exports.fchownSync = ebadfSync('fchown');
exports.fdatasync = ebadf('fdatasync');
exports.fdatasyncSync = ebadfSync('fdatasync');
exports.fstat = ebadf('fstat');
exports.fstatSync = ebadfSync('fstat');
exports.fsync = ebadf('fsync');
exports.fsyncSync = ebadfSync('fsync');
exports.ftruncate = ebadf('ftruncate');
exports.ftruncateSync = ebadfSync('ftruncate');
exports.futimes = ebadf('futimes');
exports.futimesSync = ebadfSync('futimes');
exports.lchmod = noop;
exports.lchmodSync = noopSync;
exports.lchown = noop;
exports.lchownSync = noopSync;
exports.link = noop;
exports.linkSync = noopSync;
exports.lstat = enoent('lstat');
exports.lstatSync = enoentSync('lstat');
exports.mkdir = noop;
exports.mkdirSync = noopSync;
exports.mkdtemp = async () => `/tmp/${Math.random().toString(36)}`;
exports.mkdtempSync = () => `/tmp/${Math.random().toString(36)}`;
exports.open = enoent('open');
exports.openSync = enoentSync('open');
exports.opendir = enoent('opendir');
exports.opendirSync = enoentSync('opendir');
exports.read = ebadf('read');
exports.readSync = ebadfSync('read');
exports.readdir = enoent('readdir');
exports.readdirSync = enoentSync('readdir');
exports.readFile = enoent('open');
exports.readFileSync = enoentSync('open');
exports.readlink = enoent('readlink');
exports.readlinkSync = enoentSync('readlink');
exports.realpath = enoent('stat');
exports.realpath.native = enoent('stat');
exports.realpathSync = enoentSync('stat');
exports.realpathSync.native = enoentSync('stat');
exports.rename = noop;
exports.renameSync = noopSync;
exports.rmdir = noop;
exports.rmdirSync = noopSync;
exports.stat = enoent('stat');
exports.statSync = enoentSync('stat');
exports.symlink = noop;
exports.symlinkSync = noopSync;
exports.truncate = noop;
exports.truncateSync = noopSync;
exports.unlink = noop;
exports.unlinkSync = noopSync;
exports.unwatchFile = noopSync;
exports.utimes = noop;
exports.utimesSync = noopSync;
exports.watch = () => readStream;
exports.watchFile = noopSync;
exports.write = ebadf('write');
exports.writeSync = ebadfSync('write');
exports.writeFile = noop;
exports.writeFileSync = noopSync;
exports.writev = ebadf('writev');
exports.writevSync = ebadfSync('writev');

exports.F_OK = exports.constants.F_OK || 0;
exports.R_OK = exports.constants.R_OK || 0;
exports.W_OK = exports.constants.W_OK || 0;
exports.X_OK = exports.constants.X_OK || 0;

exports.Dir = class Dir {};
exports.Dirent = class Dirent {};
exports.Stats = class Stats {};
exports.ReadStream = class ReadStream {};
exports.WriteStream = class WriteStream {};
exports.FileReadStream = class FileReadStream {};
exports.FileWriteStream = class FileWriteStream {};

exports.promises = exports;

exports.copy = noop;
exports.copySync = noopSync;
exports.empty = noop;
exports.emptySync = noopSync;
exports.exists = async () => false;
exports.existsSync = () => false;
exports.lstatTry = () => null;
exports.lstatTrySync = async () => null;
exports.mkdirp = noop;
exports.mkdirpSync = noopSync;
exports.move = noop;
exports.moveSync = noopSync;
exports.outputFile = noop;
exports.outputFileSync = noopSync;
exports.readJSON = enoent('open');
exports.readJSONSync = enoentSync('open');
exports.remove = noop;
exports.removeSync = noopSync;
exports.rimraf = noop; // Compat.
exports.rimrafSync = noopSync;
exports.statTry = async () => null;
exports.statTrySync = () => null;
exports.stats = enoent('stat');
exports.statsSync = enoentSync('stat');
exports.statsTry = async () => null;
exports.statsTrySync = () => null;
exports.traverse = async () => undefined;
exports.traverseSync = () => undefined;
exports.walk = () => [];
exports.walkSync = () => [];
exports.writeJSON = noop;
exports.writeJSONSync = noopSync;

exports.handle = exports.open;

exports.features = {
  VERSION: 0,
  HAS_STAT_NUMBERS: false,
  HAS_COPY_FILE: false,
  HAS_COPY_FILE_IMPL: false,
  HAS_REALPATH_NATIVE: false,
  HAS_REALPATH_NATIVE_IMPL: false,
  HAS_RW_READY: false,
  HAS_WATCHER_CLOSE: false,
  HAS_PROMISES: false,
  HAS_PROMISES_IMPL: false,
  HAS_STAT_BIGINTS: false,
  HAS_DEPRECATED_LCHOWN: false,
  HAS_DIRENT: false,
  HAS_DIRENT_IMPL: false,
  HAS_RW_TYPED_ARRAY: false,
  HAS_RECURSIVE_MKDIR: false,
  HAS_OPTIONAL_FLAGS: false,
  HAS_WRITE_PENDING: false,
  HAS_STABLE_PROMISES: false,
  USE_STABLE_PROMISES: false,
  HAS_WRITEV: false,
  HAS_WRITEV_IMPL: false,
  HAS_STAT_NANO: false,
  HAS_RECURSIVE_RMDIR: false,
  HAS_OPENDIR: false,
  HAS_OPENDIR_IMPL: false,
  HAS_ALL: false
};

exports.unsupported = true;
