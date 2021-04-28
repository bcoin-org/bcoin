/*!
 * features.js - feature detection for bfile
 * Copyright (c) 2014-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/file
 */

'use strict';

const fs = require('fs');

/*
 * Features
 */

const hasOwnProperty = Object.prototype.hasOwnProperty;
const parts = process.version.split(/[^\d]/);
const version = (0
  + (parts[1] & 0xff) * 0x10000
  + (parts[2] & 0xff) * 0x00100
  + (parts[3] & 0xff) * 0x00001);

// fs.Stats got millisecond times in 8.1.0.
let HAS_STAT_NUMBERS = version >= 0x080100;

// fs.copyFile{,Sync} was added in 8.5.0.
let HAS_COPY_FILE = version >= 0x080500;
let HAS_COPY_FILE_IMPL = typeof fs.copyFile === 'function';

// fs.realpath{,Sync}.native was added in 9.2.0.
let HAS_REALPATH_NATIVE = version >= 0x090200;
let HAS_REALPATH_NATIVE_IMPL = typeof fs.realpath.native === 'function';

// fs.{Read,Write}Stream got a `ready` event in 9.11.0.
let HAS_RW_READY = version >= 0x090b00;

// fs.FSWatcher got a `close` event in 10.0.0.
let HAS_WATCHER_CLOSE = version >= 0x0a0000;

// Experimental promise support was added in 10.0.0.
let HAS_PROMISES = version >= 0x0a0000;
let HAS_PROMISES_IMPL = hasOwnProperty.call(fs, 'promises');

// fs.{,l,f}stat{,Sync} got an options parameter to allow for bigints in 10.5.0.
let HAS_STAT_BIGINTS = version >= 0x0a0500;

// fs.lchown{,Sync} is no longer deprecated as of 10.6.0.
let HAS_DEPRECATED_LCHOWN = version <= 0x0a0600;

// fs.readdir and fs.readdirSync got a `withFileTypes` option in 10.10.0.
let HAS_DIRENT = version >= 0x0a0a00;
let HAS_DIRENT_IMPL = typeof fs.Dirent === 'function';

// fs.read{,Sync},fs.write{,File}{,Sync} have typed array support as of 10.10.0.
let HAS_RW_TYPED_ARRAY = version >= 0x0a0a00;

// fs.mkdir{,Sync} got an options parameter to allow for recursion in 10.12.0.
let HAS_RECURSIVE_MKDIR = version >= 0x0a0c00;

// The flags parameter is optional for fs.open{,Sync} as of 11.1.0.
let HAS_OPTIONAL_FLAGS = version >= 0x0b0100;

// fs.WriteStream got a `pending` property in 11.2.0.
let HAS_WRITE_PENDING = version >= 0x0b0200;

// Promises are considered stable as of 11.14.0.
let HAS_STABLE_PROMISES = version >= 0x0b0e00;

// Whether to actually use stable promises.
let USE_STABLE_PROMISES = HAS_STABLE_PROMISES
                       && process.env.BFILE_USE_STABLE === '1';

// fs.writev{,Sync} was added in 12.9.0.
let HAS_WRITEV = version >= 0x0c0900;
let HAS_WRITEV_IMPL = typeof fs.writev === 'function';

// Stats objects have nanosecond precision as of 12.10.0.
let HAS_STAT_NANO = version >= 0x0c0a00;

// fs.rmdir{,Sync} got an options parameter to allow for recursion in 12.10.0.
let HAS_RECURSIVE_RMDIR = version >= 0x0c0a00;

// fs.opendir{,Sync} are present as of 12.12.0.
let HAS_OPENDIR = version >= 0x0c0c00;
let HAS_OPENDIR_IMPL = typeof fs.opendir === 'function';

// The current highest modern version (12.12.0).
let HAS_ALL = HAS_OPENDIR
           && HAS_COPY_FILE_IMPL
           && HAS_REALPATH_NATIVE_IMPL
           && HAS_PROMISES_IMPL
           && HAS_DIRENT_IMPL
           && HAS_WRITEV_IMPL
           && HAS_OPENDIR_IMPL;

// Force stable promises with an env variable.
if (process.env.BFILE_FORCE_STABLE === '1' && HAS_PROMISES_IMPL)
  USE_STABLE_PROMISES = true;

// Force compat mode with an env variable.
if (process.env.BFILE_FORCE_COMPAT === '1') {
  HAS_STAT_NUMBERS = false;
  HAS_COPY_FILE = false;
  HAS_COPY_FILE_IMPL = false;
  HAS_REALPATH_NATIVE = false;
  HAS_REALPATH_NATIVE_IMPL = false;
  HAS_RW_READY = false;
  HAS_WATCHER_CLOSE = false;
  HAS_PROMISES = false;
  HAS_PROMISES_IMPL = false;
  HAS_STAT_BIGINTS = false;
  HAS_DEPRECATED_LCHOWN = false;
  HAS_DIRENT = false;
  HAS_DIRENT_IMPL = false;
  HAS_RW_TYPED_ARRAY = false;
  HAS_RECURSIVE_MKDIR = false;
  HAS_OPTIONAL_FLAGS = false;
  HAS_WRITE_PENDING = false;
  HAS_STABLE_PROMISES = false;
  USE_STABLE_PROMISES = false;
  HAS_WRITEV = false;
  HAS_WRITEV_IMPL = false;
  HAS_STAT_NANO = false;
  HAS_RECURSIVE_RMDIR = false;
  HAS_OPENDIR = false;
  HAS_OPENDIR_IMPL = false;
  HAS_ALL = false;
}

/*
 * Expose
 */

exports.VERSION = version;
exports.HAS_STAT_NUMBERS = HAS_STAT_NUMBERS;
exports.HAS_COPY_FILE = HAS_COPY_FILE;
exports.HAS_COPY_FILE_IMPL = HAS_COPY_FILE_IMPL;
exports.HAS_REALPATH_NATIVE = HAS_REALPATH_NATIVE;
exports.HAS_REALPATH_NATIVE_IMPL = HAS_REALPATH_NATIVE_IMPL;
exports.HAS_RW_READY = HAS_RW_READY;
exports.HAS_WATCHER_CLOSE = HAS_WATCHER_CLOSE;
exports.HAS_PROMISES = HAS_PROMISES;
exports.HAS_PROMISES_IMPL = HAS_PROMISES_IMPL;
exports.HAS_STAT_BIGINTS = HAS_STAT_BIGINTS;
exports.HAS_DEPRECATED_LCHOWN = HAS_DEPRECATED_LCHOWN;
exports.HAS_DIRENT = HAS_DIRENT;
exports.HAS_DIRENT_IMPL = HAS_DIRENT_IMPL;
exports.HAS_RW_TYPED_ARRAY = HAS_RW_TYPED_ARRAY;
exports.HAS_RECURSIVE_MKDIR = HAS_RECURSIVE_MKDIR;
exports.HAS_OPTIONAL_FLAGS = HAS_OPTIONAL_FLAGS;
exports.HAS_WRITE_PENDING = HAS_WRITE_PENDING;
exports.HAS_STABLE_PROMISES = HAS_STABLE_PROMISES;
exports.USE_STABLE_PROMISES = USE_STABLE_PROMISES;
exports.HAS_WRITEV = HAS_WRITEV;
exports.HAS_WRITEV_IMPL = HAS_WRITEV_IMPL;
exports.HAS_STAT_NANO = HAS_STAT_NANO;
exports.HAS_RECURSIVE_RMDIR = HAS_RECURSIVE_RMDIR;
exports.HAS_OPENDIR = HAS_OPENDIR;
exports.HAS_OPENDIR_IMPL = HAS_OPENDIR_IMPL;
exports.HAS_ALL = HAS_ALL;
