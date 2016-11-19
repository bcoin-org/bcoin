'use strict';

var utils = require('../utils/utils');
var co = require('../utils/co');
var Locker = require('../utils/locker');
var path = require('path');
var fs = require('fs');
var promisify = co.promisify;
var fsExists = promisify(fs.exists, fs);
var fsMkdir = promisify(fs.mkdir, fs);
var fsReaddir = promisify(fs.readdir, fs);
var fsOpen = promisify(fs.open, fs);
var fsStat = promisify(fs.stat, fs);
var fsFstat = promisify(fs.fstat, fs);
var fsWrite = promisify(fs.write, fs);
var fsRead = promisify(fs.read, fs);
var fsClose = promisify(fs.close, fs);
var fsFtruncate = promisify(fs.ftruncate, fs);
var fsFsync = promisify(fs.fsync, fs);
var fsUnlink = promisify(fs.unlink, fs);
var fsExists;
var assert = utils.assert;
var murmur3 = require('../utils/murmur3');

var MAX_SIZE = 512 << 20;
var MAX_FILES = 64;
var MAX_ENTRY = 12 << 20;

/**
 * Flat
 * @constructor
 */

function Flat(db) {
  if (!(this instanceof Flat))
    return new Flat(db);

  this.dir = path.resolve(db.location, '..');
  this.dir = path.resolve(this.dir, 'blocks');
  this.locker = new Locker();

  this.fileIndex = -1;
  this.current = null;
  this.files = {};
  this.openFiles = [];
  this.indexes = [];
}

Flat.prototype.hash = function hash(data) {
  return murmur3(data, 0xdeedbeef);
};

Flat.prototype.open = co(function* open() {
  var index = -1;
  var i, list, name;

  if (!(yield fsExists(this.dir)))
    yield fsMkdir(this.dir, 493);

  list = yield fsReaddir(this.dir);

  for (i = 0; i < list.length; i++) {
    name = list[i];

    if (!/^\d{10}$/.test(name))
      continue;

    name = parseInt(name, 10);

    utils.binaryInsert(this.indexes, name, cmp);

    if (name > index)
      index = name;
  }

  if (index === -1) {
    yield this.allocate();
    return;
  }

  this.fileIndex = index;
  this.current = yield this.openFile(index);
});

Flat.prototype.close = co(function* close() {
  var unlock = yield this.locker.lock();
  try {
    return yield this._close();
  } finally {
    unlock();
  }
});

Flat.prototype._close = co(function* close() {
  var i, index, file;

  for (i = this.openFiles.length - 1; i >= 0; i--) {
    index = this.openFiles[i];
    file = this.files[index];
    assert(file);
    yield this._closeFile(file.index);
  }

  assert(this.current === null);
  assert(this.openFiles.length === 0);

  this.fileIndex = -1;
  this.indexes.length = 0;
});

Flat.prototype.name = function name(index) {
  return path.resolve(this.dir, utils.pad32(index));
};

Flat.prototype.openFile = co(function* openFile(index) {
  var unlock = yield this.locker.lock();
  try {
    return yield this._openFile(index);
  } finally {
    unlock();
  }
});

Flat.prototype._openFile = co(function* _openFile(index) {
  var file = this.files[index];
  var name, fd, stat;

  if (file)
    return file;

  name = this.name(index);

  fd = yield fsOpen(name, 'a+');
  stat = yield fsFstat(fd);

  file = new File(fd, index, stat.size);

  this.files[index] = file;
  utils.binaryInsert(this.openFiles, index, cmp);

  yield this.evict(index);

  return file;
});

Flat.prototype.closeFile = co(function* closeFile(index) {
  var unlock = yield this.locker.lock();
  try {
    assert(index !== this.current.index);
    return yield this._closeFile(index);
  } finally {
    unlock();
  }
});

Flat.prototype._closeFile = co(function* _closeFile(index) {
  var file = this.files[index];
  var result;

  if (!file)
    return;

  yield fsClose(file.fd);

  result = utils.binaryRemove(this.openFiles, index, cmp);
  assert(result);

  delete this.files[index];

  if (file === this.current)
    this.current = null;
});

Flat.prototype.remove = co(function* remove(index) {
  var unlock = yield this.locker.lock();
  try {
    return yield this._remove(index);
  } finally {
    unlock();
  }
});

Flat.prototype._remove = co(function* remove(index) {
  var result;

  assert(index != null);

  if (!this.files[index])
    return;

  yield this._closeFile(index);
  yield fsUnlink(this.name(index));

  result = utils.binaryRemove(this.indexes, index, cmp);
  assert(result);

  if (!this.current) {
    index = this.indexes[this.indexes.length - 1];
    assert(index != null);
    this.current = yield this._openFile(index);
  }
});

Flat.prototype.allocate = co(function* allocate() {
  var index = this.fileIndex + 1;
  var fd = yield fsOpen(this.name(index), 'a+');
  var file = new File(fd, index, 0);

  this.files[index] = file;
  this.current = file;
  this.fileIndex++;

  utils.binaryInsert(this.openFiles, index, cmp);
  yield this.evict(-1);
});

Flat.prototype.evict = co(function* evict(not) {
  var i = 0;
  var index, file;

  if (this.openFiles.length <= MAX_FILES)
    return;

  for (;;) {
    assert(i < this.openFiles.length);

    index = this.openFiles[i];

    if (this.current) {
      if (index !== not && index !== this.current.index)
        break;
    }

    i++;
  }

  index = this.openFiles[i];
  file = this.files[index];
  assert(file);

  yield fsClose(file.fd);

  this.openFiles.splice(i, 1);
  delete this.files[index];
});

Flat.prototype.write = co(function* write(data) {
  var unlock = yield this.locker.lock();
  try {
    return yield this._write(data);
  } finally {
    unlock();
  }
});

Flat.prototype._write = co(function* write(data) {
  var pos, fd, size, chk;
  var buf = new Buffer(4);
  var len = 4 + data.length + 4;

  if (data.length > MAX_ENTRY)
    throw new Error('Size too large.');

  if (this.current.pos + len > MAX_SIZE) {
    yield this.sync();
    yield this.allocate();
  }

  pos = this.current.pos;
  fd = this.current.fd;

  buf.writeUInt32LE(data.length, 0, true);
  yield fsWrite(fd, buf, 0, 4, pos);

  yield fsWrite(fd, data, 0, data.length, pos + 4);

  buf.writeUInt32LE(this.hash(data), 0, true);
  yield fsWrite(fd, buf, 0, 4, pos + 4 + data.length);

  this.current.pos += len;

  return new FileEntry(this.current.index, pos, data.length);
});

Flat.prototype.read = co(function* read(index, offset) {
  var file = yield this.openFile(index);
  var buf = new Buffer(4);
  var size, data, chk, err;

  if (offset + 8 > file.pos)
    throw new Error('Read is out of bounds.');

  yield fsRead(file.fd, buf, 0, 4, offset);
  size = buf.readUInt32LE(0, true);

  if (size > MAX_ENTRY)
    throw new Error('Size too large.');

  if (offset + 4 + size + 4 > file.pos)
    throw new Error('Read is out of bounds.');

  data = new Buffer(size);
  yield fsRead(file.fd, data, 0, data.length, offset + 4);

  yield fsRead(file.fd, buf, 0, 4, offset + 4 + data.length);
  chk = buf.readUInt32LE(0, true);

  if (this.hash(data) !== chk) {
    err = new Error('Checksum mismatch.');
    err.type = 'ChecksumMismatch';
    throw err;
  }

  return data;
});

Flat.prototype.sync = co(function* sync() {
  yield fsFsync(this.current.fd);
});

/*
 * File
 * @constructor
 */

function File(fd, index, pos) {
  this.fd = fd;
  this.index = index;
  this.pos = pos;
}

/*
 * FileEntry
 * @constructor
 */

function FileEntry(index, offset, size) {
  this.index = index;
  this.offset = offset;
  this.size = size;
}

FileEntry.prototype.toRaw = function toRaw() {
  var data = new Buffer(12);
  data.writeUInt32LE(this.index, 0, true);
  data.writeUInt32LE(this.offset, 4, true);
  data.writeUInt32LE(this.size, 8, true);
  return data;
};

FileEntry.fromRaw = function fromRaw(data) {
  var entry = new FileEntry(0, 0, 0);
  entry.index = data.readUInt32LE(0, true);
  entry.offset = data.readUInt32LE(4, true);
  entry.size = data.readUInt32LE(8, true);
  return entry;
};

/*
 * Helpers
 */

function cmp(a, b) {
  return a - b;
}

fsExists = co(function* fsExists(name) {
  var stat;

  try {
    stat = yield fsStat(name);
  } catch (e) {
    if (e.code === 'ENOENT')
      return false;
    throw e;
  }

  if (!stat.isDirectory())
    throw new Error('File is not a directory.');

  return true;
});

/*
 * Expose
 */

exports = Flat;
exports.FileEntry = FileEntry;

module.exports = exports;
