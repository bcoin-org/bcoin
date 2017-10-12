'use strict';

const assert = require('assert');
const path = require('path');
const fs = require('../utils/fs');
const util = require('../utils/util');
const List = require('../utils/list');

const MAX_SIZE = 512 << 20;
const MAX_ENTRY = -1 >>> 0;

/**
 * Flat
 * @constructor
 */

function Flat(location, prefix = 'b', magic = 0, maxFiles = 64) {
  if (!(this instanceof Flat))
    return new Flat(location, prefix, magic);

  assert(typeof location === 'string');
  assert(typeof prefix === 'string');
  assert((magic >>> 0) === magic);
  assert((maxFiles >>> 0) === maxFiles);

  // Location of the data directory.
  this.location = location;

  // File prefix.
  this.prefix = prefix;

  // Network magic number.
  this.magic = magic;

  // Maximum open files.
  this.maxFiles = maxFiles;

  // All files.
  this.files = [];

  // Opened file map.
  this.opened = new FileList();

  // Current file.
  this.file = null;
}

Flat.prototype.open = async function open() {
  assert(!this.file, 'Already open.');

  if (!await fs.exists(this.location))
    await fs.mkdir(this.location, 0o750);

  const files = await fs.readdir(this.location);

  for (const file of files) {
    const index = parseIndex(file, this.prefix);

    if (index === -1)
      continue;

    const stat = await fs.stat(this.name(index));

    while (index >= this.files.length)
      this.files.push(null);

    this.files[index] = new File(0, index, stat.size);
  }

  if (this.files.length === 0) {
    await this.allocate();
    return;
  }

  this.file = await this.openFile(this.files.length - 1);
};

Flat.prototype.close = async function close() {
  assert(this.file, 'Already closed.');

  for (const index of this.opened.keys())
    await this.closeFile(index);

  assert(this.file === null);
  assert(this.opened.size() === 0);

  this.files.length = 0;
};

Flat.prototype.name = function name(index) {
  assert((index >>> 0) === index);
  return path.resolve(this.location, this.prefix + util.pad32(index));
};

Flat.prototype.openFile = async function openFile(index) {
  const cache = this.opened.get(index);

  if (cache) {
    await this.evict(index);
    return cache;
  }

  if (index >= this.files.length)
    throw new Error('File was removed.');

  const file = this.files[index];

  if (!file)
    throw new Error('File does not exist.');

  const name = this.name(index);

  file.fd = await fs.open(name, 'a+');

  this.opened.add(file);

  await this.evict(index);

  return file;
};

Flat.prototype.closeFile = async function closeFile(index) {
  const file = this.opened.get(index);

  if (!file)
    return;

  await fs.fsync(file.fd);
  await fs.close(file.fd);

  this.opened.delete(file);

  file.fd = -1;

  if (file === this.file)
    this.file = null;
};

Flat.prototype.remove = async function remove(index) {
  assert((index >>> 0) === index);

  if (index >= this.files.length)
    return;

  await this.closeFile(index);

  try {
    await fs.unlink(this.name(index));
  } catch (e) {
    if (e.code === 'ENOENT')
      return;
    throw e;
  }

  this.files[index] = null;

  if (index === this.files.length - 1)
    this.files.pop();

  if (!this.file) {
    if (this.files.length === 0) {
      await this.allocate();
      return;
    }
    this.file = await this.openFile(this.files.length - 1);
  }
};

Flat.prototype.allocate = async function allocate() {
  const index = this.files.length;
  const fd = await fs.open(this.name(index), 'a+');
  const file = new File(fd, index, 0);

  this.files.push(file);
  this.opened.add(file);
  this.file = file;

  await this.evict();

  return file;
};

Flat.prototype.evict = async function evict(ignore = -1) {
  let size = this.opened.size();

  if (size <= this.maxFiles)
    return;

  const stale = [];

  for (let file = this.opened.head(); file; file = file.next) {
    if (ignore !== -1 && file.index === ignore)
      continue;

    if (this.file && file.index === this.file.index)
      continue;

    if (file.reads > 0)
      continue;

    stale.push(file);
    size -= 1;

    if (size === this.maxFiles)
      break;
  }

  for (const file of stale)
    this.opened.delete(file);

  for (const file of stale) {
    await fs.fsync(file.fd);
    await fs.close(file.fd);
    file.fd = -1;
  }
};

Flat.prototype.write = async function write(data) {
  assert(this.file, 'No files open.');

  const size = data.length + 12;

  if (size > MAX_ENTRY)
    throw new Error('Size too large.');

  let alloc = false;

  if (this.file.pos + size > MAX_SIZE) {
    if (size <= MAX_SIZE) {
      await this.sync();
      await this.allocate();
    } else {
      alloc = true;
    }
  }

  const {pos, fd, index} = this.file;
  const buf = Buffer.allocUnsafe(4);
  const crc = new CRC32();

  let offset = pos;

  // Network magic
  buf.writeUInt32LE(this.magic, 0, true);
  crc.update(buf);
  offset += await pwrite(fd, buf, offset);

  // Block Length
  buf.writeUInt32LE(data.length, 0, true);
  crc.update(buf);
  offset += await pwrite(fd, buf, offset);

  // Block
  offset += await pwrite(fd, data, offset);
  crc.update(data);

  // Checksum
  buf.writeUInt32LE(crc.final(), 0, true);
  offset += await pwrite(fd, buf, offset);

  this.file.pos = offset;

  if (alloc) {
    await this.sync();
    await this.allocate();
  }

  return new FileEntry(index, pos, data.length);
};

Flat.prototype.read = async function read(entry) {
  const {index, offset, size} = entry;
  const file = await this.openFile(index);
  try {
    file.reads += 1;
    return await this._read(file, offset, size);
  } finally {
    file.reads -= 1;
  }
};

Flat.prototype._read = async function _read(file, offset, size) {
  const {fd, pos} = file;

  if (size + 12 > MAX_ENTRY)
    throw new Error('Size too large.');

  if (offset + size + 12 > pos)
    throw new Error('Read is out of bounds.');

  const buf = Buffer.allocUnsafe(4);
  const crc = new CRC32();

  // Network magic
  offset += await pread(fd, buf, offset);
  crc.update(buf);

  const magic = buf.readUInt32LE(0, true);

  if (magic !== this.magic)
    throw new Error(`Wrong magic number: ${magic}.`);

  // Size
  offset += await pread(fd, buf, offset);
  crc.update(buf);

  const len = buf.readUInt32LE(0, true);

  if (len !== size)
    throw new Error('Incorrect size.');

  // Block Data
  const data = Buffer.allocUnsafe(size);
  offset += await pread(fd, data, offset);
  crc.update(data);

  // Checksum
  offset += await pread(fd, buf, offset);

  const chk = buf.readUInt32LE(0, true);

  if (crc.final() !== chk) {
    const err = new Error('Checksum mismatch.');
    err.type = 'ChecksumMismatch';
    err.code = 'ERR_CHECKSUM_MISMATCH';
    throw err;
  }

  return data;
};

Flat.prototype.sync = async function sync() {
  assert(this.file, 'No files open.');
  return fs.fsync(this.file.fd);
};

/**
 * FileList
 * @constructor
 */

function FileList() {
  this.map = new Map();
  this.list = new List();
}

FileList.prototype.has = function has(index) {
  assert((index >>> 0) === index);
  return this.map.has(index);
};

FileList.prototype.get = function get(index) {
  assert((index >>> 0) === index);

  const item = this.map.get(index);

  if (!item)
    return null;

  assert(this.list.remove(item));
  assert(this.list.push(item));

  return item;
};

FileList.prototype.entries = function entries() {
  return this.map.entries();
};

FileList.prototype.keys = function keys() {
  return this.map.values();
};

FileList.prototype.values = function values() {
  return this.map.values();
};

FileList.prototype.add = function add(file) {
  assert(file);
  assert(!this.map.has(file.index));
  this.map.set(file.index, file);
  assert(this.list.push(file));
};

FileList.prototype.delete = function(file) {
  assert(file);
  assert(this.map.has(file.index));
  this.map.delete(file.index);
  assert(this.list.remove(file));
};

FileList.prototype.head = function head() {
  return this.list.head;
};

FileList.prototype.tail = function tail() {
  return this.list.tail;
};

FileList.prototype.size = function size() {
  return this.list.size;
};

FileList.prototype.clear = function clear() {
  this.map.clear();
  this.list.reset();
};

/**
 * File
 * @constructor
 */

function File(fd, index, pos) {
  this.fd = fd;
  this.index = index;
  this.pos = pos;
  this.prev = null;
  this.next = null;
}

/**
 * FileEntry
 * @constructor
 */

function FileEntry(index, offset, size) {
  this.index = index;
  this.offset = offset;
  this.size = size;
}

FileEntry.prototype.toRaw = function toRaw() {
  const data = Buffer.allocUnsafe(12);
  data.writeUInt32LE(this.index, 0, true);
  data.writeUInt32LE(this.offset, 4, true);
  data.writeUInt32LE(this.size, 8, true);
  return data;
};

FileEntry.fromRaw = function fromRaw(data) {
  assert(data.length >= 12);
  const index = data.readUInt32LE(0, true);
  const offset = data.readUInt32LE(4, true);
  const size = data.readUInt32LE(8, true);
  return new FileEntry(index, offset, size);
};

/*
 * CRC32
 */

const TABLE = (() => {
  const tbl = new Array(256);

  for (let i = 0; i < 256; i++) {
    let n = i;
    for (let j = 0; j < 8; j++) {
      if (n & 1)
        n = (n >>> 1) ^ 0xedb88320;
      else
        n >>>= 1;
    }
    tbl[i] = n >>> 0;
  }

  return tbl;
})();

function CRC32() {
  this.hash = 0xffffffff;
}

CRC32.prototype.update = function update(data) {
  const left = data.length % 4;
  const len = data.length - left;
  const T = TABLE;

  let h = this.hash;
  let i = 0;

  while (i < len) {
    h = (h >>> 8) ^ T[(h ^ data[i++]) & 0xff];
    h = (h >>> 8) ^ T[(h ^ data[i++]) & 0xff];
    h = (h >>> 8) ^ T[(h ^ data[i++]) & 0xff];
    h = (h >>> 8) ^ T[(h ^ data[i++]) & 0xff];
  }

  switch (left) {
    case 3:
      h = (h >>> 8) ^ T[(h ^ data[i++]) & 0xff];
    case 2:
      h = (h >>> 8) ^ T[(h ^ data[i++]) & 0xff];
    case 1:
      h = (h >>> 8) ^ T[(h ^ data[i++]) & 0xff];
  }

  this.hash = h;
};

CRC32.prototype.final = function final() {
  this.hash ^= 0xffffffff;
  return this.hash >>> 0;
};

/*
 * Helpers
 */

function parseIndex(file, prefix) {
  if (!file.startsWith(prefix))
    return -1;

  const num = file.substring(prefix.length);

  if (!/^\d{10}$/.test(num))
    return -1;

  const index = parseInt(num, 10);

  if ((index >>> 0) !== index)
    return -1;

  return index;
}

async function pread(fd, data, offset) {
  const size = await fs.read(fd, data, 0, data.length, offset);
  assert(size === data.length);
  return size;
}

async function pwrite(fd, data, offset) {
  const size = await fs.write(fd, data, 0, data.length, offset);
  assert(size === data.length);
  return size;
}

/*
 * Expose
 */

exports.Flat = Flat;
exports.FileEntry = FileEntry;
