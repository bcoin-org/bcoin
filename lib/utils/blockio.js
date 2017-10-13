/*!
 * blockio.js - blockio object for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const fs = require('../utils/fs');
const path = require('path');
const util = require('../utils/util');
const crc = require('../utils/crc');
const Network = require('../protocol/network');
const StaticWriter = require('../utils/staticwriter');
const FileLocation = require('../utils/fileloc');

/**
 * Cursor to write blocks to the disk
 * Based on max file size, BlockIO may rollover
 * this cursor to a new file
 * @constructor
 * @param {Number} fd
 * @param {Number} file
 * @param {Number} offset
 */

function FileCursor(fd, file, offset) {
  if (!(this instanceof FileCursor))
    return new FileCursor(fd, file, offset);

  this.fd = fd;
  this.file = file;
  this.offset = offset;
}

/**
 * BlockIO
 * @alias module:utils.BlockIO
 * @constructor
 * @param {Function?} options
 */

function BlockIO(options) {
  if (!(this instanceof BlockIO))
    return new BlockIO(options);

  this.cursor = null;
  // TODO: limit to 25, implement LRU eviction
  this.files = {};

  if (options)
    this.fromOptions(options);
}

/**
 * Inject properties from object.
 * @private
 * @param {Object} options
 * @returns {Object}
 */

BlockIO.prototype.fromOptions = function fromOptions(options) {
  if (options.network != null)
    this.network = Network.get(options.network);

  if (options.logger != null) {
    assert(typeof options.logger === 'object');
    this.logger = options.logger;
  }

  if (options.location != null) {
    assert(typeof options.location === 'string');
    this.location = options.location;
  }

  if (options.maxFileSize != null) {
    assert(util.isU64(options.maxFileSize));
    this.maxFileSize = options.maxFileSize;
  }

  return this;
};

/**
 * Path to file on disk corresponding to file number
 * @param {Number} file
 * @returns {String} - path
 */

BlockIO.prototype.filepath = function filepath(file) {
    return path.join(this.location, util.fmt('%d.fdb', file).padStart(13, 0));
};

/**
 * Open files
 */

BlockIO.prototype.open = async function open() {
  const [file, offset] = await this.scanFiles();
  const filepath = this.filepath(file);
  const fd = await fs.open(filepath, 'a+');
  this.cursor = new FileCursor(fd, file, offset);
};

/**
 * Rollover to the next file
 */

BlockIO.prototype.rollover = async function rollover() {
  await this.close();
  const file = this.cursor.file + 1;
  const filepath = this.filepath(file);
  const fd = await fs.open(filepath, 'a+');
  this.cursor = new FileCursor(fd, file, 0);
};

/**
 * Close files
 */

BlockIO.prototype.close = async function close() {
  fs.close(this.cursor.fd);
};

/**
 * Ensure working directory exists
 */

BlockIO.prototype.ensure = function ensure() {
  if (!fs.existsSync(this.location)) {
    fs.mkdirpSync(this.location);
  }
};

/**
 * Scan disk files and return initial cursor state
 * @param {Promise} - Returns file, offset.
 */

BlockIO.prototype.scanFiles = async function scanFiles() {
  let offset = 0;
  for(let file=0; ;file++) {
    try {
      const filepath = this.filepath(file);
      const st = await fs.stat(filepath);
      offset = st.size;
    } catch (e) {
      // Starting from scratch
      if (file === 0) {
        return [0, 0];
      }
      return [file-1, offset];
    }
  }
};

/**
 * Open corresponding file for read/write
 * @param {Number} file
 * @returns {Promise} - Returns fd.
 */

BlockIO.prototype.openReadWriteFile = async function openReadWriteFile(file) {
  const filepath = this.filepath(file);
  let fd = null;
  try {
    fd = await fs.open(filepath, 'a+');
  } catch(e) {
    throw e;
  }
  this.files[file] = fd;
  return fd;
};

/**
 * Retrieve a file by number
 * @param {Number} file
 * @returns {Promise} - Returns fd.
 */

BlockIO.prototype.blockFile = async function blockFile(file) {
  if (this.files[file] != null) {
    return this.files[file];
  }
  return await this.openReadWriteFile(file);
};

/**
 * Write raw data to disk, return bytes written
 * @param {Buffer|String} raw
 * @returns {Promise} - Returns Number.
 */

BlockIO.prototype.writeData = async function writeData(raw) {
  let len = 0;
  try {
    len = await
      fs.write(this.cursor.fd, raw, 0, raw.length, this.cursor.offset);
  } catch(e) {
    throw e;
  }
  this.cursor.offset += len;
  return len;
};

/**
 * Write a raw block
 * Serialized to a file region as
 * <4 bytes network magic bytes>
 * + <4 bytes raw block length>
 * + <n bytes raw block>
 * + <4 bytes CRC32 checksum>
 * @param {Buffer|String} block
 * @returns {Promise} - Returns {@link FileLocation}.
 */

BlockIO.prototype.writeBlock = async function writeBlock(block) {
  // 4 bytes for network, 4 bytes for block length, 4 bytes for checksum
  const size = block.length + 12;
  if (this.cursor.offset + size > this.maxFileSize) {
    // rollover to the next file
    await this.rollover();
  }

  const pos = this.cursor.offset;
  const bw = new StaticWriter(8);
  bw.writeU32(this.network.magic);
  bw.writeU32(block.length);
  const raw = bw.render();

  try {
    let len = await this.writeData(raw);
    let crc32 = crc.crc32c(raw);

    len += await this.writeData(block);
    crc32 = crc.crc32c(block, crc32);

    const checksum = Buffer.from([crc32 >> 24, crc32 >> 16, crc32 >> 8, crc32]);
    len += await this.writeData(checksum);

    return new FileLocation(this.cursor.file, pos, len);
  } catch(e) {
    throw e;
  }
};

/**
 * Retrieve a raw block
 * @param {@link FileLocation} location
 * @returns {Promise} - Returns Buffer.
 */

BlockIO.prototype.readBlock = async function readBlock(loc) {
  const block = Buffer.alloc(loc.len);
  try {
    const fd = await this.blockFile(loc.file);
    const len = await fs.read(fd, block, 0, loc.len, loc.offset);
    return block.slice(8, len-4);
  } catch(e) {
    throw e;
  }
};

/**
 * Remove a block and truncate file
 * @param {@link FileLocation} location
 */

BlockIO.prototype.removeBlock = async function removeBlock(loc) {
  try {
    const fd = await this.blockFile(loc.file);
    const st = await fs.stat(loc.file);
    if (st.size > loc.offset)
      await fs.ftruncate(fd, loc.offset);
  } catch(e) {
    throw e;
  }
};

/*
 * Expose
 */

module.exports = BlockIO;
