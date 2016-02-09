/**
 * chaindb.js - blockchain data management for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var inherits = require('inherits');
var EventEmitter = require('events').EventEmitter;

var bcoin = require('../bcoin');
var bn = require('bn.js');
var constants = bcoin.protocol.constants;
var network = bcoin.protocol.network;
var utils = bcoin.utils;
var assert = utils.assert;
var fs = bcoin.fs;

var BLOCK_SIZE = bcoin.chainblock.BLOCK_SIZE;

/**
 * ChainDB
 */

function ChainDB(chain, options) {
  if (!(this instanceof ChainDB))
    return new ChainDB(chain);

  if (!options)
    options = {};

  this.options = options;
  this.chain = chain;
  this.file = options.file;

  if (!this.file)
    this.file = process.env.HOME + '/bcoin-' + network.type + '.blockchain';

  this._queue = [];
  this._cache = {};
  this._bufferPool = { used: {} };
  this._nullBlock = new Buffer(BLOCK_SIZE);
  this._nullBlock.fill(0);
  this.tip = -1;
  this.size = 0;
  this.fd = null;

  // Need to cache up to the retarget interval
  // if we're going to be checking the damn
  // target all the time.
  if (network.powAllowMinDifficultyBlocks)
    this._cacheWindow = network.powDiffInterval + 1;
  else
    this._cacheWindow = network.block.majorityWindow + 1;

  this._init();
}

ChainDB.prototype._init = function _init() {
  if (!bcoin.fs) {
    utils.debug('`fs` module not available. Falling back to ramdisk.');
    this.ramdisk = bcoin.ramdisk(new Buffer([]), 40 * 1024 * 1024);
    return;
  }

  if (+process.env.BCOIN_FRESH === 1) {
    try {
      fs.unlinkSync(this.file);
    } catch (e) {
      ;
    }
  }

  if (!this.exists()) {
    fs.writeFileSync(this.file, new Buffer(0));
    fs.truncateSync(this.file, 0);
  }

  this.size = this.getSize();

  if (this.size % BLOCK_SIZE !== 0) {
    utils.debug('Blockchain is at an odd length. Truncating.');
    fs.truncateSync(this.file, this.size - (this.size % BLOCK_SIZE));
    this.size = this.getSize();
    assert(this.size % BLOCK_SIZE === 0);
  }

  this.fd = fs.openSync(this.file, 'r+');
};

ChainDB.prototype._malloc = function(size) {
  if (!this._bufferPool[size])
    this._bufferPool[size] = new Buffer(size);

  if (this._bufferPool.used[size] === this._bufferPool[size])
    return new Buffer(size);

  this._bufferPool.used[size] = this._bufferPool[size];

  return this._bufferPool[size];
};

ChainDB.prototype._free = function(buf) {
  if (this._bufferPool.used[buf.length] === buf) {
    assert(this._bufferPool[buf.length] === buf);
    delete this._bufferPool.used[buf.length];
  }
};

ChainDB.prototype.exists = function exists() {
  try {
    fs.statSync(this.file);
    return true;
  } catch (e) {
    return false;
  }
};

ChainDB.prototype.getSize = function getSize() {
  try {
    return fs.statSync(this.file).size;
  } catch (e) {
    return 0;
  }
};

ChainDB.prototype.count = function count() {
  var len = this.size / BLOCK_SIZE;
  assert(len % 1 === 0);
  return len;
};

ChainDB.prototype.cache = function cache(entry) {
  if (entry.height > this.tip) {
    this.tip = entry.height;
    delete this._cache[entry.height - this._cacheWindow];
    this._cache[entry.height] = entry;
    assert(Object.keys(this._cache).length <= this._cacheWindow);
  }
};

ChainDB.prototype.get = function get(height) {
  return this.getSync(height);
};

ChainDB.prototype.getSync = function getSync(height) {
  var data, entry;

  if (this._cache[height])
    return this._cache[height];

  if (this._queue[height])
    return this._queue[height];

  if (height < 0 || height == null)
    return;

  if ((height + 1) * BLOCK_SIZE > this.size)
    return;

  data = this._readSync(BLOCK_SIZE, height * BLOCK_SIZE);

  if (!data)
    return;

  // Ignore if it is a null block.
  if (utils.read32(data, 0) === 0)
    return;

  entry = bcoin.chainblock.fromRaw(this.chain, height, data);

  // Cache the past 1001 blocks in memory
  // (necessary for isSuperMajority)
  this.cache(entry);

  return entry;
};

ChainDB.prototype.getAsync = function getAsync(height, callback) {
  var self = this;

  callback = utils.asyncify(callback);

  if (this._cache[height])
    return callback(null, this._cache[height]);

  if (this._queue[height])
    return callback(null, this._queue[height]);

  if (height < 0 || height == null)
    return callback();

  if ((height + 1) * BLOCK_SIZE > this.size)
    return callback();

  return this._readAsync(BLOCK_SIZE, height * BLOCK_SIZE, function(err, data) {
    var entry;

    // We can't ensure the integrity of
    // the chain if we get an error.
    // Just throw.
    if (err)
      throw err;

    if (!data)
      return callback();

    // Ignore if it is a null block.
    if (utils.read32(data, 0) === 0)
      return callback();

    entry = bcoin.chainblock.fromRaw(self.chain, height, data);

    // Cache the past 1001 blocks in memory
    // (necessary for isSuperMajority)
    self.cache(entry);

    return callback(null, entry);
  });
};

ChainDB.prototype.save = function save(entry) {
  return this.saveAsync(entry);
};

ChainDB.prototype.saveSync = function saveSync(entry) {
  var self = this;
  var raw, offset;

  // Cache the past 1001 blocks in memory
  // (necessary for isSuperMajority)
  this.cache(entry);

  raw = entry.toRaw();
  offset = entry.height * BLOCK_SIZE;

  return this._writeSync(raw, offset);
};

ChainDB.prototype.saveAsync = function saveAsync(entry, callback) {
  var self = this;
  var raw, offset;

  callback = utils.asyncify(callback);

  // Cache the past 1001 blocks in memory
  // (necessary for isSuperMajority)
  this.cache(entry);

  // Something is already writing. Cancel it
  // and synchronously write the data after
  // it cancels.
  if (this._queue[entry.height]) {
    this._queue[entry.height] = entry;
    return callback();
  }

  // Speed up writes by doing them asynchronously
  // and keeping the data to be written in memory.
  this._queue[entry.height] = entry;

  // Write asynchronously to the db.
  raw = entry.toRaw();
  offset = entry.height * BLOCK_SIZE;

  return this._writeAsync(raw, offset, function(err, success) {
    // We can't ensure the integrity of
    // the chain if we get an error.
    // Just throw.
    if (err)
      throw err;

    var item = self._queue[entry.height];

    // Something tried to write here but couldn't.
    // Synchronously write it and get it over with.
    try {
      if (item && item !== entry)
        success = self._writeSync(item.toRaw(), offset);
    } catch (e) {
      err = e;
    }

    delete self._queue[entry.height];

    return callback(null, success);
  });
};

ChainDB.prototype.remove = function remove(height) {
  assert(height >= 0);

  // Potential race condition here. Not sure how
  // to handle this.
  if (this._queue[height]) {
    utils.debug('Warning: write job in progress.');
    delete this._queue[height];
  }

  this._writeSync(this._nullBlock, height * BLOCK_SIZE);
  delete this._cache[height];

  // If we deleted several blocks at the end, go back
  // to the last non-null block and truncate the file
  // beyond that point.
  if ((height + 1) * BLOCK_SIZE === this.size) {
    while (this.isNull(height))
      height--;

    if (height < 0)
      height = 0;

    fs.ftruncateSync(this.fd, (height + 1) * BLOCK_SIZE);

    this.size = (height + 1) * BLOCK_SIZE;
    this.tip = height;
  }

  return true;
};

ChainDB.prototype.isNull = function isNull(height) {
  var data = this._readSync(4, height * BLOCK_SIZE);
  if (!data)
    return false;
  return utils.read32(data, 0) === 0;
};

ChainDB.prototype.has = function has(height) {
  var data;

  if (this._queue[height] || this._cache[height])
    return true;

  if (height < 0 || height == null)
    return false;

  if ((height + 1) * BLOCK_SIZE > this.size)
    return false;

  data = this._readSync(4, height * BLOCK_SIZE);

  if (!data)
    return false;

  return utils.read32(data, 0) !== 0;
};

ChainDB.prototype._readSync = function _readSync(size, offset) {
  var index = 0;
  var data, bytes;

  if (offset < 0 || offset == null)
    return;

  if (!bcoin.fs)
    return this.ramdisk.read(size, offset);

  data = this._malloc(size);

  try {
    while (bytes = fs.readSync(this.fd, data, index, size, offset)) {
      index += bytes;
      size -= bytes;
      offset += bytes;
      if (index === data.length) {
        this._free(data);
        return data;
      }
    }
  } catch (e) {
    this._free(data);
    throw e;
  }

  this._free(data);

  throw new Error('_readSync() failed.');
};

ChainDB.prototype._readAsync = function _readAsync(size, offset, callback) {
  var self = this;
  var index = 0;
  var data, bytes;

  callback = utils.asyncify(callback);

  if (offset < 0 || offset == null)
    return callback();

  if (!bcoin.fs)
    return callback(null, this.ramdisk.read(size, offset));

  data = this._malloc(size);

  (function next() {
    fs.read(self.fd, data, index, size, offset, function(err, bytes) {
      if (err) {
        self._free(data);
        return callback(err);
      }

      index += bytes;
      size -= bytes;
      offset += bytes;

      if (index === data.length) {
        self._free(data);
        return callback(null, data);
      }

      next();
    });
  })();
};

ChainDB.prototype._writeSync = function _writeSync(data, offset) {
  var size = data.length;
  var added = Math.max(0, (offset + data.length) - this.size);
  var index = 0;
  var bytes;

  if (offset < 0 || offset == null)
    return false;

  if (!bcoin.fs) {
    this.size += added;
    this.ramdisk.write(data, offset);
    return;
  }

  try {
    while (bytes = fs.writeSync(this.fd, data, index, size, offset)) {
      index += bytes;
      size -= bytes;
      offset += bytes;
      if (index === data.length) {
        this.size += added;
        return true;
      }
    }
  } catch (e) {
    throw e;
  }

  throw new Error('_writeSync() failed.');
};

ChainDB.prototype._writeAsync = function _writeAsync(data, offset, callback) {
  var self = this;
  var added = Math.max(0, (offset + data.length) - this.size);
  var size = data.length;
  var index = 0;

  callback = utils.asyncify(callback);

  if (offset < 0 || offset == null)
    return callback(null, false);

  if (!bcoin.fs) {
    this.size += added;
    this.ramdisk.write(data, offset);
    return callback(null, true);
  }

  this.size += added;

  (function next() {
    fs.write(self.fd, data, index, size, offset, function(err, bytes) {
      if (err) {
        self.size -= (added - index);
        return callback(err);
      }

      index += bytes;
      size -= bytes;
      offset += bytes;

      if (index === data.length)
        return callback(null, true);

      next();
    });
  })();
};

/**
 * Expose
 */

module.exports = ChainDB;
