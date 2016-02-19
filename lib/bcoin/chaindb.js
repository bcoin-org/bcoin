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
    return new ChainDB(chain, options);

  if (!options)
    options = {};

  EventEmitter.call(this);

  this.options = options;
  this.chain = chain;
  this.file = options.file;

  if (!this.file)
    this.file = process.env.HOME + '/bcoin-chain-' + network.type + '.db';

  this.heightLookup = {};
  this._queue = {};
  this._cache = {};
  this._bufferPool = { used: {} };
  this.highest = -1;
  this.tip = null;
  this.height = -1;
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

inherits(ChainDB, EventEmitter);

ChainDB.prototype._init = function _init() {
  var genesis = bcoin.chainblock.fromJSON(this.chain, {
    hash: network.genesis.hash,
    version: network.genesis.version,
    prevBlock: network.genesis.prevBlock,
    merkleRoot: network.genesis.merkleRoot,
    ts: network.genesis.ts,
    bits: network.genesis.bits,
    nonce: network.genesis.nonce,
    height: 0
  });

  if (!bcoin.fs) {
    utils.debug('`fs` module not available. Falling back to ramdisk.');
    this.ramdisk = new bcoin.ramdisk(40 * 1024 * 1024);
    this.saveSync(genesis);
    return;
  }

  if (+process.env.BCOIN_FRESH === 1) {
    try {
      fs.unlinkSync(this.file);
    } catch (e) {
      ;
    }
  }

  if (!this.exists())
    fs.writeFileSync(this.file, new Buffer([]));

  this.size = this.getSize();

  if (this.size % BLOCK_SIZE !== 0) {
    utils.debug('Blockchain is at an odd length. Truncating.');
    fs.truncateSync(this.file, this.size - (this.size % BLOCK_SIZE));
    this.size = this.getSize();
    assert(this.size % BLOCK_SIZE === 0);
  }

  this.fd = fs.openSync(this.file, 'r+');

  if (this.size === 0) {
    this.saveSync(genesis);
  } else {
    this.getSync(0);
    assert(this.tip.hash === genesis.hash);
  }
};

ChainDB.prototype.load = function load(start, callback) {
  var self = this;
  var count = this.count();
  var i = start || 0;
  var lastEntry;

  utils.debug('Starting chain load at height: %s', i);

  function done(height) {
    if (height != null) {
      utils.debug(
        'Blockchain is corrupt after height %d. Resetting.',
        height);
      self.resetHeight(height);
    } else {
      utils.debug('Chain successfully loaded.');
    }
    callback();
  }

  (function next() {
    if (i >= count)
      return done();

    self.getAsync(i, function(err, entry) {
      if (err)
        return callback(err);

      // Do some paranoid checks.
      if (lastEntry && entry.prevBlock !== lastEntry.hash)
        return done(Math.max(0, i - 2));

      if (i % 10000 === 0)
        utils.debug('Loaded %d blocks.', i);

      lastEntry = entry;
      i += 1;
      next();
    });
  })();
};

ChainDB.prototype.closeSync = function closeSync() {
  if (!bcoin.fs) {
    this.ramdisk = null;
    return;
  }
  fs.closeSync(this.fd);
  this.fd = null;
};

ChainDB.prototype.closeAsync = function closeAsync(callback) {
  var self = this;

  callback = utils.asyncify(callback);

  if (!bcoin.fs) {
    this.ramdisk = null;
    return callback();
  }

  fs.close(this.fd, function(err) {
    if (err)
      return callback(err);
    self.fd = null;
    return callback();
  });
};

ChainDB.prototype._malloc = function _malloc(size) {
  if (!this.options.usePool)
    return new Buffer(size);

  if (!this._bufferPool[size])
    this._bufferPool[size] = new Buffer(size);

  if (this._bufferPool.used[size] === this._bufferPool[size])
    return new Buffer(size);

  this._bufferPool.used[size] = this._bufferPool[size];

  return this._bufferPool[size];
};

ChainDB.prototype._free = function _free(buf) {
  if (!this.options.usePool)
    return;

  if (this._bufferPool.used[buf.length] === buf) {
    assert(this._bufferPool[buf.length] === buf);
    delete this._bufferPool.used[buf.length];
  }
};

ChainDB.prototype.exists = function exists() {
  if (!bcoin.fs)
    return true;

  try {
    fs.statSync(this.file);
    return true;
  } catch (e) {
    return false;
  }
};

ChainDB.prototype.getSize = function getSize() {
  if (!bcoin.fs)
    return this.ramdisk.size;

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
  if (entry.height > this.highest) {
    this.highest = entry.height;
    delete this._cache[entry.height - this._cacheWindow];
    this._cache[entry.height] = entry;
    assert(Object.keys(this._cache).length <= this._cacheWindow);
  }
};

ChainDB.prototype.getHeight = function getHeight(hash) {
  var height = this.heightLookup[hash];

  if (height == null)
    return -1;

  return height;
};

ChainDB.prototype._populate = function _populate(entry) {
  this.heightLookup[entry.hash] = entry.height;

  if (!this.tip || entry.height > this.tip.height) {
    this.tip = entry;
    this.height = this.tip.height;
    this.emit('tip', this.tip);
  }
};

ChainDB.prototype.get = function get(height) {
  return this.getSync(height);
};

ChainDB.prototype.getSync = function getSync(height) {
  var data, entry;

  if (typeof height === 'string')
    height = this.heightLookup[height];

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

  entry = bcoin.chainblock.fromRaw(this.chain, height, data);

  this._populate(entry);

  // Cache the past 1001 blocks in memory
  // (necessary for isSuperMajority)
  this.cache(entry);

  return entry;
};

ChainDB.prototype.getAsync = function getAsync(height, callback) {
  var self = this;

  callback = utils.asyncify(callback);

  if (typeof height === 'string')
    height = this.heightLookup[height];

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

    entry = bcoin.chainblock.fromRaw(self.chain, height, data);

    self._populate(entry);

    // Cache the past 1001 blocks in memory
    // (necessary for isSuperMajority)
    self.cache(entry);

    return callback(null, entry);
  });
};

ChainDB.prototype.save = function save(entry, callback) {
  return this.saveAsync(entry, callback);
};

ChainDB.prototype.saveSync = function saveSync(entry) {
  var raw, offset;

  assert(entry.height >= 0);
  assert(entry.height * BLOCK_SIZE === this.size);

  // Cache the past 1001 blocks in memory
  // (necessary for isSuperMajority)
  this.cache(entry);

  this._populate(entry);

  raw = entry.toRaw();
  offset = entry.height * BLOCK_SIZE;

  return this._writeSync(raw, offset);
};

ChainDB.prototype.saveAsync = function saveAsync(entry, callback) {
  var self = this;
  var raw, offset;

  callback = utils.asyncify(callback);

  assert(entry.height >= 0);
  assert(entry.height * BLOCK_SIZE === this.size);

  // Cache the past 1001 blocks in memory
  // (necessary for isSuperMajority)
  this.cache(entry);

  this._populate(entry);

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

ChainDB.prototype.drop = function drop(height) {
  assert(height >= 0);

  // Potential race condition here. Not sure how
  // to handle this.
  if (this._queue[height]) {
    utils.debug('Warning: write job in progress.');
    delete this._queue[height];
  }

  delete this._cache[height];
};

ChainDB.prototype.resetHeight = function resetHeight(height) {
  var size, count, existing;

  if (typeof height === 'string')
    height = this.heightLookup[height];

  assert(height >= 0);

  size = (height + 1) * BLOCK_SIZE;
  count = this.count();

  if (height === count - 1)
    return;

  assert(height <= count - 1);
  assert(this.tip);

  for (i = height + 1; i < count; i++) {
    existing = this.get(i);
    assert(existing);
    this.drop(i);
    delete this.heightLookup[existing.hash];
  }

  if (!bcoin.fs)
    this.ramdisk.truncate(size);
  else
    fs.ftruncateSync(this.fd, size);

  this.size = size;
  this.highest = height;
  this.tip = this.get(height);
  assert(this.tip);
  this.height = this.tip.height;
  this.emit('tip', this.tip);
};

ChainDB.prototype.resetHeightAsync = function resetHeightAsync(height, callback) {
  var self = this;
  var size, count, pending, called;

  if (typeof height === 'string')
    height = this.heightLookup[height];

  assert(height >= 0);

  callback = utils.asyncify(callback);

  size = (height + 1) * BLOCK_SIZE;
  count = this.count() - 1;
  pending = count - (height + 1);

  if (height === count - 1)
    return callback();

  assert(height <= count - 1);
  assert(this.tip);

  for (i = height + 1; i < count; i++)
    dropEntry(i);

  function dropEntry(i) {
    self.getAsync(i, function(err, existing) {
      if (err)
        return done(err);

      assert(existing);
      self.drop(i);
      delete self.heightLookup[existing.hash];
      if (!--pending)
        done();
    });
  }

  function done(err) {
    if (called)
      return;

    called = true;

    if (err)
      return callback(err);

    if (!bcoin.fs) {
      self.ramdisk.truncate(size);
      return callback();
    }

    fs.ftruncate(self.fd, size, function(err) {
      if (err)
        return callback(err);

      self.size = size;
      self.highest = height;
      self.tip = self.get(height);
      assert(self.tip);
      self.height = self.tip.height;
      self.emit('tip', self.tip);

      return callback();
    });
  }
};

ChainDB.prototype.has = function has(height) {
  if (typeof height === 'string')
    height = this.heightLookup[height];

  if (height < 0 || height == null)
    return false;

  if ((height + 1) * BLOCK_SIZE <= this.size)
    return true;

  return false;
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

      if (!bytes)
        throw new Error('_readAsync() failed.');

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

      if (!bytes)
        throw new Error('_writeAsync() failed.');

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
