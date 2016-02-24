/**
 * chaindb.js - blockchain data management for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

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
    this.file = bcoin.prefix + '/chain-' + network.type + '.db';

  this.heightLookup = {};
  this.queue = {};
  this.queueSize = 0;
  this.cache = {};
  this.bufferPool = { used: {} };
  this.highest = -1;
  this.tip = null;
  this.height = -1;
  this.size = 0;
  this.fd = null;
  this.loading = false;
  this.loaded = false;

  // Need to cache up to the retarget interval
  // if we're going to be checking the damn
  // target all the time.
  if (network.powAllowMinDifficultyBlocks)
    this._cacheWindow = network.powDiffInterval + 1;
  else
    this._cacheWindow = network.block.majorityWindow + 1;

  this._init();
}

utils.inherits(ChainDB, EventEmitter);

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

  bcoin.ensurePrefix();

  if (+process.env.BCOIN_FRESH === 1) {
    try {
      fs.unlinkSync(this.file);
    } catch (e) {
      ;
    }
  }

  if (!this.exists())
    fs.writeFileSync(this.file, new Buffer([]));

  this.size = this.getFileSize();

  if (this.size % BLOCK_SIZE !== 0) {
    utils.debug('Blockchain is at an odd length. Truncating.');
    fs.truncateSync(this.file, this.size - (this.size % BLOCK_SIZE));
    this.size = this.getFileSize();
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
  var count = this.getSize();
  var i = start || 0;
  var lastEntry;

  this.loading = true;

  utils.debug('Starting chain load at height: %s', i);

  function finish(err) {
    self.loading = false;
    self.loaded = true;
    self.emit('load');

    if (err)
      return callback(err);

    callback();
  }

  function done(height) {
    if (height != null) {
      utils.debug(
        'Blockchain is corrupt after height %d. Resetting.',
        height);
      return self.resetHeightAsync(height, finish);
    }
    utils.debug('Chain successfully loaded.');
    finish();
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

  fs.close(this.fd);
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

  if (!this.bufferPool[size])
    this.bufferPool[size] = new Buffer(size);

  if (this.bufferPool.used[size] === this.bufferPool[size])
    return new Buffer(size);

  this.bufferPool.used[size] = this.bufferPool[size];

  return this.bufferPool[size];
};

ChainDB.prototype._free = function _free(buf) {
  if (!this.options.usePool)
    return;

  if (this.bufferPool.used[buf.length] === buf) {
    assert(this.bufferPool[buf.length] === buf);
    delete this.bufferPool.used[buf.length];
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

ChainDB.prototype.getFileSize = function getFileSize() {
  if (!bcoin.fs)
    return this.ramdisk.size;

  try {
    return fs.statSync(this.file).size;
  } catch (e) {
    return 0;
  }
};

ChainDB.prototype.getSize = function getSize() {
  var len = this.size / BLOCK_SIZE;
  assert(len % 1 === 0);
  return len;
};

ChainDB.prototype._cache = function _cache(entry) {
  if (entry.height === this.highest + 1) {
    this.highest = entry.height;
    delete this.cache[entry.height - this._cacheWindow];
    this.cache[entry.height] = entry;
    assert(Object.keys(this.cache).length <= this._cacheWindow);
  }
};

ChainDB.prototype.isCached = function isCached(height) {
  if (this.queue[height] != null)
    return true;

  if (this.cache[height] != null)
    return true;

  return false;
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

ChainDB.prototype.getSync = function getSync(height, force) {
  var data, entry;

  if (typeof height === 'string')
    height = this.heightLookup[height];

  if (height < 0 || height == null)
    return;

  if (!force) {
    if ((height + 1) * BLOCK_SIZE > this.size)
      return;
  }

  if (this.cache[height])
    return this.cache[height];

  if (this.queue[height])
    return this.queue[height];

  data = this._readSync(BLOCK_SIZE, height * BLOCK_SIZE);

  if (!data)
    return;

  entry = bcoin.chainblock.fromRaw(this.chain, height, data);

  // Populate the entry.
  this._populate(entry);

  // Cache the past 1001 blocks in memory
  // (necessary for isSuperMajority)
  this._cache(entry);

  return entry;
};

ChainDB.prototype.getAsync = function getAsync(height, callback, force) {
  var self = this;

  callback = utils.asyncify(callback);

  if (typeof height === 'string')
    height = this.heightLookup[height];

  if (height < 0 || height == null)
    return callback();

  if (!force) {
    if ((height + 1) * BLOCK_SIZE > this.size)
      return callback();
  }

  if (this.cache[height])
    return callback(null, this.cache[height]);

  if (this.queue[height])
    return callback(null, this.queue[height]);

  return this._readAsync(BLOCK_SIZE, height * BLOCK_SIZE, function(err, data) {
    var entry;

    if (err)
      return callback(err);

    if (!data)
      return callback();

    entry = bcoin.chainblock.fromRaw(self.chain, height, data);

    // Populate the entry.
    self._populate(entry);

    // Cache the past 1001 blocks in memory
    // (necessary for isSuperMajority)
    self._cache(entry);

    return callback(null, entry);
  });
};

ChainDB.prototype.saveSync = function saveSync(entry) {
  var raw, offset;

  assert(entry.height >= 0);

  if (entry.height * BLOCK_SIZE !== this.size) {
    utils.debug('Warning attempt to write to height: %d/%d',
      entry.height, this.getSize() - 1);
    return false;
  }

  // Cache the past 1001 blocks in memory
  // (necessary for isSuperMajority)
  this._cache(entry);

  // Populate the entry.
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

  if (entry.height * BLOCK_SIZE !== this.size) {
    utils.debug('Warning attempt to write to height: %d/%d',
      entry.height, this.getSize() - 1);
    return callback();
  }

  // Cache the past 1001 blocks in memory
  // (necessary for isSuperMajority)
  this._cache(entry);

  // Populate the entry.
  this._populate(entry);

  // Something is already writing.
  assert(!this.queue[entry.height]);

  // Speed up writes by doing them asynchronously
  // and keeping the data to be written in memory.
  this.queue[entry.height] = entry;
  this.queueSize++;

  // Write asynchronously to the db.
  raw = entry.toRaw();
  offset = entry.height * BLOCK_SIZE;

  return this._writeAsync(raw, offset, function(err, success) {
    if (err)
      return callback(err);

    assert(self.queue[entry.height]);

    delete self.queue[entry.height];
    self.queueSize--;

    if (self.queueSize === 0)
      self.emit('flush');

    return callback(null, success);
  });
};

ChainDB.prototype.resetHeightSync = function resetHeightSync(height, emit) {
  var self = this;
  var osize = this.size;
  var ohighest = this.highest;
  var otip = this.tip;
  var size, count, existing;

  if (typeof height === 'string')
    height = this.heightLookup[height];

  assert(height >= 0);
  assert(this.tip);

  size = (height + 1) * BLOCK_SIZE;
  count = this.getSize();

  if (height > count - 1)
    throw new Error('Height too high.');

  if (height === count - 1)
    return;

  for (i = height + 1; i < count; i++) {
    existing = this.getSync(i);

    assert(existing);

    // Emit the blocks we remove.
    if (emit)
      emit(existing);

    // Warn of potential race condition
    // (handled with _onFlush).
    if (this.queue[i])
      utils.debug('Warning: write job in progress.');

    delete this.cache[i];
    delete this.heightLookup[existing.hash];
  }

  // Prevent any more writes
  // by setting this early.
  this.size = size;
  this.highest = height;
  this.tip = this.getSync(height);
  assert(this.tip);
  this.height = this.tip.height;
  this.emit('tip', this.tip);

  // This will be synchronous 99% of the time.
  this._onFlush(function() {
    try {
      if (!bcoin.fs)
        self.ramdisk.truncate(size);
      else
        fs.ftruncateSync(self.fd, size);
    } catch (e) {
      self.size = osize;
      self.highest = ohighest;
      self.tip = otip;
      self.height = self.tip.height;
      self.emit('tip', self.tip);
      throw e;
    }
  });
};

ChainDB.prototype.resetHeightAsync = function resetHeightAsync(height, callback, emit) {
  var self = this;
  var osize = this.size;
  var ohighest = this.highest;
  var otip = this.tip;
  var size, count;

  callback = utils.asyncify(callback);

  if (typeof height === 'string')
    height = this.heightLookup[height];

  assert(height >= 0);
  assert(this.tip);

  size = (height + 1) * BLOCK_SIZE;
  count = this.getSize();

  if (height > count - 1)
    return callback(new Error('Height too high'));

  if (height === count - 1)
    return callback();

  // Prevent any more writes
  // by setting this early.
  this.size = size;
  this.highest = height;

  this.getAsync(height, function(err, tip) {
    if (err)
      return done(err);

    self.tip = tip;
    assert(self.tip);
    self.height = self.tip.height;
    self.emit('tip', self.tip);

    function finish(err) {
      if (err) {
        self.size = osize;
        self.highest = ohighest;
        self.tip = otip;
        self.height = self.tip.height;
        self.emit('tip', self.tip);
        return callback(err);
      }

      callback();
    }

    utils.forRange(height + 1, count, function(i, next) {
      self.getAsync(i, function(err, existing) {
        if (err)
          return next(err);

        assert(existing);

        // Emit the blocks we remove.
        if (emit)
          emit(existing);

        // Warn of potential race condition
        // (handled with _onFlush).
        if (self.queue[i])
          utils.debug('Warning: write job in progress.');

        delete self.cache[i];
        delete self.heightLookup[existing.hash];

        return next();
      }, true);
    }, function(err) {
      if (err)
        return finish(err);

      self._onFlush(function() {
        if (!bcoin.fs) {
          self.ramdisk.truncate(size);
          return finish();
        }

        fs.ftruncate(self.fd, size, function(err) {
          if (err)
            return finish(err);

          return finish();
        });
      });
    });
  });
};

ChainDB.prototype._onFlush = function _onFlush(callback) {
  if (this.queueSize === 0)
    return callback();
  this.once('flush', callback);
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

ChainDB.prototype._ioError = function _ioError(name, size, offset) {
  return new Error(name
    + '() failed at offset '
    + offset
    + ' with '
    + size
    + ' bytes left.');
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

  throw this._ioError('_readSync', size, offset);
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
        return callback(self._ioError('_readAsync', size, offset));

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

  fs.fsyncSync(this.fd);

  throw this._ioError('_writeSync', size, offset);
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
        return callback(self._ioError('_writeAsync', size, offset));

      index += bytes;
      size -= bytes;
      offset += bytes;

      if (index === data.length) {
        // Don't fsync when we're
        // potentially preloading headers.
        if (!self.chain.loaded)
          return callback(null, true);
        return fs.fsync(self.fd, function(err) {
          if (err)
            return callback(err);
          return callback(null, true);
        });
      }

      next();
    });
  })();
};

/**
 * Expose
 */

module.exports = ChainDB;
