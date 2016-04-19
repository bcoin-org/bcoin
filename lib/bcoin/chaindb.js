/*!
 * chaindb.js - blockchain data management for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

module.exports = function(bcoin) {

var EventEmitter = require('events').EventEmitter;
var network = bcoin.protocol.network;
var utils = require('./utils');
var assert = utils.assert;
var pad32 = utils.pad32;
var DUMMY = new Buffer([0]);

/**
 * The database backend for the {@link Chain} object.
 * @exports ChainDB
 * @constructor
 * @param {Object} options
 * @param {Boolean?} options.prune - Whether to prune the chain.
 * @param {Boolean?} options.spv - SPV-mode, will not save block
 * data, only entries.
 * @param {Number?} [options.keepBlocks=288] - Number of
 * blocks to keep when pruning.
 * @param {Boolean?} options.paranoid - Perform some paranoid checks
 * against hashes. Will throw if corruption is detected.
 * @param {String?} options.name - Database name
 * @param {String?} options.location - Database location
 * @param {String?} options.db - Database backend name
 * @property {Boolean} prune
 * @property {Boolean} loaded
 * @property {Number} keepBlocks
 * @emits ChainDB#open
 * @emits ChainDB#error
 * @emits ChainDB#add block
 * @emits ChainDB#remove block
 * @emits ChainDB#add entry
 * @emits ChainDB#remove entry
 */

function ChainDB(chain, options) {
  if (!(this instanceof ChainDB))
    return new ChainDB(chain, options);

  if (!options)
    options = {};

  EventEmitter.call(this);

  this.options = options;
  this.chain = chain;

  this.keepBlocks = options.keepBlocks || 288;
  this.prune = !!options.prune;

  this.loaded = false;

  // Need to cache up to the retarget interval
  // if we're going to be checking the damn
  // target all the time.
  if (network.pow.allowMinDifficultyBlocks)
    this._cacheWindow = network.pow.retargetInterval + 1;
  else
    this._cacheWindow = network.block.majorityWindow + 1;

  // this.cacheHash = new bcoin.lru(this._cacheWindow);
  // this.cacheHeight = new bcoin.lru(this._cacheWindow);
  this.cacheHash = new DumbCache(this._cacheWindow * 10);
  this.cacheHeight = new DumbCache(this._cacheWindow * 10);

  this._init();
}

utils.inherits(ChainDB, EventEmitter);

ChainDB.prototype._init = function _init() {
  var self = this;
  var genesis, block;

  if (this.loaded)
    return;

  this.db = bcoin.ldb({
    name: this.options.name || (this.options.spv ? 'spvchain' : 'chain'),
    location: this.options.location,
    db: this.options.db,
    compression: true,
    cacheSize: 16 << 20,
    writeBufferSize: 8 << 20
  });

  bcoin.debug('Starting chain load.');

  this.db.open(function(err) {
    if (err)
      return self.emit('error', err);

    function finish(err) {
      if (err)
        return self.emit('error', err);

      bcoin.debug('Chain successfully loaded.');

      self.loaded = true;
      self.emit('open');
    }

    self.db.get('c/b/' + network.genesis.hash, function(err, exists) {
      if (err && err.type !== 'NotFoundError')
        return self.emit('error', err);

      if (exists)
        return finish();

      genesis = new bcoin.chainblock(self.chain, {
        hash: network.genesis.hash,
        version: network.genesis.version,
        prevBlock: network.genesis.prevBlock,
        merkleRoot: network.genesis.merkleRoot,
        ts: network.genesis.ts,
        bits: network.genesis.bits,
        nonce: network.genesis.nonce,
        height: 0,
        chainwork: null
      }, null);

      block = bcoin.block.fromRaw(network.genesisBlock, 'hex');
      block.height = 0;

      self.save(genesis, block, true, finish);
    });
  });
};

/**
 * Open the chain, wait for the database to load.
 * @param {Function} callback
 */

ChainDB.prototype.open = function open(callback) {
  if (this.loaded)
    return utils.nextTick(callback);

  this.once('open', callback);
};

/**
 * Close the chain, wait for the database to close.
 * @method
 * @param {Function} callback
 */

ChainDB.prototype.close =
ChainDB.prototype.destroy = function destroy(callback) {
  callback = utils.ensure(callback);
  this.db.close(callback);
};

/**
 * Add an entry to the LRU cache.
 * @param {ChainBlock} entry
 */

ChainDB.prototype.addCache = function addCache(entry) {
  this.cacheHash.set(entry.hash, entry);
  this.cacheHeight.set(entry.height, entry);
};

/**
 * Test the cache for a present entry hash or height.
 * @param {Hash|Number} hash - Hash or height.
 */

ChainDB.prototype.hasCache = function hasCache(hash) {
  if (hash == null || hash < 0)
    return false;

  if (typeof hash === 'number')
    return this.cacheHeight.has(hash);

  return this.cacheHash.has(hash);
};

/**
 * Get an entry directly from the LRU cache. This is
 * useful for optimization if we don't want to wait on a
 * nextTick during a `get()` call.
 * @param {Hash|Number} hash - Hash or height.
 */

ChainDB.prototype.getCache = function getCache(hash) {
  if (hash == null || hash < 0)
    return;

  if (typeof hash === 'number')
    return this.cacheHeight.get(hash);

  return this.cacheHash.get(hash);
};

/**
 * Get the height of a block by hash.
 * @param {Hash} hash
 * @param {Function} callback - Returns [Error, Number].
 */

ChainDB.prototype.getHeight = function getHeight(hash, callback) {
  callback = utils.asyncify(callback);

  if (hash == null || hash < 0)
    return callback(null, -1);

  if (typeof hash === 'number')
    return callback(null, hash);

  // When prevBlock=zero-hash
  if (+hash === 0)
    return callback(null, -1);

  if (this.cacheHash.has(hash))
    return callback(null, this.cacheHash.get(hash).height);

  this.db.get('c/b/' + hash, function(err, height) {
    if (err && err.type !== 'NotFoundError')
      return callback(err);

    if (height == null)
      return callback(null, -1);

    return callback(null, utils.readU32(height, 0));
  });
};

/**
 * Get the hash of a block by height. Note that this
 * will only return hashes in the main chain.
 * @param {Number} height
 * @param {Function} callback - Returns [Error, {@link Hash}].
 */

ChainDB.prototype.getHash = function getHash(height, callback) {
  callback = utils.asyncify(callback);

  if (height == null || height < 0)
    return callback(null, null);

  if (typeof height === 'string')
    return callback(null, height);

  if (this.cacheHeight.has(height))
    return callback(null, this.cacheHeight.get(height).hash);

  this.db.get('c/h/' + pad32(height), function(err, hash) {
    if (err && err.type !== 'NotFoundError')
      return callback(err);

    if (hash == null)
      return callback(null, null);

    return callback(null, hash.toString('hex'));
  });
};

/**
 * Dump the database to a map for debugging.
 * @param {Function} callback - Returns [Error, Object].
 */

ChainDB.prototype.dump = function dump(callback) {
  var records = {};

  var iter = this.db.iterator({
    gte: 'c',
    lte: 'c~',
    keys: true,
    values: true,
    fillCache: false,
    keyAsBuffer: false,
    valueAsBuffer: true
  });

  callback = utils.ensure(callback);

  (function next() {
    iter.next(function(err, key, value) {
      if (err) {
        return iter.end(function() {
          callback(err);
        });
      }

      if (key === undefined) {
        return iter.end(function(err) {
          if (err)
            return callback(err);
          return callback(null, records);
        });
      }

      records[key] = value;

      next();
    });
  })();
};

/**
 * Get the current chain height from the tip record.
 * @param {Function} callback - Returns [Error, Number].
 */

ChainDB.prototype.getChainHeight = function getChainHeight(callback) {
  return this.getTip(function(err, entry) {
    if (err)
      return callback(err);

    if (!entry)
      return callback(null, -1);

    return callback(null, entry.height);
  });
};

/**
 * Get both hash and height depending on the value passed in.
 * @param {Hash|Number} block - Can be a has or height.
 * @param {Function} callback - Returns [Error, {@link Hash}, Number].
 */

ChainDB.prototype.getBoth = function getBoth(block, callback) {
  var hash, height;

  if (block == null || block < 0)
    return utils.asyncify(callback)(null, null, -1);

  if (typeof block === 'string')
    hash = block;
  else
    height = block;

  if (!hash) {
    return this.getHash(height, function(err, hash) {
      if (err)
        return callback(err);

      if (hash == null)
        height = -1;

      return callback(null, hash, height);
    });
  }

  return this.getHeight(hash, function(err, height) {
    if (err)
      return callback(err);

    if (height === -1)
      hash = null;

    return callback(null, hash, height);
  });
};

/**
 * Retrieve a chain entry but do _not_ add it to the LRU cache.
 * @param {Hash} hash
 * @param {Function} callback - Returns [Error, {@link ChainBlock}].
 */

ChainDB.prototype._getEntry = function _getEntry(hash, callback) {
  var self = this;
  var entry;

  if (hash == null || hash < 0)
    return utils.nextTick(callback);

  return this.getBoth(hash, function(err, hash, height) {
    if (err && err.type !== 'NotFoundError')
      return callback(err);

    if (!hash)
      return callback();

    if (self.cacheHash.has(hash))
      return callback(null, self.cacheHash.get(hash));

    return self.db.get('c/c/' + hash, function(err, data) {
      if (err && err.type !== 'NotFoundError')
        return callback(err);

      if (!data)
        return callback();

      entry = bcoin.chainblock.fromRaw(self.chain, data);

      return callback(null, entry);
    });
  });
};

/**
 * Retrieve a chain entry and add it to the LRU cache.
 * @param {Hash} hash
 * @param {Function} callback - Returns [Error, {@link ChainBlock}].
 */

ChainDB.prototype.get = function get(height, callback) {
  var self = this;

  return this._getEntry(height, function(err, entry) {
    if (err)
      return callback(err);

    if (!entry)
      return callback();

    // There's no efficient way to check whether
    // this is in the main chain or not, so
    // don't add it to the height cache.
    self.cacheHash.set(entry.hash, entry);

    return callback(null, entry);
  });
};

/**
 * Save an entry to the database and optionally
 * connect it as the tip. Note that this method
 * does _not_ perform any verification which is
 * instead performed in {@link Chain#add}.
 * @param {ChainBlock} entry
 * @param {Block} block
 * @param {Boolean} connect - Whether to connect the
 * block's inputs and add it as a tip.
 * @param {Function} callback
 */

ChainDB.prototype.save = function save(entry, block, connect, callback) {
  var self = this;
  var batch, hash, height;

  callback = utils.ensure(callback);

  assert(entry.height >= 0);

  batch = this.db.batch();

  hash = new Buffer(entry.hash, 'hex');

  height = new Buffer(4);
  utils.writeU32(height, entry.height, 0);

  batch.put('c/b/' + entry.hash, height);
  batch.put('c/c/' + entry.hash, entry.toRaw());

  this.cacheHash.set(entry.hash, entry);

  if (!connect) {
    return this.saveBlock(block, batch, false, function(err) {
      if (err)
        return callback(err);
      return batch.write(callback);
    });
  }

  this.cacheHeight.set(entry.height, entry);

  batch.put('c/n/' + entry.prevBlock, hash);
  batch.put('c/h/' + pad32(entry.height), hash);
  batch.put('c/t', hash);

  this.emit('add entry', entry);

  this.saveBlock(block, batch, true, function(err) {
    if (err)
      return callback(err);
    return batch.write(callback);
  });
};

/**
 * Retrieve the tip entry from the tip record.
 * @param {Function} callback - Returns [Error, {@link ChainBlock}].
 */

ChainDB.prototype.getTip = function getTip(callback) {
  var self = this;
  return this.db.get('c/t', function(err, hash) {
    if (err && err.type !== 'NotFoundError')
      return callback(err);

    if (!hash)
      return callback();

    return self.get(hash.toString('hex'), callback);
  });
};

/**
 * Connect the block to the chain.
 * @param {ChainBlock|Hash|Height} block - entry, height, or hash.
 * @param {Function} callback - Returns [Error, {@link ChainBlock}].
 */

ChainDB.prototype.connect = function connect(entry, block, callback) {
  var self = this;
  var batch = this.db.batch();
  var hash = new Buffer(entry.hash, 'hex');

  batch.put('c/n/' + entry.prevBlock, hash);
  batch.put('c/h/' + pad32(entry.height), hash);
  batch.put('c/t', hash);

  this.cacheHash.set(entry.hash, entry);
  this.cacheHeight.set(entry.height, entry);

  this.emit('add entry', entry);

  this.connectBlock(block, batch, function(err) {
    if (err)
      return callback(err);

    batch.write(function(err) {
      if (err)
        return callback(err);
      return callback(null, entry);
    });
  });
};

/**
 * Disconnect block from the chain.
 * @param {ChainBlock|Hash|Height} block - Entry, height, or hash.
 * @param {Function} callback - Returns [Error, {@link ChainBlock}].
 */

ChainDB.prototype.disconnect = function disconnect(block, callback) {
  var self = this;
  var batch;

  this._ensureEntry(block, function(err, entry) {
    if (err)
      return callback(err);

    if (!entry)
      return callback(new Error('Entry not found.'));

    batch = self.db.batch();

    batch.del('c/n/' + entry.prevBlock);
    batch.del('c/h/' + pad32(entry.height));
    batch.put('c/t', new Buffer(entry.prevBlock, 'hex'));

    self.cacheHeight.remove(entry.height);

    self.emit('remove entry', entry);

    self.disconnectBlock(entry.hash, batch, function(err) {
      if (err)
        return callback(err);

      batch.write(function(err) {
        if (err)
          return callback(err);
        return callback(null, entry);
      });
    });
  });
};

ChainDB.prototype._ensureEntry = function _ensureEntry(block, callback) {
  if (block instanceof bcoin.chainblock)
    return callback(null, block);
  return this.get(block, callback);
};

/**
 * Get the _next_ block hash (does not work by height).
 * @param {Hash} hash
 * @param {Function} callback - Returns [Error, {@link Hash}].
 */

ChainDB.prototype.getNextHash = function getNextHash(hash, callback) {
  return this.db.get('c/n/' + hash, function(err, nextHash) {
    if (err && err.type !== 'NotFoundError')
      return callback(err);

    if (!nextHash)
      return callback();

    return callback(null, nextHash.toString('hex'));
  });
};

/**
 * Check to see if a block is on the main chain.
 * @param {ChainBlock|Hash} hash
 * @param {Function} callback - Returns [Error, Boolean].
 */

ChainDB.prototype.isMainChain = function isMainChain(hash, callback) {
  var self = this;
  var query;

  if (hash instanceof bcoin.chainblock) {
    query = hash.height;
    hash = hash.hash;
  } else {
    query = hash;
  }

  return this.getHeight(query, function(err, height) {
    if (err)
      return callback(err);

    return self.getHash(height, function(err, existing) {
      if (err)
        return callback(err);

      if (!existing)
        return callback(null, false);

      return callback(null, hash === existing);
    });
  });
};

/**
 * Reset the chain to a height or hash. Useful for replaying
 * the blockchain download for SPV.
 * @param {Hash|Number} block - hash/height
 * @param {Function} callback
 */

ChainDB.prototype.reset = function reset(block, callback) {
  var self = this;
  var batch;

  this.get(block, function(err, entry) {
    if (err)
      return callback(err);

    if (!entry)
      return callback();

    self.getTip(function(err, tip) {
      if (err)
        return callback(err);

      if (!tip)
        return callback();

      (function next(err, tip) {
        if (err)
          return callback(err);

        if (!tip)
          return callback();

        batch = self.db.batch();

        if (tip.hash === entry.hash) {
          batch.put('c/t', new Buffer(tip.hash, 'hex'));
          return batch.write(callback);
        }

        batch.del('c/h/' + pad32(tip.height));
        batch.del('c/b/' + tip.hash);
        batch.del('c/c/' + tip.hash);
        batch.del('c/n/' + tip.prevBlock);

        self.emit('remove entry', tip);

        self.removeBlock(tip.hash, batch, function(err) {
          if (err)
            return callback(err);

          batch.write(function(err) {
            if (err)
              return next(err);
            self.get(tip.prevBlock, next);
          });
        });
      })(null, tip);
    });
  });
};

/**
 * Test whether the chain contains a block in the
 * main chain or side chain. Side chains will only
 * be tested if the lookup is done by hash.
 * @param {Hash|Number} height - Hash or height.
 * @param {Function} callback - Returns [Error, Boolean].
 */

ChainDB.prototype.has = function has(height, callback) {
  if (height == null || height < 0)
    return utils.asyncify(callback)(null, false);

  return this.getBoth(height, function(err, hash, height) {
    if (err)
      return callback(err);
    return callback(null, hash != null);
  });
};

/**
 * Save a block (not an entry) to the
 * database and potentially connect the inputs.
 * @param {Block} block
 * @param {Batch} batch
 * @param {Boolean} connect - Whether to connect the inputs.
 * @param {Function} callback - Returns [Error, {@link Block}].
 */

ChainDB.prototype.saveBlock = function saveBlock(block, batch, connect, callback) {
  var i, tx;

  if (this.options.spv)
    return utils.nextTick(callback);

  batch.put('b/b/' + block.hash('hex'), block.toCompact());

  for (i = 0; i < block.txs.length; i++) {
    tx = block.txs[i];
    batch.put('t/t/' + tx.hash('hex'), tx.toExtended());
  }

  if (!connect)
    return utils.nextTick(callback);

  this.connectBlock(block, batch, callback);
};

/**
 * Remove a block (not an entry) to the database.
 * Disconnect inputs.
 * @param {Block|Hash} block - {@link Block} or hash.
 * @param {Batch} batch
 * @param {Function} callback - Returns [Error, {@link Block}].
 */

ChainDB.prototype.removeBlock = function removeBlock(hash, batch, callback) {
  var self = this;
  var i, tx;

  if (this.options.spv)
    return utils.nextTick(callback);

  this._ensureHistory(hash, function(err, block) {
    if (err)
      return callback(err);

    if (!block)
      return callback();

    batch.del('b/b/' + block.hash('hex'));

    for (i = 0; i < block.txs.length; i++) {
      tx = block.txs[i];
      batch.del('t/t/' + tx.hash('hex'));
    }

    self.disconnectBlock(block, batch, callback);
  });
};

/**
 * Connect block inputs.
 * @param {Block} block
 * @param {Batch} batch
 * @param {Function} callback - Returns [Error, {@link Block}].
 */

ChainDB.prototype.connectBlock = function connectBlock(block, batch, callback) {
  var self = this;
  var i, j, tx, input, output, key, address, hash, uniq;

  if (this.options.spv) {
    self.emit('add block', block);
    return utils.nextTick(callback);
  }

  this._ensureBlock(block, function(err, block) {
    if (err)
      return callback(err);

    if (!block)
      return callback();

    for (i = 0; i < block.txs.length; i++) {
      tx = block.txs[i];
      hash = tx.hash('hex');
      uniq = {};

      for (j = 0; j < tx.inputs.length; j++) {
        input = tx.inputs[j];
        key = input.prevout.hash + '/' + input.prevout.index;

        if (tx.isCoinbase())
          break;

        assert(input.coin);

        if (self.options.indexAddress) {
          address = input.getAddress();

          if (address && !uniq[address] && !self.prune) {
            uniq[address] = true;
            batch.put('t/a/' + address + '/' + hash, DUMMY);
          }

          if (address)
            batch.del('u/a/' + address + '/' + key);
        }

        batch.del('u/t/' + key);
      }

      for (j = 0; j < tx.outputs.length; j++) {
        output = tx.outputs[j];
        key = hash + '/' + j;

        if (self.options.indexAddress) {
          address = output.getAddress();

          if (address && !uniq[address] && !self.prune) {
            uniq[address] = true;
            batch.put('t/a/' + address + '/' + hash, DUMMY);
          }

          if (address)
            batch.put('u/a/' + address + '/' + key, DUMMY);
        }

        batch.put('u/t/' + key, bcoin.coin(tx, j).toRaw());
      }
    }

    self.emit('add block', block);

    self._pruneBlock(block, batch, function(err) {
      if (err)
        return callback(err);
      return callback(null, block);
    });
  });
};

/**
 * Disconnect block inputs.
 * @param {Block|Hash} block - {@link Block} or hash.
 * @param {Batch} batch
 * @param {Function} callback - Returns [Error, {@link Block}].
 */

ChainDB.prototype.disconnectBlock = function disconnectBlock(block, batch, callback) {
  var self = this;
  var i, j, tx, input, output, key, address, hash, uniq;

  if (this.options.spv)
    return utils.nextTick(callback);

  this._ensureHistory(block, function(err, block) {
    if (err)
      return callback(err);

    if (!block)
      return callback(new Error('Block not found.'));

    for (i = block.txs.length - 1; i >= 0; i--) {
      tx = block.txs[i];
      hash = tx.hash('hex');
      uniq = {};

      for (j = 0; j < tx.inputs.length; j++) {
        input = tx.inputs[j];
        key = input.prevout.hash + '/' + input.prevout.index;

        if (tx.isCoinbase())
          break;

        assert(input.coin);

        if (self.options.indexAddress) {
          address = input.getAddress();

          if (address && !uniq[address] && !self.prune) {
            uniq[address] = true;
            batch.del('t/a/' + address + '/' + hash);
          }

          if (address)
            batch.put('u/a/' + address + '/' + key, DUMMY);
        }

        batch.put('u/t/' + key, input.coin.toRaw());
      }

      for (j = 0; j < tx.outputs.length; j++) {
        output = tx.outputs[j];
        key = hash + '/' + j;

        if (self.options.indexAddress) {
          address = output.getAddress();

          if (address && !uniq[address] && !self.prune) {
            uniq[address] = true;
            batch.del('t/a/' + address + '/' + hash);
          }

          if (address)
            batch.del('u/a/' + address + '/' + key);
        }

        batch.del('u/t/' + key);
      }
    }

    self.emit('remove block', block);

    return callback(null, block);
  });
};

/**
 * Fill a transaction with coins (only unspents).
 * @param {TX} tx
 * @param {Function} callback - Returns [Error, {@link TX}].
 */

ChainDB.prototype.fillCoins = function fillCoins(tx, callback) {
  var self = this;

  if (Array.isArray(tx)) {
    return utils.forEachSerial(tx, function(tx, next) {
      self.fillCoins(tx, next);
    }, function(err) {
      if (err)
        return callback(err);
      return callback(null, tx);
    });
  }

  if (tx.isCoinbase())
    return utils.asyncify(callback)(null, tx);

  utils.forEachSerial(tx.inputs, function(input, next) {
    if (input.coin)
      return next();

    self.getCoin(input.prevout.hash, input.prevout.index, function(err, coin) {
      if (err)
        return callback(err);

      if (coin)
        input.coin = coin;

      next();
    });
  }, function(err) {
    if (err)
      return callback(err);
    return callback(null, tx);
  });
};

/**
 * Fill a transaction with coins (all historical coins).
 * @param {TX} tx
 * @param {Function} callback - Returns [Error, {@link TX}].
 */

ChainDB.prototype.fillHistory = function fillHistory(tx, callback) {
  var self = this;

  if (Array.isArray(tx)) {
    return utils.forEachSerial(tx, function(tx, next) {
      self.fillHistory(tx, next);
    }, function(err) {
      if (err)
        return callback(err);
      return callback(null, tx);
    });
  }

  if (tx.isCoinbase())
    return utils.asyncify(callback)(null, tx);

  if (this.prune) {
    return utils.forEachSerial(tx.inputs, function(input, next) {
      if (input.coin)
        return next();

      self._getPruneCoin(input.prevout.hash, input.prevout.index, function(err, coin) {
        if (err)
          return callback(err);

        if (coin)
          input.coin = coin;

        next();
      });
    }, function(err) {
      if (err)
        return callback(err);
      return callback(null, tx);
    });
  }

  utils.forEachSerial(tx.inputs, function(input, next) {
    if (input.coin)
      return next();

    self.getTX(input.prevout.hash, function(err, tx) {
      if (err)
        return next(err);

      if (tx)
        input.coin = bcoin.coin(tx, input.prevout.index);

      next();
    });
  }, function(err) {
    if (err)
      return callback(err);
    return callback(null, tx);
  });
};

/**
 * Get all coins pertinent to an address.
 * @param {Base58Address|Base58Address[]} addresses
 * @param {Function} callback - Returns [Error, {@link Coin}[]].
 */

ChainDB.prototype.getCoinsByAddress = function getCoinsByAddress(addresses, callback) {
  var self = this;
  var ids = [];
  var coins = [];

  if (typeof addresses === 'string')
    addresses = [addresses];

  addresses = utils.uniqs(addresses);

  utils.forEach(addresses, function(address, done) {
    var iter = self.db.iterator({
      gte: 'u/a/' + address + '/',
      lte: 'u/a/' + address + '/~',
      keys: true,
      values: true,
      fillCache: true,
      keyAsBuffer: false,
      valueAsBuffer: true
    });

    (function next() {
      iter.next(function(err, key, value) {
        var parts, hash, index;

        if (err) {
          return iter.end(function() {
            done(err);
          });
        }

        if (key === undefined)
          return iter.end(done);

        parts = key.split('/');
        hash = parts[3];
        index = +parts[4];

        ids.push([hash, index]);

        next();
      });
    })();
  }, function(err) {
    if (err)
      return callback(err);

    utils.forEach(ids, function(item, next) {
      var hash = item[0];
      var index = item[1];
      self.getCoin(hash, index, function(err, coin) {
        if (err)
          return next(err);

        if (!coin)
          return next();

        coins.push(coin);
        next();
      });
    }, function(err) {
      if (err)
        return callback(err);
      return callback(null, coins);
    });
  });
};

/**
 * Get a coin (unspents only).
 * @param {Hash} hash
 * @param {Number} index
 * @param {Function} callback - Returns [Error, {@link Coin}].
 */

ChainDB.prototype.getCoin = function getCoin(hash, index, callback) {
  var key = 'u/t/' + hash + '/' + index;
  var coin;

  this.db.get(key, function(err, data) {
    if (err && err.type !== 'NotFoundError')
      return callback(err);

    if (!data)
      return callback();

    try {
      coin = bcoin.coin.fromRaw(data);
      coin.hash = hash;
      coin.index = index;
    } catch (e) {
      return callback(e);
    }

    return callback(null, coin);
  });
};

/**
 * Get all transactions pertinent to an address.
 * @param {Base58Address|Base58Address[]} addresses
 * @param {Function} callback - Returns [Error, {@link TX}[]].
 */

ChainDB.prototype.getTXByAddress = function getTXByAddress(addresses, callback) {
  var self = this;
  var hashes = [];
  var txs = [];
  var have = {};

  if (typeof addresses === 'string')
    addresses = [addresses];

  addresses = utils.uniqs(addresses);

  utils.forEach(addresses, function(address, done) {
    var iter = self.db.iterator({
      gte: 't/a/' + address + '/',
      lte: 't/a/' + address + '/~',
      keys: true,
      values: true,
      fillCache: true,
      keyAsBuffer: false,
      valueAsBuffer: true
    });

    (function next() {
      iter.next(function(err, key, value) {
        var hash;

        if (err) {
          return iter.end(function() {
            done(err);
          });
        }

        if (key === undefined)
          return iter.end(done);

        hash = key.split('/')[3];

        if (addresses.length > 1) {
          if (have[hash])
            return next();

          have[hash] = true;
        }

        hashes.push(hash);

        next();
      });
    })();
  }, function(err) {
    if (err)
      return callback(err);

    utils.forEach(hashes, function(hash, next) {
      self.getTX(hash, function(err, tx) {
        if (err)
          return next(err);

        if (!tx)
          return next();

        txs.push(tx);
        next();
      });
    }, function(err) {
      if (err)
        return callback(err);
      return callback(null, txs);
    });
  });
};

/**
 * Retrieve a transaction (not filled with coins).
 * @param {Hash} hash
 * @param {Function} callback - Returns [Error, {@link TX}].
 */

ChainDB.prototype.getTX = function getTX(hash, callback) {
  var self = this;
  var key = 't/t/' + hash;
  var tx;

  this.db.get(key, function(err, data) {
    if (err) {
      if (err.type === 'NotFoundError')
        return callback();
      return callback(err);
    }

    try {
      tx = bcoin.tx.fromExtended(data);
    } catch (e) {
      return callback(e);
    }

    if (self.options.paranoid)
      assert(tx.hash('hex') === hash, 'Database is corrupt.');

    return callback(null, tx);
  });
};

/**
 * @param {Hash} hash
 * @param {Function} callback - Returns [Error, Boolean].
 */

ChainDB.prototype.hasTX = function hasTX(hash, callback) {
  return this.getTX(hash, function(err, tx) {
    if (err)
      return callback(err);

    return callback(null, tx != null);
  });
};

/**
 * Get a transaction and fill it with coins (historical).
 * @param {Hash} hash
 * @param {Function} callback - Returns [Error, {@link TX}].
 */

ChainDB.prototype.getFullTX = function getFullTX(hash, callback) {
  var self = this;

  return this.getTX(hash, function(err, tx) {
    if (err)
      return callback(err);

    if (!tx)
      return callback();

    return self.fillHistory(tx, function(err) {
      if (err)
        return callback(err);

      return callback(null, tx);
    });
  });
};

/**
 * Get a block and fill it with coins (historical).
 * @param {Hash} hash
 * @param {Function} callback - Returns [Error, {@link Block}].
 */

ChainDB.prototype.getFullBlock = function getFullBlock(hash, callback) {
  var self = this;

  return this.getBlock(hash, function(err, block) {
    if (err)
      return callback(err);

    if (!block)
      return callback();

    return self.fillHistory(block.txs, function(err) {
      if (err)
        return callback(err);

      return callback(null, block);
    });
  });
};

ChainDB.prototype._ensureBlock = function _ensureBlock(hash, callback) {
  var self = this;

  if (hash instanceof bcoin.block)
    return utils.asyncify(callback)(null, hash);

  return this.getBlock(hash, function(err, block) {
    if (err)
      return callback(err);

    if (!block)
      return callback();

    return self.fillBlock(block, callback);
  });
};

ChainDB.prototype._ensureHistory = function _ensureHistory(hash, callback) {
  var self = this;

  if (hash instanceof bcoin.block)
    return utils.asyncify(callback)(null, hash);

  return this.getBlock(hash, function(err, block) {
    if (err)
      return callback(err);

    if (!block)
      return callback();

    return self.fillHistoryBlock(block, callback);
  });
};

/**
 * Fill a block with coins (unspent only).
 * @param {Block} block
 * @param {Function} callback - Returns [Error, {@link Block}].
 */

ChainDB.prototype.fillBlock = function fillBlock(block, callback) {
  return this.fillCoins(block.txs, function(err) {
    var coins, i, tx, hash, j, input, key;

    if (err)
      return callback(err);

    coins = {};

    for (i = 0; i < block.txs.length; i++) {
      tx = block.txs[i];
      hash = tx.hash('hex');

      for (j = 0; j < tx.inputs.length; j++) {
        input = tx.inputs[j];
        key = input.prevout.hash + '/' + input.prevout.index;
        if (!input.coin && coins[key]) {
          input.coin = coins[key];
          delete coins[key];
        }
      }

      for (j = 0; j < tx.outputs.length; j++)
        coins[hash + '/' + j] = bcoin.coin(tx, j);
    }

    return callback(null, block);
  });
};

/**
 * Fill a block with coins (historical).
 * @param {Block} block
 * @param {Function} callback - Returns [Error, {@link Block}].
 */

ChainDB.prototype.fillHistoryBlock = function fillHistoryBlock(block, callback) {
  return this.fillHistory(block.txs, function(err) {
    var coins, i, tx, hash, j, input, key;

    if (err)
      return callback(err);

    coins = {};

    for (i = 0; i < block.txs.length; i++) {
      tx = block.txs[i];
      hash = tx.hash('hex');

      for (j = 0; j < tx.inputs.length; j++) {
        input = tx.inputs[j];
        key = input.prevout.hash + '/' + input.prevout.index;
        if (!input.coin && coins[key]) {
          input.coin = coins[key];
          delete coins[key];
        }
      }

      for (j = 0; j < tx.outputs.length; j++)
        coins[hash + '/' + j] = bcoin.coin(tx, j);
    }

    return callback(null, block);
  });
};

/**
 * Retrieve a block from the database (not filled with coins).
 * @param {Hash} hash
 * @param {Function} callback - Returns [Error, {@link Block}].
 */

ChainDB.prototype.getBlock = function getBlock(hash, callback) {
  var self = this;
  var key, block;

  return this.getHash(hash, function(err, hash) {
    if (err)
      return callback(err);

    if (!hash)
      return callback();

    key = 'b/b/' + hash;

    self.db.get(key, function(err, data) {
      if (err && err.type !== 'NotFoundError')
        return callback(err);

      if (!data)
        return callback();

      try {
        block = bcoin.block.parseCompact(data);
      } catch (e) {
        return callback(e);
      }

      block.txs = [];

      utils.forEach(block.hashes, function(hash, next, i) {
        self.getTX(hash, function(err, tx) {
          if (err)
            return next(err);

          if (!tx)
            return next(new Error('TX not found.'));

          block.txs[i] = tx;

          next();
        });
      }, function(err) {
        if (err)
          return callback(err);

        delete block.hashes;
        block = new bcoin.block(block);

        if (self.options.paranoid)
          assert(block.hash('hex') === hash, 'Database is corrupt.');

        return callback(null, block);
      });
    });
  });
};

ChainDB.prototype._getTX = function _getTX(hash, callback) {
  if (hash instanceof bcoin.tx)
    return callback(null, hash);
  return this.getTX(hash);
};

/**
 * Check whether a transaction is unspent (i.e. not yet _fully_ spent).
 * @see https://bitcointalk.org/index.php?topic=67738.0
 * @param {Hash} hash
 * @param {Function} callback - Returns [Error, Boolean].
 */

ChainDB.prototype.isUnspentTX = function isUnspentTX(hash, callback) {
  if (this.options.spv)
    return callback(null, false);

  return this.isSpentTX(hash, function(err, spent) {
    if (err)
      return callback(err);

    return callback(null, !spent);
  });
};

/**
 * Check whether a transaction is _fully_ spent.
 * @see https://bitcointalk.org/index.php?topic=67738.0
 * @param {Hash} hash
 * @param {Function} callback - Returns [Error, Boolean].
 */

ChainDB.prototype.isSpentTX = function isSpentTX(hash, callback) {
  if (hash.hash)
    hash = hash.hash('hex');

  var iter = this.db.iterator({
    gte: 'u/t/' + hash,
    lte: 'u/t/' + hash + '~',
    keys: true,
    values: false,
    fillCache: false,
    keyAsBuffer: false
  });

  iter.next(function(err, key, value) {
    if (err) {
      return iter.end(function() {
        callback(err);
      });
    }

    iter.end(function(err) {
      if (err)
        return callback(err);
      return callback(null, key === undefined);
    });
  });
};

ChainDB.prototype._pruneBlock = function _pruneBlock(block, batch, callback) {
  var futureHeight, i, j, key, tx, input;

  if (this.options.spv)
    return callback();

  if (!this.prune)
    return callback();

  if (block.height <= network.block.pruneAfterHeight)
    return callback();

  futureHeight = pad32(block.height + this.keepBlocks);

  batch.put('b/q/' + futureHeight, block.hash());

  for (i = 0; i < block.txs.length; i++) {
    tx = block.txs[i];

    for (j = 0; j < tx.inputs.length; j++) {
      input = tx.inputs[j];
      key = input.prevout.hash + '/' + input.prevout.index;

      if (tx.isCoinbase())
        break;

      assert(input.coin);

      batch.put('u/x/' + key, input.coin.toRaw());
      batch.put('u/q/' + futureHeight + '/' + key, DUMMY);
    }
  }

  this._pruneQueue(block, batch, callback);
};

ChainDB.prototype._pruneQueue = function _pruneQueue(block, batch, callback) {
  var self = this;
  var key = 'b/q/' + pad32(block.height);
  var i;

  this.db.get(key, function(err, hash) {
    if (err && err.type !== 'NotFoundError')
      return callback(err);

    if (!hash)
      return callback();

    hash = hash.toString('hex');

    self.db.get('b/b/' + hash, function(err, compact) {
      if (err && err.type !== 'NotFoundError')
        return callback(err);

      batch.del(key);

      if (!compact)
        return callback();

      try {
        compact = bcoin.block.parseCompact(compact);
      } catch (e) {
        return callback(e);
      }

      batch.del('b/b/' + hash);

      for (i = 0; i < compact.hashes.length; i++)
        batch.del('t/t/' + compact.hashes[i]);

      self._pruneCoinQueue(block, batch, callback);
    });
  });
};

ChainDB.prototype._pruneCoinQueue = function _pruneQueue(block, batch, callback) {
  var iter = this.db.iterator({
    gte: 'u/q/' + pad32(block.height),
    lte: 'u/q/' + pad32(block.height) + '~',
    keys: true,
    values: false,
    fillCache: false,
    keyAsBuffer: false
  });

  (function next() {
    iter.next(function(err, key, value) {
      var parts, hash, index;

      if (err) {
        return iter.end(function() {
          callback(err);
        });
      }

      if (key === undefined)
        return iter.end(callback);

      parts = key.split('/');
      hash = parts[3];
      index = +parts[4];

      batch.del(key);
      batch.del('u/x/' + hash + '/' + index);

      next();
    });
  })();
};

ChainDB.prototype._getPruneCoin = function _getPruneCoin(hash, index, callback) {
  var self = this;
  var key = 'u/x/' + hash + '/' + index;
  var coin;

  this.db.get(key, function(err, data) {
    if (err && err.type !== 'NotFoundError')
      return callback(err);

    if (!data)
      return self.getCoin(hash, index, callback);

    try {
      coin = bcoin.coin.fromRaw(data);
      coin.hash = hash;
      coin.index = index;
    } catch (e) {
      return callback(e);
    }

    return callback(null, coin);
  });
};

function DumbCache(size) {
  this.data = {};
  this.count = 0;
  this.size = size;
}

DumbCache.prototype.set = function set(key, value) {
  key = key + '';

  assert(value !== undefined);

  if (this.count > this.size)
    this.reset();

  if (this.data[key] === undefined)
    this.count++;

  this.data[key] = value;
};

DumbCache.prototype.remove = function remove(key) {
  key = key + '';

  if (this.data[key] === undefined)
    return;

  this.count--;
  delete this.data[key];
};

DumbCache.prototype.get = function get(key) {
  key = key + '';
  return this.data[key];
};

DumbCache.prototype.has = function has(key) {
  key = key + '';
  return this.data[key] !== undefined;
};

DumbCache.prototype.reset = function reset() {
  this.data = {};
  this.count = 0;
};

function NullCache(size) {}

NullCache.prototype.set = function set(key, value) {};
NullCache.prototype.remove = function remove(key) {};
NullCache.prototype.get = function get(key) {};
NullCache.prototype.has = function has(key) {};
NullCache.prototype.reset = function reset() {};

/**
 * Expose
 */

return ChainDB;
};
