/*!
 * chaindb.js - blockchain data management for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var bcoin = require('../env');
var AsyncObject = require('../utils/async');
var constants = bcoin.constants;
var utils = require('../utils/utils');
var assert = utils.assert;
var DUMMY = new Buffer([0]);
var BufferWriter = require('../utils/writer');
var BufferReader = require('../utils/reader');

/*
 * Database Layout:
 *   R -> tip hash
 *   e[hash] -> entry
 *   h[hash] -> height
 *   H[height] -> hash
 *   n[hash] -> next hash
 *   b[hash] -> block
 *   t[hash] -> extended tx
 *   c[hash] -> coins
 *   u[hash] -> undo coins
 *   T[addr-hash][hash] -> dummy (tx by address)
 *   C[addr-hash][hash][index] -> dummy (coin by address)
 *   W+T[witaddr-hash][hash] -> dummy (tx by address)
 *   W+C[witaddr-hash][hash][index] -> dummy (coin by address)
 *   q[height] -> block hash to be pruned
 */

/* String keys
var layout = {
  R: 'R',
  e: function e(hash) {
    return 'e' + hash;
  },
  h: function h(hash) {
    return 'h' + hash;
  },
  H: function H(height) {
    return 'H' + pad32(height);
  },
  n: function n(hash) {
    return 'n' + hash;
  },
  b: function b(hash) {
    return 'b' + hash;
  },
  t: function t(hash) {
    return 't' + hash;
  },
  c: function c(hash) {
    return 'c' + hash;
  },
  u: function u(hash) {
    return 'u' + hash;
  },
  q: function q(height) {
    return 'q' + pad32(height);
  },
  T: function T(address, hash) {
    var len = address.length;
    var key;

    if (address.length === 64)
      return 'W' + address + hash;

    return 'T' + address + hash;
  },
  C: function C(address, hash, index) {
    var len = address.length;
    var key;

    if (address.length === 64)
      return 'X' + address + hash + pad32(index);

    return 'C' + address + hash + pad32(index);
  },
  Cc: function Cc(key) {
    var hash, index;

    if (key.length === 139) {
      hash = key.slice(65, 129);
      index = +key.slice(129);
    } else {
      hash = key.slice(41, 105).toString('hex');
      index = +key.slice(105);
    }

    return [hash, index];
  },
  Tt: function Tt(key) {
    return key.length === 129
      ? key.slice(64)
      : key.slice(41);
  }
};
*/

var layout = {
  R: new Buffer([0x52]),
  e: function e(hash) {
    return pair(0x65, hash);
  },
  h: function h(hash) {
    return pair(0x68, hash);
  },
  H: function H(height) {
    return ipair(0x48, height);
  },
  n: function n(hash) {
    return pair(0x6e, hash);
  },
  b: function b(hash) {
    return pair(0x62, hash);
  },
  t: function t(hash) {
    return pair(0x74, hash);
  },
  c: function c(hash) {
    return pair(0x63, hash);
  },
  u: function u(hash) {
    return pair(0x75, hash);
  },
  q: function q(height) {
    return ipair(0x71, height);
  },
  T: function T(address, hash) {
    var len = address.length;
    var key;

    if (typeof address === 'string')
      len /= 2;

    if (len === 32) {
      key = new Buffer(65);
      key[0] = 0xab; // W + T
      write(key, address, 1);
      write(key, hash, 33);
    } else {
      key = new Buffer(53);
      key[0] = 0x54; // T
      write(key, address, 1);
      write(key, hash, 21);
    }

    return key;
  },
  C: function C(address, hash, index) {
    var len = address.length;
    var key;

    if (typeof address === 'string')
      len /= 2;

    if (len === 32) {
      key = new Buffer(69);
      key[0] = 0x9a; // W + C
      write(key, address, 1);
      write(key, hash, 33);
      key.writeUInt32BE(index, 65, true);
    } else {
      key = new Buffer(57);
      key[0] = 0x43; // C
      write(key, address, 1);
      write(key, hash, 21);
      key.writeUInt32BE(index, 53, true);
    }

    return key;
  },
  Cc: function Cc(key) {
    var hash, index;

    if (key.length === 69) {
      hash = key.slice(33, 65).toString('hex');
      index = key.readUInt32BE(65, 0);
    } else {
      hash = key.slice(21, 53).toString('hex');
      index = key.readUInt32BE(53, 0);
    }

    return [hash, index];
  },
  Tt: function Tt(key) {
    return key.length === 65
      ? key.slice(33).toString('hex')
      : key.slice(21).toString('hex');
  }
};

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
 * @param {String?} options.name - Database name
 * @param {String?} options.location - Database location
 * @param {String?} options.db - Database backend name
 * @property {Boolean} prune
 * @property {Boolean} loaded
 * @property {Number} keepBlocks
 * @emits ChainDB#open
 * @emits ChainDB#error
 */

function ChainDB(chain, options) {
  if (!(this instanceof ChainDB))
    return new ChainDB(chain, options);

  if (!options)
    options = {};

  AsyncObject.call(this);

  this.options = options;
  this.chain = chain;
  this.logger = chain.logger;
  this.network = this.chain.network;

  this.db = bcoin.ldb({
    location: this.options.location,
    db: this.options.db,
    compression: true,
    cacheSize: 16 << 20,
    writeBufferSize: 8 << 20,
    bufferKeys: true
  });

  this.keepBlocks = options.keepBlocks || 288;
  this.prune = !!options.prune;
  this.state = new ChainState();
  this.pending = null;
  this.current = null;

  this.loaded = false;

  // We want at least 1 retarget interval cached
  // for retargetting, but we need at least two
  // cached for optimal versionbits state checks.
  // We add a padding of 100 for forked chains,
  // reorgs, chain locator creation and the bip34
  // check.
  this.cacheWindow = (this.network.pow.retargetInterval + 1) * 2 + 100;

  // We want to keep the last 5 blocks of unspents in memory.
  this.coinWindow = 25 << 20;

  this.coinCache = new bcoin.lru.nil();
  this.cacheHash = new bcoin.lru(this.cacheWindow);
  this.cacheHeight = new bcoin.lru(this.cacheWindow);

  if (this.options.coinCache)
    this.coinCache = new bcoin.lru(this.coinWindow, getSize);
}

utils.inherits(ChainDB, AsyncObject);

/**
 * Database layout.
 * @type {Object}
 */

ChainDB.layout = layout;

/**
 * Open the chain db, wait for the database to load.
 * @alias ChainDB#open
 * @param {Function} callback
 */

ChainDB.prototype._open = function open(callback) {
  var self = this;
  var genesis, block;

  this.logger.info('Starting chain load.');

  function done(err) {
    if (err)
      return callback(err);

    self.logger.info('Chain successfully loaded.');
    self.logger.info('Chain State: hash=%s tx=%d coin=%d value=%s.',
      self.state.rhash,
      self.state.tx,
      self.state.coin,
      utils.btc(self.state.value)
    );

    self.db.checkVersion('V', 1, callback);
  }

  this.db.open(function(err) {
    if (err)
      return done(err);

    self.db.has(layout.e(self.network.genesis.hash), function(err, exists) {
      if (err)
        return done(err);

      if (exists)
        return self.initState(done);

      block = bcoin.block.fromRaw(self.network.genesisBlock, 'hex');
      block.setHeight(0);

      genesis = bcoin.chainentry.fromBlock(self.chain, block);

      self.save(genesis, block, null, true, done);
    });
  });
};

/**
 * Close the chain db, wait for the database to close.
 * @alias ChainDB#close
 * @param {Function} callback
 */

ChainDB.prototype._close = function close(callback) {
  this.db.close(callback);
};

/**
 * Start a batch.
 * @returns {Batch}
 */

ChainDB.prototype.start = function start() {
  assert(!this.current);
  assert(!this.pending);
  this.current = this.db.batch();
  this.pending = this.state.clone();
  return this.current;
};

/**
 * Put key and value to current batch.
 * @param {String} key
 * @param {Buffer} value
 */

ChainDB.prototype.put = function put(key, value) {
  assert(this.current);
  this.current.put(key, value);
};

/**
 * Delete key from current batch.
 * @param {String} key
 */

ChainDB.prototype.del = function del(key) {
  assert(this.current);
  this.current.del(key);
};

/**
 * Get current batch.
 * @returns {Batch}
 */

ChainDB.prototype.batch = function batch() {
  assert(this.current);
  return this.current;
};

/**
 * Drop current batch.
 * @returns {Batch}
 */

ChainDB.prototype.drop = function drop() {
  assert(this.current);
  assert(this.pending);
  this.current.clear();
  this.current = null;
  this.pending = null;
};

/**
 * Commit current batch.
 * @param {Function} callback
 */

ChainDB.prototype.commit = function commit(callback) {
  var self = this;

  assert(this.current);
  assert(this.pending);

  this.current.write(function(err) {
    if (err) {
      self.current = null;
      self.pending = null;
      return callback(err);
    }

    self.current = null;

    // Overwrite the entire state
    // with our new best state
    // only if it is committed.
    // Note that alternate chain
    // tips do not commit anything.
    if (self.pending.committed)
      self.state = self.pending;

    self.pending = null;

    callback();
  });
};

/**
 * Add an entry to the LRU cache.
 * @param {ChainEntry} entry
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
  checkHash(hash);

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
  checkHash(hash);

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
  var entry;

  checkHash(hash);

  if (typeof hash === 'number') {
    callback = utils.asyncify(callback);
    return callback(null, hash);
  }

  if (hash === constants.NULL_HASH) {
    callback = utils.asyncify(callback);
    return callback(null, -1);
  }

  entry = this.cacheHash.get(hash);

  if (entry) {
    callback = utils.asyncify(callback);
    return callback(null, entry.height);
  }

  this.db.fetch(layout.h(hash), function(data) {
    assert(data.length === 4, 'Database corruption.');
    return data.readUInt32LE(0, true);
  }, function(err, height) {
    if (err)
      return callback(err);

    if (height == null)
      return callback(null, -1);

    callback(null, height);
  });
};

/**
 * Get the hash of a block by height. Note that this
 * will only return hashes in the main chain.
 * @param {Number} height
 * @param {Function} callback - Returns [Error, {@link Hash}].
 */

ChainDB.prototype.getHash = function getHash(height, callback) {
  var entry;

  checkHash(height);

  if (typeof height === 'string') {
    callback = utils.asyncify(callback);
    return callback(null, height);
  }

  entry = this.cacheHeight.get(height);

  if (entry) {
    callback = utils.asyncify(callback);
    return callback(null, entry.hash);
  }

  this.db.fetch(layout.H(height), function(data) {
    assert(data.length === 32, 'Database corruption.');
    return data.toString('hex');
  }, callback);
};

/**
 * Get the current chain height from the tip record.
 * @param {Function} callback - Returns [Error, Number].
 */

ChainDB.prototype.getChainHeight = function getChainHeight(callback) {
  this.getTip(function(err, entry) {
    if (err)
      return callback(err);

    if (!entry)
      return callback(null, -1);

    callback(null, entry.height);
  });
};

/**
 * Get both hash and height depending on the value passed in.
 * @param {Hash|Number} block - Can be a has or height.
 * @param {Function} callback - Returns [Error, {@link Hash}, Number].
 */

ChainDB.prototype.getBoth = function getBoth(block, callback) {
  var hash, height;

  checkHash(block);

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

      callback(null, hash, height);
    });
  }

  this.getHeight(hash, function(err, height) {
    if (err)
      return callback(err);

    if (height === -1)
      hash = null;

    callback(null, hash, height);
  });
};

/**
 * Retrieve a chain entry but do _not_ add it to the LRU cache.
 * @param {Hash} hash
 * @param {Function} callback - Returns [Error, {@link ChainEntry}].
 */

ChainDB.prototype.getEntry = function getEntry(hash, callback) {
  var self = this;
  var entry;

  checkHash(hash);

  this.getHash(hash, function(err, hash) {
    if (err)
      return callback(err);

    if (!hash)
      return callback();

    entry = self.cacheHash.get(hash);

    if (entry)
      return callback(null, entry);

    self.db.fetch(layout.e(hash), function(data) {
      return bcoin.chainentry.fromRaw(self.chain, data);
    }, callback);
  });
};

/**
 * Retrieve a chain entry and add it to the LRU cache.
 * @param {Hash} hash
 * @param {Function} callback - Returns [Error, {@link ChainEntry}].
 */

ChainDB.prototype.get = function get(hash, callback) {
  var self = this;

  this.getEntry(hash, function(err, entry) {
    if (err)
      return callback(err);

    if (!entry)
      return callback();

    // There's no efficient way to check whether
    // this is in the main chain or not, so
    // don't add it to the height cache.
    self.cacheHash.set(entry.hash, entry);

    callback(null, entry);
  });
};

/**
 * Save an entry to the database and optionally
 * connect it as the tip. Note that this method
 * does _not_ perform any verification which is
 * instead performed in {@link Chain#add}.
 * @param {ChainEntry} entry
 * @param {Block} block
 * @param {CoinView} view
 * @param {Boolean} connect - Whether to connect the
 * block's inputs and add it as a tip.
 * @param {Function} callback
 */

ChainDB.prototype.save = function save(entry, block, view, connect, callback) {
  var self = this;
  var hash = block.hash();
  var height = new Buffer(4);

  this.start();

  height.writeUInt32LE(entry.height, 0, true);

  this.put(layout.h(hash), height);
  this.put(layout.e(hash), entry.toRaw());

  this.cacheHash.set(entry.hash, entry);

  if (!connect) {
    return this.saveBlock(block, view, false, function(err) {
      if (err) {
        self.drop();
        return callback(err);
      }
      self.commit(callback);
    });
  }

  this.cacheHeight.set(entry.height, entry);

  this.put(layout.n(entry.prevBlock), hash);
  this.put(layout.H(entry.height), hash);

  this.saveBlock(block, view, true, function(err) {
    if (err) {
      self.drop();
      return callback(err);
    }
    self.put(layout.R, self.pending.commit(hash));
    self.commit(callback);
  });
};

/**
 * Retrieve the chain state.
 * @param {Function} callback - Returns [Error, {@link ChainState}].
 */

ChainDB.prototype.initState = function initState(callback) {
  var self = this;
  this.db.fetch(layout.R, function(data) {
    return ChainState.fromRaw(data);
  }, function(err, state) {
    if (err)
      return callback(err);
    assert(state);
    self.state = state;
    return callback(null, state);
  });
};

/**
 * Retrieve the tip entry from the tip record.
 * @param {Function} callback - Returns [Error, {@link ChainEntry}].
 */

ChainDB.prototype.getTip = function getTip(callback) {
  this.get(this.state.hash, callback);
};

/**
 * Reconnect the block to the chain.
 * @param {ChainEntry} entry
 * @param {Block} block
 * @param {CoinView} view
 * @param {Function} callback -
 * Returns [Error, {@link ChainEntry}, {@link Block}].
 */

ChainDB.prototype.reconnect = function reconnect(entry, block, view, callback) {
  var self = this;
  var hash = block.hash();

  this.start();

  this.put(layout.n(entry.prevBlock), hash);
  this.put(layout.H(entry.height), hash);

  this.cacheHash.set(entry.hash, entry);
  this.cacheHeight.set(entry.height, entry);

  this.connectBlock(block, view, function(err) {
    if (err) {
      self.drop();
      return callback(err);
    }

    self.put(layout.R, self.pending.commit(hash));
    self.commit(function(err) {
      if (err)
        return callback(err);
      callback(null, entry, block);
    });
  });
};

/**
 * Disconnect block from the chain.
 * @param {ChainEntry} entry
 * @param {Function} callback -
 * Returns [Error, {@link ChainEntry}, {@link Block}].
 */

ChainDB.prototype.disconnect = function disconnect(entry, callback) {
  var self = this;

  this.start();
  this.del(layout.n(entry.prevBlock));
  this.del(layout.H(entry.height));

  this.cacheHeight.remove(entry.height);

  if (this.options.spv) {
    this.put(layout.R, this.pending.commit(entry.prevBlock));
    return this.commit(function(err) {
      if (err)
        return callback(err);
      callback(null, entry, entry.toHeaders());
    });
  }

  this.getBlock(entry.hash, function(err, block) {
    if (err) {
      self.drop();
      return callback(err);
    }

    if (!block) {
      self.drop();
      return callback(new Error('Block not found.'));
    }

    self.disconnectBlock(block, function(err) {
      if (err) {
        self.drop();
        return callback(err);
      }

      self.put(layout.R, self.pending.commit(entry.prevBlock));
      self.commit(function(err) {
        if (err)
          return callback(err);
        callback(null, entry, block);
      });
    });
  });
};

/**
 * Get the _next_ block hash (does not work by height).
 * @param {Hash} hash
 * @param {Function} callback - Returns [Error, {@link Hash}].
 */

ChainDB.prototype.getNextHash = function getNextHash(hash, callback) {
  return this.db.fetch(layout.n(hash), function(data) {
    assert(data.length === 32, 'Database corruption.');
    return data.toString('hex');
  }, callback);
};

/**
 * Check to see if a block is on the main chain.
 * @param {ChainEntry|Hash} hash
 * @param {Function} callback - Returns [Error, Boolean].
 */

ChainDB.prototype.isMainChain = function isMainChain(hash, callback) {
  var self = this;
  var query;

  if (hash instanceof bcoin.chainentry) {
    query = hash.height;
    hash = hash.hash;
  } else {
    query = hash;
  }

  if (hash === this.chain.tip.hash
      || hash === this.network.genesis.hash) {
    return utils.asyncify(callback)(null, true);
  }

  this.getHeight(query, function(err, height) {
    if (err)
      return callback(err);

    self.getHash(height, function(err, existing) {
      if (err)
        return callback(err);

      if (!existing)
        return callback(null, false);

      callback(null, hash === existing);
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

        self.start();

        if (tip.hash === entry.hash) {
          self.put(layout.R, self.pending.commit(tip.hash));
          return self.commit(callback);
        }

        self.del(layout.H(tip.height));
        self.del(layout.h(tip.hash));
        self.del(layout.e(tip.hash));
        self.del(layout.n(tip.prevBlock));

        self.removeBlock(tip.hash, function(err) {
          if (err) {
            self.drop();
            return callback(err);
          }

          self.commit(function(err) {
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
 * main chain or an alternate chain. Alternate chains will only
 * be tested if the lookup is done by hash.
 * @param {Hash|Number} height - Hash or height.
 * @param {Function} callback - Returns [Error, Boolean].
 */

ChainDB.prototype.has = function has(height, callback) {
  checkHash(height);

  this.getBoth(height, function(err, hash, height) {
    if (err)
      return callback(err);
    callback(null, hash != null);
  });
};

/**
 * Save a block (not an entry) to the
 * database and potentially connect the inputs.
 * @param {Block} block
 * @param {Boolean} connect - Whether to connect the inputs.
 * @param {Function} callback - Returns [Error, {@link Block}].
 */

ChainDB.prototype.saveBlock = function saveBlock(block, view, connect, callback) {
  if (this.options.spv)
    return utils.asyncify(callback)(null, block);

  this.put(layout.b(block.hash()), block.toRaw());

  if (!connect)
    return utils.asyncify(callback)(null, block);

  this.connectBlock(block, view, callback);
};

/**
 * Remove a block (not an entry) to the database.
 * Disconnect inputs.
 * @param {Block|Hash} block - {@link Block} or hash.
 * @param {Function} callback - Returns [Error, {@link Block}].
 */

ChainDB.prototype.removeBlock = function removeBlock(hash, callback) {
  var self = this;

  this.getBlock(hash, function(err, block) {
    if (err)
      return callback(err);

    if (!block)
      return callback();

    self.del(layout.b(block.hash()));

    self.disconnectBlock(block, callback);
  });
};

/**
 * Connect block inputs.
 * @param {Block} block
 * @param {Function} callback - Returns [Error, {@link Block}].
 */

ChainDB.prototype.connectBlock = function connectBlock(block, view, callback) {
  var undo = new BufferWriter();
  var i, j, tx, input, output, prev;
  var hashes, address, hash, coins, raw;

  if (this.options.spv)
    return utils.asyncify(callback)(null, block);

  // Genesis block's coinbase is unspendable.
  if (this.chain.isGenesis(block)) {
    this.pending.connect(block);
    return utils.asyncify(callback)(null, block);
  }

  this.pending.connect(block);

  for (i = 0; i < block.txs.length; i++) {
    tx = block.txs[i];
    hash = tx.hash();

    if (this.options.indexTX) {
      this.put(layout.t(hash), tx.toExtended());
      if (this.options.indexAddress) {
        hashes = tx.getHashes();
        for (j = 0; j < hashes.length; j++) {
          address = hashes[j];
          this.put(layout.T(address, hash), DUMMY);
        }
      }
    }

    if (!tx.isCoinbase()) {
      for (j = 0; j < tx.inputs.length; j++) {
        input = tx.inputs[j];

        assert(input.coin);

        if (this.options.indexAddress) {
          address = input.getHash();
          if (address) {
            prev = input.prevout;
            this.del(layout.C(address, prev.hash, prev.index));
          }
        }

        // Add coin to set of undo
        // coins for the block.
        input.coin.toRaw(undo);

        this.pending.spend(input.coin);
      }
    }

    for (j = 0; j < tx.outputs.length; j++) {
      output = tx.outputs[j];

      if (output.script.isUnspendable())
        continue;

      if (this.options.indexAddress) {
        address = output.getHash();
        if (address)
          this.put(layout.C(address, hash, j), DUMMY);
      }

      this.pending.add(output);
    }
  }

  // Commit new coin state.
  view = view.toArray();

  for (i = 0; i < view.length; i++) {
    coins = view[i];
    raw = coins.toRaw();
    if (!raw) {
      this.del(layout.c(coins.hash));
      this.coinCache.remove(coins.hash);
    } else {
      this.put(layout.c(coins.hash), raw);
      this.coinCache.set(coins.hash, raw);
    }
  }

  // Write undo coins (if there are any).
  if (undo.written > 0)
    this.put(layout.u(block.hash()), undo.render());

  this.pruneBlock(block, function(err) {
    if (err)
      return callback(err);
    callback(null, block);
  });
};

/**
 * Disconnect block inputs.
 * @param {Block|Hash} block - {@link Block} or hash.
 * @param {Function} callback - Returns [Error, {@link Block}].
 */

ChainDB.prototype.disconnectBlock = function disconnectBlock(block, callback) {
  var self = this;
  var i, j, tx, input, output, prev;
  var hashes, address, hash, coins, raw;

  if (this.options.spv)
    return utils.asyncify(callback)(null, block);

  this.getUndoView(block, function(err, view) {
    if (err)
      return callback(err);

    self.pending.disconnect(block);

    for (i = block.txs.length - 1; i >= 0; i--) {
      tx = block.txs[i];
      hash = tx.hash('hex');

      if (self.options.indexTX) {
        self.del(layout.t(hash));
        if (self.options.indexAddress) {
          hashes = tx.getHashes();
          for (j = 0; j < hashes.length; j++) {
            address = hashes[j];
            self.del(layout.T(address, hash));
          }
        }
      }

      if (!tx.isCoinbase()) {
        for (j = 0; j < tx.inputs.length; j++) {
          input = tx.inputs[j];

          assert(input.coin);

          if (self.options.indexAddress) {
            address = input.getHash();
            if (address) {
              prev = input.prevout;
              self.put(layout.C(address, prev.hash, prev.index), DUMMY);
            }
          }

          self.pending.add(input.coin);
        }
      }

      // Add all of the coins we are about to
      // remove. This is to ensure they appear
      // in the view array below.
      view.addTX(tx);

      for (j = 0; j < tx.outputs.length; j++) {
        output = tx.outputs[j];

        if (output.script.isUnspendable())
          continue;

        if (self.options.indexAddress) {
          address = output.getHash();
          if (address)
            self.del(layout.C(address, hash, j));
        }

        // Spend added coin.
        view.spend(hash, j);

        self.pending.spend(output);
      }
    }

    // Commit new coin state.
    view = view.toArray();

    for (i = 0; i < view.length; i++) {
      coins = view[i];
      raw = coins.toRaw();
      if (!raw) {
        self.del(layout.c(coins.hash));
        self.coinCache.remove(coins.hash);
      } else {
        self.put(layout.c(coins.hash), raw);
        self.coinCache.set(coins.hash, raw);
      }
    }

    self.del(layout.u(block.hash()));

    callback(null, block);
  });
};

/**
 * Fill a transaction with coins (only unspents).
 * @param {TX} tx
 * @param {Function} callback - Returns [Error, {@link TX}].
 */

ChainDB.prototype.fillCoins = function fillCoins(tx, callback) {
  var self = this;

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
    callback(null, tx);
  });
};

/**
 * Fill a transaction with coins (all historical coins).
 * @param {TX} tx
 * @param {Function} callback - Returns [Error, {@link TX}].
 */

ChainDB.prototype.fillHistory = function fillHistory(tx, callback) {
  var self = this;

  if (!this.options.indexTX)
    return utils.asyncify(callback)(null, tx);

  if (tx.isCoinbase())
    return utils.asyncify(callback)(null, tx);

  utils.forEachSerial(tx.inputs, function(input, next) {
    if (input.coin)
      return next();

    self.getTX(input.prevout.hash, function(err, tx) {
      if (err)
        return next(err);

      if (tx)
        input.coin = bcoin.coin.fromTX(tx, input.prevout.index);

      next();
    });
  }, function(err) {
    if (err)
      return callback(err);
    callback(null, tx);
  });
};

/**
 * Get a coin (unspents only).
 * @param {Hash} hash
 * @param {Number} index
 * @param {Function} callback - Returns [Error, {@link Coin}].
 */

ChainDB.prototype.getCoin = function getCoin(hash, index, callback) {
  var self = this;
  var coins = this.coinCache.get(hash);

  if (coins) {
    callback = utils.asyncify(callback);

    try {
      coins = bcoin.coins.parseCoin(coins, hash, index);
    } catch (e) {
      return callback(e);
    }

    return callback(null, coins);
  }

  this.db.fetch(layout.c(hash), function(data) {
    self.coinCache.set(hash, data);
    return bcoin.coins.parseCoin(data, hash, index);
  }, callback);
};

/**
 * Get coins (unspents only).
 * @param {Hash} hash
 * @param {Function} callback - Returns [Error, {@link Coins}].
 */

ChainDB.prototype.getCoins = function getCoins(hash, callback) {
  var self = this;
  var coins = this.coinCache.get(hash);

  if (coins) {
    callback = utils.asyncify(callback);

    try {
      coins = bcoin.coins.fromRaw(coins, hash);
    } catch (e) {
      return callback(e);
    }

    return callback(null, coins);
  }

  this.db.fetch(layout.c(hash), function(data) {
    self.coinCache.set(hash, data);
    return bcoin.coins.fromRaw(data, hash);
  }, callback);
};

/**
 * Scan the blockchain for transactions containing specified address hashes.
 * @param {Hash} start - Block hash to start at.
 * @param {Hash[]} hashes - Address hashes.
 * @param {Function} iter - Iterator. Accepts ({@link TX}, {@link Function}).
 * @param {Function} callback
 */

ChainDB.prototype.scan = function scan(start, filter, iter, callback) {
  var self = this;
  var total = 0;
  var i, j, hashes, address, tx, txs;

  if (start == null)
    start = this.network.genesis.hash;

  if (typeof start === 'number')
    this.logger.info('Scanning from height %d.', start);
  else
    this.logger.info('Scanning from block %s.', utils.revHex(start));

  if (Array.isArray(filter))
    filter = utils.toMap(filter);

  (function next(err, hash) {
    if (err)
      return callback(err);

    if (hash == null) {
      self.logger.info('Finished scanning %d blocks.', total);
      return callback();
    }

    total++;

    self.getEntry(hash, function(err, entry) {
      if (err)
        return next(err);

      if (!entry)
        return next();

      self.getFullBlock(hash, function(err, block) {
        if (err)
          return next(err);

        if (!block)
          return next();

        self.logger.info('Scanning block %s (%d).',
          utils.revHex(entry.hash),
          block.height);

        txs = [];

        for (i = 0; i < block.txs.length; i++) {
          tx = block.txs[i];
          hashes = tx.getHashes('hex');

          for (j = 0; j < hashes.length; j++) {
            address = hashes[j];
            if (filter[address]) {
              txs.push(tx);
              break;
            }
          }
        }

        iter(entry, txs, function(err) {
          if (err)
            return next(err);
          self.getNextHash(entry.hash, next);
        });
      });
    });
  })(null, start);
};

/**
 * Retrieve a transaction (not filled with coins).
 * @param {Hash} hash
 * @param {Function} callback - Returns [Error, {@link TX}].
 */

ChainDB.prototype.getTX = function getTX(hash, callback) {
  if (!this.options.indexTX)
    return utils.nextTick(callback);

  this.db.fetch(layout.t(hash), function(data) {
    return bcoin.tx.fromExtended(data);
  }, callback);
};

/**
 * @param {Hash} hash
 * @param {Function} callback - Returns [Error, Boolean].
 */

ChainDB.prototype.hasTX = function hasTX(hash, callback) {
  if (!this.options.indexTX)
    return utils.asyncify(callback)(null, false);

  this.db.has(layout.t(hash), callback);
};

/**
 * Get all coins pertinent to an address.
 * @param {Address[]} addresses
 * @param {Function} callback - Returns [Error, {@link Coin}[]].
 */

ChainDB.prototype.getCoinsByAddress = function getCoinsByAddress(addresses, callback) {
  var self = this;
  var coins = [];

  if (!this.options.indexAddress)
    return utils.asyncify(callback)(null, coins);

  if (!Array.isArray(addresses))
    addresses = [addresses];

  utils.forEachSerial(addresses, function(address, next) {
    var hash = bcoin.address.getHash(address);

    if (!hash)
      return next();

    self.db.iterate({
      gte: layout.C(hash, constants.ZERO_HASH, 0),
      lte: layout.C(hash, constants.MAX_HASH, 0xffffffff),
      parse: layout.Cc
    }, function(err, keys) {
      if (err)
        return next(err);

      utils.forEachSerial(keys, function(key, next) {
        self.getCoin(key[0], key[1], function(err, coin) {
          if (err)
            return callback(err);

          if (coin)
            coins.push(coin);

          next();
        });
      }, next);
    });
  }, function(err) {
    if (err)
      return callback(err);
    callback(null, coins);
  });
};

/**
 * Get all entries.
 * @param {Function} callback - Returns [Error, {@link ChainEntry}[]].
 */

ChainDB.prototype.getEntries = function getEntries(callback) {
  var self = this;
  this.db.iterate({
    gte: layout.e(constants.ZERO_HASH),
    lte: layout.e(constants.MAX_HASH),
    keys: false,
    values: true,
    parse: function(key, value) {
      return bcoin.chainentry.fromRaw(self.chain, value);
    }
  }, callback);
};

/**
 * Get all transaction hashes to an address.
 * @param {Address[]} addresses
 * @param {Function} callback - Returns [Error, {@link Hash}[]].
 */

ChainDB.prototype.getHashesByAddress = function getHashesByAddress(addresses, callback) {
  var self = this;
  var hashes = {};

  if (!this.options.indexTX || !this.options.indexAddress)
    return utils.asyncify(callback)(null, []);

  utils.forEachSerial(addresses, function(address, next) {
    var hash = bcoin.address.getHash(address);

    if (!hash)
      return next();

    self.db.iterate({
      gte: layout.T(hash, constants.ZERO_HASH),
      lte: layout.T(hash, constants.MAX_HASH),
      parse: function(key) {
        var hash = layout.Tt(key);
        hashes[hash] = true;
      }
    }, next);
  }, function(err) {
    if (err)
      return callback(err);
    callback(null, Object.keys(hashes));
  });
};

/**
 * Get all transactions pertinent to an address.
 * @param {Address[]} addresses
 * @param {Function} callback - Returns [Error, {@link TX}[]].
 */

ChainDB.prototype.getTXByAddress = function getTXByAddress(addresses, callback) {
  var self = this;
  var txs = [];

  if (!this.options.indexTX || !this.options.indexAddress)
    return utils.asyncify(callback)(null, txs);

  if (!Array.isArray(addresses))
    addresses = [addresses];

  this.getHashesByAddress(addresses, function(err, hashes) {
    if (err)
      return callback(err);

    utils.forEachSerial(hashes, function(hash, next) {
      self.getTX(hash, function(err, tx) {
        if (err)
          return next(err);
        txs.push(tx);
        next();
      });
    }, function(err) {
      if (err)
        return callback(err);
      callback(null, txs);
    });
  });
};

/**
 * Get a transaction and fill it with coins (historical).
 * @param {Hash} hash
 * @param {Function} callback - Returns [Error, {@link TX}].
 */

ChainDB.prototype.getFullTX = function getFullTX(hash, callback) {
  var self = this;

  if (!this.options.indexTX)
    return utils.nextTick(callback);

  this.getTX(hash, function(err, tx) {
    if (err)
      return callback(err);

    if (!tx)
      return callback();

    self.fillHistory(tx, function(err) {
      if (err)
        return callback(err);

      callback(null, tx);
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

  this.getBlock(hash, function(err, block) {
    if (err)
      return callback(err);

    if (!block)
      return callback();

    self.getUndoView(block, function(err, view) {
      if (err)
        return callback(err);

      callback(null, block);
    });
  });
};

/**
 * Get a view of the existing coins necessary to verify a block.
 * @param {Block} block
 * @param {Function} callback - Returns [Error, {@link CoinView}].
 */

ChainDB.prototype.getCoinView = function getCoinView(block, callback) {
  var self = this;
  var view = new bcoin.coinview();

  utils.forEachSerial(block.getPrevout(), function(prevout, next) {
    self.getCoins(prevout, function(err, coins) {
      if (err)
        return next(err);

      if (coins)
        view.add(coins);

      next();
    });
  }, function(err) {
    if (err)
      return callback(err);

    callback(null, view);
  });
};

/**
 * Get coins necessary to be resurrected during a reorg.
 * @param {Hash} hash
 * @param {Function} callback - Returns [Error, {@link Coin}[]].
 */

ChainDB.prototype.getUndoCoins = function getUndoCoins(hash, callback) {
  this.db.fetch(layout.u(hash), function(data) {
    var p = new BufferReader(data);
    var coins = [];

    while (p.left())
      coins.push(bcoin.coin.fromRaw(p));

    return coins;
  }, callback);
};

/**
 * Get a coin view containing unspent coins as
 * well as the coins to be resurrected for a reorg.
 * (Note: fills block with undo coins).
 * @param {Block} block
 * @param {Function} callback - Returns [Error, {@link CoinView}].
 */

ChainDB.prototype.getUndoView = function getUndoView(block, callback) {
  var self = this;
  var i, j, k, tx, input, coin;

  this.getCoinView(block, function(err, view) {
    if (err)
      return callback(err);

    self.getUndoCoins(block.hash(), function(err, coins) {
      if (err)
        return callback(err);

      if (!coins)
        return callback(null, view);

      for (i = 0, k = 0; i < block.txs.length; i++) {
        tx = block.txs[i];

        if (tx.isCoinbase())
          continue;

        for (j = 0; j < tx.inputs.length; j++) {
          input = tx.inputs[j];
          coin = coins[k++];
          coin.hash = input.prevout.hash;
          coin.index = input.prevout.index;
          input.coin = coin;
          view.addCoin(coin);
        }
      }

      callback(null, view);
    });
  });
};

/**
 * Retrieve a block from the database (not filled with coins).
 * @param {Hash} hash
 * @param {Function} callback - Returns [Error, {@link Block}].
 */

ChainDB.prototype.getBlock = function getBlock(hash, callback) {
  var self = this;
  this.getBoth(hash, function(err, hash, height) {
    if (err)
      return callback(err);

    if (!hash)
      return callback();

    self.db.fetch(layout.b(hash), function(data) {
      var block = bcoin.block.fromRaw(data);
      block.setHeight(height);
      return block;
    }, callback);
  });
};

/**
 * Check whether coins are still unspent. Necessary for bip30.
 * @see https://bitcointalk.org/index.php?topic=67738.0
 * @param {Hash} hash
 * @param {Function} callback - Returns [Error, Boolean].
 */

ChainDB.prototype.hasCoins = function hasCoins(hash, callback) {
  this.db.has(layout.c(hash), callback);
};

/**
 * Prune a block from the chain and
 * add current block to the prune queue.
 * @private
 * @param {Block}
 * @param {Function} callback
 */

ChainDB.prototype.pruneBlock = function pruneBlock(block, callback) {
  var self = this;
  var futureHeight, key;

  if (this.options.spv)
    return callback();

  if (!this.prune)
    return callback();

  if (block.height <= this.network.block.pruneAfterHeight)
    return callback();

  futureHeight = block.height + this.keepBlocks;

  this.put(layout.q(futureHeight), block.hash());

  key = layout.q(block.height);

  this.db.fetch(key, function(data) {
    assert(data.length === 32, 'Database corruption.');
    return data.toString('hex');
  }, function(err, hash) {
    if (err)
      return callback(err);

    if (!hash)
      return callback();

    self.del(key);
    self.del(layout.b(hash));
    self.del(layout.u(hash));

    callback();
  });
};

function ChainState() {
  this.tip = constants.ZERO_HASH;
  this.tx = 0;
  this.coin = 0;
  this.value = 0;
  this.committed = false;
}

ChainState.prototype.__defineGetter__('hash', function() {
  return this.tip.toString('hex');
});

ChainState.prototype.__defineGetter__('rhash', function() {
  return utils.revHex(this.hash);
});

ChainState.prototype.clone = function clone() {
  var state = new ChainState();
  state.tip = this.tip;
  state.tx = this.tx;
  state.coin = this.coin;
  state.value = this.value;
  return state;
};

ChainState.prototype.connect = function connect(block) {
  this.tx += block.txs.length;
};

ChainState.prototype.disconnect = function connect(block) {
  this.tx -= block.txs.length;
};

ChainState.prototype.add = function add(coin) {
  this.coin++;
  this.value += coin.value;
};

ChainState.prototype.spend = function spend(coin) {
  this.coin--;
  this.value -= coin.value;
};

ChainState.prototype.commit = function commit(hash) {
  if (typeof hash === 'string')
    hash = new Buffer(hash, 'hex');
  this.tip = hash;
  this.committed = true;
  return this.toRaw();
};

ChainState.prototype.toRaw = function toRaw() {
  var p = new BufferWriter();
  p.writeHash(this.tip);
  p.writeU64(this.tx);
  p.writeU64(this.coin);
  p.writeU64(this.value);
  return p.render();
};

ChainState.fromRaw = function fromRaw(data) {
  var state = new ChainState();
  var p = new BufferReader(data);
  state.tip = p.readHash();
  state.tx = p.readU53();
  state.coin = p.readU53();
  state.value = p.readU53();
  return state;
};

/*
 * Helpers
 */

function write(data, str, off) {
  if (Buffer.isBuffer(str))
    return str.copy(data, off);
  data.write(str, off, 'hex');
}

function pair(prefix, hash) {
  var key = new Buffer(33);
  key[0] = prefix;
  write(key, hash, 1);
  return key;
}

function ipair(prefix, num) {
  var key = new Buffer(5);
  key[0] = prefix;
  key.writeUInt32BE(num, 1, true);
  return key;
}

function getSize(value) {
  return 80 + value.length;
}

function checkHash(hash) {
  assert(typeof hash === 'string' || typeof hash === 'number',
    'Must pass in height or hash.');
}

/*
 * Expose
 */

module.exports = ChainDB;
