/*!
 * chaindb.js - blockchain data management for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

var bcoin = require('./env');
var EventEmitter = require('events').EventEmitter;
var constants = bcoin.protocol.constants;
var utils = require('./utils');
var assert = utils.assert;
var DUMMY = new Buffer([0]);
var BufferWriter = require('./writer');
var BufferReader = require('./reader');
var Framer = bcoin.protocol.framer;
var Parser = bcoin.protocol.parser;

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

var layout = {
  R: !utils.isBrowser
    ? new Buffer([0x52]) // R
    : '52',
  e: function e(hash) {
    var key = new Buffer(33);
    key[0] = 0x65; // e
    write(key, hash, 1);
    if (utils.isBrowser)
      key = key.toString('hex');
    return key;
  },
  h: function h(hash) {
    var key = new Buffer(33);
    key[0] = 0x68; // h
    write(key, hash, 1);
    if (utils.isBrowser)
      key = key.toString('hex');
    return key;
  },
  H: function H(height) {
    var key = new Buffer(5);
    key[0] = 0x48; // H
    key.writeUInt32LE(height, 1, true);
    if (utils.isBrowser)
      key = key.toString('hex');
    return key;
  },
  n: function n(hash) {
    var key = new Buffer(33);
    key[0] = 0x6e; // n
    write(key, hash, 1);
    if (utils.isBrowser)
      key = key.toString('hex');
    return key;
  },
  b: function b(hash) {
    var key = new Buffer(33);
    key[0] = 0x62; // b
    write(key, hash, 1);
    if (utils.isBrowser)
      key = key.toString('hex');
    return key;
  },
  t: function t(hash) {
    var key = new Buffer(33);
    key[0] = 0x74; // t
    write(key, hash, 1);
    if (utils.isBrowser)
      key = key.toString('hex');
    return key;
  },
  c: function c(hash) {
    var key = new Buffer(33);
    key[0] = 0x63; // c
    write(key, hash, 1);
    if (utils.isBrowser)
      key = key.toString('hex');
    return key;
  },
  u: function u(hash) {
    var key = new Buffer(33);
    key[0] = 0x75; // u
    write(key, hash, 1);
    if (utils.isBrowser)
      key = key.toString('hex');
    return key;
  },
  q: function q(height) {
    var key = new Buffer(5);
    key[0] = 0x71; // q
    key.writeUInt32LE(height, 1, true);
    if (utils.isBrowser)
      key = key.toString('hex');
    return key;
  },
  T: function T(address, hash) {
    var key;
    if (address.length === 32 || address.length === 64) {
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
    if (utils.isBrowser)
      key = key.toString('hex');
    return key;
  },
  C: function C(address, hash, index) {
    var key;
    if (address.length === 32 || address.length === 64) {
      key = new Buffer(69);
      key[0] = 0x9a; // W + C
      write(key, address, 1);
      write(key, hash, 33);
      key.writeUInt32LE(index, 65, true);
    } else {
      key = new Buffer(57);
      key[0] = 0x43; // C
      write(key, address, 1);
      write(key, hash, 21);
      key.writeUInt32LE(index, 53, true);
    }
    if (utils.isBrowser)
      key = key.toString('hex');
    return key;
  },
  Cc: function Cc(key) {
    var hash, index;

    if (utils.isBrowser)
      key = new Buffer(key, 'hex');

    if (key.length === 69) {
      hash = key.slice(33, 65).toString('hex');
      index = key.readUInt32LE(65, 0);
    } else {
      hash = key.slice(21, 53).toString('hex');
      index = key.readUInt32LE(53, 0);
    }

    return [hash, index];
  },
  Tt: function Tt(key) {
    if (utils.isBrowser)
      key = new Buffer(key, 'hex');

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
  this.network = this.chain.network;

  this.keepBlocks = options.keepBlocks || 288;
  this.prune = !!options.prune;

  this.loaded = false;

  // We want at least 1 retarget interval cached
  // for retargetting, but we need at least two
  // cached for optimal versionbits state checks.
  // We add a padding of 100 for forked chains,
  // reorgs, chain locator creation and the bip34
  // check.
  this.cacheWindow = (this.network.pow.retargetInterval + 1) * 2 + 100;

  // We want to keep the last 5 blocks of unspents in memory.
  // Some explanation for the numbers:
  // Average block output size: 165kb
  // Average number of outputs: 5000
  // Average output size: 33.6b
  // Average number of outputs per tx: 2.2
  // Average size of outputs per tx: 74b
  // Average number of txs: 2300
  // Key size: 66b (* 2)
  this.coinWindow = ((165 * 1024 + 2300 * 4) + (2300 * 66 * 2)) * 5;

  this.coinCache = new NullCache(this.coinWindow);
  this.cacheHash = new bcoin.lru(this.cacheWindow, 1);
  this.cacheHeight = new bcoin.lru(this.cacheWindow, 1);

  this._init();
}

utils.inherits(ChainDB, EventEmitter);

ChainDB.prototype._init = function _init() {
  var self = this;
  var genesis, block;

  if (this.loaded)
    return;

  this.db = bcoin.ldb({
    network: this.network,
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

    self.db.has(layout.h(self.network.genesis.hash), function(err, exists) {
      if (err)
        return self.emit('error', err);

      if (exists)
        return finish();

      genesis = new bcoin.chainentry(self.chain, {
        hash: self.network.genesis.hash,
        version: self.network.genesis.version,
        prevBlock: self.network.genesis.prevBlock,
        merkleRoot: self.network.genesis.merkleRoot,
        ts: self.network.genesis.ts,
        bits: self.network.genesis.bits,
        nonce: self.network.genesis.nonce,
        height: 0,
        chainwork: null
      }, null);

      block = bcoin.block.fromRaw(self.network.genesisBlock, 'hex');
      block.setHeight(0);

      self.save(genesis, block, null, true, finish);
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
  if (hash == null || hash < 0) {
    callback = utils.asyncify(callback);
    return callback(null, -1);
  }

  if (typeof hash === 'number') {
    callback = utils.asyncify(callback);
    return callback(null, hash);
  }

  if (hash === constants.NULL_HASH) {
    callback = utils.asyncify(callback);
    return callback(null, -1);
  }

  if (this.cacheHash.has(hash)) {
    callback = utils.asyncify(callback);
    return callback(null, this.cacheHash.get(hash).height);
  }

  this.db.fetch(layout.h(hash), function(data) {
    assert(data.length === 4, 'Database corruption.');
    return data.readUInt32LE(0, true);
  }, function(err, height) {
    if (err)
      return callback(err);

    if (height == null)
      return callback(null, -1);

    return callback(null, height);
  });
};

/**
 * Get the hash of a block by height. Note that this
 * will only return hashes in the main chain.
 * @param {Number} height
 * @param {Function} callback - Returns [Error, {@link Hash}].
 */

ChainDB.prototype.getHash = function getHash(height, callback) {
  if (height == null || height < 0) {
    callback = utils.asyncify(callback);
    return callback(null, null);
  }

  if (typeof height === 'string') {
    callback = utils.asyncify(callback);
    return callback(null, height);
  }

  if (this.cacheHeight.has(height)) {
    callback = utils.asyncify(callback);
    return callback(null, this.cacheHeight.get(height).hash);
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
 * @param {Function} callback - Returns [Error, {@link ChainEntry}].
 */

ChainDB.prototype.getEntry = function getEntry(hash, callback) {
  var self = this;

  if (hash == null || hash < 0)
    return utils.nextTick(callback);

  return this.getHash(hash, function(err, hash) {
    if (err && err.type !== 'NotFoundError')
      return callback(err);

    if (!hash)
      return callback();

    if (self.cacheHash.has(hash))
      return callback(null, self.cacheHash.get(hash));

    return self.db.fetch(layout.e(hash), function(data) {
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

  return this.getEntry(hash, function(err, entry) {
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
 * @param {ChainEntry} entry
 * @param {Block} block
 * @param {Boolean} connect - Whether to connect the
 * block's inputs and add it as a tip.
 * @param {Function} callback
 */

ChainDB.prototype.save = function save(entry, block, view, connect, callback) {
  var batch = this.db.batch();
  var hash = block.hash();
  var height = new Buffer(4);

  height.writeUInt32LE(height, 0, true);

  batch.put(layout.h(hash), height);
  batch.put(layout.e(hash), entry.toRaw());

  this.cacheHash.set(entry.hash, entry);

  if (!connect) {
    return this.saveBlock(block, view, batch, false, function(err) {
      if (err)
        return callback(err);
      return batch.write(callback);
    });
  }

  this.cacheHeight.set(entry.height, entry);

  batch.put(layout.n(entry.prevBlock), hash);
  batch.put(layout.H(entry.height), hash);
  batch.put(layout.R, hash);

  this.emit('add entry', entry);

  this.saveBlock(block, view, batch, true, function(err) {
    if (err)
      return callback(err);
    return batch.write(callback);
  });
};

/**
 * Retrieve the tip entry from the tip record.
 * @param {Function} callback - Returns [Error, {@link ChainEntry}].
 */

ChainDB.prototype.getTip = function getTip(callback) {
  var self = this;
  return this.db.fetch(layout.R, function(data) {
    assert(data.length === 32, 'Database corruption.');
    return data.toString('hex');
  }, function(err, hash) {
    if (err)
      return callback(err);

    if (!hash)
      return callback();

    return self.get(hash, callback);
  });
};

/**
 * Connect the block to the chain.
 * @param {ChainEntry|Hash|Height} block - entry, height, or hash.
 * @param {Function} callback - Returns [Error, {@link ChainEntry}].
 */

ChainDB.prototype.connect = function connect(entry, block, view, callback) {
  var batch = this.db.batch();
  var hash = block.hash();

  batch.put(layout.n(entry.prevBlock), hash);
  batch.put(layout.H(entry.height), hash);
  batch.put(layout.R, hash);

  this.cacheHash.set(entry.hash, entry);
  this.cacheHeight.set(entry.height, entry);

  this.emit('add entry', entry);

  this.connectBlock(block, view, batch, function(err) {
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
 * @param {ChainEntry|Hash|Height} block - Entry, height, or hash.
 * @param {Function} callback - Returns [Error, {@link ChainEntry}].
 */

ChainDB.prototype.disconnect = function disconnect(entry, callback) {
  var self = this;
  var batch = this.db.batch();

  batch.del(layout.n(entry.prevBlock));
  batch.del(layout.H(entry.height));
  batch.put(layout.R, new Buffer(entry.prevBlock, 'hex'));

  this.cacheHeight.remove(entry.height);

  this.emit('remove entry', entry);

  this.getBlock(entry.hash, function(err, block) {
    if (err)
      return callback(err);

    if (!block)
      return callback(new Error('Block not found.'));

    self.disconnectBlock(block, batch, function(err) {
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

  if (hash === this.chain.tip.hash || hash === this.network.genesis.hash)
    return utils.asyncify(callback)(null, true);

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
          batch.put(layout.R, new Buffer(tip.hash, 'hex'));
          return batch.write(callback);
        }

        batch.del(layout.H(tip.height));
        batch.del(layout.h(tip.hash));
        batch.del(layout.e(tip.hash));
        batch.del(layout.n(tip.prevBlock));

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
 * main chain or an alternate chain. Alternate chains will only
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

ChainDB.prototype.saveBlock = function saveBlock(block, view, batch, connect, callback) {
  if (this.options.spv)
    return utils.nextTick(callback);

  batch.put(layout.b(block.hash()), block.render());

  if (!connect)
    return utils.nextTick(callback);

  this.connectBlock(block, view, batch, callback);
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

  this.getBlock(hash, function(err, block) {
    if (err)
      return callback(err);

    if (!block)
      return callback();

    batch.del(layout.b(block.hash()));

    if (self.options.spv)
      return callback(null, block);

    self.disconnectBlock(block, batch, callback);
  });
};

/**
 * Connect block inputs.
 * @param {Block} block
 * @param {Batch} batch
 * @param {Function} callback - Returns [Error, {@link Block}].
 */

ChainDB.prototype.connectBlock = function connectBlock(block, view, batch, callback) {
  var undo = new BufferWriter();
  var i, j, tx, input, output, key, addresses, address, hash, coins, raw;

  if (this.options.spv) {
    this.emit('add block', block);
    return utils.nextTick(callback);
  }

  // Genesis block's coinbase is unspendable.
  if (this.chain.isGenesis(block))
    return utils.nextTick(callback);

  for (i = 0; i < block.txs.length; i++) {
    tx = block.txs[i];
    hash = tx.hash('hex');

    if (this.options.indexTX) {
      batch.put(layout.t(hash), tx.toExtended());
      if (this.options.indexAddress) {
        addresses = tx.getHashes();
        for (j = 0; j < addresses.length; j++) {
          address = addresses[j];
          batch.put(layout.T(address, hash), DUMMY);
        }
      }
    }

    for (j = 0; j < tx.inputs.length; j++) {
      input = tx.inputs[j];
      key = input.prevout.hash + '/' + input.prevout.index;

      if (tx.isCoinbase())
        break;

      assert(input.coin);

      if (this.options.indexAddress) {
        address = input.getHash();
        if (address)
          batch.del(layout.C(address, input.prevout.hash, input.prevout.index));
      }

      Framer.coin(input.coin, false, undo);
    }

    for (j = 0; j < tx.outputs.length; j++) {
      output = tx.outputs[j];

      if (output.script.isUnspendable())
        continue;

      if (this.options.indexAddress) {
        address = output.getHash();
        if (address)
          batch.put(layout.C(address, hash, j), DUMMY);
      }
    }
  }

  view = view.toArray();

  for (i = 0; i < view.length; i++) {
    coins = view[i];
    if (coins.count() === 0) {
      batch.del(layout.c(coins.hash));
      this.coinCache.remove(coins.hash);
    } else {
      raw = coins.toRaw();
      batch.put(layout.c(coins.hash), raw);
      this.coinCache.set(coins.hash, raw);
    }
  }

  if (undo.written > 0)
    batch.put(layout.u(block.hash()), undo.render());

  this.emit('add block', block);

  this._pruneBlock(block, batch, function(err) {
    if (err)
      return callback(err);
    return callback(null, block);
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
  var i, j, tx, input, output, key, addresses, address, hash, coins, raw;

  if (this.options.spv)
    return utils.nextTick(callback);

  this.getUndoView(block, function(err, view) {
    if (err)
      return callback(err);

    for (i = block.txs.length - 1; i >= 0; i--) {
      tx = block.txs[i];
      hash = tx.hash('hex');

      if (self.options.indexTX) {
        batch.del(layout.t(hash));
        if (self.options.indexAddress) {
          addresses = tx.getHashes();
          for (j = 0; j < addresses.length; j++) {
            address = addresses[j];
            batch.del(layout.T(address, hash));
          }
        }
      }

      for (j = 0; j < tx.inputs.length; j++) {
        input = tx.inputs[j];
        key = input.prevout.hash + '/' + input.prevout.index;

        if (tx.isCoinbase())
          break;

        assert(input.coin);

        if (self.options.indexAddress) {
          address = input.getHash();
          if (address)
            batch.put(layout.C(address, input.prevout.hash, input.prevout.index), DUMMY);
        }
      }

      view.add(tx.toCoins());

      for (j = 0; j < tx.outputs.length; j++) {
        output = tx.outputs[j];
        key = hash + '/' + j;

        if (output.script.isUnspendable())
          continue;

        if (self.options.indexAddress) {
          address = output.getHash();
          if (address)
            batch.del(layout.C(address, hash, j));
        }

        view.spend(hash, j);
      }
    }

    view = view.toArray();

    for (i = 0; i < view.length; i++) {
      coins = view[i];
      if (coins.count() === 0) {
        batch.del(layout.c(coins.hash));
        self.coinCache.remove(coins.hash);
      } else {
        raw = coins.toRaw();
        batch.put(layout.c(coins.hash), raw);
        self.coinCache.set(coins.hash, raw);
      }
    }

    batch.del(layout.u(block.hash()));

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
    return callback(null, tx);
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
 * Retrieve a transaction (not filled with coins).
 * @param {Hash} hash
 * @param {Function} callback - Returns [Error, {@link TX}].
 */

ChainDB.prototype.getTX = function getTX(hash, callback) {
  var self = this;

  if (!this.options.indexTX)
    return utils.nextTick(callback);

  this.db.fetch(layout.t(hash), function(data) {
    return bcoin.tx.fromExtended(data);
  }, function(err, tx) {
    if (err)
      return callback(err);

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
  if (!this.options.indexTX)
    return utils.asyncify(callback)(null, false);

  return this.db.has(layout.t(hash), callback);
};

/**
 * Get all coins pertinent to an address.
 * @param {Base58Address|Base58Address[]} addresses
 * @param {Function} callback - Returns [Error, {@link Coin}[]].
 */

ChainDB.prototype.getCoinsByAddress = function getCoinsByAddress(addresses, callback) {
  var self = this;
  var coins = [];

  if (!Array.isArray(addresses))
    addresses = [addresses];

  addresses = utils.uniq(addresses);

  utils.forEachSerial(addresses, function(address, next) {
    address = bcoin.address.getHash(address);

    if (!address)
      return next();

    self.db.iterate({
      gte: layout.C(address, constants.ZERO_HASH, 0),
      lte: layout.C(address, constants.MAX_HASH, 0xffffffff),
      keyAsBuffer: !utils.isBrowser,
      transform: layout.Cc
    }, function(err, keys) {
      if (err)
        return next(err);

      utils.forEachSerial(keys, function(key, next) {
        self.getCoin(key[0], key[1], function(err, coin) {
          if (err)
            return callback(err);

          if (coin)
            coins.push(coin);

          return next();
        });
      }, next);
    });
  }, function(err) {
    if (err)
      return callback(err);
    return callback(null, coins);
  });
};

/**
 * Get all transactions pertinent to an address.
 * @param {Base58Address|Base58Address[]} addresses
 * @param {Function} callback - Returns [Error, {@link TX}[]].
 */

ChainDB.prototype.getTXByAddress = function getTXByAddress(addresses, callback) {
  var self = this;
  var txs = [];
  var have = {};

  if (!Array.isArray(addresses))
    addresses = [addresses];

  addresses = utils.uniq(addresses);

  utils.forEachSerial(addresses, function(address, next) {
    address = bcoin.address.getHash(address);

    if (!address)
      return next();

    self.db.lookup({
      gte: layout.T(address, constants.ZERO_HASH),
      lte: layout.T(address, constants.MAX_HASH),
      keyAsBuffer: !utils.isBrowser,
      transform: function(key) {
        var hash = layout.Tt(key);

        if (have[hash])
          return;

        have[hash] = true;

        return layout.t(hash);
      },
      parse: function(data, key) {
        txs.push(bcoin.tx.fromRaw(data));
      }
    }, next);
  }, function(err) {
    if (err)
      return callback(err);
    return callback(null, txs);
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

    return self.getUndoView(block, function(err, view) {
      if (err)
        return callback(err);

      return callback(null, block);
    });
  });
};

/**
 * Fill a block with coins (unspent only).
 * @param {Block} block
 * @param {Function} callback - Returns [Error, {@link Block}].
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

    return callback(null, view);
  });
};

/**
 * Get coins necessary to be resurrected during a reorg.
 * @param {Hash} hash
 * @param {Function} callback - Returns [Error, Object].
 */

ChainDB.prototype.getUndoCoins = function getUndoCoins(hash, callback) {
  return this.db.fetch(layout.u(hash), function(data) {
    var p = new BufferReader(data);
    var coins = [];
    var coin;

    while (p.left()) {
      coin = Parser.parseCoin(p, false);
      coins.push(new bcoin.coin(coin));
    }

    return coins;
  }, callback);
};

/**
 * Fill a block with coins necessary to be resurrected during a reorg.
 * @param {Block} block
 * @param {Function} callback - Returns [Error, {@link Block}].
 */

ChainDB.prototype.getUndoView = function getUndoView(block, callback) {
  var self = this;
  var i, j, k, tx, input, coin;

  return this.getCoinView(block, function(err, view) {
    if (err)
      return callback(err);

    return self.getUndoCoins(block.hash(), function(err, coins) {
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

      return callback(null, view);
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
  return this.getBoth(hash, function(err, hash, height) {
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

ChainDB.prototype._pruneBlock = function _pruneBlock(block, batch, callback) {
  var futureHeight, key;

  if (this.options.spv)
    return callback();

  if (!this.prune)
    return callback();

  if (block.height <= this.network.block.pruneAfterHeight)
    return callback();

  futureHeight = block.height + this.keepBlocks;

  batch.put(layout.q(futureHeight), block.hash());

  key = layout.q(block.height);

  this.db.fetch(key, function(data) {
    assert(data.length === 32, 'Database corruption.');
    return data.toString('hex');
  }, function(err, hash) {
    if (err)
      return callback(err);

    if (!hash)
      return callback();

    batch.del(key);
    batch.del(layout.b(hash));
    batch.del(layout.u(hash));

    return callback();
  });
};

/**
 * A null cache. Every method is a NOP.
 * @constructor
 * @param {Number} size
 */

function NullCache(size) {}

NullCache.prototype.set = function set(key, value) {};
NullCache.prototype.remove = function remove(key) {};
NullCache.prototype.get = function get(key) {};
NullCache.prototype.has = function has(key) {};
NullCache.prototype.reset = function reset() {};

/*
 * Helpers
 */

function write(data, str, off) {
  if (Buffer.isBuffer(str))
    return str.copy(data, off);
  data.write(str, off, 'hex');
}

/*
 * Expose
 */

module.exports = ChainDB;
