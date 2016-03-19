/**
 * chaindb.js - blockchain data management for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var EventEmitter = require('events').EventEmitter;

var bcoin = require('../bcoin');
var network = bcoin.protocol.network;
var utils = require('./utils');
var assert = utils.assert;
var pad32 = utils.pad32;
var DUMMY = new Buffer([0]);

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
  this.node = chain.node;
  this.network = chain.node.network;
  this.chain = chain;

  this.queue = {};
  this.queueSize = 0;
  this.size = 0;
  this.fd = null;
  this.loaded = false;
  this.fsync = !!options.fsync;

  this.keepBlocks = options.keepBlocks || 288;
  this.prune = !!options.prune;

  // Keep track of block hashes in a
  // bloom filter to avoid DB lookups.
  // 1% false positive rate for 800k blocks
  // http://hur.st/bloomfilter?n=800000&p=0.01 (m=936kb, k=7)
  // 10% false positive rate for 800k blocks
  // http://hur.st/bloomfilter?n=800000&p=0.10 (m=468kb, k=3)
  // this.bloom = new bcoin.bloom(937 * 1024, 7, 0xdeadbeef);

  // Need to cache up to the retarget interval
  // if we're going to be checking the damn
  // target all the time.
  if (network.powAllowMinDifficultyBlocks)
    this._cacheWindow = network.powDiffInterval + 1;
  else
    this._cacheWindow = network.block.majorityWindow + 1;

  this.cacheHash = new bcoin.lru(this._cacheWindow);
  this.cacheHeight = new bcoin.lru(this._cacheWindow);

  this._init();
}

utils.inherits(ChainDB, EventEmitter);

ChainDB.prototype._init = function _init() {
  var self = this;
  var genesis, block;

  if (this.loaded)
    return;

  this.db = bcoin.ldb((this.options.spv ? 'spv' : '') + 'chain', {
    compression: false,
    cacheSize: 16 * 1024 * 1024,
    writeBufferSize: 8 * 1024 * 1024
  });

  if (!bcoin.isBrowser) {
    //var DataStore = require('./data' + 'store');
    //this.db = new DataStore(this.db);
  }

  utils.debug('Starting chain load.');

  this.db.open(function(err) {
    if (err)
      return self.emit('error', err);

    function finish(err) {
      if (err)
        return self.emit('error', err);

      self.loaded = true;
      self.emit('open');

      utils.debug('Chain successfully loaded.');
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

      self.save(genesis, block, finish);
    });
  });
};

ChainDB.prototype.open = function open(callback) {
  if (this.loaded)
    return utils.nextTick(callback);

  this.once('open', callback);
};

ChainDB.prototype.close = function close(callback) {
  callback = utils.ensure(callback);
  this.db.close(callback);
};

ChainDB.prototype.addCache = function addCache(entry) {
  this.cacheHash.set(entry.hash, entry);
  this.cacheHeight.set(entry.height, entry);
};

ChainDB.prototype.hasCache = function hasCache(hash) {
  if (hash == null || hash < 0)
    return false;

  if (typeof hash === 'number')
    return this.cacheHeight.has(hash);

  return this.cacheHash.has(hash);
};

ChainDB.prototype.getCache = function getCache(hash) {
  if (hash == null || hash < 0)
    return;

  if (typeof hash === 'number')
    return this.cacheHeight.get(hash);

  return this.cacheHash.get(hash);
};

ChainDB.prototype.getHeight = function getHeight(hash, callback) {
  if (hash == null || hash < 0)
    return callback(null, -1);

  if (typeof hash === 'number')
    return callback(null, hash);

  // When prevBlock=zero-hash
  if (+hash === 0)
    return callback(null, -1);

  if (this.cacheHash.has(hash))
    return callback(null, this.cacheHash.get(hash).height);

  // if (!this.bloom.test(hash, 'hex'))
  //   return callback(null, -1);

  this.db.get('c/b/' + hash, function(err, height) {
    if (err && err.type !== 'NotFoundError')
      return callback(err);

    if (height == null)
      return callback(null, -1);

    return callback(null, utils.readU32(height, 0));
  });
};

ChainDB.prototype.getHash = function getHash(height, callback) {
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

    return callback(null, utils.toHex(hash));
  });
};

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

ChainDB.prototype.getChainHeight = function getChainHeight(callback) {
  return this.getTip(function(err, entry) {
    if (err)
      return callback(err);

    if (!entry)
      return callback(null, -1);

    return callback(null, entry.height);
  });
};

ChainDB.prototype.getBoth = function getBoth(block, callback) {
  var hash, height;

  if (block == null || block < 0)
    return callback(null, null, -1);

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

ChainDB.prototype._getEntry = function _getEntry(hash, callback) {
  var self = this;
  var entry;

  if (hash == null || hash < 0)
    return callback();

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

ChainDB.prototype.get = function get(height, callback) {
  var self = this;

  callback = utils.asyncify(callback);

  return this._getEntry(height, function(err, entry) {
    if (err)
      return callback(err);

    if (!entry)
      return callback();

    // Cache the past 1001 blocks in memory
    // (necessary for isSuperMajority)
    self.addCache(entry);

    return callback(null, entry);
  });
};

ChainDB.prototype.save = function save(entry, block, callback) {
  var self = this;
  var batch, height;

  callback = utils.asyncify(callback);

  assert(entry.height >= 0);

  // Cache the past 1001 blocks in memory
  // (necessary for isSuperMajority)
  this.addCache(entry);

  // this.bloom.add(entry.hash, 'hex');

  batch = this.batch();
  height = new Buffer(4);
  utils.writeU32(height, entry.height, 0);

  batch.put('c/b/' + entry.hash, height);
  batch.put('c/c/' + entry.hash, entry.toRaw());
  batch.put('c/n/' + entry.prevBlock, new Buffer(entry.hash, 'hex'));
  batch.put('c/h/' + pad32(entry.height), new Buffer(entry.hash, 'hex'));
  batch.put('c/t', new Buffer(entry.hash, 'hex'));

  this.emit('add entry', entry);

  self.saveBlock(block, batch, function(err) {
    if (err)
      return callback(err);

    self._pruneBlock(block, batch, function(err) {
      if (err)
        return callback(err);
      return batch.write(callback);
    });
  });
};

ChainDB.prototype.getTip = function getTip(callback) {
  var self = this;
  return this.db.get('c/t', function(err, hash) {
    if (err && err.type !== 'NotFoundError')
      return callback(err);

    if (!hash)
      return callback();

    return self.get(utils.toHex(hash), callback);
  });
};

ChainDB.prototype.connect = function connect(block, callback) {
  var self = this;
  var batch;

  this._get(block, function(err, entry) {
    if (err)
      return callback(err);

    if (!entry)
      return callback();

    batch = self.batch();

    batch.put('c/h/' + pad32(entry.height), new Buffer(entry.hash, 'hex'));
    batch.put('c/t', new Buffer(entry.hash, 'hex'));

    self.cacheHeight.set(entry.height, entry);

    self.emit('add entry', entry);

    self.connectBlock(entry.hash, batch, function(err) {
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

ChainDB.prototype.disconnect = function disconnect(block, callback) {
  var self = this;
  var batch;

  this._get(block, function(err, entry) {
    if (err)
      return callback(err);

    if (!entry)
      return callback();

    batch = self.batch();

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

ChainDB.prototype._get = function _get(block, callback) {
  if (block instanceof bcoin.chainblock)
    return callback(null, block);
  return this.get(block, callback);
};

ChainDB.prototype.getNextHash = function getNextHash(hash, callback) {
  return this.db.get('c/n/' + hash, function(err, nextHash) {
    if (err && err.type !== 'NotFoundError')
      return callback(err);

    if (!nextHash)
      return callback();

    return callback(null, utils.toHex(nextHash));
  });
};

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

        batch = self.batch();

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

ChainDB.prototype.has = function has(height, callback) {
  if (height == null || height < 0)
    return callback(null, false);

  return this.getBoth(height, function(err, hash, height) {
    if (err)
      return callback(err);
    return callback(null, hash != null);
  });
};

ChainDB.prototype.batch = function batch() {
  if (this.fsync)
    return new utils.SyncBatch(this.db);
  return this.db.batch();
};

ChainDB.prototype.saveBlock = function saveBlock(block, batch, callback) {
  if (this.options.spv)
    return callback();

  // batch.put('b/b/' + block.hash('hex'), block.toCompact());

  // block.txs.forEach(function(tx) {
  //   batch.put('t/t/' + tx.hash('hex'), tx.toExtended());
  // });

  this.connectBlock(block, batch, callback);
};

ChainDB.prototype.removeBlock = function removeBlock(hash, batch, callback) {
  var self = this;

  if (this.options.spv)
    return callback();

  this._getTXBlock(hash, function(err, block) {
    if (err)
      return callback(err);

    if (!block)
      return callback();

    batch.del('b/b/' + block.hash('hex'));

    block.txs.forEach(function(tx) {
      batch.del('t/t/' + tx.hash('hex'));
    });

    self.disconnectBlock(block, batch, callback);
  });
};

ChainDB.prototype.connectBlock = function connectBlock(block, batch, callback) {
  var self = this;

  if (this.options.spv) {
    self.emit('add block', block);
    return callback();
  }

  this._getCoinBlock(block, function(err, block) {
    var height;

    if (err)
      return callback(err);

    if (!block)
      return callback();

    block.txs.forEach(function(tx) {
      var hash = tx.hash('hex');
      var uniq = {};

      tx.inputs.forEach(function(input) {
        var address;

        if (input.isCoinbase())
          return;

        assert(input.output);

        if (self.options.indexAddress) {
          address = input.getAddress();

          if (address && !uniq[address] && !self.prune) {
            uniq[address] = true;
            batch.put('t/a/' + address + '/' + hash, DUMMY);
          }

          if (address) {
            batch.del(
              'u/a/' + address
              + '/' + input.prevout.hash
              + '/' + input.prevout.index);
          }
        }

        batch.del('u/t/' + input.prevout.hash + '/' + input.prevout.index);
      });

      tx.outputs.forEach(function(output, i) {
        var address;

        if (self.options.indexAddress) {
          address = output.getAddress();

          if (address && !uniq[address] && !self.prune) {
            uniq[address] = true;
            batch.put('t/a/' + address + '/' + hash, DUMMY);
          }

          if (address)
            batch.put('u/a/' + address + '/' + hash + '/' + i, DUMMY);
        }

        batch.put('u/t/' + hash + '/' + i, bcoin.coin(tx, i).toRaw());
      });
    });

    self.emit('add block', block);

    return callback(null, block);
  });
};

ChainDB.prototype.disconnectBlock = function disconnectBlock(hash, batch, callback) {
  var self = this;

  if (this.options.spv)
    return callback();

  this._getTXBlock(hash, function(err, block) {
    if (err)
      return callback(err);

    if (!block)
      return callback();

    if (typeof hash === 'string')
      assert(block.hash('hex') === hash);

    block.txs.forEach(function(tx) {
      var hash = tx.hash('hex');
      var uniq = {};

      tx.inputs.forEach(function(input) {
        var address;

        if (input.isCoinbase())
          return;

        assert(input.output);

        if (self.options.indexAddress) {
          address = input.getAddress();

          if (address && !uniq[address] && !self.prune) {
            uniq[address] = true;
            batch.del('t/a/' + address + '/' + hash);
          }

          if (address) {
            batch.put('u/a/' + address
              + '/' + input.prevout.hash
              + '/' + input.prevout.index,
              DUMMY);
          }
        }

        batch.put('u/t/'
          + input.prevout.hash
          + '/' + input.prevout.index,
          input.output.toRaw());
      });

      tx.outputs.forEach(function(output, i) {
        var address;

        if (self.options.indexAddress) {
          address = output.getAddress();

          if (address && !uniq[address] && !self.prune) {
            uniq[address] = true;
            batch.del('t/a/' + address + '/' + hash);
          }

          if (address)
            batch.del('u/a/' + address + '/' + hash + '/' + i);
        }

        batch.del('u/t/' + hash + '/' + i);
      });
    });

    self.emit('remove block', block);

    return callback(null, block);
  });
};

ChainDB.prototype.fillCoin = function fillCoin(tx, callback) {
  var self = this;

  callback = utils.asyncify(callback);

  if (Array.isArray(tx)) {
    return utils.forEachSerial(tx, function(tx, next) {
      self.fillCoin(tx, next);
    }, function(err) {
      if (err)
        return callback(err);
      return callback(null, tx);
    });
  }

  if (tx.isCoinbase())
    return callback(null, tx);

  utils.forEachSerial(tx.inputs, function(input, next) {
    if (input.output)
      return next();

    self.getCoin(input.prevout.hash, input.prevout.index, function(err, coin) {
      if (err)
        return callback(err);

      if (coin)
        input.output = coin;

      next();
    });
  }, function(err) {
    if (err)
      return callback(err);
    return callback(null, tx);
  });
};

ChainDB.prototype.fillTX = function fillTX(tx, callback) {
  var self = this;

  callback = utils.asyncify(callback);

  if (Array.isArray(tx)) {
    return utils.forEachSerial(tx, function(tx, next) {
      self.fillTX(tx, next);
    }, function(err) {
      if (err)
        return callback(err);
      return callback(null, tx);
    });
  }

  if (tx.isCoinbase())
    return callback(null, tx);

  if (this.prune) {
    return utils.forEachSerial(tx.inputs, function(input, next) {
      if (input.output)
        return next();

      self._getPruneCoin(input.prevout.hash, input.prevout.index, function(err, coin) {
        if (err)
          return callback(err);

        if (coin)
          input.output = coin;

        next();
      });
    }, function(err) {
      if (err)
        return callback(err);
      return callback(null, tx);
    });
  }

  utils.forEachSerial(tx.inputs, function(input, next) {
    if (input.output)
      return next();

    self.getTX(input.prevout.hash, function(err, tx) {
      if (err)
        return next(err);

      if (tx)
        input.output = bcoin.coin(tx, input.prevout.index);

      next();
    });
  }, function(err) {
    if (err)
      return callback(err);
    return callback(null, tx);
  });
};

ChainDB.prototype.getCoinsByAddress = function getCoinsByAddress(addresses, options, callback) {
  var self = this;
  var ids = [];
  var coins = [];

  if (!callback) {
    callback = options;
    options = {};
  }

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

ChainDB.prototype.getCoin = function getCoin(hash, index, callback) {
  var id = 'u/t/' + hash + '/' + index;
  var coin;

  this.db.get(id, function(err, data) {
    if (err) {
      if (err.type === 'NotFoundError')
        return callback();
      return callback(err);
    }

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

ChainDB.prototype.getTXByAddress = function getTXByAddress(addresses, options, callback) {
  var self = this;
  var hashes = [];
  var txs = [];
  var have = {};

  if (!callback) {
    callback = options;
    options = {};
  }

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

ChainDB.prototype.getTX = function getTX(hash, callback) {
  var self = this;
  var id = 't/t/' + hash;
  var tx;

  this.db.get(id, function(err, data) {
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

    if (self.options.paranoid && tx.hash('hex') !== hash)
      return callback(new Error('ChainDB is corrupt. All is lost.'));

    return callback(null, tx);
  });
};

ChainDB.prototype.getFullTX = function getFullTX(hash, callback) {
  var self = this;

  return this.getTX(hash, function(err, tx) {
    if (err)
      return callback(err);

    if (!tx)
      return callback();

    return self.fillTX(tx, function(err) {
      if (err)
        return callback(err);

      return callback(null, tx);
    });
  });
};

ChainDB.prototype.getFullBlock = function getFullBlock(hash, callback) {
  var self = this;

  return this.getBlock(hash, function(err, block) {
    if (err)
      return callback(err);

    if (!block)
      return callback();

    return self.fillTX(block.txs, function(err) {
      if (err)
        return callback(err);

      return callback(null, block);
    });
  });
};

ChainDB.prototype._getCoinBlock = function _getCoinBlock(hash, callback) {
  var self = this;

  if (hash instanceof bcoin.block)
    return callback(null, hash);

  return this.getBlock(hash, function(err, block) {
    if (err)
      return callback(err);

    if (!block)
      return callback();

    return self.fillBlock(block, callback);
  });
};

ChainDB.prototype._getTXBlock = function _getTXBlock(hash, callback) {
  var self = this;

  if (hash instanceof bcoin.block)
    return callback(null, hash);

  return this.getBlock(hash, function(err, block) {
    if (err)
      return callback(err);

    if (!block)
      return callback();

    return self.fillTXBlock(block, callback);
  });
};

ChainDB.prototype.fillBlock = function fillBlock(block, callback) {
  return this.fillCoin(block.txs, function(err) {
    var coins, i, tx, hash, j, input, id;

    if (err)
      return callback(err);

    coins = {};

    for (i = 0; i < block.txs.length; i++) {
      tx = block.txs[i];
      hash = tx.hash('hex');

      for (j = 0; j < tx.inputs.length; j++) {
        input = tx.inputs[j];
        id = input.prevout.hash + '/' + input.prevout.index;
        if (!input.output && coins[id]) {
          input.output = coins[id];
          delete coins[id];
        }
      }

      for (j = 0; j < tx.outputs.length; j++)
        coins[hash + '/' + j] = bcoin.coin(tx, j);
    }

    return callback(null, block);
  });
};

ChainDB.prototype.fillTXBlock = function fillTXBlock(block, callback) {
  return this.fillTX(block.txs, function(err) {
    var coins, i, tx, hash, j, input, id;

    if (err)
      return callback(err);

    coins = {};

    for (i = 0; i < block.txs.length; i++) {
      tx = block.txs[i];
      hash = tx.hash('hex');

      for (j = 0; j < tx.inputs.length; j++) {
        input = tx.inputs[j];
        id = input.prevout.hash + '/' + input.prevout.index;
        if (!input.output && coins[id]) {
          input.output = coins[id];
          delete coins[id];
        }
      }

      for (j = 0; j < tx.outputs.length; j++)
        coins[hash + '/' + j] = bcoin.coin(tx, j);
    }

    return callback(null, block);
  });
};

ChainDB.prototype.getBlock = function getBlock(hash, callback) {
  var self = this;
  var id, block;

  return this.getHash(hash, function(err, hash) {
    if (err)
      return callback(err);

    if (!hash)
      return callback();

    id = 'b/b/' + hash;

    self.db.get(id, function(err, data) {
      if (err) {
        if (err.type === 'NotFoundError')
          return callback();
        return callback(err);
      }

      try {
        block = bcoin.block.fromCompact(data);
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

// For BIP30
// https://bitcointalk.org/index.php?topic=67738.0
ChainDB.prototype.isUnspentTX = function isUnspentTX(hash, callback) {
  return callback(null, false);

  if (this.options.spv)
    return callback(null, false);
  return this.isSpentTX(hash, function(err, spent) {
    if (err)
      return callback(err);

    return callback(null, !spent);
  });
};

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
  var futureHeight;

  if (this.options.spv)
    return callback();

  if (!this.prune)
    return callback();

  // Keep the genesis block
  if (block.isGenesis())
    return callback();

  futureHeight = pad32(block.height + this.keepBlocks);

  batch.put('b/q/' + futureHeight, block.hash());

  block.txs.forEach(function(tx) {
    tx.inputs.forEach(function(input) {
      if (input.isCoinbase())
        return;

      assert(input.output);

      batch.put('u/x/'
        + input.prevout.hash
        + '/' + input.prevout.index,
        input.output.toRaw());

      batch.put('u/q/'
        + futureHeight
        + '/' + input.prevout.hash
        + '/' + input.prevout.index,
        DUMMY);
    });
  });

  this._pruneQueue(block, batch, callback);
};

ChainDB.prototype._pruneQueue = function _pruneQueue(block, batch, callback) {
  var self = this;
  var key = 'b/q/' + pad32(block.height);
  this.db.get(key, function(err, hash) {
    if (err && err.type !== 'NotFoundError')
      return callback(err);

    if (!hash)
      return callback();

    hash = utils.toHex(hash);

    self.db.get('b/b/' + hash, function(err, cblock) {
      if (err && err.type !== 'NotFoundError')
        return callback(err);

      batch.del(key);

      if (!cblock)
        return callback();

      try {
        cblock = bcoin.block.fromCompact(cblock);
      } catch (e) {
        return callback(e);
      }

      batch.del('b/b/' + hash);

      cblock.hashes.forEach(function(hash) {
        batch.del('t/t/' + hash);
      });

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
  var id = 'u/x/' + hash + '/' + index;
  var coin;

  this.db.get(id, function(err, data) {
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

/**
 * Expose
 */

module.exports = ChainDB;
