/**
 * db.js - db object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bcoin = require('../bcoin');
var utils = bcoin.utils;
var assert = utils.assert;
var EventEmitter = require('events').EventEmitter;
var network = bcoin.protocol.network;
var DUMMY = new Buffer([]);
var pad32 = utils.pad32;

/**
 * BlockDB
 */

function BlockDB(node, options) {
  var self = this;

  if (!(this instanceof BlockDB))
    return new BlockDB(node, options);

  EventEmitter.call(this);

  if (!options)
    options = {};

  this.options = options;
  this.fsync = !!options.fsync;

  this.node = node;

  this.db = bcoin.ldb('block', {
    cacheSize: 16 * 1024 * 1024,
    writeBufferSize: 8 * 1024 * 1024
  });
}

utils.inherits(BlockDB, EventEmitter);

BlockDB.prototype.close = function close(callback) {
  var self = this;
  this.db.close(function(err) {
    if (err)
      return callback(err);

    return callback();
  });
};

BlockDB.prototype.saveBlock = function saveBlock(block, callback) {
  var self = this;
  var batch = this.batch();

  batch.put('b/b/' + block.hash('hex'), block.toCompact());

  block.txs.forEach(function(tx, i) {
    batch.put('t/t/' + tx.hash('hex'), tx.toExtended());
  });

  self.connectBlock(block, callback, batch);
};

BlockDB.prototype.removeBlock = function removeBlock(hash, callback) {
  var self = this;

  this._getTXBlock(hash, function(err, block) {
    var batch;

    if (err)
      return callback(err);

    if (!block)
      return callback();

    batch = self.batch();

    batch.del('b/b/' + block.hash('hex'));

    block.txs.forEach(function(tx, i) {
      batch.del('t/t/' + tx.hash('hex'));
    });

    self.disconnectBlock(block, callback, batch);
  });
};

BlockDB.prototype.connectBlock = function connectBlock(block, callback, batch) {
  var self = this;

  this._getCoinBlock(block, function(err, block) {
    var height;

    if (err)
      return callback(err);

    if (!block) {
      assert(!batch);
      return callback();
    }

    if (!batch)
      batch = self.batch();

    batch.put('b/h/' + pad32(block.height), block.hash());

    height = new Buffer(4);
    utils.writeU32(height, block.height, 0);
    batch.put('b/t', height);

    block.txs.forEach(function(tx, i) {
      var hash = tx.hash('hex');
      var uniq = {};

      tx.inputs.forEach(function(input) {
        var address;

        if (input.isCoinbase())
          return;

        assert(input.output);

        if (self.options.indexAddress) {
          address = input.getAddress();

          if (address && !uniq[address]) {
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

          if (address && !uniq[address]) {
            uniq[address] = true;
            batch.put('t/a/' + address + '/' + hash, DUMMY);
          }

          if (address)
            batch.put('u/a/' + address + '/' + hash + '/' + i, DUMMY);
        }

        batch.put('u/t/' + hash + '/' + i, bcoin.coin(tx, i).toExtended());
      });
    });

    batch.write(function(err) {
      if (err)
        return callback(err);
      self.emit('save block', block);
      return callback(null, block);
    });
  });
};

BlockDB.prototype.disconnectBlock = function disconnectBlock(hash, callback, batch) {
  var self = this;

  this._getTXBlock(hash, function(err, block) {
    if (err)
      return callback(err);

    if (!block) {
      assert(!batch);
      return callback();
    }

    if (!batch)
      batch = self.batch();

    if (typeof hash === 'string')
      assert(block.hash('hex') === hash);

    batch.del('b/t');
    batch.del('b/h/' + pad32(block.height));

    block.txs.forEach(function(tx, i) {
      var hash = tx.hash('hex');
      var uniq = {};

      tx.inputs.forEach(function(input) {
        var coin, address;

        if (input.isCoinbase())
          return;

        assert(input.output);

        if (self.options.indexAddress) {
          address = input.getAddress();

          if (address && !uniq[address]) {
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
          input.output.toExtended());
      });

      tx.outputs.forEach(function(output, i) {
        var address;

        if (self.options.indexAddress) {
          address = output.getAddress();

          if (address && !uniq[address]) {
            uniq[address] = true;
            batch.del('t/a/' + address + '/' + hash);
          }

          if (address)
            batch.del('u/a/' + address + '/' + hash + '/' + i);
        }

        batch.del('u/t/' + hash + '/' + i);
      });
    });

    batch.write(function(err) {
      if (err)
        return callback(err);
      self.emit('remove block', block);
      return callback(null, block);
    });
  });
};

BlockDB.prototype.fillCoin = function fillCoin(tx, callback) {
  var self = this;

  callback = utils.asyncify(callback);

  if (Array.isArray(tx)) {
    return utils.forEach(tx, function(tx, next) {
      self.fillCoin(tx, next);
    }, function(err) {
      if (err)
        return callback(err);
      return callback(null, tx);
    });
  }

  if (tx.isCoinbase())
    return callback(null, tx);

  utils.forEach(tx.inputs, function(input, next) {
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

BlockDB.prototype.fillTX = function fillTX(tx, callback) {
  var self = this;

  callback = utils.asyncify(callback);

  if (Array.isArray(tx)) {
    return utils.forEach(tx, function(tx, next) {
      self.fillTX(tx, next);
    }, function(err) {
      if (err)
        return callback(err);
      return callback(null, tx);
    });
  }

  if (tx.isCoinbase())
    return callback(null, tx);

  utils.forEach(tx.inputs, function(input, next) {
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

BlockDB.prototype.getCoinsByAddress = function getCoinsByAddress(addresses, options, callback) {
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
    var iter = self.db.db.iterator({
      gte: 'u/a/' + address,
      lte: 'u/a/' + address + '~',
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

        if (key === undefined) {
          return iter.end(function(err) {
            if (err)
              return done(err);
            done();
          });
        }

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

BlockDB.prototype.getCoin = function getCoin(hash, index, callback) {
  var self = this;
  var id = 'u/t/' + hash + '/' + index;
  var coin;

  this.db.get(id, function(err, data) {
    if (err) {
      if (err.type === 'NotFoundError')
        return callback();
      return callback(err);
    }

    try {
      coin = bcoin.coin.fromExtended(data);
    } catch (e) {
      return callback(e);
    }

    return callback(null, coin);
  });
};

BlockDB.prototype.getTXByAddress = function getTXByAddress(addresses, options, callback) {
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
    var iter = self.db.db.iterator({
      gte: 't/a/' + address,
      lte: 't/a/' + address + '~',
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

        if (key === undefined) {
          return iter.end(function(err) {
            if (err)
              return done(err);
            done();
          });
        }

        hash = key.split('/')[3];

        if (addresses.length > 1) {
          if (have[hash])
            return next();

          have[hash] = true;
        }

        hashes.push(hash);
      });
    })();
  }, function(err) {
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

BlockDB.prototype.getTX = function getTX(hash, callback) {
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
      return callback(new Error('BlockDB is corrupt. All is lost.'));

    return callback(null, tx);
  });
};

BlockDB.prototype.getFullTX = function getFullTX(hash, callback) {
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

BlockDB.prototype.getFullBlock = function getFullBlock(hash, callback) {
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

BlockDB.prototype._getCoinBlock = function _getCoinBlock(hash, callback) {
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

BlockDB.prototype._getTXBlock = function _getTXBlock(hash, callback) {
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

BlockDB.prototype.fillBlock = function fillBlock(block, callback) {
  var self = this;

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

BlockDB.prototype.fillTXBlock = function fillTXBlock(block, callback) {
  var self = this;

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

BlockDB.prototype._getHash = function _getHash(height, callback) {
  if (typeof height === 'string')
    return callback(null, height);

  this.db.get('b/h/' + pad32(height), function(err, hash) {
    if (err)
      return callback(err);
    if (!hash)
      return callback();
    return callback(null, utils.toHex(hash));
  });
};

BlockDB.prototype.getBlock = function getBlock(hash, callback) {
  var self = this;
  var id, block;

  return this._getHash(hash, function(err, hash) {
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

BlockDB.prototype.hasBlock = function hasBlock(hash, callback) {
  var self = this;
  var id = 'b/b/' + hash;

  if (typeof hash === 'number')
    id = 'b/h/' + pad32(hash);

  this.db.get(id, function(err, data) {
    if (err && err.type !== 'NotFoundError')
      return callback(err);

    if (!data)
      return callback(null, false);

    return callback(null, true);
  });
};

BlockDB.prototype.hasCoin = function hasCoin(hash, index, callback) {
  var self = this;
  var id = 'u/t/' + hash + '/' + index;

  this.db.get(id, function(err, data) {
    if (err && err.type !== 'NotFoundError')
      return callback(err);

    if (!data)
      return callback(null, false);

    return callback(null, true);
  });
};

BlockDB.prototype._getTX = function _getTX(hash, callback) {
  if (hash instanceof bcoin.tx)
    return callback(null, hash);
  return this.getTX(hash);
};

BlockDB.prototype._spentTX = function _spentTX(hash, callback) {
  var self = this;
  this._getTX(hash, function(err, tx) {
    var hash, spent;

    if (err)
      return callback(err);

    if (!tx)
      return callback(null, 0, -1);

    hash = tx.hash('hex');
    spent = 0;

    utils.forEach(tx.outputs, function(output, next, i) {
      self.isSpent(hash, i, function(err, result) {
        if (err)
          return next(err);

        if (result)
          spent++;

        next();
      });
    });
  }, function(err) {
    if (err)
      return callback(err);
    return callback(null, spent, tx.outputs.length);
  });
};

// For BIP30
// https://bitcointalk.org/index.php?topic=67738.0
BlockDB.prototype.isUnspentTX = function isUnspentTX(hash, callback) {
  return this._spentTX(hash, function(err, spent, outputs) {
    if (err)
      return callback(err);

    return callback(null, spent < outputs);
  });
};

BlockDB.prototype.isSpentTX = function isSpentTX(hash, callback) {
  return this._spentTX(hash, function(err, spent, outputs) {
    if (err)
      return callback(err);

    return callback(null, spent === outputs);
  });
};

BlockDB.prototype.hasTX = function hasTX(hash, callback) {
  var self = this;
  var id = 't/t/' + hash;

  this.db.get(id, function(err, data) {
    if (err && err.type !== 'NotFoundError')
      return callback(err);

    if (!data)
      return callback(null, false);

    return callback(null, true);
  });
};

BlockDB.prototype.isSpent = function isSpent(hash, index, callback) {
  return this.hasCoin(hash, index, function(err, result) {
    if (err)
      return callback(err);

    return callback(null, !result);
  });
};

BlockDB.prototype.getHeight = function getHeight(callback) {
  var self = this;

  return this.db.get('b/t', function(err, height) {
    if (err && err.type !== 'NotFoundError')
      return callback(err);

    if (!height)
      return callback(null, -1);

    return callback(null, utils.readU32(height, 0));
  });
};

BlockDB.prototype.getTipHash = function getTipHash(callback) {
  return this.getHeight(function(err, height) {
    if (err)
      return callback(err);

    if (height === -1)
      return callback();

    return self.db.get('b/h/' + pad32(height), function(err, hash) {
      if (err && err.type !== 'NotFoundError')
        return callback(err);

      if (!hash)
        return callback();

      return callback(null, utils.toHex(hash));
    });
  });
};

BlockDB.prototype.reset = function reset(height, callback, emit) {
  var self = this;
  this.getHeight(function(err, currentHeight) {
    if (err)
      return callback(err);

    if (currentHeight < height)
      return callback(new Error('Cannot reset to height ' + height));

    (function next() {
      if (currentHeight === height)
        return callback();

      self.removeBlock(currentHeight, function(err, block) {
        if (err)
          return callback(err);

        // Emit the blocks we removed.
        if (emit && block)
          emit(block);

        currentHeight--;
        next();
      });
    })();
  });
};

BlockDB.prototype.batch = function batch() {
  if (this.fsync)
    return new utils.SyncBatch(this.db);
  return this.db.batch();
};

/**
 * Expose
 */

module.exports = BlockDB;
