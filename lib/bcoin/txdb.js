/**
 * txdb.js - persistent transaction pool
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bn = require('bn.js');
var bcoin = require('../bcoin');
var utils = bcoin.utils;
var assert = bcoin.utils.assert;
var EventEmitter = require('events').EventEmitter;
var DUMMY = new Buffer([]);

/**
 * TXPool
 */

function TXPool(prefix, db, options) {
  var self = this;

  if (!(this instanceof TXPool))
    return new TXPool(prefix, db, options);

  EventEmitter.call(this);

  if (!options)
    options = {};

  this.db = db;
  this.prefix = prefix || 'pool';
  this.options = options;
  this.busy = false;
  this.jobs = [];

  this.setMaxListeners(Number.MAX_SAFE_INTEGER);
}

utils.inherits(TXPool, EventEmitter);

TXPool.prototype._lock = function _lock(func, args, force) {
  var self = this;
  var called;

  if (force) {
    assert(this.busy);
    return function unlock() {
      assert(!called);
      called = true;
    };
  }

  if (this.busy) {
    this.jobs.push([func, args]);
    return;
  }

  this.busy = true;

  return function unlock() {
    var item, block;

    assert(!called);
    called = true;

    self.busy = false;

    if (self.jobs.length === 0) {
      self.emit('flush');
      return;
    }

    item = self.jobs.shift();
    item[0].apply(self, item[1]);
  };
};

TXPool.prototype.getMap = function getMap(tx, callback) {
  var self = this;
  var addresses = tx.getAddresses();
  var map;

  function cb(err, map) {
    if (err)
      return callback(err);

    map.input = [];
    map.output = [];
    map.all = [];

    tx.getInputAddresses().forEach(function(address) {
      assert(map[address]);
      map.input = map.input.concat(map[address]);
    });

    tx.getOutputAddresses().forEach(function(address) {
      assert(map[address]);
      map.output = map.output.concat(map[address]);
    });

    map.input = utils.uniqs(map.input);
    map.output = utils.uniqs(map.output);
    map.all = utils.uniqs(map.input.concat(map.output));

    return callback(null, map);
  }

  if (!this.options.ids) {
    map = addresses.reduce(function(out, address) {
      out[address] = [address];
      return out;
    }, {});
    return cb(null, map);
  }

  return this.mapAddresses(addresses, cb);
};

TXPool.prototype.mapAddresses = function mapAddresses(address, callback) {
  var prefix = this.prefix + '/';
  var self = this;
  var map = {};
  var iter;

  if (Array.isArray(address)) {
    address = utils.uniqs(address);
    return utils.forEachSerial(address, function(address, next) {
      self.mapAddresses(address, function(err, res) {
        if (err)
          return next(err);

        assert(res[address]);
        map[address] = res[address];

        next();
      });
    }, function(err) {
      if (err)
        return callback(err);

      return callback(null, map);
    });
  }

  iter = this.db.db.iterator({
    gte: prefix + 'a/' + address,
    lte: prefix + 'a/' + address + '~',
    keys: true,
    values: false,
    fillCache: false,
    keyAsBuffer: false
  });

  callback = utils.ensure(callback);

  map[address] = [];

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
          map[address] = utils.uniqs(map[address]);
          return callback(null, map);
        });
      }

      key = key.split('/')[3];
      map[address].push(key);

      next();
    });
  })();
};

TXPool.prototype._addOrphan = function add(key, hash, index, callback) {
  var prefix = this.prefix + '/';
  var self = this;
  var orphans;

  this.db.get(prefix + 'o/' + key, function(err, buf) {
    if (err && err.type !== 'NotFoundError')
      return callback(err);

    if (!buf)
      buf = new Buffer([]);

    orphans = new Buffer(buf.length + 36);
    utils.copy(buf, orphans, 0);
    utils.copy(new Buffer(hash, 'hex'), orphans, buf.length);
    utils.writeU32(orphans, index, buf.length + 32);

    return callback(null, orphans);
  });
};

TXPool.prototype._getOrphans = function _getOrphans(key, callback) {
  var prefix = this.prefix + '/';
  var self = this;
  var orphans = [];
  var i;

  this.db.get(prefix + 'o/' + key, function(err, buf) {
    if (err && err.type !== 'NotFoundError')
      return callback(err);

    if (!buf)
      return callback();

    for (i = 0; i < buf.length; i += 36) {
      if (i + 36 > buf.length)
        return callback(new Error('Incomplete orphan list.'));

      orphans.push({
        hash: utils.toHex(buf.slice(i, i + 32)),
        index: utils.readU32(buf, i + 32)
      });
    }

    utils.forEach(orphans, function(orphan, next) {
      self.getTX(orphan.hash, function(err, tx) {
        if (err)
          return done(err);

        orphan.tx = tx;

        next();
      });
    }, function(err) {
      if (err)
        return callback(err);

      return callback(null, orphans);
    });
  });
};

TXPool.prototype.add = function add(tx, callback) {
  var self = this;

  if (Array.isArray(tx)) {
    return utils.forEachSerial(tx, function(tx, next) {
      self.add(tx, next);
    }, callback);
  }

  return this.getMap(tx, function(err, map) {
    if (err)
      return callback(err);

    if (map.all.length === 0)
      return callback(null, false);

    return self._add(tx, map, callback);
  });
};

// This big scary function is what a persistent tx pool
// looks like. It's a semi mempool in that it can handle
// receiving txs out of order.
TXPool.prototype._add = function add(tx, map, callback, force) {
  var self = this;
  var prefix = this.prefix + '/';
  var hash = tx.hash('hex');
  var updated = false;
  var own = false;
  var uniq = {};
  var batch;

  var unlock = this._lock(add, [tx, map, callback], force);
  if (!unlock)
    return;

  function done(err, result) {
    unlock();
    if (callback)
      callback(err, result);
  };

  this.getTX(hash, function(err, existing) {
    if (err)
      return done(err);

    batch = self.db.batch();

    if (existing) {
      own = true;
      // Tricky - update the tx and coin in storage,
      // and remove pending flag to mark as confirmed.
      if (existing.ts === 0 && tx.ts !== 0) {
        batch.put(prefix + 't/t/' + hash, tx.toExtended());
        batch.put(prefix + 't/h/' + tx.height + '/' + hash, DUMMY);
        batch.del(prefix + 'p/t/' + hash);

        tx.inputs.forEach(function(input) {
          var address = input.getAddress();

          if (input.isCoinbase())
            return;

          if (address && !uniq[address]) {
            uniq[address] = true;
            map[address].forEach(function(id) {
              batch.del(prefix + 'p/a/' + id + '/' + hash);
            });
          }
        });

        utils.forEachSerial(tx.outputs, function(output, next, i) {
          var address = output.getAddress();

          if (address && !uniq[address]) {
            uniq[address] = true;
            map[address].forEach(function(id) {
              batch.del(prefix + 'p/a/' + id + '/' + hash);
            });
          }

          self.getCoin(hash, i, function(err, coin) {
            if (err)
              return next(err);

            if (!coin)
              return next();

            coin.height = tx.height;

            batch.put(prefix + 'u/t/' + hash + '/' + i, coin.toRaw());

            next();
          });
        }, function(err) {
          if (err)
            return done(err);

          batch.write(function(err) {
            if (err)
              return done(err);

            self.emit('confirmed', tx, map);
            self.emit('tx', tx, map);

            return done(null, true);
          });
        });

        return;
      }
      return done(null, false);
    }

    // Consume unspent money or add orphans
    utils.forEachSerial(tx.inputs, function(input, next, i) {
      var key;

      if (input.isCoinbase())
        return next();

      key = input.prevout.hash + '/' + input.prevout.index;

      self.getCoin(input.prevout.hash, input.prevout.index, function(err, coin) {
        var address;

        if (err)
          return next(err);

        address = input.getAddress();

        if (address && !uniq[address]) {
          uniq[address] = true;
          map[address].forEach(function(id) {
            batch.put(prefix + 't/a/' + id + '/' + hash, DUMMY);
            if (tx.ts === 0)
              batch.put(prefix + 'p/a/' + id + '/' + hash, DUMMY);
          });
        }

        if (coin) {
          // Add TX to inputs and spend money
          input.output = coin;

          assert(input.prevout.hash === coin.hash);
          assert(input.prevout.index === coin.index);

          // Skip invalid transactions
          if (!tx.verify(i))
            return done(null, false);

          updated = true;
          own = true;

          if (address) {
            map[address].forEach(function(id) {
              batch.del(
                prefix + 'u/a/' + id
                + '/' + input.prevout.hash
                + '/' + input.prevout.index);
            });
          }

          batch.del(
            prefix + 'u/t/'
            + input.prevout.hash
            + '/' + input.prevout.index);

          return next();
        }

        // Only add orphans if this input is ours.
        if (!address || !map[address].length)
          return next();

        own = true;

        self.getTX(input.prevout.hash, function(err, result) {
          if (err)
            return done(err);

          // Are we double-spending?
          if (result)
            return done(new Error('Transaction is double-spending.'));

          // Add orphan, if no parent transaction is yet known
          self._addOrphan(key, hash, i, function(err, orphans) {
            if (err)
              return done(err);

            batch.put(prefix + 'o/' + key, orphans);

            return next();
          });
        });
      });
    }, function(err) {
      if (err)
        return done(err);

      // Add unspent outputs or resolve orphans
      utils.forEachSerial(tx.outputs, function(output, next, i) {
        var address = output.getAddress();
        var key, coin;

        // Do not add unspents for outputs that aren't ours.
        if (!address || !map[address].length)
          return next();

        key = hash + '/' + i;
        coin = bcoin.coin(tx, i);
        own = true;

        self._getOrphans(key, function(err, orphans) {
          var some = false;

          if (err)
            return done(err);

          if (!orphans)
            return finish();

          // Add input to orphan
          utils.forEachSerial(orphans, function(orphan, next, j) {
            if (some)
              return next();

            // Probably removed by some other means.
            if (!orphan.tx)
              return next();

            orphan.tx.inputs[orphan.index].output = coin;

            assert(orphan.tx.inputs[orphan.index].prevout.hash === hash);
            assert(orphan.tx.inputs[orphan.index].prevout.index === i);

            // Verify that input script is correct, if not - add
            // output to unspent and remove orphan from storage
            if (orphan.tx.verify(orphan.index)) {
              some = true;
              return next();
            }

            self.lazyRemove(orphan.tx, function(err) {
              if (err)
                return next(err);
              return next();
            });
          }, function(err) {
            if (err)
              return next(err);

            if (!some)
              orphans = null;

            self.db.del(prefix + 'o/' + key, finish);
          });

          function finish(err) {
            if (err)
              return next(err);

            if (!orphans) {
              if (address && !uniq[address]) {
                uniq[address] = true;
                map[address].forEach(function(id) {
                  batch.put(prefix + 't/a/' + id + '/' + hash, DUMMY);
                  if (tx.ts === 0)
                    batch.put(prefix + 'p/a/' + id + '/' + hash, DUMMY);
                });
              }

              if (address) {
                map[address].forEach(function(id) {
                  batch.put(
                    prefix + 'u/a/' + id
                    + '/' + hash + '/' + i,
                    DUMMY);
                });
              }

              batch.put(prefix + 'u/t/' + hash + '/' + i, coin.toRaw());
              updated = true;
            }

            next();
          }
        });
      }, function(err) {
        if (err)
          return done(err);

        if (!own)
          return done(null, false);

        batch.put(prefix + 't/t/' + hash, tx.toExtended());
        if (tx.ts === 0)
          batch.put(prefix + 'p/t/' + hash, DUMMY);
        else
          batch.put(prefix + 't/h/' + tx.height + '/' + hash, DUMMY);

        batch.write(function(err) {
          if (err)
            return done(err);

          self.emit('tx', tx, map);

          if (updated) {
            if (tx.ts !== 0)
              self.emit('confirmed', tx, map);

            self.emit('updated', tx, map);
          }

          return done(null, true);
        });
      });
    });
  });
};

TXPool.prototype.remove = function remove(hash, callback) {
  var self = this;

  if (Array.isArray(hash)) {
    return utils.forEachSerial(hash, function(hash, next) {
      self.remove(hash, next);
    }, callback);
  }

  if (hash.hash)
    hash = hash.hash('hex');

  this.getTX(hash, function(err, tx) {
    if (err)
      return callback(err);

    if (!tx)
      return callback(null, true);

    assert(tx.hash('hex') === hash);

    return self.getMap(tx, function(err, map) {
      if (err)
        return callback(err);

      if (map.all.length === 0)
        return callback(null, false);

      return self._remove(tx, map, callback);
    });
  });
};

TXPool.prototype.lazyRemove = function lazyRemove(tx, callback) {
  var self = this;

  if (Array.isArray(tx)) {
    return utils.forEachSerial(tx, function(tx, next) {
      self.lazyRemove(tx, next);
    }, callback);
  }

  return this.getMap(tx, function(err, map) {
    if (err)
      return callback(err);

    if (map.all.length === 0)
      return callback(null, false);

    return self._remove(tx, map, callback);
  });
};

TXPool.prototype._remove = function remove(tx, map, callback) {
  var self = this;
  var prefix = this.prefix + '/';
  var hash = tx.hash('hex');
  var batch = this.db.batch();
  var uniq = {};

  batch.del(prefix + 't/t/' + hash);
  if (tx.ts === 0)
    batch.del(prefix + 'p/t/' + hash);
  else
    batch.del(prefix + 't/h/' + tx.height + '/' + hash);

  this.fillTX(tx, function(err) {
    if (err)
      return next(err);

    tx.inputs.forEach(function(input) {
      var address = input.getAddress();

      if (input.isCoinbase())
        return;

      if (address && !uniq[address]) {
        uniq[address] = true;
        map[address].forEach(function(id) {
          batch.del(prefix + 't/a/' + id + '/' + hash);
          if (tx.ts === 0)
            batch.del(prefix + 'p/a/' + id + '/' + hash);
        });
      }

      if (!input.output)
        return;

      if (address) {
        map[address].forEach(function(id) {
          batch.put(prefix + 'u/a/' + id
            + '/' + input.prevout.hash
            + '/' + input.prevout.index,
            DUMMY);
        });
      }

      batch.put(prefix + 'u/t/'
        + input.prevout.hash
        + '/' + input.prevout.index,
        input.output.toRaw());

      batch.del(prefix + 'o/' + input.prevout.hash + '/' + input.prevout.index);
    });

    tx.outputs.forEach(function(output, i) {
      var address = output.getAddress();

      if (address && !uniq[address]) {
        uniq[address] = true;
        map[address].forEach(function(id) {
          batch.del(prefix + 't/a/' + id + '/' + hash);
          if (tx.ts === 0)
            batch.del(prefix + 'p/a/' + id + '/' + hash);
        });
      }

      if (address) {
        map[address].forEach(function(id) {
          batch.del(prefix + 'u/a/' + id + '/' + hash + '/' + i);
        });
      }

      batch.del(prefix + 'u/t/' + hash + '/' + i);
    });

    batch.write(function(err) {
      if (err)
        return callback(err);

      self.emit('remove tx', tx, map);

      return callback(null, true);
    });
  });
};

TXPool.prototype.unconfirm = function unconfirm(hash, callback) {
  var self = this;

  if (Array.isArray(hash)) {
    return utils.forEachSerial(hash, function(hash, next) {
      self.unconfirm(hash, next);
    }, callback);
  }

  if (hash.hash)
    hash = hash.hash('hex');

  this.getTX(hash, function(err, tx) {
    if (err)
      return callback(err);

    if (!tx)
      return callback(null, true);

    assert(tx.hash('hex') === hash);

    return self.getMap(tx, function(err, map) {
      if (err)
        return callback(err);

      if (map.all.length === 0)
        return callback(null, false);

      return self._unconfirm(tx, map, callback);
    });
  });
};

TXPool.prototype._unconfirm = function unconfirm(tx, map, callback) {
  var self = this;
  var prefix = this.prefix + '/';
  var uniq = {};
  var hash = tx.hash('hex');
  var batch = this.db.batch();
  var height = tx.height;

  tx.height = -1;
  tx.ps = utils.now();
  tx.ts = 0;
  tx.index = -1;
  tx.block = null;

  batch.put(prefix + 't/t/' + hash, tx.toExtended());
  batch.put(prefix + 'p/t/' + hash, DUMMY);
  batch.del(prefix + 't/h/' + height + '/' + hash);

  tx.inputs.forEach(function(input) {
    var address;

    if (input.isCoinbase())
      return;

    address = input.getAddress();

    if (address && !uniq[address]) {
      uniq[address] = true;
      map[address].forEach(function(id) {
        batch.put(prefix + 'p/a/' + id + '/' + hash, DUMMY);
      });
    }
  });

  utils.forEachSerial(tx.outputs, function(output, next, i) {
    var address = output.getAddress();

    if (address && !uniq[address]) {
      uniq[address] = true;
      map[address].forEach(function(id) {
        batch.put(prefix + 'p/a/' + id + '/' + hash, DUMMY);
      });
    }

    self.getCoin(hash, i, function(err, coin) {
      if (err)
        return next(err);

      if (!coin)
        return next();

      coin.height = tx.height;

      batch.put(prefix + 'u/t/' + hash + '/' + i, coin.toRaw());

      next();
    });
  }, function(err) {
    if (err)
      return callback(err);

    batch.write(function(err) {
      if (err)
        return callback(err);

      self.emit('unconfirmed', tx, map);

      return callback(null, true);
    });
  });
};

TXPool.prototype.getTXHashes = function getTXHashes(address, callback) {
  var prefix = this.prefix + '/';
  var self = this;
  var txs = [];
  var iter;

  callback = utils.ensure(callback);

  if (Array.isArray(address)) {
    return utils.forEachSerial(address, function(address, next) {
      self.getTXHashes(address, function(err, tx) {
        if (err)
          return next(err);

        txs = txs.concat(tx);

        next();
      });
    }, function(err) {
      if (err)
        return callback(err);

      txs = utils.uniqs(txs);

      return callback(null, txs);
    });
  }

  iter = this.db.db.iterator({
    gte: address ? prefix + 't/a/' + address : prefix + 't/t',
    lte: address ? prefix + 't/a/' + address + '~' : prefix + 't/t~',
    keys: true,
    values: false,
    fillCache: false,
    keyAsBuffer: false
  });

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
          return callback(null, txs);
        });
      }

      if (address)
        txs.push(key.split('/')[4]);
      else
        txs.push(key.split('/')[3]);

      next();
    });
  })();
};

TXPool.prototype.getPendingHashes = function getPendingHashes(address, callback) {
  var prefix = this.prefix + '/';
  var self = this;
  var txs = [];
  var iter;

  callback = utils.ensure(callback);

  if (Array.isArray(address)) {
    return utils.forEachSerial(address, function(address, next) {
      assert(address);
      self.getPendingHashes(address, function(err, tx) {
        if (err)
          return next(err);

        txs = txs.concat(tx);

        next();
      });
    }, function(err) {
      if (err)
        return callback(err);

      txs = utils.uniqs(txs);

      return callback(null, txs);
    });
  }

  iter = this.db.db.iterator({
    gte: address ? prefix + 'p/a/' + address : prefix + 'p/t',
    lte: address ? prefix + 'p/a/' + address + '~' : prefix + 'p/t~',
    keys: true,
    values: false,
    fillCache: false,
    keyAsBuffer: false
  });

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
          return callback(null, txs);
        });
      }

      if (address)
        txs.push(key.split('/')[4]);
      else
        txs.push(key.split('/')[3]);

      next();
    });
  })();
};

TXPool.prototype.getCoinIDs = function getCoinIDs(address, callback) {
  var prefix = this.prefix + '/';
  var self = this;
  var coins = [];
  var iter;

  callback = utils.ensure(callback);

  if (Array.isArray(address)) {
    return utils.forEachSerial(address, function(address, next) {
      self.getCoinIDs(address, function(err, coin) {
        if (err)
          return next(err);

        coins = coins.concat(coin);

        next();
      });
    }, function(err) {
      if (err)
        return callback(err);

      coins = utils.uniqs(coins);

      return callback(null, coins);
    });
  }

  iter = this.db.db.iterator({
    gte: address ? prefix + 'u/a/' + address : prefix + 'u/t',
    lte: address ? prefix + 'u/a/' + address + '~' : prefix + 'u/t~',
    keys: true,
    values: false,
    fillCache: false,
    keyAsBuffer: false
  });

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
          return callback(null, coins);
        });
      }

      if (address)
        coins.push(key.split('/').slice(4).join('/'));
      else
        coins.push(key.split('/').slice(3).join('/'));

      next();
    });
  })();
};

TXPool.prototype.getHeightHashes = function getHeightHashes(height, callback) {
  var prefix = this.prefix + '/';
  var self = this;
  var txs = [];
  var iter;

  callback = utils.ensure(callback);

  if (Array.isArray(height)) {
    return utils.forEachSerial(height, function(height, next) {
      self.getHeightHashes(height, function(err, tx) {
        if (err)
          return next(err);

        txs = txs.concat(tx);

        next();
      });
    }, function(err) {
      if (err)
        return callback(err);

      txs = utils.uniqs(txs);

      return callback(null, txs);
    });
  }

  iter = this.db.db.iterator({
    gte: prefix + 't/h/' + height,
    lte: prefix + 't/h/' + height + '~',
    keys: true,
    values: false,
    fillCache: false,
    keyAsBuffer: false
  });

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
          return callback(null, txs);
        });
      }

      txs.push(key.split('/')[4]);

      next();
    });
  })();
};

TXPool.prototype.getAllByAddress = function getAllByAddress(address, callback) {
  var self = this;
  var txs = [];

  return this.getTXHashes(address, function(err, hashes) {
    if (err)
      return callback(err);

    utils.forEachSerial(hashes, function(hash, next) {
      self.getTX(hash, function(err, tx) {
        if (err)
          return callback(err);

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

TXPool.prototype.getLast = function getLast(address, callback) {
  return this.getAllByAddress(address, function(err, txs) {
    var lastTs, lastHeight;

    if (err)
      return callback(err);

    lastTs = 0;
    lastHeight = -1;

    txs.forEach(function(tx) {
      if (tx.ts > lastTs)
        lastTs = tx.ts;

      if (tx.height > lastHeight)
        lastHeight = tx.height;
    });

    return callback(null, lastTs, lastHeight);
  });
};

TXPool.prototype.getPendingByAddress = function getPendingByAddress(address, callback) {
  var txs = [];

  return this.getPendingHashes(address, function(err, hashes) {
    if (err)
      return callback(err);

    utils.forEachSerial(hashes, function(hash, next) {
      self.getTX(hash, function(err, tx) {
        if (err)
          return callback(err);

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

TXPool.prototype.getCoinsByAddress = function getCoinsByAddress(address, callback) {
  var self = this;
  var coins = [];

  return this.getCoinIDs(address, function(err, map) {
    if (err)
      return callback(err);

    utils.forEachSerial(map, function(id, next) {
      var parts = id.split('/');
      self.getCoin(parts[0], +parts[1], function(err, coin) {
        if (err)
          return callback(err);

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

TXPool.prototype.fillTX = function fillTX(tx, callback) {
  var self = this;

  if (Array.isArray(tx)) {
    return utils.forEachSerial(tx, function(tx, next) {
      self.fillTX(tx, function(err) {
        if (err)
          return next(err);

        next();
      });
    }, callback);
  }

  callback = utils.asyncify(callback);

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

TXPool.prototype.fillCoin = function fillCoin(tx, callback) {
  var self = this;

  if (Array.isArray(tx)) {
    return utils.forEachSerial(tx, function(tx, next) {
      self.fillCoin(tx, function(err) {
        if (err)
          return next(err);

        next();
      });
    }, callback);
  }

  callback = utils.asyncify(callback);

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

TXPool.prototype.getTX = function getTX(hash, callback) {
  var prefix = this.prefix + '/';
  var id = prefix + 't/t/' + hash;

  this.db.get(id, function(err, tx) {
    if (err) {
      if (err.type === 'NotFoundError')
        return callback();
      return callback(err);
    }
    return callback(null, bcoin.tx.fromExtended(tx));
  });
};

TXPool.prototype.getCoin = function getCoin(hash, index, callback) {
  var prefix = this.prefix + '/';
  var id = prefix + 'u/t/' + hash + '/' + index;

  this.db.get(id, function(err, coin) {
    if (err) {
      if (err.type === 'NotFoundError')
        return callback();
      return callback(err);
    }

    return callback(null, bcoin.coin.fromRaw(coin));
  });
};

TXPool.prototype.getBalanceByAddress = function getBalanceByAddress(address, callback) {
  return this.getCoinsByAddress(address, function(err, coins) {
    if (err)
      return callback(err);

    coins = coins.reduce(function(acc, coin) {
      return acc.iadd(coin.value);
    }, new bn(0));

    return callback(null, coins);
  });
};

TXPool.prototype.getAll = function getAll(callback) {
  return this.getAllByAddress(null, callback);
};

TXPool.prototype.getCoins = function getCoins(callback) {
  return this.getCoinsByAddress(null, callback);
};

TXPool.prototype.getPending = function getPending(callback) {
  return this.getPendingByAddress(null, callback);
};

TXPool.prototype.getBalance = function getBalance(callback) {
  return this.getBalanceByAddress(null, callback);
};

/**
 * Expose
 */

module.exports = TXPool;
