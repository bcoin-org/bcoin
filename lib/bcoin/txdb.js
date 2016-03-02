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

/**
 * TXPool
 */

function TXPool(prefix, db) {
  var self = this;

  if (!(this instanceof TXPool))
    return new TXPool(wallet, txs);

  EventEmitter.call(this);

  this.db = db;
  this.prefix = prefix || 'pool';
  this.busy = false;
  this.jobs = [];
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

TXPool.prototype.add = function add(tx, callback) {
  var self = this;

  if (Array.isArray(tx)) {
    return utils.forEachSerial(tx, function(tx, next) {
      self.add(tx, next);
    }, callback);
  }

  return self._add(tx, callback);
};

TXPool.prototype._hasAddress = function _hasAddress(address, callback) {
  if (!address)
    return callback(null, false);
  return callback(null, true);
};

// This big scary function is what a persistent tx pool
// looks like. It's a semi mempool in that it can handle
// receiving txs out of order.
TXPool.prototype._add = function add(tx, callback, force) {
  var self = this;
  var p = this.prefix + '/';
  var hash = tx.hash('hex');
  var updated = false;
  var batch;

  var unlock = this._lock(add, [tx, callback], force);
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
      // Tricky - update the tx and coin in storage,
      // and remove pending flag to mark as confirmed.
      if (existing.ts === 0 && tx.ts !== 0) {
        batch.put(p + 't/t/' + hash, tx.toExtended());
        batch.put(p + 't/h/' + tx.height + '/' + hash, new Buffer([]));
        batch.del(p + 'p/t/' + hash);

        tx.inputs.forEach(function(input) {
          var type = input.getType();
          var address = input.getAddress();
          var uaddr;

          if (input.isCoinbase())
            return;

          if (type === 'pubkey' || type === 'multisig')
            address = null;

          uaddr = address;

          if (uaddr) {
            if (!uniq[uaddr])
              uniq[uaddr] = true;
            else
              uaddr = null;
          }

          if (uaddr)
            batch.del(p + 'p/a/' + uaddr + '/' + hash);
        });

        utils.forEachSerial(tx.outputs, function(output, next, i) {
          var type = output.getType();
          var address = output.getAddress();
          var uaddr;

          if (type === 'pubkey' || type === 'multisig')
            address = null;

          uaddr = address;

          if (uaddr) {
            if (!uniq[uaddr])
              uniq[uaddr] = true;
            else
              uaddr = null;
          }

          if (uaddr)
            batch.del(p + 'p/a/' + uaddr + '/' + hash);

          self.getCoin(hash, i, function(err, coin) {
            if (err)
              return next(err);

            if (!coin)
              return next();

            coin.height = tx.height;

            batch.put(p + 'u/t/' + hash + '/' + i, coin.toRaw());

            next();
          });
        }, function(err) {
          if (err)
            return done(err);

          batch.write(function(err) {
            if (err)
              return done(err);

            self.emit('confirmed', tx);
            self.emit('tx', tx);

            return done(null, true);
          });
        });

        return;
      }
      return done(null, false);
    }

    // Consume unspent money or add orphans
    utils.forEachSerial(tx.inputs, function(input, next, i) {
      var key = input.prevout.hash + '/' + input.prevout.index;
      self.getCoin(input.prevout.hash, input.prevout.index, function(err, coin) {
        var type, address;

        if (err)
          return next(err);

        if (coin) {
          // Add TX to inputs and spend money
          input.output = coin;

          assert(input.prevout.hash === coin.hash);
          assert(input.prevout.index === coin.index);

          // Skip invalid transactions
          if (!tx.verify(i))
            return done(null, false);

          updated = true;

          type = input.getType();
          address = input.getAddress();

          if (type === 'pubkey' || type === 'multisig')
            address = null;

          if (input.isCoinbase())
            return next();

          if (address) {
            batch.del(
              p + 'u/a/' + address
              + '/' + input.prevout.hash
              + '/' + input.prevout.index);
          }

          batch.del(
            p + 'u/t/'
            + input.prevout.hash
            + '/' + input.prevout.index);

          return next();
        }

        // Only add orphans if this input is ours.
        self._hasAddress(input.getAddress(), function(err, result) {
          if (err)
            return done(err);

          if (!result)
            return next();

          self.getTX(input.prevout.hash, function(err, result) {
            if (err)
              return done(err);

            // Are we double-spending?
            if (result)
              return done(new Error('Transaction is double-spending.'));

            // Add orphan, if no parent transaction is yet known
            self.db.get(p + 'o/' + key, function(err, orphans) {
              if (err && err.type !== 'NotFoundError')
                return done(err);

              if (orphans) {
                try {
                  orphans = JSON.parse(orphans.toString('ascii'));
                } catch (e) {
                  return done(e);
                }
              } else {
                orphans = [];
              }

              orphans.push({
                tx: hash,
                index: i
              });

              orphans = new Buffer(JSON.stringify(orphans), 'ascii');

              batch.put(p + 'o/' + key, orphans);

              return next();
            });
          });
        });
      });
    }, function(err) {
      if (err)
        return done(err);

      // Add unspent outputs or resolve orphans
      utils.forEachSerial(tx.outputs, function(output, next, i) {
        // Do not add unspents for outputs that aren't ours.
        self._hasAddress(output.getAddress(), function(err, result) {
          var key, coin;

          if (err)
            return done(err);

          if (!result)
            return next();

          key = hash + '/' + i;
          coin = bcoin.coin(tx, i);

          self.db.get(p + 'o/' + key, function(err, orphans) {
            var some;

            if (err && err.type !== 'NotFoundError')
              return done(err);

            // Add input to orphan
            if (orphans) {
              some = false;

              try {
                orphans = JSON.parse(orphans.toString('ascii'));
              } catch (e) {
                return done(e);
              }

              utils.forEachSerial(orphans, function(orphan, next, j) {
                if (some)
                  return next();

                self.getTX(orphan.tx, function(err, otx) {
                  if (err)
                    return done(err);

                  // Probably removed by some other means.
                  if (!otx)
                    return next();

                  orphan.tx = otx;
                  orphan.tx.inputs[orphan.index].output = coin;

                  assert(orphan.tx.inputs[orphan.index].prevout.hash === hash);
                  assert(orphan.tx.inputs[orphan.index].prevout.index === i);

                  // Verify that input script is correct, if not - add
                  // output to unspent and remove orphan from storage
                  if (orphan.tx.verify(orphan.index)) {
                    some = true;
                    return next();
                  }

                  self.remove(orphan.tx, function(err) {
                    if (err)
                      return next(err);
                    return next();
                  });
                });
              }, function(err) {
                if (err)
                  return next(err);

                if (!some)
                  orphans = null;

                self.db.del(p + 'o/' + key, finish);
              });
            } else {
              finish();
            }

            function finish(err) {
              var type, adddress;

              if (err)
                return next(err);

              if (!orphans) {
                type = output.getType();
                address = output.getAddress();

                if (type === 'pubkey' || type === 'multisig')
                  address = null;

                if (address) {
                  batch.put(
                    p + 'u/a/' + address
                    + '/' + hash + '/' + i,
                    new Buffer([]));
                }

                batch.put(p + 'u/t/' + hash + '/' + i, coin.toRaw());
                updated = true;
              }

              next();
            }
          });

          return true;
        });
      }, function(err) {
        if (err)
          return done(err);

        batch.put(p + 't/t/' + hash, tx.toExtended());
        if (tx.ts === 0)
          batch.put(p + 'p/t/' + hash, new Buffer([]));
        else
          batch.put(p + 't/h/' + tx.height + '/' + hash, new Buffer([]));

        tx.getAddresses().forEach(function(address) {
          batch.put(p + 't/a/' + address + '/' + hash, new Buffer([]));
          if (tx.ts === 0)
            batch.put(p + 'p/a/' + address + '/' + hash, new Buffer([]));
        });

        batch.write(function(err) {
          if (err)
            return done(err);

          self.emit('tx', tx);

          if (tx.ts !== 0)
            self.emit('confirmed', tx);

          if (updated)
            self.emit('updated', tx);

          return done(null, true);
        });
      });
    });
  });
};

TXPool.prototype.remove = function remove(hash, callback) {
  var self = this;
  var p = this.prefix + '/';
  var uniq = {};

  if (hash.hash)
    hash = hash.hash('hex');

  this.getTX(hash, function(err, tx) {
    var batch;

    if (err)
      return callback(err);

    if (!tx)
      return callback(null, true);

    batch = self.db.batch();

    assert(tx.hash('hex') === hash);

    batch.del(p + 't/t/' + hash);
    if (tx.ts === 0)
      batch.del(p + 'p/t/' + hash);
    else
      batch.del(p + 't/h/' + tx.height + '/' + hash);

    self.fillTX(tx, function(err) {
      if (err)
        return next(err);

      tx.inputs.forEach(function(input) {
        var type = input.getType();
        var address = input.getAddress();
        var uaddr;

        if (input.isCoinbase())
          return;

        if (type === 'pubkey' || type === 'multisig')
          address = null;

        uaddr = address;

        if (uaddr) {
          if (!uniq[uaddr])
            uniq[uaddr] = true;
          else
            uaddr = null;
        }

        if (uaddr) {
          batch.del(p + 't/a/' + uaddr + '/' + hash);
          if (tx.ts === 0)
            batch.del(p + 'p/a/' + uaddr + '/' + hash);
        }

        if (address) {
          batch.put(p + 'u/a/' + address
            + '/' + input.prevout.hash
            + '/' + input.prevout.index,
            new Buffer([]));
        }

        if (input.output) {
          batch.put(p + 'u/t/'
            + input.prevout.hash
            + '/' + input.prevout.index,
            input.output.toRaw());
        }

        batch.del(p + 'o/' + input.prevout.hash + '/' + input.prevout.index);
      });

      tx.outputs.forEach(function(output, i) {
        var type = output.getType();
        var address = output.getAddress();
        var uaddr;

        if (type === 'pubkey' || type === 'multisig')
          address = null;

        uaddr = address;

        if (uaddr) {
          if (!uniq[uaddr])
            uniq[uaddr] = true;
          else
            uaddr = null;
        }

        if (uaddr) {
          batch.del(p + 't/a/' + uaddr + '/' + hash);
          if (tx.ts === 0)
            batch.del(p + 'p/a/' + uaddr + '/' + hash);
        }

        if (address)
          batch.del(p + 'u/a/' + address + '/' + hash + '/' + i);

        batch.del(p + 'u/t/' + hash + '/' + i);
      });

      batch.write(function(err) {
        if (err)
          return callback(err);

        self.emit('remove tx', tx);
        return callback(null, true);
      });
    });
  });
};

TXPool.prototype.unconfirm = function unconfirm(hash, callback) {
  var self = this;
  var p = this.prefix + '/';
  var uniq = {};

  if (hash.hash)
    hash = hash.hash('hex');

  this.getTX(hash, function(err, tx) {
    var batch, height;

    if (err)
      return callback(err);

    if (!tx)
      return callback(null, true);

    height = tx.height;
    tx.height = -1;
    tx.ps = utils.now();
    tx.ts = 0;
    tx.index = -1;
    tx.block = null;

    batch.put(p + 't/t/' + hash, tx.toExtended());
    batch.put(p + 'p/t/' + hash, new Buffer([]));
    batch.del(p + 't/h/' + height + '/' + hash);

    tx.inputs.forEach(function(input) {
      var type = input.getType();
      var address = input.getAddress();
      var uaddr;

      if (input.isCoinbase())
        return;

      if (type === 'pubkey' || type === 'multisig')
        address = null;

      uaddr = address;

      if (uaddr) {
        if (!uniq[uaddr])
          uniq[uaddr] = true;
        else
          uaddr = null;
      }

      if (uaddr)
        batch.put(p + 'p/a/' + uaddr + '/' + hash, new Buffer([]));
    });

    utils.forEachSerial(tx.outputs, function(output, next, i) {
      var type = output.getType();
      var address = output.getAddress();
      var uaddr;

      if (type === 'pubkey' || type === 'multisig')
        address = null;

      uaddr = address;

      if (uaddr) {
        if (!uniq[uaddr])
          uniq[uaddr] = true;
        else
          uaddr = null;
      }

      if (uaddr)
        batch.put(p + 'p/a/' + uaddr + '/' + hash, new Buffer([]));

      self.getCoin(hash, i, function(err, coin) {
        if (err)
          return next(err);

        if (!coin)
          return next();

        coin.height = tx.height;

        batch.put(p + 'u/t/' + hash + '/' + i, coin.toRaw());

        next();
      });
    }, function(err) {
      if (err)
        return callback(err);

      batch.write(function(err) {
        if (err)
          return callback(err);
        self.emit('unconfirmed', tx);
        return callback(null, true);
      });
    });
  });
};

TXPool.prototype.getTXHashes = function getTXHashes(address, callback) {
  var p = this.prefix + '/';
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
    gte: address ? p + 't/a/' + address : p + 't/t',
    lte: address ? p + 't/a/' + address + '~' : p + 't/t~',
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
  var p = this.prefix + '/';
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
    gte: address ? p + 'p/a/' + address : p + 'p/t',
    lte: address ? p + 'p/a/' + address + '~' : p + 'p/t~',
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
  var p = this.prefix + '/';
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
    gte: address ? p + 'u/a/' + address : p + 'u/t',
    lte: address ? p + 'u/a/' + address + '~' : p + 'u/t~',
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
  var p = this.prefix + '/';
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

      return callback(null, txs);
    });
  }

  iter = this.db.db.iterator({
    gte: p + 't/h/' + height,
    lte: p + 't/h/' + height + '~',
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

TXPool.prototype.getTXByAddress = function getTXByAddress(address, callback) {
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
  return this.getTXByAddress(address, function(err, txs) {
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

TXPool.prototype.getCoinByAddress = function getCoinByAddress(address, callback) {
  var self = this;
  var coins = [];

  return this.getCoinIDs(address, function(err, ids) {
    if (err)
      return callback(err);

    utils.forEachSerial(ids, function(id, next) {
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
  var p = this.prefix + '/';
  var id = p + 't/t/' + hash;

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
  var p = this.prefix + '/';
  var id = p + 'u/t/' + hash + '/' + index;

  this.db.get(id, function(err, coin) {
    if (err) {
      if (err.type === 'NotFoundError')
        return callback();
      return callback(err);
    }

    return callback(null, bcoin.coin.fromRaw(coin));
  });
};

TXPool.prototype.getAll = function getAll(callback) {
  return this.getTXByAddress(null, callback);
};

TXPool.prototype.getUnspent = function getUnspent(callback) {
  return this.getCoinByAddress(null, callback);
};

TXPool.prototype.getPending = function getPending(callback) {
  return this.getPendingByAddress(null, callback);
};

TXPool.prototype.getBalance = function getBalance(callback) {
  return this.getBalanceByAddress(null, callback);
};

TXPool.prototype.getAllByAddress = function getAllByAddress(address, callback) {
  return this.getTXByAddress(address, callback);
};

TXPool.prototype.getUnspentByAddress = function getUnspentByAddress(address, callback) {
  return this.getCoinByAddress(address, callback);
};

TXPool.prototype.getPendingByAddress = function getPendingByAddress(address, callback) {
  return this.getPendingByAddress(address, callback);
};

TXPool.prototype.getBalanceByAddress = function getBalanceByAddress(address, callback) {
  return this.getCoinByAddress(address, function(err, coins) {
    if (err)
      return callback(err);

    coins = coins.reduce(function(acc, coin) {
      return acc.iadd(coin.value);
    }, new bn(0));

    return callback(null, coins);
  });
};

/**
 * Expose
 */

module.exports = TXPool;
