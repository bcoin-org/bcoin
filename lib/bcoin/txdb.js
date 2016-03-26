/**
 * txdb.js - persistent transaction pool
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bn = require('bn.js');
var bcoin = require('../bcoin');
var utils = require('./utils');
var assert = bcoin.utils.assert;
var EventEmitter = require('events').EventEmitter;
var DUMMY = new Buffer([0]);
var pad32 = utils.pad32;

/**
 * TXPool
 */

function TXPool(prefix, db, options) {
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
  this.locker = new bcoin.locker(this);

  if (this.options.mapAddress)
    this.options.indexAddress = true;
}

utils.inherits(TXPool, EventEmitter);

TXPool.prototype._lock = function _lock(func, args, force) {
  return this.locker.lock(func, args, force);
};

TXPool.prototype.getMap = function getMap(tx, callback) {
  var input, output, addresses, map;

  if (!this.options.indexAddress)
    return callback();

  input = tx.getInputAddresses();
  output = tx.getOutputAddresses();
  addresses = utils.uniqs(input.concat(output));

  function cb(err, map) {
    if (err)
      return callback(err);

    map.input = [];
    map.output = [];
    map.all = [];

    input.forEach(function(address) {
      assert(map[address]);
      map.input = map.input.concat(map[address]);
    });

    output.forEach(function(address) {
      assert(map[address]);
      map.output = map.output.concat(map[address]);
    });

    map.input = utils.uniqs(map.input);
    map.output = utils.uniqs(map.output);
    map.all = utils.uniqs(map.input.concat(map.output));

    return callback(null, map);
  }

  if (!this.options.mapAddress) {
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

  iter = this.db.iterator({
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
          return callback(null, map);
        });
      }

      key = key.split('/')[3];
      map[address].push(key);

      next();
    });
  })();
};

TXPool.prototype._addOrphan = function _addOrphan(key, hash, index, callback) {
  var prefix = this.prefix + '/';
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
          return next(err);

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

TXPool.prototype.add = function add(tx, callback, force) {
  var self = this;

  if (Array.isArray(tx)) {
    return utils.forEachSerial(tx, function(tx, next) {
      self.add(tx, next, force);
    }, callback);
  }

  return this.getMap(tx, function(err, map) {
    if (err)
      return callback(err);

    if (self.options.mapAddress) {
      if (map.all.length === 0)
        return callback(null, false);
    }

    return self._add(tx, map, callback, force);
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
  var batch;

  assert(tx.ts > 0 || tx.ps > 0);

  var unlock = this._lock(add, [tx, map, callback], force);
  if (!unlock)
    return;

  callback = utils.wrap(callback, unlock);

  // Attempt to confirm tx before adding it.
  this._confirm(tx, map, function(err, existing) {
    if (err)
      return callback(err);

    // Ignore if we already have this tx.
    if (existing)
      return callback(null, true);

    batch = self.db.batch();

    batch.put(prefix + 't/t/' + hash, tx.toExtended());

    if (self.options.indexExtra) {
      if (tx.ts === 0) {
        assert(tx.ps > 0);
        batch.put(prefix + 't/p/t/' + hash, DUMMY);
        batch.put(prefix + 't/s/s/' + pad32(tx.ps) + '/' + hash, DUMMY);
      } else {
        batch.put(prefix + 't/h/h/' + pad32(tx.height) + '/' + hash, DUMMY);
        batch.put(prefix + 't/s/s/' + pad32(tx.ts) + '/' + hash, DUMMY);
      }

      if (self.options.indexAddress) {
        map.all.forEach(function(id) {
          batch.put(prefix + 't/a/' + id + '/' + hash, DUMMY);
          if (tx.ts === 0) {
            batch.put(prefix + 't/p/a/' + id + '/' + hash, DUMMY);
            batch.put(
              prefix + 't/s/a/' + id + '/' + pad32(tx.ps) + '/' + hash, DUMMY);
          } else {
            batch.put(
              prefix + 't/h/a/' + id + '/' + pad32(tx.height) + '/' + hash, DUMMY);
            batch.put(
              prefix + 't/s/a/' + id + '/' + pad32(tx.ts) + '/' + hash, DUMMY);
          }
        });
      }
    }

    // Consume unspent money or add orphans
    utils.forEachSerial(tx.inputs, function(input, next, i) {
      var key, address;

      if (tx.isCoinbase())
        return next();

      address = input.getAddress();

      // Only add orphans if this input is ours.
      if (self.options.mapAddress) {
        if (!address || !map[address].length)
          return next();
      }

      self.getCoin(input.prevout.hash, input.prevout.index, function(err, coin) {
        if (err)
          return next(err);

        key = input.prevout.hash + '/' + input.prevout.index;

        if (coin) {
          // Add TX to inputs and spend money
          input.output = coin;

          // Skip invalid transactions
          if (self.options.verify) {
            if (!tx.verify(i))
              return callback(null, false);
          }

          updated = true;

          if (self.options.indexAddress && address) {
            map[address].forEach(function(id) {
              batch.del(prefix + 'u/a/' + id + '/' + key);
            });
          }

          batch.del(prefix + 'u/t/' + key);
          batch.put(prefix + 's/t/' + key, tx.hash());

          return next();
        }

        input.output = null;

        self.isSpent(input.prevout.hash, input.prevout.index, function(err, spentBy) {
          if (err)
            return next(err);

          // Are we double-spending?
          // Replace older txs with newer ones.
          if (spentBy) {
            return self.getTX(input.prevout.hash, function(err, prev) {
              if (err)
                return next(err);

              if (!prev)
                return callback(new Error('Could not find double-spent coin.'));

              input.output = bcoin.coin(prev, input.prevout.index);

              // Skip invalid transactions
              if (self.options.verify) {
                if (!tx.verify(i))
                  return callback(null, false);
              }

              return self._removeSpenders(spentBy, tx, function(err, result) {
                if (err)
                  return next(err);

                if (!result) {
                  assert(tx.ts === 0, 'I\'m confused');
                  return callback(null, false);
                }

                batch.clear();
                self._add(tx, map, callback, true);
              });
            });
          }

          // Add orphan, if no parent transaction is yet known
          self._addOrphan(key, hash, i, function(err, orphans) {
            if (err)
              return next(err);

            batch.put(prefix + 'o/' + key, orphans);

            return next();
          });
        });
      });
    }, function(err) {
      if (err)
        return callback(err);

      // Add unspent outputs or resolve orphans
      utils.forEachSerial(tx.outputs, function(output, next, i) {
        var address = output.getAddress();
        var key, coin;

        // Do not add unspents for outputs that aren't ours.
        if (self.options.mapAddress) {
          if (!address || !map[address].length)
            return next();
        }

        key = hash + '/' + i;
        coin = bcoin.coin(tx, i);

        self._getOrphans(key, function(err, orphans) {
          var some = false;

          if (err)
            return callback(err);

          if (!orphans)
            return finish();

          // Add input to orphan
          utils.forEachSerial(orphans, function(orphan, next) {
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
            if (!self.options.verify) {
              some = true;
              return next();
            }

            if (orphan.tx.verify(orphan.index)) {
              some = true;
              return next();
            }

            self.lazyRemove(orphan.tx, function(err) {
              if (err)
                return next(err);
              return next();
            }, true);
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
              if (self.options.indexAddress && address) {
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
          return callback(err);

        batch.write(function(err) {
          if (err)
            return callback(err);

          self.emit('tx', tx, map);

          if (updated) {
            if (tx.ts !== 0)
              self.emit('confirmed', tx, map);

            self.emit('updated', tx, map);
          }

          return callback(null, true);
        });
      });
    });
  }, true);
};

TXPool.prototype._removeSpenders = function removeSpenders(hash, ref, callback) {
  var self = this;
  this.getTX(hash, function(err, tx) {
    if (err)
      return callback(err);

    if (!tx)
      return callback(new Error('Could not find spender.'));

    if (tx.ts !== 0)
      return callback(null, false);

    if (ref.ts === 0 && ref.ps < ts.ps)
      return callback(null, false);

    utils.forEachSerial(tx.outputs, function(output, next, i) {
      self.isSpent(hash, i, function(err, spent) {
        if (err)
          return next(err);
        if (spent)
          return self._removeSpenders(spent, ref, next);
        next();
      });
    }, function(err) {
      if (err)
        return callback(err);
      return self.lazyRemove(tx, function(err) {
        if (err)
          return callback(err);
        return callback(null, true);
      }, true);
    });
  });
};

TXPool.prototype.isDoubleSpend = function isDoubleSpend(tx, callback) {
  var self = this;
  utils.everySerial(tx.inputs, function(input, next) {
    self.isSpent(input.prevout.hash, input.prevout.index, function(err, spent) {
      if (err)
        return next(err);
      if (spent)
        return next(null, false);
      return next(null, true);
    });
  }, function(err, result) {
    if (err)
      return callback(err);

    return callback(null, !result);
  });
};

TXPool.prototype.isSpent = function isSpent(hash, index, callback) {
  var self = this;
  var prefix = this.prefix + '/';
  var key = prefix + 's/t/' + hash + '/' + index;

  return this.db.get(key, function(err, hash) {
    if (err && err.type !== 'NotFoundError')
      return callback(err);

    if (!hash)
      return callback(null, null);

    return callback(null, utils.toHex(hash));
  });
};

TXPool.prototype._confirm = function _confirm(tx, map, callback, force) {
  var self = this;
  var prefix = this.prefix + '/';
  var hash = tx.hash('hex');
  var batch;

  var unlock = this._lock(_confirm, [tx, map, callback], force);
  if (!unlock)
    return;

  callback = utils.wrap(callback, unlock);

  this.getTX(hash, function(err, existing) {
    if (err)
      return callback(err);

    // Haven't seen this tx before, add it.
    if (!existing)
      return callback(null, false);

    // Existing tx is already confirmed. Ignore.
    if (existing.ts !== 0)
      return callback(null, true);

    // The incoming tx won't confirm the existing one anyway. Ignore.
    if (tx.ts === 0)
      return callback(null, true);

    batch = self.db.batch();

    // Tricky - update the tx and coin in storage,
    // and remove pending flag to mark as confirmed.
    assert(tx.height >= 0);
    assert(existing.ps > 0);

    batch.put(prefix + 't/t/' + hash, tx.toExtended());

    if (self.options.indexExtra) {
      batch.del(prefix + 't/p/t/' + hash);
      batch.put(prefix + 't/h/h/' + pad32(tx.height) + '/' + hash, DUMMY);
      batch.del(prefix + 't/s/s/' + pad32(existing.ps) + '/' + hash);
      batch.put(prefix + 't/s/s/' + pad32(tx.ts) + '/' + hash, DUMMY);

      if (self.options.indexAddress) {
        map.all.forEach(function(id) {
          batch.del(prefix + 't/p/a/' + id + '/' + hash);
          batch.put(prefix + 't/h/a/' + id + '/' + pad32(tx.height) + '/' + hash, DUMMY);
          batch.del(prefix + 't/s/a/' + id + '/' + pad32(existing.ps) + '/' + hash);
          batch.put(prefix + 't/s/a/' + id + '/' + pad32(tx.ts) + '/' + hash, DUMMY);
        });
      }
    }

    utils.forEachSerial(tx.outputs, function(output, next, i) {
      var address = output.getAddress();

      // Only update coins if this output is ours.
      if (self.options.mapAddress) {
        if (!address || !map[address].length)
          return next();
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

        self.emit('confirmed', tx, map);
        self.emit('tx', tx, map);

        return callback(null, true);
      });
    });
  });
};

TXPool.prototype.remove = function remove(hash, callback, force) {
  var self = this;

  if (Array.isArray(hash)) {
    return utils.forEachSerial(hash, function(hash, next) {
      self.remove(hash, next, force);
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

      if (self.options.mapAddress) {
        if (map.all.length === 0)
          return callback(null, false);
      }

      return self._remove(tx, map, callback, force);
    });
  });
};

TXPool.prototype.lazyRemove = function lazyRemove(tx, callback, force) {
  var self = this;

  if (Array.isArray(tx)) {
    return utils.forEachSerial(tx, function(tx, next) {
      self.lazyRemove(tx, next, force);
    }, callback);
  }

  return this.getMap(tx, function(err, map) {
    if (err)
      return callback(err);

    if (self.options.mapAddress) {
      if (map.all.length === 0)
        return callback(null, false);
    }

    return self._remove(tx, map, callback, force);
  });
};

TXPool.prototype._remove = function remove(tx, map, callback, force) {
  var self = this;
  var prefix = this.prefix + '/';
  var hash = tx.hash('hex');
  var batch;

  var unlock = this._lock(remove, [tx, map, callback], force);
  if (!unlock)
    return;

  callback = utils.wrap(callback, unlock);

  batch = this.db.batch();

  batch.del(prefix + 't/t/' + hash);

  if (self.options.indexExtra) {
    if (tx.ts === 0) {
      batch.del(prefix + 't/p/t/' + hash);
      batch.del(prefix + 't/s/s/' + pad32(tx.ps) + '/' + hash);
    } else {
      batch.del(prefix + 't/h/h/' + pad32(tx.height) + '/' + hash);
      batch.del(prefix + 't/s/s/' + pad32(tx.ts) + '/' + hash);
    }

    if (self.options.indexAddress) {
      map.all.forEach(function(id) {
        batch.del(prefix + 't/a/' + id + '/' + hash);
        if (tx.ts === 0) {
          batch.del(prefix + 't/p/a/' + id + '/' + hash);
          batch.del(prefix + 't/s/a/' + id + '/' + pad32(tx.ps) + '/' + hash);
        } else {
          batch.del(prefix + 't/h/a/' + id + '/' + pad32(tx.height) + '/' + hash);
          batch.del(prefix + 't/s/a/' + id + '/' + pad32(tx.ts) + '/' + hash);
        }
      });
    }
  }

  this.fillTX(tx, function(err) {
    if (err)
      return callback(err);

    tx.inputs.forEach(function(input) {
      var address = input.getAddress();

      if (tx.isCoinbase())
        return;

      if (!input.output)
        return;

      if (self.options.mapAddress) {
        if (!address || !map[address].length)
          return;
      }

      if (self.options.indexAddress && address) {
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

      batch.del(prefix + 's/t/'
        + input.prevout.hash
        + '/' + input.prevout.index);

      batch.del(prefix + 'o/' + input.prevout.hash + '/' + input.prevout.index);
    });

    tx.outputs.forEach(function(output, i) {
      var address = output.getAddress();

      if (self.options.mapAddress) {
        if (!address || !map[address].length)
          return;
      }

      if (self.options.indexAddress && address) {
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

TXPool.prototype.unconfirm = function unconfirm(hash, callback, force) {
  var self = this;

  if (Array.isArray(hash)) {
    return utils.forEachSerial(hash, function(hash, next) {
      self.unconfirm(hash, next, force);
    }, callback);
  }

  if (hash.hash)
    hash = hash.hash('hex');

  callback = utils.ensure(callback);

  this.getTX(hash, function(err, tx) {
    if (err)
      return callback(err);

    if (!tx)
      return callback(null, true);

    assert(tx.hash('hex') === hash);

    return self.getMap(tx, function(err, map) {
      if (err)
        return callback(err);

      if (self.options.mapAddress) {
        if (map.all.length === 0)
          return callback(null, false);
      }

      return self._unconfirm(tx, map, callback, force);
    });
  });
};

TXPool.prototype._unconfirm = function unconfirm(tx, map, callback, force) {
  var self = this;
  var prefix = this.prefix + '/';
  var hash, batch, height, ts;

  var unlock = this._lock(unconfirm, [tx, map, callback], force);
  if (!unlock)
    return;

  callback = utils.wrap(callback, unlock);

  hash = tx.hash('hex');
  batch = this.db.batch();
  height = tx.height;
  ts = tx.ts;

  if (height !== -1)
    return callback(null, false);

  tx.height = -1;
  tx.ps = utils.now();
  tx.ts = 0;
  tx.index = -1;
  tx.block = null;

  batch.put(prefix + 't/t/' + hash, tx.toExtended());

  if (self.options.indexExtra) {
    batch.put(prefix + 't/p/t/' + hash, DUMMY);
    batch.del(prefix + 't/h/h/' + pad32(height) + '/' + hash);
    batch.del(prefix + 't/s/s/' + pad32(ts) + '/' + hash);
    batch.put(prefix + 't/s/s/' + pad32(tx.ps) + '/' + hash, DUMMY);

    if (self.options.indexAddress) {
      map.all.forEach(function(id) {
        batch.put(prefix + 't/p/a/' + id + '/' + hash, DUMMY);
        batch.del(prefix + 't/h/a/' + id + '/' + pad32(height) + '/' + hash);
        batch.del(prefix + 't/s/a/' + id + '/' + pad32(ts) + '/' + hash);
        batch.put(prefix + 't/s/a/' + id + '/' + pad32(tx.ps) + '/' + hash, DUMMY);
      });
    }
  }

  utils.forEachSerial(tx.outputs, function(output, next, i) {
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

  iter = this.db.iterator({
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

  iter = this.db.iterator({
    gte: address ? prefix + 't/p/a/' + address : prefix + 't/p/t',
    lte: address ? prefix + 't/p/a/' + address + '~' : prefix + 't/p/t~',
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
        txs.push(key.split('/')[5]);
      else
        txs.push(key.split('/')[4]);

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

  iter = this.db.iterator({
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

TXPool.prototype.getHeightRangeHashes = function getHeightRangeHashes(address, options, callback) {
  var prefix = this.prefix + '/';
  var txs = [];
  var iter;

  callback = utils.ensure(callback);

  iter = this.db.iterator({
    gte: address
      ? prefix + 't/h/a/' + address + '/' + pad32(options.start) + '/'
      : prefix + 't/h/h/' + pad32(options.start) + '/',
    lte: address
      ? prefix + 't/h/a/' + address + '/' + pad32(options.end) + '/~'
      : prefix + 't/h/h/' + pad32(options.end) + '/~',
    keys: true,
    values: false,
    fillCache: false,
    keyAsBuffer: false,
    limit: options.limit,
    reverse: options.reverse
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
        txs.push(key.split('/')[6]);
      else
        txs.push(key.split('/')[5]);

      next();
    });
  })();
};

TXPool.prototype.getHeightHashes = function getHeightHashes(height, callback) {
  return this.getHeightRangeHashes({ start: height, end: height }, callback);
};

TXPool.prototype.getRangeHashes = function getRangeHashes(address, options, callback) {
  var prefix = this.prefix + '/';
  var txs = [];
  var iter;

  callback = utils.ensure(callback);

  iter = this.db.iterator({
    gte: address
      ? prefix + 't/s/a/' + address + '/' + pad32(options.start) + '/'
      : prefix + 't/s/s/' + pad32(options.start) + '/',
    lte: address
      ? prefix + 't/s/a/' + address + '/' + pad32(options.end) + '/~'
      : prefix + 't/s/s/' + pad32(options.end) + '/~',
    keys: true,
    values: false,
    fillCache: false,
    keyAsBuffer: false,
    limit: options.limit,
    reverse: options.reverse
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
        txs.push(key.split('/')[6]);
      else
        txs.push(key.split('/')[5]);

      next();
    });
  })();
};

TXPool.prototype.getRange = function getLast(address, options, callback) {
  var self = this;
  var txs = [];

  return this.getRangeHashes(address, options, function(err, hashes) {
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

TXPool.prototype.getLast = function getLast(address, limit, callback) {
  return this.getRange(address, {
    start: 0,
    end: 0xffffffff,
    reverse: true,
    limit: limit
  }, callback);
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

TXPool.prototype.getLastTime = function getLastTime(address, callback) {
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
  var self = this;
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

    if (!tx)
      return callback();

    try {
      tx = bcoin.tx.fromExtended(tx);
    } catch (e) {
      return callback(e);
    }

    return callback(null, tx);
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

    if (!coin)
      return callback();

    try {
      coin = bcoin.coin.fromRaw(coin);
      coin.hash = hash;
      coin.index = index;
    } catch (e) {
      return callback(e);
    }

    return callback(null, coin);
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

TXPool.prototype.getAllHashes = function getAllHashes(callback) {
  return this.getTXHashes(null, callback);
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

TXPool.prototype.addUnchecked = function addUnchecked(tx, callback, force) {
  var self = this;
  var prefix = this.prefix + '/';
  var hash = tx.hash('hex');
  var batch;

  var unlock = this._lock(addUnchecked, [tx, callback], force);
  if (!unlock)
    return;

  callback = utils.wrap(callback, unlock);

  batch = this.db.batch();

  batch.put(prefix + 't/t/' + hash, tx.toExtended());

  tx.getAddresses().forEach(function(address) {
    batch.put(prefix + 't/a/' + address + '/' + hash, DUMMY);
  });

  tx.inputs.forEach(function(input) {
    var key = input.prevout.hash + '/' + input.prevout.index;
    var address;

    if (tx.isCoinbase())
      return;

    assert(input.output);
    address = input.getAddress();

    batch.del(prefix + 'u/t/' + key);
    batch.put(prefix + 's/t/' + key, tx.hash());

    if (address)
      batch.del(prefix + 'u/a/' + address + '/' + key);
  });

  tx.outputs.forEach(function(output, i) {
    var key = hash + '/' + i;
    var address = output.getAddress();
    var coin = bcoin.coin(tx, i).toRaw();
    batch.put(prefix + 'u/t/' + key, coin);

    if (address)
      batch.put(prefix + 'u/a/' + address + '/' + key, DUMMY);
  });

  return batch.write(function(err) {
    if (err)
      return callback(err);
    self.emit('add tx', tx);
    return callback();
  });
};

TXPool.prototype.removeUnchecked = function removeUnchecked(tx, callback, force) {
  var self = this;
  var prefix = this.prefix + '/';
  var hash = tx.hash('hex');
  var batch;

  var unlock = this._lock(removeUnchecked, [tx, callback], force);
  if (!unlock)
    return;

  callback = utils.wrap(callback, unlock);

  batch = this.db.batch();

  batch.del(prefix + 't/t/' + hash);
  batch.del(prefix + 'D/' + hash);

  tx.getAddresses().forEach(function(address) {
    batch.del(prefix + 't/a/' + address + '/' + hash);
  });

  tx.inputs.forEach(function(input) {
    var key = input.prevout.hash + '/' + input.prevout.index;
    var address;

    if (tx.isCoinbase())
      return;

    if (!input.output)
      return;

    address = input.getAddress();

    batch.del(prefix + 'u/t/' + key);
    batch.del(prefix + 's/t/' + key);

    if (address)
      batch.del(prefix + 'u/a/' + address + '/' + key);
  });

  tx.outputs.forEach(function(output, i) {
    var key = hash + '/' + i;
    var address = output.getAddress();

    batch.del(prefix + 'u/t/' + key);

    if (address)
      batch.del(prefix + 'u/a/' + address + '/' + key);
  });

  batch.write(function(err) {
    if (err)
      return callback(err);
    self.emit('remove tx', tx);
    return callback();
  });
};

TXPool.prototype.zap = function zap(tip, callback, force) {
  var self = this;
  var now = tip.ts;
  var age = 10 * 60 * 60;

  var unlock = this._lock(zap, [tip, callback], force);
  if (!unlock)
    return;

  callback = utils.wrap(callback, unlock);

  // return this.getRange(null, {
  //   start: 0,
  //   end: now - age
  // }, function(err, txs) {
  // });

  this.getPending(function(err, txs) {
    if (err)
      return callback(err);

    txs = txs.filter(function(tx) {
      return now > tx.ps + age;
    });

    if (txs.length === 0)
      return callback();

    self.fillTX(txs, function(err) {
      if (err)
        return callback(err);

      utils.forEachSerial(txs, function(tx, next) {
        self.lazyRemove(tx, next);
      }, callback);
    });
  });
};

/**
 * Expose
 */

module.exports = TXPool;
