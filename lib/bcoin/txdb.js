/*!
 * txdb.js - persistent transaction pool
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

/*
 * Database Layout:
 *   t/[hash] -> extended tx
 *   c/[hash]/[index] -> coin
 *   s/[hash]/[index] -> spent by hash
 *   o/[hash]/[index] -> orphan inputs
 *   p/[hash] -> dummy (pending flag)
 *   m/[time]/[hash] -> dummy (tx by time)
 *   h/[height]/[hash] -> dummy (tx by height)
 *   T/[id]/[hash] -> dummy (tx by wallet id)
 *   P/[id]/[hash] -> dummy (pending tx by wallet id)
 *   M/[id]/[time]/[hash] -> dummy (tx by time + id)
 *   H/[id]/[height]/[hash] -> dummy (tx by height + id)
 *   C/[id]/[hash]/[index] -> dummy (coin by address)
 */

var bcoin = require('./env');
var utils = require('./utils');
var assert = bcoin.utils.assert;
var EventEmitter = require('events').EventEmitter;
var DUMMY = new Buffer([0]);
var pad32 = utils.pad32;
var BufferReader = require('./reader');
var BufferWriter = require('./writer');

/**
 * TXDB
 * @exports TXDB
 * @constructor
 * @param {LowlevelUp} db
 * @param {Object?} options
 * @param {Boolean?} options.mapAddress - Map addresses to IDs.
 * @param {Boolean?} options.indexAddress - Index addresses/IDs.
 * @param {Boolean?} options.indexExtra - Index timestamps, heights, etc.
 * @param {Boolean?} options.verify - Verify transactions as they
 * come in (note that this will not happen on the worker pool).
 */

function TXDB(db, options) {
  if (!(this instanceof TXDB))
    return new TXDB(db, options);

  EventEmitter.call(this);

  if (!options)
    options = {};

  this.wdb = db;
  this.db = db.db;
  this.options = options;
  this.network = bcoin.network.get(options.network);
  this.busy = false;
  this.jobs = [];
  this.locker = new bcoin.locker(this);
  this.filter = this.options.useFilter
    ? new bcoin.bloom.rolling(800000, 0.01)
    : null;
}

utils.inherits(TXDB, EventEmitter);

TXDB.prototype._lock = function _lock(func, args, force) {
  return this.locker.lock(func, args, force);
};

TXDB.prototype._loadFilter = function loadFilter(callback) {
  var self = this;
  var iter;

  if (!this.filter)
    return callback();

  iter = this.db.iterator({
    gte: 'W',
    lte: 'W~',
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

      if (key === undefined)
        return iter.end(callback);

      key = key.split('/')[1];

      self.filter.add(key, 'hex');

      next();
    });
  })();
};

TXDB.prototype._testFilter = function _testFilter(addresses) {
  var i;

  if (!this.filter)
    return true;

  for (i = 0; i < addresses.length; i++) {
    if (this.filter.test(addresses[i], 'hex'))
      return true;
  }

  return false;
};

/**
 * Map a transactions' addresses to wallet IDs.
 * @param {TX} tx
 * @param {Function} callback - Returns [Error, {@link AddressMap}].
 */

TXDB.prototype.getMap = function getMap(tx, callback) {
  var input, output, addresses, table, map;

  input = tx.getInputHashes();
  output = tx.getOutputHashes();
  addresses = utils.uniq(input.concat(output));

  if (!this._testFilter(addresses))
    return callback();

  function cb(err, table) {
    if (err)
      return callback(err);

    if (table.count === 0)
      return callback();

    map = {
      table: table,
      input: [],
      output: [],
      all: []
    };

    input.forEach(function(address) {
      assert(map.table[address]);
      map.input = map.input.concat(map.table[address]);
    });

    output.forEach(function(address) {
      assert(map.table[address]);
      map.output = map.output.concat(map.table[address]);
    });

    map.input = utils.uniq(map.input);
    map.output = utils.uniq(map.output);
    map.all = utils.uniq(map.input.concat(map.output));

    return callback(null, map);
  }

  return this.mapAddresses(addresses, cb);
};

/**
 * Map an address to a wallet ID.
 * @param {Base58Address|Base58Address[]} address
 * @param {Function} callback - Returns [Error, {@link AddressTable}].
 */

TXDB.prototype.mapAddresses = function mapAddresses(address, callback) {
  var self = this;
  var table = { count: 0 };

  if (Array.isArray(address)) {
    return utils.forEachSerial(address, function(address, next) {
      self.mapAddresses(address, function(err, res) {
        if (err)
          return next(err);

        assert(res[address]);
        table[address] = res[address];
        table.count += res.count;

        next();
      });
    }, function(err) {
      if (err)
        return callback(err);

      return callback(null, table);
    });
  }

  this.wdb.getAddress(address, function(err, paths) {
    if (err)
      return callback(err);

    table[address] = paths ? Object.keys(paths) : [];
    table.count += table[address].length;

    return callback(null, table);
  });
};

/**
 * Add an orphan (tx hash + input index)
 * to orphan list. Stored by its required coin ID.
 * @private
 * @param {String} key - Required coin hash + index.
 * @param {Hash} hash - Orphan transaction hash.
 * @param {Number} index - Orphan input index.
 * @param {Function} callback - Returns [Error, Buffer].
 */

TXDB.prototype._addOrphan = function _addOrphan(key, hash, index, callback) {
  var p;

  this.db.get('o/' + key, function(err, buf) {
    if (err && err.type !== 'NotFoundError')
      return callback(err);

    p = new BufferWriter();

    if (buf)
      p.writeBytes(buf);

    p.writeHash(hash);
    p.writeU32(index);

    return callback(null, p.render());
  });
};

/**
 * Retrieve orphan list by coin ID.
 * @private
 * @param {String} key
 * @param {Function} callback - Returns [Error, {@link Orphan}].
 */

TXDB.prototype._getOrphans = function _getOrphans(key, callback) {
  var self = this;

  this.db.fetch('o/' + key, function(buf) {
    var p = new BufferReader(buf);
    var orphans = [];

    while (p.left()) {
      orphans.push({
        hash: p.readHash('hex'),
        index: p.readU32()
      });
    }

    return orphans;
  }, function(err, orphans) {
    if (err)
      return callback(err);

    if (!orphans)
      return callback();

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

/**
 * Add a transaction to the database, map addresses
 * to wallet IDs, potentially store orphans, resolve
 * orphans, or confirm a transaction.
 * @param {TX} tx
 * @param {Function} callback - Returns [Error].
 */

TXDB.prototype.add = function add(tx, callback, force) {
  var self = this;

  if (Array.isArray(tx)) {
    return utils.forEachSerial(tx, function(tx, next) {
      self.add(tx, next, force);
    }, callback);
  }

  return this.getMap(tx, function(err, map) {
    if (err)
      return callback(err);

    if (!map)
      return callback(null, false);

    return self._add(tx, map, callback, force);
  });
};

// This big scary function is what a persistent tx pool
// looks like. It's a semi mempool in that it can handle
// receiving txs out of order.
TXDB.prototype._add = function add(tx, map, callback, force) {
  var self = this;
  var hash = tx.hash('hex');
  var updated = false;
  var batch;

  assert(tx.ts > 0 || tx.ps > 0);

  var unlock = this._lock(add, [tx, map, callback], force);
  if (!unlock)
    return;

  callback = utils.wrap(callback, unlock);

  if (tx.mutable)
    tx = tx.toTX();

  // Attempt to confirm tx before adding it.
  this._confirm(tx, map, function(err, existing) {
    if (err)
      return callback(err);

    // Ignore if we already have this tx.
    if (existing)
      return callback(null, true);

    batch = self.db.batch();

    batch.put('t/' + hash, tx.toExtended());

    if (tx.ts === 0) {
      assert(tx.ps > 0);
      batch.put('p/' + hash, DUMMY);
      batch.put('m/' + pad32(tx.ps) + '/' + hash, DUMMY);
    } else {
      batch.put('h/' + pad32(tx.height) + '/' + hash, DUMMY);
      batch.put('m/' + pad32(tx.ts) + '/' + hash, DUMMY);
    }

    map.all.forEach(function(id) {
      batch.put('T/' + id + '/' + hash, DUMMY);
      if (tx.ts === 0) {
        batch.put('P/' + id + '/' + hash, DUMMY);
        batch.put('M/' + id + '/' + pad32(tx.ps) + '/' + hash, DUMMY);
      } else {
        batch.put('H/' + id + '/' + pad32(tx.height) + '/' + hash, DUMMY);
        batch.put('M/' + id + '/' + pad32(tx.ts) + '/' + hash, DUMMY);
      }
    });

    // Consume unspent money or add orphans
    utils.forEachSerial(tx.inputs, function(input, next, i) {
      var key, address;

      if (tx.isCoinbase())
        return next();

      address = input.getHash();

      // Only add orphans if this input is ours.
      if (!address || !map.table[address].length)
        return next();

      self.getCoin(input.prevout.hash, input.prevout.index, function(err, coin) {
        if (err)
          return next(err);

        key = input.prevout.hash + '/' + input.prevout.index;

        if (coin) {
          // Add TX to inputs and spend money
          input.coin = coin;

          // Skip invalid transactions
          if (self.options.verify) {
            if (!tx.verify(i))
              return callback(null, false);
          }

          updated = true;

          if (address) {
            map.table[address].forEach(function(id) {
              batch.del('C/' + id + '/' + key);
            });
          }

          batch.del('c/' + key);
          batch.put('s/' + key, tx.hash());

          return next();
        }

        input.coin = null;

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

              input.coin = bcoin.coin.fromTX(prev, input.prevout.index);

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

            batch.put('o/' + key, orphans);

            return next();
          });
        });
      });
    }, function(err) {
      if (err)
        return callback(err);

      // Add unspent outputs or resolve orphans
      utils.forEachSerial(tx.outputs, function(output, next, i) {
        var address = output.getHash();
        var key, coin;

        // Do not add unspents for outputs that aren't ours.
        if (!address || !map.table[address].length)
          return next();

        key = hash + '/' + i;

        if (output.script.isUnspendable())
          return next();

        coin = bcoin.coin.fromTX(tx, i);

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

            orphan.tx.inputs[orphan.index].coin = coin;

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

            self.db.del('o/' + key, finish);
          });

          function finish(err) {
            if (err)
              return next(err);

            if (!orphans) {
              if (address) {
                map.table[address].forEach(function(id) {
                  batch.put('C/' + id + '/' + key, DUMMY);
                });
              }

              batch.put('c/' + key, coin.toRaw());
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

          self.wdb.sync(tx, map, function(err) {
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
    });
  }, true);
};

/**
 * Remove spenders that have not been confirmed. We do this in the
 * odd case of stuck transactions or when a coin is double-spent
 * by a newer transaction. All previously-spending transactions
 * of that coin that are _not_ confirmed will be removed from
 * the database.
 * @private
 * @param {Hash} hash
 * @param {TX} ref - Reference tx, the tx that double-spent.
 * @param {Function} callback - Returns [Error, Boolean].
 */

TXDB.prototype._removeSpenders = function removeSpenders(hash, ref, callback) {
  var self = this;
  this.getTX(hash, function(err, tx) {
    if (err)
      return callback(err);

    if (!tx)
      return callback(new Error('Could not find spender.'));

    if (tx.ts !== 0)
      return callback(null, false);

    if (ref.ts === 0 && ref.ps < tx.ps)
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

/**
 * Test an entire transaction to see
 * if any of its outpoints are a double-spend.
 * @param {TX} tx
 * @param {Function} callback - Returns [Error, Boolean].
 */

TXDB.prototype.isDoubleSpend = function isDoubleSpend(tx, callback) {
  var self = this;
  utils.everySerial(tx.inputs, function(input, next) {
    self.isSpent(input.prevout.hash, input.prevout.index, function(err, spent) {
      if (err)
        return next(err);
      return next(null, !spent);
    });
  }, function(err, result) {
    if (err)
      return callback(err);
    return callback(null, !result);
  });
};

/**
 * Test a whether a coin has been spent.
 * @param {Hash} hash
 * @param {Number} index
 * @param {Function} callback - Returns [Error, Boolean].
 */

TXDB.prototype.isSpent = function isSpent(hash, index, callback) {
  var key = 's/' + hash + '/' + index;
  return this.db.fetch(key, function(hash) {
    return hash.toString('hex');
  }, callback);
};

/**
 * Attempt to confirm a transaction.
 * @private
 * @param {TX} tx
 * @param {AddressMap} map
 * @param {Function} callback - Returns [Error, Boolean]. `false` if
 * the transaction should be added to the database, `true` if the
 * transaction was confirmed, or should be ignored.
 */

TXDB.prototype._confirm = function _confirm(tx, map, callback, force) {
  var self = this;
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

    batch.put('t/' + hash, tx.toExtended());

    batch.del('p/' + hash);
    batch.put('h/' + pad32(tx.height) + '/' + hash, DUMMY);
    batch.del('m/' + pad32(existing.ps) + '/' + hash);
    batch.put('m/' + pad32(tx.ts) + '/' + hash, DUMMY);

    map.all.forEach(function(id) {
      batch.del('P/' + id + '/' + hash);
      batch.put('H/' + id + '/' + pad32(tx.height) + '/' + hash, DUMMY);
      batch.del('M/' + id + '/' + pad32(existing.ps) + '/' + hash);
      batch.put('M/' + id + '/' + pad32(tx.ts) + '/' + hash, DUMMY);
    });

    utils.forEachSerial(tx.outputs, function(output, next, i) {
      var address = output.getHash();

      // Only update coins if this output is ours.
      if (!address || !map.table[address].length)
        return next();

      self.getCoin(hash, i, function(err, coin) {
        if (err)
          return next(err);

        if (!coin)
          return next();

        coin.height = tx.height;

        batch.put('c/' + hash + '/' + i, coin.toRaw());

        next();
      });
    }, function(err) {
      if (err)
        return callback(err);

      batch.write(function(err) {
        if (err)
          return callback(err);

        self.wdb.sync(tx, map, function(err) {
          if (err)
            return callback(err);

          self.emit('confirmed');
          self.emit('tx', tx, map);

          return callback(null, true);
        });
      });
    });
  });
};

/**
 * Remove a transaction from the database. Disconnect inputs.
 * @param {Hash} hash
 * @param {Function} callback - Returns [Error].
 */

TXDB.prototype.remove = function remove(hash, callback, force) {
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

      if (!map)
        return callback(null, false);

      return self._remove(tx, map, callback, force);
    });
  });
};

/**
 * Remove a transaction from the database, but do not
 * look up the transaction. Use the passed-in transaction
 * to disconnect.
 * @param {TX} tx
 * @param {Function} callback - Returns [Error].
 */

TXDB.prototype.lazyRemove = function lazyRemove(tx, callback, force) {
  var self = this;

  if (Array.isArray(tx)) {
    return utils.forEachSerial(tx, function(tx, next) {
      self.lazyRemove(tx, next, force);
    }, callback);
  }

  return this.getMap(tx, function(err, map) {
    if (err)
      return callback(err);

    if (!map)
      return callback(null, false);

    return self._remove(tx, map, callback, force);
  });
};

/**
 * Remove a transaction from the database. Disconnect inputs.
 * @private
 * @param {TX} tx
 * @param {AddressMap} map
 * @param {Function} callback - Returns [Error].
 */

TXDB.prototype._remove = function remove(tx, map, callback, force) {
  var self = this;
  var hash = tx.hash('hex');
  var batch;

  var unlock = this._lock(remove, [tx, map, callback], force);
  if (!unlock)
    return;

  callback = utils.wrap(callback, unlock);

  batch = this.db.batch();

  batch.del('t/' + hash);

  if (tx.ts === 0) {
    batch.del('p/' + hash);
    batch.del('m/' + pad32(tx.ps) + '/' + hash);
  } else {
    batch.del('h/' + pad32(tx.height) + '/' + hash);
    batch.del('m/' + pad32(tx.ts) + '/' + hash);
  }

  map.all.forEach(function(id) {
    batch.del('T/' + id + '/' + hash);
    if (tx.ts === 0) {
      batch.del('P/' + id + '/' + hash);
      batch.del('M/' + id + '/' + pad32(tx.ps) + '/' + hash);
    } else {
      batch.del('H/' + id + '/' + pad32(tx.height) + '/' + hash);
      batch.del('M/' + id + '/' + pad32(tx.ts) + '/' + hash);
    }
  });

  this.fillHistory(tx, function(err) {
    if (err)
      return callback(err);

    tx.inputs.forEach(function(input) {
      var key = input.prevout.hash + '/' + input.prevout.index;
      var address = input.getHash();

      if (tx.isCoinbase())
        return;

      if (!input.coin)
        return;

      if (!address || !map.table[address].length)
        return;

      if (address) {
        map.table[address].forEach(function(id) {
          batch.put('C/' + id + '/' + key, DUMMY);
        });
      }

      batch.put('c/' + key, input.coin.toRaw());
      batch.del('s/' + key);
      batch.del('o/' + key);
    });

    tx.outputs.forEach(function(output, i) {
      var key = hash + '/' + i;
      var address = output.getHash();

      if (!address || !map.table[address].length)
        return;

      if (output.script.isUnspendable())
        return;

      if (address) {
        map.table[address].forEach(function(id) {
          batch.del('C/' + id + '/' + key);
        });
      }

      batch.del('c/' + key);
    });

    batch.write(function(err) {
      if (err)
        return callback(err);

      self.emit('remove tx', tx, map);

      return callback(null, true);
    });
  });
};

/**
 * Unconfirm a transaction. This is usually necessary after a reorg.
 * @param {Hash} hash
 * @param {Function} callback
 */

TXDB.prototype.unconfirm = function unconfirm(hash, callback, force) {
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

      if (!map)
        return callback(null, false);

      return self._unconfirm(tx, map, callback, force);
    });
  });
};

/**
 * Unconfirm a transaction. This is usually necessary after a reorg.
 * @param {Hash} hash
 * @param {AddressMap} map
 * @param {Function} callback
 */

TXDB.prototype._unconfirm = function unconfirm(tx, map, callback, force) {
  var self = this;
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

  batch.put('t/' + hash, tx.toExtended());

  batch.put('p/' + hash, DUMMY);
  batch.del('h/' + pad32(height) + '/' + hash);
  batch.del('m/' + pad32(ts) + '/' + hash);
  batch.put('m/' + pad32(tx.ps) + '/' + hash, DUMMY);

  map.all.forEach(function(id) {
    batch.put('P/' + id + '/' + hash, DUMMY);
    batch.del('H/' + id + '/' + pad32(height) + '/' + hash);
    batch.del('M/' + id + '/' + pad32(ts) + '/' + hash);
    batch.put('M/' + id + '/' + pad32(tx.ps) + '/' + hash, DUMMY);
  });

  utils.forEachSerial(tx.outputs, function(output, next, i) {
    self.getCoin(hash, i, function(err, coin) {
      if (err)
        return next(err);

      if (!coin)
        return next();

      coin.height = tx.height;

      batch.put('c/' + hash + '/' + i, coin.toRaw());

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

/**
 * Get hashes of all transactions in the database.
 * @param {WalletID|WalletID[]} address - By address (can be null).
 * @param {Function} callback - Returns [Error, {@link Hash}[]].
 */

TXDB.prototype.getHistoryHashes = function getHistoryHashes(address, callback) {
  var self = this;
  var txs = [];

  if (typeof address === 'function') {
    callback = address;
    address = null;
  }

  callback = utils.ensure(callback);

  if (Array.isArray(address)) {
    return utils.forEachSerial(address, function(address, next) {
      self.getHistoryHashes(address, function(err, tx) {
        if (err)
          return next(err);

        txs = txs.concat(tx);

        next();
      });
    }, function(err) {
      if (err)
        return callback(err);

      txs = utils.uniq(txs);

      return callback(null, txs);
    });
  }

  this.db.iterate({
    gte: address ? 'T/' + address : 't',
    lte: address ? 'T/' + address + '~' : 't~',
    transform: function(key) {
      key = key.split('/');
      if (address)
        return key[2];
      return key[1];
    }
  }, callback);
};

/**
 * Get hashes of all unconfirmed transactions in the database.
 * @param {WalletID|WalletID[]} address - By address (can be null).
 * @param {Function} callback - Returns [Error, {@link Hash}[]].
 */

TXDB.prototype.getUnconfirmedHashes = function getUnconfirmedHashes(address, callback) {
  var self = this;
  var txs = [];

  if (typeof address === 'function') {
    callback = address;
    address = null;
  }

  callback = utils.ensure(callback);

  if (Array.isArray(address)) {
    return utils.forEachSerial(address, function(address, next) {
      assert(address);
      self.getUnconfirmedHashes(address, function(err, tx) {
        if (err)
          return next(err);

        txs = txs.concat(tx);

        next();
      });
    }, function(err) {
      if (err)
        return callback(err);

      txs = utils.uniq(txs);

      return callback(null, txs);
    });
  }

  this.db.iterate({
    gte: address ? 'P/' + address : 'p',
    lte: address ? 'P/' + address + '~' : 'p~',
    transform: function(key) {
      key = key.split('/');
      if (address)
        return key[2];
      return key[1];
    }
  }, callback);
};

/**
 * Get all coin hashes in the database.
 * @param {WalletID|WalletID[]} address - By address (can be null).
 * @param {Function} callback - Returns [Error, {@link Hash}[]].
 */

TXDB.prototype.getCoinHashes = function getCoinHashes(address, callback) {
  var self = this;
  var coins = [];

  if (typeof address === 'function') {
    callback = address;
    address = null;
  }

  callback = utils.ensure(callback);

  if (Array.isArray(address)) {
    return utils.forEachSerial(address, function(address, next) {
      self.getCoinHashes(address, function(err, coin) {
        if (err)
          return next(err);

        coins = coins.concat(coin);

        next();
      });
    }, function(err) {
      if (err)
        return callback(err);

      return callback(null, coins);
    });
  }

  this.db.iterate({
    gte: address ? 'C/' + address : 'c',
    lte: address ? 'C/' + address + '~' : 'c~',
    transform: function(key) {
      key = key.split('/');
      if (address)
        return [key[2], +key[3]];
      return [key[1], +key[2]];
    }
  }, callback);
};

/**
 * Get TX hashes by height range.
 * @param {WalletID|WalletID[]} address - By address (can be null).
 * @param {Object} options
 * @param {Number} options.start - Start height.
 * @param {Number} options.end - End height.
 * @param {Number?} options.limit - Max number of records.
 * @param {Boolean?} options.reverse - Reverse order.
 * @param {Function} callback - Returns [Error, {@link Hash}[]].
 */

TXDB.prototype.getHeightRangeHashes = function getHeightRangeHashes(address, options, callback) {
  if (typeof address !== 'string') {
    callback = options;
    options = address;
    address = null;
  }

  callback = utils.ensure(callback);

  this.db.iterate({
    gte: address
      ? 'H/' + address + '/' + pad32(options.start) + '/'
      : 'h/' + pad32(options.start) + '/',
    lte: address
      ? 'H/' + address + '/' + pad32(options.end) + '/~'
      : 'h/' + pad32(options.end) + '/~',
    limit: options.limit,
    reverse: options.reverse,
    transform: function(key) {
      key = key.split('/');
      if (address)
        return key[3];
      return key[2];
    }
  }, callback);
};

/**
 * Get TX hashes by height.
 * @param {Number} height
 * @param {Function} callback - Returns [Error, {@link Hash}[]].
 */

TXDB.prototype.getHeightHashes = function getHeightHashes(height, callback) {
  return this.getHeightRangeHashes({ start: height, end: height }, callback);
};

/**
 * Get TX hashes by timestamp range.
 * @param {WalletID|WalletID[]} address - By address (can be null).
 * @param {Object} options
 * @param {Number} options.start - Start height.
 * @param {Number} options.end - End height.
 * @param {Number?} options.limit - Max number of records.
 * @param {Boolean?} options.reverse - Reverse order.
 * @param {Function} callback - Returns [Error, {@link Hash}[]].
 */

TXDB.prototype.getRangeHashes = function getRangeHashes(address, options, callback) {
  if (typeof address === 'function') {
    callback = address;
    address = null;
  }

  callback = utils.ensure(callback);

  this.db.iterate({
    gte: address
      ? 'M/' + address + '/' + pad32(options.start) + '/'
      : 'm/' + pad32(options.start) + '/',
    lte: address
      ? 'M/' + address + '/' + pad32(options.end) + '/~'
      : 'm/' + pad32(options.end) + '/~',
    limit: options.limit,
    reverse: options.reverse,
    transform: function(key) {
      key = key.split('/');
      if (address)
        return key[3];
      return key[2];
    }
  }, callback);
};

/**
 * Get transactions by timestamp range.
 * @param {WalletID|WalletID[]} address - By address (can be null).
 * @param {Object} options
 * @param {Number} options.start - Start height.
 * @param {Number} options.end - End height.
 * @param {Number?} options.limit - Max number of records.
 * @param {Boolean?} options.reverse - Reverse order.
 * @param {Function} callback - Returns [Error, {@link TX}[]].
 */

TXDB.prototype.getRange = function getLast(address, options, callback) {
  var self = this;
  var txs = [];

  if (typeof address === 'function') {
    callback = address;
    address = null;
  }

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

/**
 * Get last N transactions.
 * @param {WalletID|WalletID[]} address - By address (can be null).
 * @param {Number} limit - Max number of transactions.
 * @param {Function} callback - Returns [Error, {@link TX}[]].
 */

TXDB.prototype.getLast = function getLast(address, limit, callback) {
  if (typeof limit === 'function') {
    callback = limit;
    limit = address;
    address = null;
  }

  return this.getRange(address, {
    start: 0,
    end: 0xffffffff,
    reverse: true,
    limit: limit
  }, callback);
};

/**
 * Get all transactions.
 * @param {WalletID|WalletID[]} address - By address (can be null).
 * @param {Function} callback - Returns [Error, {@link TX}[]].
 */

TXDB.prototype.getHistory = function getHistory(address, callback) {
  var self = this;
  var txs = [];

  if (typeof address === 'function') {
    callback = address;
    address = null;
  }

  return this.getHistoryHashes(address, function(err, hashes) {
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

      return callback(null, utils.sortTX(txs));
    });
  });
};

/**
 * Get last active timestamp and height.
 * @param {WalletID|WalletID[]} address - By address (can be null).
 * @param {Function} callback - Returns [Error, Number(ts), Number(height)].
 */

TXDB.prototype.getLastTime = function getLastTime(address, callback) {
  if (typeof address === 'function') {
    callback = address;
    address = null;
  }

  return this.getHistory(address, function(err, txs) {
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

/**
 * Get unconfirmed transactions.
 * @param {WalletID|WalletID[]} address - By address (can be null).
 * @param {Function} callback - Returns [Error, {@link TX}[]].
 */

TXDB.prototype.getUnconfirmed = function getUnconfirmed(address, callback) {
  var self = this;
  var txs = [];

  if (typeof address === 'function') {
    callback = address;
    address = null;
  }

  return this.getUnconfirmedHashes(address, function(err, hashes) {
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

/**
 * Get coins.
 * @param {WalletID|WalletID[]} address - By address (can be null).
 * @param {Function} callback - Returns [Error, {@link Coin}[]].
 */

TXDB.prototype.getCoins = function getCoins(address, callback) {
  var self = this;
  var coins = [];

  if (typeof address === 'function') {
    callback = address;
    address = null;
  }

  return this.getCoinHashes(address, function(err, hashes) {
    if (err)
      return callback(err);

    utils.forEachSerial(hashes, function(key, next) {
      self.getCoin(key[0], key[1], function(err, coin) {
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

/**
 * Fill a transaction with coins (all historical coins).
 * @param {TX} tx
 * @param {Function} callback - Returns [Error, {@link TX}].
 */

TXDB.prototype.fillHistory = function fillHistory(tx, callback) {
  var self = this;

  if (Array.isArray(tx)) {
    return utils.forEachSerial(tx, function(tx, next) {
      self.fillHistory(tx, next);
    }, callback);
  }

  callback = utils.asyncify(callback);

  if (tx.isCoinbase())
    return callback(null, tx);

  utils.forEach(tx.inputs, function(input, next) {
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
 * Fill a transaction with coins.
 * @param {TX} tx
 * @param {Function} callback - Returns [Error, {@link TX}].
 */

TXDB.prototype.fillCoins = function fillCoins(tx, callback) {
  var self = this;

  if (Array.isArray(tx)) {
    return utils.forEachSerial(tx, function(tx, next) {
      self.fillCoins(tx, next);
    }, callback);
  }

  callback = utils.asyncify(callback);

  if (tx.isCoinbase())
    return callback(null, tx);

  utils.forEach(tx.inputs, function(input, next) {
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
 * Get transaction.
 * @param {Hash} hash
 * @param {Function} callback - Returns [Error, {@link TX}].
 */

TXDB.prototype.getTX = function getTX(hash, callback) {
  this.db.fetch('t/' + hash, function(tx) {
    return bcoin.tx.fromExtended(tx);
  }, callback);
};

/**
 * Test whether the database has a transaction.
 * @param {Hash} hash
 * @param {Function} callback - Returns [Error, Boolean].
 */

TXDB.prototype.hasTX = function hasTX(hash, callback) {
  return this.db.has('t/' + hash, callback);
};

/**
 * Get coin.
 * @param {Hash} hash
 * @param {Number} index
 * @param {Function} callback - Returns [Error, {@link Coin}].
 */

TXDB.prototype.getCoin = function getCoin(hash, index, callback) {
  this.db.fetch('c/' + hash + '/' + index, function(coin) {
    coin = bcoin.coin.fromRaw(coin);
    coin.hash = hash;
    coin.index = index;
    return coin;
  }, callback);
};

/**
 * Test whether the database has a transaction.
 * @param {Hash} hash
 * @param {Function} callback - Returns [Error, Boolean].
 */

TXDB.prototype.hasCoin = function hasCoin(hash, index, callback) {
  return this.db.has('c/' + hash + '/' + index, callback);
};

/**
 * Calculate balance.
 * @param {WalletID|WalletID[]} address - By address (can be null).
 * @param {Function} callback - Returns [Error, {@link Balance}].
 */

TXDB.prototype.getBalance = function getBalance(address, callback) {
  var self = this;
  var confirmed = 0;
  var unconfirmed = 0;

  if (typeof address === 'function') {
    callback = address;
    address = null;
  }

  // return this.getCoins(address, function(err, coins) {
  //   if (err)
  //     return callback(err);
  //
  //   for (i = 0; i < coins.length; i++) {
  //     if (coins[i].height === -1)
  //       unconfirmed += coins[i].value;
  //     else
  //       confirmed += coins[i].value;
  //   }
  //
  //   return callback(null, {
  //     confirmed: confirmed,
  //     unconfirmed: unconfirmed,
  //     total: confirmed + unconfirmed
  //   });
  // });

  return this.getCoinHashes(address, function(err, hashes) {
    if (err)
      return callback(err);

    utils.forEachSerial(hashes, function(hash, next) {
      self.db.fetch('c/' + hash[0] + '/' + hash[1], function(data, key) {
        var height = data.readUInt32LE(4, true);
        var value = utils.read64N(data, 8);

        assert(data.length >= 16);

        if (height === 0x7fffffff)
          unconfirmed += value;
        else
          confirmed += value;
      }, next);
    }, function(err) {
      if (err)
        return callback(err);

      return callback(null, {
        confirmed: confirmed,
        unconfirmed: unconfirmed,
        total: confirmed + unconfirmed
      });
    });
  });
};

/**
 * @param {WalletID|WalletID[]} address - By address (can be null).
 * @param {Number} now - Current time.
 * @param {Number} age - Age delta (delete transactions older than `now - age`).
 * @param {Function} callback
 */

TXDB.prototype.zap = function zap(address, now, age, callback, force) {
  var self = this;

  if (typeof address !== 'string') {
    force = callback;
    callback = age;
    age = now;
    now = address;
    address = null;
  }

  var unlock = this._lock(zap, [address, now, age, callback], force);
  if (!unlock)
    return;

  callback = utils.wrap(callback, unlock);

  assert(utils.isNumber(now));
  assert(utils.isNumber(age));
  assert(now >= age);

  return this.getRange(address, {
    start: 0,
    end: now - age
  }, function(err, txs) {
    if (err)
      return callback(err);

    self.fillHistory(txs, function(err) {
      if (err)
        return callback(err);

      utils.forEachSerial(txs, function(tx, next) {
        if (tx.ts !== 0)
          return next();
        self.lazyRemove(tx, next);
      }, callback);
    });
  });
};

/*
 * Expose
 */

module.exports = TXDB;
