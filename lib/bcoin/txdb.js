/*!
 * txdb.js - persistent transaction pool
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/*
 * Database Layout:
 *   t/[hash] -> extended tx
 *   c/[hash]/[index] -> coin
 *   s/[hash]/[index] -> spent by hash
 *   o/[hash]/[index] -> orphan inputs
 *   p/[hash] -> dummy (pending flag)
 *   m/[time]/[hash] -> dummy (tx by time)
 *   h/[height]/[hash] -> dummy (tx by height)
 *   T/[id]/[name]/[hash] -> dummy (tx by wallet id)
 *   P/[id]/[name]/[hash] -> dummy (pending tx by wallet/account id)
 *   M/[id]/[name]/[time]/[hash] -> dummy (tx by time + id/account)
 *   H/[id]/[name]/[height]/[hash] -> dummy (tx by height + id/account)
 *   C/[id]/[name]/[hash]/[index] -> dummy (coin by id/account)
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
 * come in (note that this will not happen on the worker
 * pool -- only used for SPV).
 */

function TXDB(db, options) {
  if (!(this instanceof TXDB))
    return new TXDB(db, options);

  EventEmitter.call(this);

  if (!options)
    options = {};

  this.walletdb = db;
  this.db = db.db;
  this.options = options;
  this.network = bcoin.network.get(options.network);
  this.busy = false;
  this.jobs = [];
  this.locker = new bcoin.locker(this);

  // Try to optimize for up to 1m addresses.
  // We use a regular bloom filter here
  // because we never want members to
  // lose membership, even if quality
  // degrades.
  // Memory used: 1.7mb
  this.filter = this.options.useFilter
    ? bcoin.bloom.fromRate(1000000, 0.001, -1)
    : null;
}

utils.inherits(TXDB, EventEmitter);

TXDB.prototype._lock = function _lock(func, args, force) {
  return this.locker.lock(func, args, force);
};

TXDB.prototype._loadFilter = function loadFilter(callback) {
  var self = this;

  if (!this.filter)
    return callback();

  this.db.iterate({
    gte: 'W',
    lte: 'W~',
    transform: function(key) {
      key = key.split('/')[1];
      self.filter.add(key, 'hex');
    }
  }, callback);
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
 * @param {Function} callback - Returns [Error, {@link WalletMap}].
 */

TXDB.prototype.getMap = function getMap(tx, callback) {
  var addresses = tx.getHashes('hex');
  var map;

  if (!this._testFilter(addresses))
    return callback();

  this.mapAddresses(addresses, function(err, table) {
    if (err)
      return callback(err);

    if (!table)
      return callback();

    map = WalletMap.fromTX(table, tx);

    return callback(null, map);
  });
};

/**
 * Map address hashes to a wallet ID.
 * @param {Hash[]} address - Address hashes.
 * @param {Function} callback - Returns [Error, {@link AddressTable}].
 */

TXDB.prototype.mapAddresses = function mapAddresses(address, callback) {
  var self = this;
  var table = {};
  var count = 0;
  var i, keys, values;

  utils.forEachSerial(address, function(address, next) {
    self.walletdb.getAddress(address, function(err, paths) {
      if (err)
        return next(err);

      if (!paths) {
        assert(!table[address]);
        table[address] = [];
        return next();
      }

      keys = Object.keys(paths);
      values = [];

      for (i = 0; i < keys.length; i++)
        values.push(paths[keys[i]]);

      assert(!table[address]);
      table[address] = values;
      count += values.length;

      return next();
    });
  }, function(err) {
    if (err)
      return callback(err);

    if (count === 0)
      return callback();

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

    utils.forEachSerial(orphans, function(orphan, next) {
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

  return this.getMap(tx, function(err, map) {
    if (err)
      return callback(err);

    if (!map)
      return callback(null, false);

    return self._add(tx, map, callback, force);
  });
};

TXDB.prototype._add = function add(tx, map, callback, force) {
  var self = this;
  var updated = false;
  var batch, hash, i, j, unlock, path, paths, id;

  unlock = this._lock(add, [tx, map, callback], force);

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
      return callback(null, true, map);

    hash = tx.hash('hex');

    batch = self.db.batch();

    batch.put('t/' + hash, tx.toExtended());

    if (tx.ts === 0) {
      batch.put('p/' + hash, DUMMY);
      batch.put('m/' + pad32(tx.ps) + '/' + hash, DUMMY);
    } else {
      batch.put('h/' + pad32(tx.height) + '/' + hash, DUMMY);
      batch.put('m/' + pad32(tx.ts) + '/' + hash, DUMMY);
    }

    for (i = 0; i < map.accounts.length; i++) {
      path = map.accounts[i];
      id = path.id + '/' + path.account;
      batch.put('T/' + id + '/' + hash, DUMMY);
      if (tx.ts === 0) {
        batch.put('P/' + id + '/' + hash, DUMMY);
        batch.put('M/' + id + '/' + pad32(tx.ps) + '/' + hash, DUMMY);
      } else {
        batch.put('H/' + id + '/' + pad32(tx.height) + '/' + hash, DUMMY);
        batch.put('M/' + id + '/' + pad32(tx.ts) + '/' + hash, DUMMY);
      }
    }

    // Consume unspent money or add orphans
    utils.forEachSerial(tx.inputs, function(input, next, i) {
      var prevout = input.prevout;
      var key, address;

      if (tx.isCoinbase())
        return next();

      address = input.getHash('hex');

      // Only add orphans if this input is ours.
      if (!map.hasPaths(address))
        return next();

      self.getCoin(prevout.hash, prevout.index, function(err, coin) {
        if (err)
          return next(err);

        key = prevout.hash + '/' + prevout.index;

        batch.put('s/' + key, tx.hash());

        if (coin) {
          // Add TX to inputs and spend money
          input.coin = coin;

          // Skip invalid transactions
          if (self.options.verify) {
            if (!tx.verifyInput(i))
              return callback(null, false);
          }

          updated = true;

          paths = map.getPaths(address);

          for (j = 0; j < paths.length; j++) {
            path = paths[j];
            id = path.id + '/' + path.account;
            batch.del('C/' + id + '/' + key);
          }

          batch.del('c/' + key);

          return next();
        }

        input.coin = null;

        self.isSpent(prevout.hash, prevout.index, function(err, spent) {
          if (err)
            return next(err);

          // Are we double-spending?
          // Replace older txs with newer ones.
          if (spent) {
            return self.getTX(prevout.hash, function(err, prev) {
              if (err)
                return next(err);

              if (!prev)
                return callback(new Error('Could not find double-spent coin.'));

              input.coin = bcoin.coin.fromTX(prev, prevout.index);

              // Skip invalid transactions
              if (self.options.verify) {
                if (!tx.verifyInput(i))
                  return callback(null, false, map);
              }

              return self._removeConflict(spent, tx, function(err, rtx, rmap) {
                if (err)
                  return next(err);

                // Spender was not removed, the current
                // transaction is not elligible to be added.
                if (!rtx)
                  return callback(null, false, map);

                self.emit('conflict', rtx, rmap);

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
        var address = output.getHash('hex');
        var key = hash + '/' + i;
        var coin;

        // Do not add unspents for outputs that aren't ours.
        if (!map.hasPaths(address))
          return next();

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

            if (orphan.tx.verifyInput(orphan.index)) {
              some = true;
              return next();
            }

            self.lazyRemove(orphan.tx, next, true);
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
              paths = map.getPaths(address);

              for (j = 0; j < paths.length; j++) {
                path = paths[j];
                id = path.id + '/' + path.account;
                batch.put('C/' + id + '/' + key, DUMMY);
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

          self.walletdb.syncOutputs(tx, map, function(err) {
            if (err)
              return callback(err);

            self.emit('tx', tx, map);

            if (updated) {
              if (tx.ts !== 0)
                self.emit('confirmed', tx, map);

              self.emit('updated', tx, map);
            }

            return callback(null, true, map);
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

TXDB.prototype._removeConflict = function _removeConflict(hash, ref, callback) {
  var self = this;

  this.getTX(hash, function(err, tx) {
    if (err)
      return callback(err);

    if (!tx)
      return callback(new Error('Could not find spender.'));

    if (tx.ts !== 0) {
      // If spender is confirmed and replacement
      // is not confirmed, do nothing.
      if (ref.ts === 0)
        return callback();

      // If both are confirmed but replacement
      // is older than spender, do nothing.
      if (ref.ts < tx.ts)
        return callback();
    } else {
      // If spender is unconfirmed and replacement
      // is confirmed, do nothing.
      if (ref.ts !== 0)
        return callback();

      // If both are unconfirmed but replacement
      // is older than spender, do nothing.
      if (ref.ps < tx.ps)
        return callback();
    }

    self._removeRecursive(tx, function(err, result, map) {
      if (err)
        return callback(err);
      return callback(null, tx, map);
    });
  });
};

/**
 * Remove a transaction and recursively
 * remove all of its spenders.
 * @private
 * @param {TX} tx - Transaction to be removed.
 * @param {Function} callback - Returns [Error, Boolean].
 */

TXDB.prototype._removeRecursive = function _removeRecursive(tx, callback) {
  var self = this;
  var hash = tx.hash('hex');

  utils.forEachSerial(tx.outputs, function(output, next, i) {
    self.isSpent(hash, i, function(err, spent) {
      if (err)
        return next(err);

      // Remove all of the spender's spenders first.
      if (spent) {
        return self.getTX(spent, function(err, tx) {
          if (err)
            return callback(err);

          if (!tx)
            return callback(new Error('Could not find spender.'));

          return self._removeRecursive(tx, next);
        });
      }

      next();
    });
  }, function(err) {
    if (err)
      return callback(err);

    // Remove the spender.
    return self.lazyRemove(tx, callback, true);
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
  var hash, batch, unlock, i, path, id;

  unlock = this._lock(_confirm, [tx, map, callback], force);

  if (!unlock)
    return;

  callback = utils.wrap(callback, unlock);

  hash = tx.hash('hex');

  this.getTX(hash, function(err, existing) {
    if (err)
      return callback(err);

    // Haven't seen this tx before, add it.
    if (!existing)
      return callback(null, false, map);

    // Existing tx is already confirmed. Ignore.
    if (existing.ts !== 0)
      return callback(null, true, map);

    // The incoming tx won't confirm the
    // existing one anyway. Ignore.
    if (tx.ts === 0)
      return callback(null, true, map);

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

    for (i = 0; i < map.accounts.length; i++) {
      path = map.accounts[i];
      id = path.id + '/' + path.account;
      batch.del('P/' + id + '/' + hash);
      batch.put('H/' + id + '/' + pad32(tx.height) + '/' + hash, DUMMY);
      batch.del('M/' + id + '/' + pad32(existing.ps) + '/' + hash);
      batch.put('M/' + id + '/' + pad32(tx.ts) + '/' + hash, DUMMY);
    }

    utils.forEachSerial(tx.outputs, function(output, next, i) {
      var address = output.getHash('hex');

      // Only update coins if this output is ours.
      if (!map.hasPaths(address))
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

        self.walletdb.syncOutputs(tx, map, function(err) {
          if (err)
            return callback(err);

          self.emit('confirmed', tx, map);
          self.emit('tx', tx, map);

          return callback(null, true, map);
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
  var unlock, hash, batch, i, j, path, id, key, paths, address, input, output;

  unlock = this._lock(remove, [tx, map, callback], force);

  if (!unlock)
    return;

  callback = utils.wrap(callback, unlock);

  hash = tx.hash('hex');

  batch = this.db.batch();

  batch.del('t/' + hash);

  if (tx.ts === 0) {
    batch.del('p/' + hash);
    batch.del('m/' + pad32(tx.ps) + '/' + hash);
  } else {
    batch.del('h/' + pad32(tx.height) + '/' + hash);
    batch.del('m/' + pad32(tx.ts) + '/' + hash);
  }

  for (i = 0; i < map.accounts.length; i++) {
    path = map.accounts[i];
    id = path.id + '/' + path.account;
    batch.del('T/' + id + '/' + hash);
    if (tx.ts === 0) {
      batch.del('P/' + id + '/' + hash);
      batch.del('M/' + id + '/' + pad32(tx.ps) + '/' + hash);
    } else {
      batch.del('H/' + id + '/' + pad32(tx.height) + '/' + hash);
      batch.del('M/' + id + '/' + pad32(tx.ts) + '/' + hash);
    }
  }

  this.fillHistory(tx, function(err) {
    if (err)
      return callback(err);

    for (i = 0; i < tx.inputs.length; i++) {
      input = tx.inputs[i];
      key = input.prevout.hash + '/' + input.prevout.index;
      address = input.getHash('hex');

      if (tx.isCoinbase())
        break;

      if (!input.coin)
        continue;

      if (!map.hasPaths(address))
        continue;

      paths = map.getPaths(address);

      for (j = 0; j < paths.length; j++) {
        path = paths[j];
        id = path.id + '/' + path.account;
        batch.put('C/' + id + '/' + key, DUMMY);
      }

      batch.put('c/' + key, input.coin.toRaw());
      batch.del('s/' + key);
      batch.del('o/' + key);
    }

    for (i = 0; i < tx.outputs.length; i++) {
      output = tx.outputs[i];
      key = hash + '/' + i;
      address = output.getHash('hex');

      if (!map.hasPaths(address))
        continue;

      if (output.script.isUnspendable())
        continue;

      paths = map.getPaths(address);

      for (j = 0; j < paths.length; j++) {
        path = paths[j];
        id = path.id + '/' + path.account;
        batch.del('C/' + id + '/' + key);
      }

      batch.del('c/' + key);
    }

    batch.write(function(err) {
      if (err)
        return callback(err);

      self.emit('remove tx', tx, map);

      return callback(null, true, map);
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
  var batch, unlock, hash, height, ts, i, path, id;

  unlock = this._lock(unconfirm, [tx, map, callback], force);

  if (!unlock)
    return;

  callback = utils.wrap(callback, unlock);

  hash = tx.hash('hex');
  height = tx.height;
  ts = tx.ts;

  batch = this.db.batch();

  if (height !== -1)
    return callback(null, false, map);

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

  for (i = 0; i < map.accounts.length; i++) {
    path = map.accounts[i];
    id = path.id + '/' + path.account;
    batch.put('P/' + id + '/' + hash, DUMMY);
    batch.del('H/' + id + '/' + pad32(height) + '/' + hash);
    batch.del('M/' + id + '/' + pad32(ts) + '/' + hash);
    batch.put('M/' + id + '/' + pad32(tx.ps) + '/' + hash, DUMMY);
  }

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

      return callback(null, true, map);
    });
  });
};

/**
 * Get hashes of all transactions in the database.
 * @param {WalletID?} id
 * @param {Function} callback - Returns [Error, {@link Hash}[]].
 */

TXDB.prototype.getHistoryHashes = function getHistoryHashes(id, callback) {
  if (typeof id === 'function') {
    callback = id;
    id = null;
  }

  this.db.iterate({
    gte: id ? 'T/' + id + '/' : 't',
    lte: id ? 'T/' + id + '/~' : 't~',
    transform: function(key) {
      key = key.split('/');
      if (id)
        return key[3];
      return key[1];
    }
  }, callback);
};

/**
 * Get hashes of all unconfirmed transactions in the database.
 * @param {WalletID?} id
 * @param {Function} callback - Returns [Error, {@link Hash}[]].
 */

TXDB.prototype.getUnconfirmedHashes = function getUnconfirmedHashes(id, callback) {
  if (typeof id === 'function') {
    callback = id;
    id = null;
  }

  this.db.iterate({
    gte: id ? 'P/' + id + '/' : 'p',
    lte: id ? 'P/' + id + '/~' : 'p~',
    transform: function(key) {
      key = key.split('/');
      if (id)
        return key[3];
      return key[1];
    }
  }, callback);
};

/**
 * Get all coin hashes in the database.
 * @param {WalletID?} id
 * @param {Function} callback - Returns [Error, {@link Hash}[]].
 */

TXDB.prototype.getCoinHashes = function getCoinHashes(id, callback) {
  if (typeof id === 'function') {
    callback = id;
    id = null;
  }

  this.db.iterate({
    gte: id ? 'C/' + id + '/' : 'c',
    lte: id ? 'C/' + id + '/~' : 'c~',
    transform: function(key) {
      key = key.split('/');
      if (id)
        return [key[3], +key[4]];
      return [key[1], +key[2]];
    }
  }, callback);
};

/**
 * Get TX hashes by height range.
 * @param {WalletID?} id
 * @param {Object} options
 * @param {Number} options.start - Start height.
 * @param {Number} options.end - End height.
 * @param {Number?} options.limit - Max number of records.
 * @param {Boolean?} options.reverse - Reverse order.
 * @param {Function} callback - Returns [Error, {@link Hash}[]].
 */

TXDB.prototype.getHeightRangeHashes = function getHeightRangeHashes(id, options, callback) {
  if (typeof id !== 'string') {
    callback = options;
    options = id;
    id = null;
  }

  this.db.iterate({
    gte: id
      ? 'H/' + id + '/' + pad32(options.start) + '/'
      : 'h/' + pad32(options.start) + '/',
    lte: id
      ? 'H/' + id + '/' + pad32(options.end) + '/~'
      : 'h/' + pad32(options.end) + '/~',
    limit: options.limit,
    reverse: options.reverse,
    transform: function(key) {
      key = key.split('/');
      if (id)
        return key[4];
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
 * @param {WalletID?} id
 * @param {Object} options
 * @param {Number} options.start - Start height.
 * @param {Number} options.end - End height.
 * @param {Number?} options.limit - Max number of records.
 * @param {Boolean?} options.reverse - Reverse order.
 * @param {Function} callback - Returns [Error, {@link Hash}[]].
 */

TXDB.prototype.getRangeHashes = function getRangeHashes(id, options, callback) {
  if (typeof id === 'function') {
    callback = id;
    id = null;
  }

  this.db.iterate({
    gte: id
      ? 'M/' + id + '/' + pad32(options.start) + '/'
      : 'm/' + pad32(options.start) + '/',
    lte: id
      ? 'M/' + id + '/' + pad32(options.end) + '/~'
      : 'm/' + pad32(options.end) + '/~',
    limit: options.limit,
    reverse: options.reverse,
    transform: function(key) {
      key = key.split('/');
      if (id)
        return key[4];
      return key[2];
    }
  }, callback);
};

/**
 * Get transactions by timestamp range.
 * @param {WalletID?} id
 * @param {Object} options
 * @param {Number} options.start - Start height.
 * @param {Number} options.end - End height.
 * @param {Number?} options.limit - Max number of records.
 * @param {Boolean?} options.reverse - Reverse order.
 * @param {Function} callback - Returns [Error, {@link TX}[]].
 */

TXDB.prototype.getRange = function getLast(id, options, callback) {
  var self = this;
  var txs = [];

  if (typeof id === 'function') {
    callback = id;
    id = null;
  }

  return this.getRangeHashes(id, options, function(err, hashes) {
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
 * @param {WalletID?} id
 * @param {Number} limit - Max number of transactions.
 * @param {Function} callback - Returns [Error, {@link TX}[]].
 */

TXDB.prototype.getLast = function getLast(id, limit, callback) {
  if (typeof limit === 'function') {
    callback = limit;
    limit = id;
    id = null;
  }

  return this.getRange(id, {
    start: 0,
    end: 0xffffffff,
    reverse: true,
    limit: limit
  }, callback);
};

/**
 * Get all transactions.
 * @param {WalletID?} id
 * @param {Function} callback - Returns [Error, {@link TX}[]].
 */

TXDB.prototype.getHistory = function getHistory(id, callback) {
  var self = this;
  var txs = [];

  if (typeof id === 'function') {
    callback = id;
    id = null;
  }

  return this.getHistoryHashes(id, function(err, hashes) {
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
 * @param {WalletID?} id
 * @param {Function} callback - Returns [Error, Number(ts), Number(height)].
 */

TXDB.prototype.getLastTime = function getLastTime(id, callback) {
  var i, tx, lastTs, lastHeight;

  if (typeof id === 'function') {
    callback = id;
    id = null;
  }

  return this.getHistory(id, function(err, txs) {
    if (err)
      return callback(err);

    lastTs = 0;
    lastHeight = -1;

    for (i = 0; i < txs.length; i++) {
      tx = txs[i];

      if (tx.ts > lastTs)
        lastTs = tx.ts;

      if (tx.height > lastHeight)
        lastHeight = tx.height;
    }

    return callback(null, lastTs, lastHeight);
  });
};

/**
 * Get unconfirmed transactions.
 * @param {WalletID?} id
 * @param {Function} callback - Returns [Error, {@link TX}[]].
 */

TXDB.prototype.getUnconfirmed = function getUnconfirmed(id, callback) {
  var self = this;
  var txs = [];

  if (typeof id === 'function') {
    callback = id;
    id = null;
  }

  return this.getUnconfirmedHashes(id, function(err, hashes) {
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
 * @param {WalletID?} id
 * @param {Function} callback - Returns [Error, {@link Coin}[]].
 */

TXDB.prototype.getCoins = function getCoins(id, callback) {
  var self = this;
  var coins = [];

  if (typeof id === 'function') {
    callback = id;
    id = null;
  }

  return this.getCoinHashes(id, function(err, hashes) {
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

  if (tx.isCoinbase()) {
    callback = utils.asyncify(callback);
    return callback(null, tx);
  }

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
 * Fill a transaction with coins.
 * @param {TX} tx
 * @param {Function} callback - Returns [Error, {@link TX}].
 */

TXDB.prototype.fillCoins = function fillCoins(tx, callback) {
  var self = this;

  if (tx.isCoinbase()) {
    callback = utils.asyncify(callback);
    return callback(null, tx);
  }

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
  this.db.fetch('c/' + hash + '/' + index, function(data) {
    var coin = bcoin.coin.fromRaw(data);
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
 * @param {WalletID?} id
 * @param {Function} callback - Returns [Error, {@link Balance}].
 */

TXDB.prototype.getBalance = function getBalance(id, callback) {
  var self = this;
  var confirmed = 0;
  var unconfirmed = 0;

  if (typeof id === 'function') {
    callback = id;
    id = null;
  }

  return this.getCoinHashes(id, function(err, hashes) {
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
 * @param {WalletID?} id
 * @param {Number} age - Age delta (delete transactions older than `now - age`).
 * @param {Function} callback
 */

TXDB.prototype.zap = function zap(id, age, callback, force) {
  var self = this;
  var unlock;

  if (typeof age === 'function') {
    force = callback;
    callback = age;
    age = id;
    id = null;
  }

  unlock = this._lock(zap, [id, age, callback], force);

  if (!unlock)
    return;

  callback = utils.wrap(callback, unlock);

  if (!utils.isNumber(age))
    return callback(new Error('Age must be a number.'));

  return this.getRange(id, {
    start: 0,
    end: bcoin.now() - age
  }, function(err, txs) {
    if (err)
      return callback(err);

    self.fillHistory(txs, function(err) {
      if (err)
        return callback(err);

      utils.forEachSerial(txs, function(tx, next) {
        if (tx.ts !== 0)
          return next();
        self.lazyRemove(tx, next, true);
      }, callback);
    });
  });
};

/*
 * Address->Wallet Mapping
 */

// Each address can potentially map to multiple
// accounts and wallets due to the fact that
// multisig accounts can have shared addresses.
// An address could map to 2 accounts on different
// wallets, or 2 accounts on the same wallet!
// In summary, bitcoin is hard. Use Bobchain instead.
//
// Table:
// [address-hash] -> [array of Path objects]
// '1edc6b6858fd12c64b26d8bd1e0e50d44b5bafb9':
//   [Path {
//     id: 'WLTZ3f5mMBsgWr1TcLzAdtLD8pkLcmWuBfPt',
//     name: 'default',
//     account: 0,
//     change: 0,
//     index: 0
//   }]
//

/**
 * WalletMap
 * @constructor
 * @private
 */

function WalletMap() {
  if (!(this instanceof WalletMap))
    return new WalletMap();

  this.inputs = [];
  this.outputs = [];
  this.accounts = [];
  this.table = null;
}

WalletMap.prototype.fromTX = function fromTX(table, tx) {
  var i, members, input, output, key;

  // This is a scary function, but what it is
  // designed to do is uniqify inputs and
  // outputs by account. This is easier said
  // than done due to two facts: transactions
  // can have multiple outputs with the same
  // address, and wallets can have multiple
  // accounts with the same address. On top
  // of that, it will calculate the total
  // value sent to or received from each
  // account.

  function insert(vector, target) {
    var i, io, hash, members, member;
    var j, paths, path, key, address, hashes;

    // Keeps track of unique addresses.
    hashes = {};

    // Maps address hashes to members.
    members = {};

    for (i = 0; i < vector.length; i++) {
      io = vector[i];
      address = io.getAddress();

      if (!address)
        continue;

      hash = address.getHash('hex');

      // Get all paths for this address.
      paths = table[hash];

      for (j = 0; j < paths.length; j++) {
        path = paths[j];
        key = path.toKey();
        member = members[key];

        // We no doubt already created a member
        // for this account, and not only that,
        // we're guaranteed to be on a different
        // input/output due to the fact that we
        // add the address hash after this loop
        // completes. Now we can update the value.
        if (hashes[hash]) {
          assert(member);
          if (io.coin)
            member.value += io.coin.value;
          else if (io.value)
            member.value += io.value;
          continue;
        }

        // Create a member for this account.
        assert(!member);
        member = MapMember.fromPath(path);

        // Set the _initial_ value.
        if (io.coin)
          member.value = io.coin.value;
        else if (io.value)
          member.value = io.value;

        // Add the address to the path object
        // and push onto the member's paths.
        // We only do this during instantiation,
        // since paths are just as unique as
        // addresses.
        path.address = address;
        member.paths.push(path);

        // Remember it by wallet id / account
        // name so we can update the value later.
        members[key] = member;

        // Push onto _our_ input/output array.
        target.push(member);
      }

      // Update this guy last so the above if
      // clause does not return true while
      // we're still iterating over paths.
      hashes[hash] = true;
    }
  }

  // Finally, we convert both inputs
  // and outputs to map members.
  insert(tx.inputs, this.inputs);
  insert(tx.outputs, this.outputs);

  // Combine both input and output map
  // members and uniqify them by account.
  members = {};

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];
    key = input.toKey();
    if (!members[key]) {
      members[key] = true;
      this.accounts.push(input);
    }
  }

  for (i = 0; i < this.outputs.length; i++) {
    output = this.outputs[i];
    key = output.toKey();
    if (!members[key]) {
      members[key] = true;
      this.accounts.push(output);
    }
  }

  this.table = table;

  return this;
};

WalletMap.fromTX = function fromTX(table, tx) {
  return new WalletMap().fromTX(table, tx);
};

WalletMap.prototype.hasPaths = function hasPaths(address) {
  var paths;

  if (!address)
    return false;

  paths = this.table[address];

  return paths && paths.length !== 0;
};

WalletMap.prototype.getPaths = function getPaths(address) {
  return this.table[address];
};

WalletMap.prototype.toJSON = function toJSON() {
  return {
    inputs: this.inputs.map(function(input) {
      return input.toJSON();
    }),
    outputs: this.outputs.map(function(output) {
      return output.toJSON();
    }),
    accounts: this.accounts.map(function(path) {
      return path.toKey();
    })
  };
};

WalletMap.prototype.fromJSON = function fromJSON(json) {
  var table = {};
  var i, j, account, input, output, path;
  var hash, paths, hashes, accounts, values, key;

  for (i = 0; i < json.inputs.length; i++) {
    input = json.inputs[i];
    input = MapMember.fromJSON(input);
    this.inputs.push(input);
    for (j = 0; j < input.paths.length; j++) {
      path = input.paths[j];
      path.id = input.id;
      path.name = input.name;
      path.account = input.account;
      hash = path.address.getHash('hex');
      if (!table[hash])
        table[hash] = [];
      table[hash].push(path);
    }
  }

  for (i = 0; i < json.outputs.length; i++) {
    output = json.outputs[i];
    output = MapMember.fromJSON(output);
    this.outputs.push(output);
    for (j = 0; j < output.paths.length; j++) {
      path = output.paths[j];
      path.id = output.id;
      path.name = output.name;
      path.account = output.account;
      hash = path.address.getHash('hex');
      if (!table[hash])
        table[hash] = [];
      table[hash].push(path);
    }
  }

  for (i = 0; i < json.accounts.length; i++) {
    account = json.accounts[i];
    this.accounts.push(bcoin.path.fromKey(account));
  }

  // We need to rebuild to address->paths table.
  hashes = Object.keys(table);

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];
    paths = table[hash];
    values = [];
    accounts = {};
    for (j = 0; j < paths.length; j++) {
      path = paths[j];
      key = path.toKey();
      if (!accounts[key]) {
        accounts[key] = true;
        values.push(path);
      }
    }
    table[hash] = values;
  }

  this.table = table;

  return this;
};

WalletMap.fromJSON = function fromJSON(json) {
  return new WalletMap().fromJSON(json);
};

/**
 * MapMember
 * @constructor
 * @private
 */

function MapMember() {
  if (!(this instanceof MapMember))
    return new MapMember();

  this.id = null;
  this.name = null;
  this.account = 0;
  this.paths = [];
  this.value = 0;
}

MapMember.prototype.toKey = function toKey() {
  return this.id + '/' + this.name + ':' + this.account;
};

MapMember.prototype.toJSON = function toJSON() {
  return {
    id: this.id,
    name: this.name,
    account: this.account,
    paths: this.paths.map(function(path) {
      return path.toCompact();
    }),
    value: utils.btc(this.value)
  };
};

MapMember.prototype.fromJSON = function fromJSON(json) {
  var i, path;

  this.id = json.id;
  this.name = json.name;
  this.account = json.account;

  for (i = 0; i < json.paths.length; i++) {
    path = json.paths[i];
    this.paths.push(bcoin.path.fromCompact(path));
  }

  this.value = utils.satoshi(json.value);

  return this;
};

MapMember.fromJSON = function fromJSON(json) {
  return new MapMember().fromJSON(json);
};

MapMember.prototype.fromPath = function fromPath(path) {
  this.id = path.id;
  this.name = path.name;
  this.account = path.account;
  return this;
};

MapMember.fromPath = function fromPath(path) {
  return new MapMember().fromPath(path);
};

/*
 * Expose
 */

module.exports = TXDB;
