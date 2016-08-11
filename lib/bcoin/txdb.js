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
  this.logger = db.logger;
  this.network = db.network;
  this.options = options;
  this.network = bcoin.network.get(options.network);
  this.busy = false;
  this.jobs = [];
  this.locker = new bcoin.locker(this);

  this.coinCache = new bcoin.lru(10000, 1);

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

/**
 * Invoke the mutex lock.
 * @private
 * @returns {Function} unlock
 */

TXDB.prototype._lock = function _lock(func, args, force) {
  return this.locker.lock(func, args, force);
};

/**
 * Load the bloom filter into memory.
 * @private
 * @param {Function} callback
 */

TXDB.prototype.loadFilter = function loadFilter(callback) {
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

/**
 * Test the bloom filter against an array of address hashes.
 * @private
 * @param {Hash[]} addresses
 * @returns {Boolean}
 */

TXDB.prototype.testFilter = function testFilter(addresses) {
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

TXDB.prototype.getInfo = function getInfo(tx, callback) {
  var addresses = tx.getHashes('hex');
  var info;

  if (!this.testFilter(addresses))
    return callback();

  this.mapAddresses(addresses, function(err, table) {
    if (err)
      return callback(err);

    if (!table)
      return callback();

    info = PathInfo.fromTX(tx, table);

    return callback(null, info);
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
    if (err)
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
 * Write the genesis block as the best hash.
 * @param {Function} callback
 */

TXDB.prototype.writeGenesis = function writeGenesis(callback) {
  var self = this;
  var unlock, hash;

  unlock = this._lock(writeGenesis, [callback]);

  if (!unlock)
    return;

  callback = utils.wrap(callback, unlock);

  self.db.has('R', function(err, result) {
    if (err)
      return callback(err);

    if (result)
      return callback();

    hash = new Buffer(self.network.genesis.hash, 'hex');
    self.db.put('R', hash, callback);
  });
};

/**
 * Get the best block hash.
 * @param {Function} callback
 */

TXDB.prototype.getTip = function getTip(callback) {
  this.db.fetch('R', function(data) {
    return data.toString('hex');
  }, callback);
};

/**
 * Write the best block hash.
 * @param {Hash} hash
 * @param {Function} callback
 */

TXDB.prototype.writeTip = function writeTip(hash, callback) {
  if (typeof hash === 'string')
    hash = new Buffer(hash, 'hex');
  this.db.put('R', hash, callback);
};

/**
 * Add a block's transactions and write the new best hash.
 * @param {Block} block
 * @param {Function} callback
 */

TXDB.prototype.addBlock = function addBlock(block, txs, callback, force) {
  var self = this;
  var unlock;

  unlock = this._lock(addBlock, [block, txs, callback], force);

  if (!unlock)
    return;

  callback = utils.wrap(callback, unlock);

  if (this.options.useCheckpoints) {
    if (block.height < this.network.checkpoints.lastHeight)
      return this.writeTip(block.hash, callback);
  }

  if (!Array.isArray(txs))
    txs = [txs];

  utils.forEachSerial(txs, function(tx, next) {
    self.add(tx, next, true);
  }, function(err) {
    if (err)
      return callback(err);

    self.writeTip(block.hash, callback);
  });
};

/**
 * Unconfirm a block's transactions
 * and write the new best hash (SPV version).
 * @param {Block} block
 * @param {Function} callback
 */

TXDB.prototype.removeBlock = function removeBlock(block, callback, force) {
  var self = this;
  var unlock;

  unlock = this._lock(removeBlock, [block, callback], force);

  if (!unlock)
    return;

  callback = utils.wrap(callback, unlock);

  this.getHeightHashes(block.height, function(err, hashes) {
    if (err)
      return callback(err);

    utils.forEachSerial(hashes, function(hash, next) {
      self.unconfirm(hash, next, true);
    }, function(err) {
      if (err)
        return callback(err);

      self.writeTip(block.prevBlock, callback);
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

  return this.getInfo(tx, function(err, info) {
    if (err)
      return callback(err);

    if (!info)
      return callback(null, false);

    self.logger.info(
      'Incoming transaction for %d addresses.',
      info.paths.length);

    self.logger.debug(info.paths);

    return self._add(tx, info, callback, force);
  });
};

TXDB.prototype._add = function add(tx, info, callback, force) {
  var self = this;
  var updated = false;
  var batch, hash, i, j, unlock, path, paths, id;

  unlock = this._lock(add, [tx, info, callback], force);

  if (!unlock)
    return;

  callback = utils.wrap(callback, unlock);

  if (tx.mutable)
    tx = tx.toTX();

  // Attempt to confirm tx before adding it.
  this._confirm(tx, info, function(err, existing) {
    if (err)
      return callback(err);

    // Ignore if we already have this tx.
    if (existing)
      return callback(null, true, info);

    hash = tx.hash('hex');

    batch = self.db.batch();

    batch.put('t/' + hash, tx.toExtended());

    if (tx.ts === 0)
      batch.put('p/' + hash, DUMMY);
    else
      batch.put('h/' + pad32(tx.height) + '/' + hash, DUMMY);

    batch.put('m/' + pad32(tx.ps) + '/' + hash, DUMMY);

    for (i = 0; i < info.keys.length; i++) {
      id = info.keys[i];
      batch.put('T/' + id + '/' + hash, DUMMY);
      if (tx.ts === 0)
        batch.put('P/' + id + '/' + hash, DUMMY);
      else
        batch.put('H/' + id + '/' + pad32(tx.height) + '/' + hash, DUMMY);
      batch.put('M/' + id + '/' + pad32(tx.ps) + '/' + hash, DUMMY);
    }

    // Consume unspent money or add orphans
    utils.forEachSerial(tx.inputs, function(input, next, i) {
      var prevout = input.prevout;
      var key, address;

      if (tx.isCoinbase())
        return next();

      address = input.getHash('hex');
      paths = info.getPaths(address);

      // Only bother if this input is ours.
      if (!paths)
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

          for (j = 0; j < paths.length; j++) {
            path = paths[j];
            id = path.id + '/' + path.account;
            batch.del('C/' + id + '/' + key);
          }

          batch.del('c/' + key);

          self.coinCache.remove(key);

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
                  return callback(null, false, info);
              }

              return self._removeConflict(spent, tx, function(err, rtx, rinfo) {
                if (err)
                  return next(err);

                // Spender was not removed, the current
                // transaction is not elligible to be added.
                if (!rtx)
                  return callback(null, false, info);

                self.emit('conflict', rtx, rinfo);

                batch.clear();

                self._add(tx, info, callback, true);
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

        if (output.script.isUnspendable())
          return next();

        paths = info.getPaths(address);

        // Do not add unspents for outputs that aren't ours.
        if (!paths)
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
              for (j = 0; j < paths.length; j++) {
                path = paths[j];
                id = path.id + '/' + path.account;
                batch.put('C/' + id + '/' + key, DUMMY);
              }

              coin = coin.toRaw();

              batch.put('c/' + key, coin);

              self.coinCache.set(key, coin);

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

          self.walletdb.handleTX(tx, info, function(err) {
            if (err)
              return callback(err);

            self.emit('tx', tx, info);

            if (updated) {
              if (tx.ts !== 0)
                self.emit('confirmed', tx, info);

              self.emit('updated', tx, info);
            }

            return callback(null, true, info);
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

    self._removeRecursive(tx, function(err, result, info) {
      if (err)
        return callback(err);
      return callback(null, tx, info);
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
 * @param {AddressMap} info
 * @param {Function} callback - Returns [Error, Boolean]. `false` if
 * the transaction should be added to the database, `true` if the
 * transaction was confirmed, or should be ignored.
 */

TXDB.prototype._confirm = function _confirm(tx, info, callback, force) {
  var self = this;
  var hash, batch, unlock, i, id;

  unlock = this._lock(_confirm, [tx, info, callback], force);

  if (!unlock)
    return;

  callback = utils.wrap(callback, unlock);

  hash = tx.hash('hex');

  this.getTX(hash, function(err, existing) {
    if (err)
      return callback(err);

    // Haven't seen this tx before, add it.
    if (!existing)
      return callback(null, false, info);

    // Existing tx is already confirmed. Ignore.
    if (existing.ts !== 0)
      return callback(null, true, info);

    // The incoming tx won't confirm the
    // existing one anyway. Ignore.
    if (tx.ts === 0)
      return callback(null, true, info);

    batch = self.db.batch();

    // Tricky - update the tx and coin in storage,
    // and remove pending flag to mark as confirmed.
    assert(tx.height >= 0);

    batch.put('t/' + hash, tx.toExtended());

    batch.del('p/' + hash);
    batch.put('h/' + pad32(tx.height) + '/' + hash, DUMMY);

    for (i = 0; i < info.keys.length; i++) {
      id = info.keys[i];
      batch.del('P/' + id + '/' + hash);
      batch.put('H/' + id + '/' + pad32(tx.height) + '/' + hash, DUMMY);
    }

    utils.forEachSerial(tx.outputs, function(output, next, i) {
      var address = output.getHash('hex');
      var key = hash + '/' + i;

      // Only update coins if this output is ours.
      if (!info.hasPaths(address))
        return next();

      self.getCoin(hash, i, function(err, coin) {
        if (err)
          return next(err);

        if (!coin)
          return next();

        coin.height = tx.height;
        coin = coin.toRaw();

        batch.put('c/' + key, coin);

        self.coinCache.set(key, coin);

        next();
      });
    }, function(err) {
      if (err)
        return callback(err);

      batch.write(function(err) {
        if (err)
          return callback(err);

        self.walletdb.syncOutputs(tx, info, function(err) {
          if (err)
            return callback(err);

          self.emit('confirmed', tx, info);
          self.emit('tx', tx, info);

          return callback(null, true, info);
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

    return self.getInfo(tx, function(err, info) {
      if (err)
        return callback(err);

      if (!info)
        return callback(null, false);

      return self._remove(tx, info, callback, force);
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

  return this.getInfo(tx, function(err, info) {
    if (err)
      return callback(err);

    if (!info)
      return callback(null, false);

    return self._remove(tx, info, callback, force);
  });
};

/**
 * Remove a transaction from the database. Disconnect inputs.
 * @private
 * @param {TX} tx
 * @param {AddressMap} info
 * @param {Function} callback - Returns [Error].
 */

TXDB.prototype._remove = function remove(tx, info, callback, force) {
  var self = this;
  var unlock, hash, batch, i, j, path, id;
  var key, paths, address, input, output, coin;

  unlock = this._lock(remove, [tx, info, callback], force);

  if (!unlock)
    return;

  callback = utils.wrap(callback, unlock);

  hash = tx.hash('hex');

  batch = this.db.batch();

  batch.del('t/' + hash);

  if (tx.ts === 0)
    batch.del('p/' + hash);
  else
    batch.del('h/' + pad32(tx.height) + '/' + hash);

  batch.del('m/' + pad32(tx.ps) + '/' + hash);

  for (i = 0; i < info.keys.length; i++) {
    id = info.keys[i];
    batch.del('T/' + id + '/' + hash);
    if (tx.ts === 0)
      batch.del('P/' + id + '/' + hash);
    else
      batch.del('H/' + id + '/' + pad32(tx.height) + '/' + hash);
    batch.del('M/' + id + '/' + pad32(tx.ps) + '/' + hash);
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

      paths = info.getPaths(address);

      if (!paths)
        continue;

      for (j = 0; j < paths.length; j++) {
        path = paths[j];
        id = path.id + '/' + path.account;
        batch.put('C/' + id + '/' + key, DUMMY);
      }

      coin = input.coin.toRaw();

      batch.put('c/' + key, coin);
      batch.del('s/' + key);
      batch.del('o/' + key);

      self.coinCache.set(key, coin);
    }

    for (i = 0; i < tx.outputs.length; i++) {
      output = tx.outputs[i];
      key = hash + '/' + i;
      address = output.getHash('hex');

      if (output.script.isUnspendable())
        continue;

      paths = info.getPaths(address);

      if (!paths)
        continue;

      for (j = 0; j < paths.length; j++) {
        path = paths[j];
        id = path.id + '/' + path.account;
        batch.del('C/' + id + '/' + key);
      }

      batch.del('c/' + key);

      self.coinCache.remove(key);
    }

    batch.write(function(err) {
      if (err)
        return callback(err);

      self.emit('remove tx', tx, info);

      return callback(null, true, info);
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

    return self.getInfo(tx, function(err, info) {
      if (err)
        return callback(err);

      if (!info)
        return callback(null, false);

      return self._unconfirm(tx, info, callback, force);
    });
  });
};

/**
 * Unconfirm a transaction. This is usually necessary after a reorg.
 * @param {Hash} hash
 * @param {AddressMap} info
 * @param {Function} callback
 */

TXDB.prototype._unconfirm = function unconfirm(tx, info, callback, force) {
  var self = this;
  var batch, unlock, hash, height, i, id;

  unlock = this._lock(unconfirm, [tx, info, callback], force);

  if (!unlock)
    return;

  callback = utils.wrap(callback, unlock);

  hash = tx.hash('hex');
  height = tx.height;

  batch = this.db.batch();

  if (height !== -1)
    return callback(null, false, info);

  tx.height = -1;
  tx.ts = 0;
  tx.index = -1;
  tx.block = null;

  batch.put('t/' + hash, tx.toExtended());

  batch.put('p/' + hash, DUMMY);
  batch.del('h/' + pad32(height) + '/' + hash);

  for (i = 0; i < info.keys.length; i++) {
    id = info.keys[i];
    batch.put('P/' + id + '/' + hash, DUMMY);
    batch.del('H/' + id + '/' + pad32(height) + '/' + hash);
  }

  utils.forEachSerial(tx.outputs, function(output, next, i) {
    var key = hash + '/' + i;
    self.getCoin(hash, i, function(err, coin) {
      if (err)
        return next(err);

      if (!coin)
        return next();

      coin.height = tx.height;
      coin = coin.toRaw();

      batch.put('c/' + key, coin);

      self.coinCache.set(key, coin);

      next();
    });
  }, function(err) {
    if (err)
      return callback(err);

    batch.write(function(err) {
      if (err)
        return callback(err);

      self.emit('unconfirmed', tx, info);

      return callback(null, true, info);
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
 * Get transaction details.
 * @param {WalletID} id
 * @param {Hash} hash
 * @param {Function} callback - Returns [Error, {@link TXDetails}].
 */

TXDB.prototype.getDetails = function getDetails(id, hash, callback) {
  var self = this;
  this.getTX(hash, function(err, tx) {
    if (err)
      return callback(err);

    if (!tx)
      return callback();

    self.toDetails(id, tx, callback);
  });
};

/**
 * Convert transaction to transaction details.
 * @param {WalletID} id
 * @param {TX|TX[]} tx
 * @param {Function} callback
 */

TXDB.prototype.toDetails = function toDetails(id, tx, callback) {
  var self = this;
  var out;

  if (Array.isArray(tx)) {
    out = [];
    utils.forEachSerial(tx, function(tx, next) {
      self.toDetails(tx, function(err, details) {
        if (err)
          return next(err);

        if (!details)
          return next();

        out.push(details);
        next();
      });
    }, function(err) {
      if (err)
        return callback(err);
      return callback(null, out);
    });
  }

  this.fillHistory(tx, function(err) {
    if (err)
      return callback(err);

    self.getInfo(tx, function(err, info) {
      if (err)
        return callback(err);

      if (!info)
        return callback();

      return callback(null, info.toDetails(id));
    });
  });
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
  var self = this;
  var key = hash + '/' + index;
  var coin = this.coinCache.get(key);

  if (coin) {
    try {
      coin = bcoin.coin.fromRaw(coin);
    } catch (e) {
      return callback(e);
    }
    coin.hash = hash;
    coin.index = index;
    return callback(null, coin);
  }

  this.db.fetch('c/' + key, function(data) {
    var coin = bcoin.coin.fromRaw(data);
    coin.hash = hash;
    coin.index = index;
    self.coinCache.set(key, data);
    return coin;
  }, callback);
};

/**
 * Test whether the database has a transaction.
 * @param {Hash} hash
 * @param {Function} callback - Returns [Error, Boolean].
 */

TXDB.prototype.hasCoin = function hasCoin(hash, index, callback) {
  var key = hash + '/' + index;

  if (this.coinCache.has(key))
    return callback(null, true);

  return this.db.has('c/' + key, callback);
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
  var key, coin;

  if (typeof id === 'function') {
    callback = id;
    id = null;
  }

  function parse(data) {
    var height = data.readUInt32LE(4, true);
    var value = utils.read64N(data, 8);

    assert(data.length >= 16);

    if (height === 0x7fffffff)
      unconfirmed += value;
    else
      confirmed += value;
  }

  return this.getCoinHashes(id, function(err, hashes) {
    if (err)
      return callback(err);

    utils.forEachSerial(hashes, function(hash, next) {
      key = hash[0] + '/' + hash[1];
      coin = self.coinCache.get(key);

      if (coin) {
        try {
          parse(coin);
        } catch (e) {
          return next(e);
        }
        return next();
      }

      self.db.get('c/' + key, function(err, data) {
        if (err)
          return next(err);

        if (!data)
          return next();

        try {
          parse(data);
        } catch (e) {
          return callback(e);
        }

        self.coinCache.set(key, data);

        next();
      });
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

function PathInfo(tx, table) {
  // All relevant Wallet-ID/Accounts for
  // inputs and outputs (for database indexing).
  this.keys = [];

  // All output paths (for deriving during sync).
  this.paths = [];

  // All wallet IDs (for balance & syncing).
  this.wallets = [];

  // Map of address hashes->paths (for everything).
  this.table = null;

  // Current transaction.
  this.tx = null;

  // Wallet-specific details cache.
  this._cache = {};

  if (tx)
    this.fromTX(tx, table);
}

PathInfo.prototype.fromTX = function fromTX(tx, table) {
  var i, j, keys, wallets, hashes, hash, paths, path, key;

  this.tx = tx;
  this.table = table;

  keys = {};
  wallets = {};
  hashes = Object.keys(table);

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];
    paths = table[hash];
    for (j = 0; j < paths.length; j++) {
      path = paths[j];
      key = path.id + '/' + path.account;
      keys[key] = true;
      wallets[path.id] = true;
    }
  }

  this.keys = Object.keys(keys);
  this.wallets = Object.keys(wallets);

  hashes = tx.getOutputHashes('hex');

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];
    paths = table[hash];
    for (j = 0; j < paths.length; j++) {
      path = paths[j];
      this.paths.push(path);
    }
  }

  return this;
};

PathInfo.fromTX = function fromTX(tx, table) {
  return new PathInfo().fromTX(tx, table);
};

/**
 * Test whether the map has paths
 * for a given address hash.
 * @param {Hash} address
 * @returns {Boolean}
 */

PathInfo.prototype.hasPaths = function hasPaths(address) {
  var paths;

  if (!address)
    return false;

  paths = this.table[address];

  return paths && paths.length !== 0;
};

/**
 * Get paths for a given address hash.
 * @param {Hash} address
 * @returns {Path[]|null}
 */

PathInfo.prototype.getPaths = function getPaths(address) {
  var paths;

  if (!address)
    return;

  paths = this.table[address];

  if (!paths || paths.length === 0)
    return;

  return paths;
};

PathInfo.prototype.toDetails = function toDetails(id) {
  var details;

  assert(utils.isAlpha(id));

  details = this._cache[id];

  if (!details) {
    details = new Details(id, this.tx, this.table);
    this._cache[id] = details;
  }

  return details;
};

function Details(id, tx, table) {
  this.id = id;
  this.hash = tx.hash('hex');
  this.height = tx.height;
  this.block = tx.block;
  this.index = tx.index;
  this.confirmations = tx.getConfirmations();
  this.ts = tx.ts;
  this.ps = tx.ps;
  this.fee = tx.getFee();
  this.tx = tx;
  this.inputs = [];
  this.outputs = [];
  this.init(table);
}

Details.prototype.init = function init(table) {
  this._insert(this.tx.inputs, this.inputs, table);
  this._insert(this.tx.outputs, this.outputs, table);
};

Details.prototype._insert = function _insert(vector, target, table) {
  var i, j, io, address, hash, paths, path, member;

  for (i = 0; i < vector.length; i++) {
    io = vector[i];
    member = new DetailsMember();

    if (io instanceof bcoin.input)
      member.value = io.coin ? io.coin.value : 0;
    else
      member.value = io.value;

    address = io.getAddress();

    if (address) {
      member.address = address;

      hash = address.getHash('hex');
      paths = table[hash];

      for (j = 0; j < paths.length; j++) {
        path = paths[j];
        if (path.id === this.id) {
          member.path = path;
          break;
        }
      }
    }

    target.push(member);
  }
};

Details.prototype.toJSON = function toJSON() {
  return {
    id: this.id,
    hash: utils.revHex(this.hash),
    height: this.height,
    block: this.block ? utils.revHex(this.block) : null,
    ts: this.ts,
    ps: this.ps,
    index: this.index,
    fee: utils.btc(this.fee),
    confirmations: this.confirmations,
    inputs: this.inputs.map(function(input) {
      return input.toJSON();
    }),
    outputs: this.outputs.map(function(output) {
      return output.toJSON();
    }),
    tx: this.tx.toRaw().toString('hex')
  };
};

Details.prototype.isReceive = function isReceive() {
  var i, input;

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];
    if (input.path)
      return false;
  }

  return true;
};

Details.prototype.getValue = function getValue() {
  var value = 0;
  var receive = this.isReceive();
  var i, member;

  for (i = 0; i < this.outputs.length; i++) {
    member = this.outputs[i];
    if (receive) {
      if (!member.path)
        continue;
    } else {
      if (member.path)
        continue;
    }
    value += member.value;
  }

  return value;
};

Details.prototype.getMember = function getMember() {
  var receive = this.isReceive();
  var vector = receive ? this.outputs : this.inputs;
  var i, member;

  for (i = 0; i < vector.length; i++) {
    member = vector[i];
    if (!member.path)
      continue;
    return member;
  }

  assert(false);
};

function DetailsMember() {
  this.value = 0;
  this.address = null;
  this.path = null;
}

DetailsMember.prototype.toJSON = function toJSON() {
  return {
    value: utils.btc(this.value),
    address: this.address
      ? this.address.toBase58()
      : null,
    path: this.path
      ? this.path.toJSON()
      : null
  };
};


/*
 * Expose
 */

module.exports = TXDB;
