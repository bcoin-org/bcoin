/**
 * mempool.js - mempool for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

module.exports = function(bcoin) {

var EventEmitter = require('events').EventEmitter;

var bn = require('bn.js');
var constants = bcoin.protocol.constants;
var network = bcoin.protocol.network;
var utils = require('./utils');
var assert = utils.assert;
var BufferWriter = require('./writer');
var BufferReader = require('./reader');
var VerifyError = utils.VerifyError;
var pad32 = utils.pad32;
var DUMMY = new Buffer([0]);

/**
 * Mempool
 */

function Mempool(options) {
  if (!(this instanceof Mempool))
    return new Mempool(options);

  EventEmitter.call(this);

  if (!options)
    options = {};

  this.options = options;
  this.chain = options.chain;

  assert(this.chain, 'Mempool requires a blockchain.');

  this.loaded = false;

  this.locker = new bcoin.locker(this, this.addTX, 20 << 20);
  this.writeLock = new bcoin.locker(this);

  this.db = null;
  this.tx = null;
  this.size = 0;
  this.orphans = 0;

  this.freeCount = 0;
  this.lastTime = 0;

  this.limitFree = this.options.limitFree !== false;
  this.limitFreeRelay = this.options.limitFreeRelay || 15;
  this.relayPriority = this.options.relayPriority !== false;
  this.requireStandard = this.options.requireStandard !== false;
  this.rejectInsaneFees = this.options.rejectInsaneFees !== false;
  this.relay = this.options.relay || false;

  // Use an in-memory binary search tree by default
  this.backend = this.options.memory === false ? 'leveldb' : 'memory';

  this._init();
}

utils.inherits(Mempool, EventEmitter);

Mempool.flags = constants.flags.STANDARD_VERIFY_FLAGS;
Mempool.mandatory = constants.flags.MANDATORY_VERIFY_FLAGS;
Mempool.lockFlags = constants.flags.STANDARD_LOCKTIME_FLAGS;

Mempool.ANCESTOR_LIMIT = 25;
Mempool.MAX_MEMPOOL_SIZE = 300 << 20;
Mempool.MEMPOOL_EXPIRY = 72 * 60 * 60;
Mempool.MAX_ORPHAN_TX = 100;

Mempool.prototype._lock = function _lock(func, args, force) {
  return this.locker.lock(func, args, force);
};

Mempool.prototype.purgePending = function purgePending() {
  return this.locker.purgePending();
};

Mempool.prototype._init = function _init() {
  var self = this;
  var unlock = this._lock(utils.nop, []);
  var options = {
    name: this.options.name || 'mempool',
    location: this.options.location,
    db: this.options.db || this.backend
  };

  assert(unlock);

  // Clean the database before loading. The only
  // reason for using an on-disk db for the mempool
  // is not for persistence, but to keep ~300mb of
  // txs out of main memory.
  bcoin.ldb.destroy(options, function(err) {
    if (err) {
      unlock();
      return self.emit('error', err);
    }

    self.db = bcoin.ldb(options);

    // Use the txdb object for its get methods.
    self.tx = new bcoin.txdb('m', self.db);

    self.db.open(function(err) {
      if (err) {
        unlock();
        return self.emit('error', err);
      }
      self.dynamicMemoryUsage(function(err, size) {
        if (err)
          self.emit('error', err);
        else
          self.size = size;

        self.chain.open(function(err) {
          if (err) {
            unlock();
            return self.emit('error', err);
          }
          unlock();
          self.loaded = true;
          self.emit('open');
        });
      });
    });
  });
};

Mempool.prototype.dynamicMemoryUsage = function dynamicMemoryUsage(callback) {
  return this.db.approximateSize('m', 'm~', callback);
};

Mempool.prototype.open = function open(callback) {
  if (this.loaded)
    return utils.nextTick(callback);

  return this.once('open', callback);
};

Mempool.prototype.close =
Mempool.prototype.destroy = function destroy(callback) {
  this.db.close(utils.ensure(callback));
};

Mempool.prototype.addBlock = function addBlock(block, callback, force) {
  var self = this;
  var txs = [];
  var unlock = this._lock(addBlock, [block, callback], force);
  if (!unlock)
    return;

  callback = utils.wrap(callback, unlock);

  utils.forEachSerial(block.txs, function(tx, next) {
    var hash = tx.hash('hex');
    var copy;

    if (tx.isCoinbase())
      return next();

    self.getTX(hash, function(err, existing) {
      if (err)
        return callback(err);

      if (!existing)
        return self.removeOrphan(hash, next);

      copy = tx.clone();
      copy.ts = existing.ts;
      copy.block = existing.block;
      copy.height = existing.height;
      copy.ps = existing.ps;

      self.removeUnchecked(copy, function(err) {
        if (err)
          return next(err);

        self.emit('confirmed', tx, block);

        return next();
      });
    });
  }, callback);
};

Mempool.prototype.removeBlock = function removeBlock(block, callback, force) {
  var self = this;
  var unlock = this._lock(removeBlock, [block, callback], force);

  if (!unlock)
    return;

  callback = utils.wrap(callback, unlock);

  utils.forEachSerial(block.txs.slice().reverse(), function(tx, next) {
    var copy;

    if (tx.isCoinbase())
      return next();

    self.hasTX(tx.hash('hex'), function(err, result) {
      if (err)
        return next(err);

      if (result)
        return next();

      copy = tx.clone();
      copy.ts = 0;
      copy.block = null;
      copy.height = -1;
      copy.ps = utils.now();

      self.addUnchecked(copy, function(err) {
        if (err)
          return next(err);

        self.emit('unconfirmed', tx, block);

        return next();
      });
    });
  }, callback);
};

Mempool.prototype.limitMempoolSize = function limitMempoolSize(callback) {
  var self = this;

  if (this.size <= Mempool.MAX_MEMPOOL_SIZE)
    return callback(null, true);

  this.tx.getRange({
    start: 0,
    end: utils.now() - Mempool.MEMPOOL_EXPIRY
  }, function(err, txs) {
    if (err)
      return callback(err);

    utils.forEachSerial(function(tx, next) {
      self.removeUnchecked(tx, next);
    }, function(err) {
      if (err)
        return callback(err);

      self.purgeOrphans(function(err) {
        if (err)
          return callback(err);

        return callback(self.size <= Mempool.MAX_MEMPOOL_SIZE);
      });
    });
  });
};

Mempool.prototype.purgeOrphans = function purgeOrphans(callback) {
  var self = this;
  var batch = this.db.batch();

  callback = utils.ensure(callback);

  utils.forEachSerial(['m/D', 'm/d'], function(type, callback) {
    var iter = self.db.iterator({
      gte: type,
      lte: type + '~',
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

        batch.del(key);

        next();
      });
    })();
  }, function(err) {
    if (err)
      return callback(err);

    batch.write(function(err) {
      if (err)
        return callback(err);

      self.dynamicMemoryUsage(function(err, size) {
        if (err)
          return callback(err);

        self.size = size;
        self.orphans = 0;

        return callback();
      });
    });
  });
};

Mempool.prototype.getTX = function getTX(hash, callback) {
  if (hash instanceof bcoin.tx)
    hash = hash.hash('hex');
  return this.tx.getTX(hash, callback);
};

Mempool.prototype.getCoin = function getCoin(hash, index, callback) {
  return this.tx.getCoin(hash, index, callback);
};

Mempool.prototype.isSpent = function isSpent(hash, index, callback) {
  return this.tx.isSpent(hash, index, callback);
};

Mempool.prototype.getCoinsByAddress = function getCoinsByAddress(addresses, callback) {
  return this.tx.getCoinsByAddress(addresses, callback);
};

Mempool.prototype.getTXByAddress = function getTXByAddress(addresses, callback) {
  return this.tx.getTXByAddress(addresses, callback);
};

Mempool.prototype.fillTX = function fillTX(tx, callback) {
  return this.tx.fillTX(tx, callback);
};

Mempool.prototype.fillCoins = function fillCoins(tx, callback) {
  return this.tx.fillCoins(tx, callback);
};

Mempool.prototype.hasTX = function hasTX(hash, callback) {
  return this.tx.hasTX(hash, callback);
};

Mempool.prototype.addTX = function addTX(tx, callback, force) {
  var self = this;
  var flags = Mempool.flags;
  var lockFlags = Mempool.lockFlags;
  var ret = {};
  var now;

  var unlock = this._lock(addTX, [tx, callback], force);
  if (!unlock)
    return;

  if (this.chain.segwitActive) {
    flags |= constants.flags.VERIFY_WITNESS;
    flags |= constants.flags.VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM;
  }

  callback = utils.wrap(callback, unlock);
  callback = utils.asyncify(callback);

  if (tx.ts !== 0) {
    return callback(new VerifyError(tx,
      'alreadyknown',
      'txn-already-in-mempool',
      0));
  }

  if (!this.chain.segwitActive) {
    if (tx.hasWitness())
      return callback(new VerifyError(tx, 'nonstandard', 'no-witness-yet', 0));
  }

  if (!tx.isSane(ret))
    return callback(new VerifyError(tx, 'invalid', ret.reason, ret.score));

  if (tx.isCoinbase())
    return callback(new VerifyError(tx, 'invalid', 'coinbase', 100));

  this.chain.checkFinal(this.chain.tip, tx, lockFlags, function(err, isFinal) {
    if (err)
      return callback(err);

    if (!isFinal)
      return callback(new VerifyError(tx, 'nonstandard', 'non-final', 0));

    if (self.requireStandard) {
      if (!tx.isStandard(flags, ret))
        return callback(new VerifyError(tx, ret.reason, 0));
    }

    self.seenTX(tx, function(err, exists) {
      if (err)
        return callback(err);

      if (exists) {
        return callback(new VerifyError(tx,
          'alreadyknown',
          'txn-already-in-mempool',
          0));
      }

      self.isDoubleSpend(tx, function(err, doubleSpend) {
        if (err)
          return callback(err);

        if (doubleSpend) {
          return callback(new VerifyError(tx,
            'duplicate',
            'bad-txns-inputs-spent',
            0));
        }

        self.fillAllCoins(tx, function(err) {
          if (err)
            return callback(err);

          if (!tx.hasCoins()) {
            if (self.totalSize > Mempool.MAX_MEMPOOL_SIZE) {
              return callback(new VerifyError(tx,
                'insufficientfee',
                'mempool full',
                0));
            }
            bcoin.debug('Added orphan %s to mempool.', tx.rhash);
            return self.storeOrphan(tx, callback);
          }

          self.verify(tx, function(err) {
            if (err)
              return callback(err);

            self.limitMempoolSize(function(err, result) {
              if (err)
                return callback(err);

              if (!result) {
                return callback(new VerifyError(tx,
                  'insufficientfee',
                  'mempool full',
                  0));
              }

              self.addUnchecked(tx, callback);
            });
          });
        });
      });
    });
  });
};

Mempool.prototype.addUnchecked = function addUnchecked(tx, callback) {
  var self = this;
  this._addUnchecked(tx, function(err) {
    if (err)
      return callback(err);

    self.size += tx.getSize();
    self.emit('tx', tx);
    self.emit('add tx', tx);

    bcoin.debug('Added tx %s to the mempool.', tx.rhash);

    self.resolveOrphans(tx, function(err, resolved) {
      if (err)
        return callback(err);

      utils.forEachSerial(resolved, function(tx, next) {
        self.verify(tx, function(err) {
          if (err) {
            if (err.type === 'VerifyError') {
              bcoin.debug('Could not resolved orphan %s: %s.',
                tx.rhash,
                err.message);
              return next();
            }
            self.emit('error', err);
            return next();
          }
          self.addUnchecked(tx, function(err) {
            if (err) {
              self.emit('error', err);
              return next();
            }
            bcoin.debug('Resolved orphan %s in mempool.', tx.rhash);
            next();
          });
        });
      }, callback);
    });
  });
};

Mempool.prototype.removeUnchecked = function removeUnchecked(tx, callback) {
  var self = this;
  this.fillAllTX(tx, function(err, tx) {
    if (err)
      return callback(err);

    self.removeOrphan(tx, function(err) {
      if (err)
        return callback(err);

      self._removeUnchecked(tx, function(err) {
        if (err)
          return callback(err);
        self.size -= tx.getSize();
        self.emit('remove tx', tx);
        return callback();
      });
    });
  });
};

Mempool.prototype.verify = function verify(tx, callback) {
  var self = this;
  var height = this.chain.height + 1;
  var lockFlags = Mempool.lockFlags;
  var flags = Mempool.flags;
  var mandatory = Mempool.mandatory;
  var ret = {};
  var fee, now, free, minFee;

  if (this.chain.segwitActive) {
    flags |= constants.flags.VERIFY_WITNESS;
    flags |= constants.flags.VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM;
    mandatory |= constants.flags.VERIFY_WITNESS;
  }

  this.checkLocks(tx, lockFlags, function(err, result) {
    if (err)
      return callback(err);

    if (!result) {
      return callback(new VerifyError(tx,
        'nonstandard',
        'non-BIP68-final',
        0));
    }

    if (self.requireStandard && !tx.hasStandardInputs(flags)) {
      return callback(new VerifyError(tx,
        'nonstandard',
        'bad-txns-nonstandard-inputs',
        0));
    }

    if (tx.getSigops(true) > constants.tx.maxSigops) {
      return callback(new VerifyError(tx,
        'nonstandard',
        'bad-txns-too-many-sigops',
        0));
    }

    if (!tx.checkInputs(height, ret))
      return callback(new VerifyError(tx, 'invalid', ret.reason, ret.score));

    fee = tx.getFee();
    minFee = tx.getMinFee();
    if (fee.cmp(minFee) < 0) {
      if (self.relayPriority) {
        free = tx.isFree(height);
        if (!free) {
          return callback(new VerifyError(tx,
            'insufficientfee',
            'insufficient priority',
            0));
        }
      } else {
        return callback(new VerifyError(tx,
          'insufficientfee',
          'insufficient fee',
          0));
      }
    }

    if (self.limitFree && free) {
      now = utils.now();

      if (!self.lastTime)
        self.lastTime = now;

      self.freeCount *= Math.pow(1 - 1 / 600, now - self.lastTime);
      self.lastTime = now;

      if (self.freeCount > self.limitFreeRelay * 10 * 1000) {
        return callback(new VerifyError(tx,
          'insufficientfee',
          'rate limited free transaction',
          0));
      }

      self.freeCount += tx.getSize();
    }

    if (self.rejectInsaneFees && fee.cmp(minFee.muln(10000)) > 0)
      return callback(new VerifyError(tx, 'highfee', 'absurdly-high-fee', 0));

    self.countAncestors(tx, function(err, count) {
      if (err)
        return callback(err);

      if (count > Mempool.ANCESTOR_LIMIT) {
        return callback(new VerifyError(tx,
          'nonstandard',
          'too-long-mempool-chain',
          0));
      }

      // Do this in the worker pool.
      tx.verifyAsync(null, true, flags, function(err, result) {
        if (err)
          return callback(err);

        if (!result) {
          return tx.verifyAsync(null, true, mandatory, function(err, result) {
            if (err)
              return callback(err);

            if (result) {
              return callback(new VerifyError(tx,
                'nonstandard',
                'non-mandatory-script-verify-flag',
                0));
            }

            return callback(new VerifyError(tx,
              'nonstandard',
              'mandatory-script-verify-flag',
              0));
          });
        }

        return callback();
      });
    });
  });
};

Mempool.prototype.countAncestors = function countAncestors(tx, callback) {
  var self = this;
  var max = 0;

  utils.forEachSerial(tx.inputs, function(input, next, i) {
    var count = 0;
    self.getTX(input.prevout.hash, function(err, tx) {
      if (err)
        return next(err);

      if (!tx)
        return next();

      count += 1;

      self.countAncestors(tx, function(err, prev) {
        if (err)
          return next(err);

        count += prev;

        if (count > max)
          max = count;

        next();
      });
    });
  }, function(err) {
    if (err)
      return callback(err);

    return callback(null, max);
  });
};

Mempool.prototype.storeOrphan = function storeOrphan(tx, callback, force) {
  var self = this;
  var prevout = {};
  var batch = this.db.batch();
  var hash = tx.hash('hex');
  var i, input, p;

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    if (!input.coin)
      prevout[input.prevout.hash] = true;
  }

  prevout = Object.keys(prevout);

  assert(prevout.length > 0);

  utils.forEachSerial(prevout, function(prev, next) {
    self.getWaiting(prev, function(err, orphans, buf) {
      if (err)
        return next(err);

      p = new BufferWriter();

      if (buf)
        p.writeBytes(buf);

      p.writeHash(hash);

      batch.put('m/d/' + prev, p.render());

      next();
    });
  }, function(err) {
    if (err)
      return callback(err);

    self.orphans++;

    batch.put('m/D/' + hash, tx.toExtended(true));

    if (self.orphans > Mempool.MAX_ORPHAN_TX) {
      return self.purgeOrphans(function(err) {
        if (err)
          return callback(err);
        batch.write(callback);
      });
    }

    batch.write(callback);
  });
};

Mempool.prototype.getBalance = function getBalance(callback) {
  return this.tx.getBalance(callback);
};

Mempool.prototype.getAll = function getAll(callback) {
  return this.tx.getAll(callback);
};

Mempool.prototype.getWaiting = function getWaiting(hash, callback) {
  var self = this;
  var hashes = [];
  var p;

  this.db.get('m/d/' + hash, function(err, buf) {
    if (err && err.type !== 'NotFoundError')
      return callback(err);

    if (!buf)
      return callback(null, hashes, buf);

    p = new BufferReader(buf);

    p.start();

    try {
      while (p.left())
        hashes.push(p.readHash('hex'));
    } catch (e) {
      return callback(e);
    }

    p.end();

    return callback(null, hashes, buf);
  });
};

Mempool.prototype.getOrphan = function getOrphan(orphanHash, callback) {
  var self = this;

  this.db.get('m/D/' + orphanHash, function(err, orphan) {
    if (err && err.type !== 'NotFoundError')
      return next(err);

    if (!orphan)
      return callback();

    try {
      orphan = bcoin.tx.fromExtended(orphan, true);
    } catch (e) {
      return callback(e);
    }

    return callback(null, orphan);
  });
};

Mempool.prototype.hasOrphan = function hasOrphan(orphanHash, callback) {
  return this.getOrphan(orphanHash, function(err, tx) {
    if (err)
      return callback(err);

    return callback(null, tx != null);
  });
};

Mempool.prototype.resolveOrphans = function resolveOrphans(tx, callback, force) {
  var self = this;
  var hash = tx.hash('hex');
  var resolved = [];
  var batch = this.db.batch();

  this.getWaiting(hash, function(err, hashes) {
    if (err)
      return callback(err);

    utils.forEachSerial(hashes, function(orphanHash, next, i) {
      self.getOrphan(orphanHash, function(err, orphan) {
        if (err)
          return next(err);

        if (!orphan)
          return next();

        orphan.fillCoins(tx);

        if (orphan.hasCoins()) {
          self.orphans--;
          batch.del('m/D/' + orphanHash);
          resolved.push(orphan);
          return next();
        }

        batch.put('m/D/' + orphanHash, orphan.toExtended(true));
        next();
      });
    }, function(err) {
      if (err)
        return callback(err);

      function done(err) {
        if (err)
          return callback(err);

        return callback(null, resolved);
      }

      batch.del('m/d/' + hash);

      return batch.write(done);
    });
  });
};

Mempool.prototype.removeOrphan = function removeOrphan(tx, callback) {
  var self = this;
  var batch, prevout, hash;

  function getOrphan(tx, callback) {
    if (typeof tx === 'string')
      return self.getOrphan(tx, callback);
    return callback(null, tx);
  }

  return getOrphan(tx, function(err, tx) {
    if (err)
      return callback(err);

    if (!tx)
      return callback();

    batch = self.db.batch();

    hash = tx.hash('hex');
    prevout = tx.getPrevout();

    batch.del('m/D/' + hash);

    utils.forEach(prevout, function(prev, next) {
      var i, p;
      self.getWaiting(prev, function(err, hashes) {
        if (err)
          return next(err);

        if (hashes.length === 0)
          return next();

        i = hashes.indexOf(hash);
        if (i !== -1)
          hashes.splice(i, 1);

        if (hashes.length === 0) {
          batch.del('m/d/' + prev);
          return next();
        }

        p = new BufferWriter();
        hashes.forEach(function(hash) {
          p.writeHash(hash);
        });

        batch.put('m/d/' + prev, p.render());

        next();
      });
    }, function(err) {
      if (err)
        return callback(err);
      batch.write(callback);
    });
  });
};

Mempool.prototype.seenTX = function seenTX(tx, callback) {
  var self = this;
  var hash = tx.hash('hex');

  return this.hasOrphan(hash, function(err, result) {
    if (err)
      return callback(err);

    if (result)
      return callback(null, true);

    return self.hasTX(hash, function(err, result) {
      if (err)
        return callback(err);

      if (result)
        return callback(null, true);

      return self.chain.db.hasTX(hash, callback);
    });
  });
};

Mempool.prototype.fillAllTX = function fillAllTX(tx, callback) {
  var self = this;

  this.fillTX(tx, function(err) {
    if (err)
      return callback(err);

    if (tx.hasCoins())
      return callback(null, tx);

    self.chain.db.fillTX(tx, callback);
  });
};

Mempool.prototype.fillAllCoins = function fillAllCoins(tx, callback) {
  var self = this;
  var doubleSpend = false;

  this.fillCoins(tx, function(err) {
    if (err)
      return callback(err);

    if (tx.hasCoins())
      return callback(null, tx);

    utils.forEach(tx.inputs, function(input, next) {
      var hash = input.prevout.hash;
      var index = input.prevout.index;

      self.isSpent(hash, index, function(err, spent) {
        if (err)
          return callback(err);

        if (spent) {
          doubleSpend = true;
          return next();
        }

        self.chain.db.getCoin(hash, index, function(err, coin) {
          if (err)
            return next(err);

          if (!coin)
            return next();

          input.coin = coin;

          next();
        });
      });
    }, function(err) {
      if (err)
        return callback(err);

      return callback(null, tx, doubleSpend);
    });
  });
};

Mempool.prototype.getSnapshot = function getSnapshot(callback) {
  return this.tx.getAllHashes(callback);
};

Mempool.prototype.checkLocks = function checkLocks(tx, flags, callback) {
  var self = this;
  var tip = this.chain.tip;

  var index = new bcoin.chainblock(this.chain, {
    hash: utils.toHex(constants.zeroHash),
    version: tip.version,
    prevBlock: tip.hash,
    merkleRoot: utils.toHex(constants.zeroHash),
    ts: utils.now(),
    bits: 0,
    nonce: 0,
    height: tip.height + 1,
    chainwork: tip.chainwork
  });

  return this.chain.checkLocks(tx, flags, index, callback);
};

Mempool.prototype.isDoubleSpend = function isDoubleSpend(tx, callback) {
  return this.tx.isDoubleSpend(tx, callback);
};

// Use bitcoinj-style confidence calculation
Mempool.prototype.getConfidence = function getConfidence(hash, callback) {
  var self = this;
  var tx;

  callback = utils.asyncify(callback);

  function isDoubleSpend(callback) {
    if (tx)
      return self.isDoubleSpend(tx, callback);
    return callback(null, false);
  }

  function done(tx, hash) {
    return isDoubleSpend(function(err, result) {
      if (err)
        return callback(err);

      if (result)
        return callback(null, constants.confidence.INCONFLICT);

      return self.hasTX(hash, function(err, result) {
        if (err)
          return callback(err);

        if (result)
          return callback(null, constants.confidence.PENDING);

        function getBlock(callback) {
          if (tx && tx.block)
            return callback(null, tx.block);
          return self.chain.db.getTX(hash, function(err, existing) {
            if (err)
              return callback(err);

            if (!existing)
              return callback();

            return callback(null, existing.block);
          });
        }

        return getBlock(function(err, block) {
          if (err)
            return callback(err);

          if (!block)
            return callback(null, constants.confidence.UNKNOWN);

          self.chain.db.isMainChain(block, function(err, result) {
            if (err)
              return callback(err);

            if (result)
              return callback(null, constants.confidence.BUILDING);

            return callback(null, constants.confidence.DEAD);
          });
        });
      });
    });
  }

  if (hash instanceof bcoin.tx)
    return done(hash, hash.hash('hex'));

  return this.getTX(hash, function(err, tx) {
    if (err)
      return callback(err);
    done(tx, hash);
  });
};

Mempool.prototype._addUnchecked = function addUnchecked(tx, callback, force) {
  var self = this;
  var prefix = 'm/';
  var hash = tx.hash('hex');
  var batch;

  var unlock = this.writeLock.lock(addUnchecked, [tx, callback], force);
  if (!unlock)
    return;

  callback = utils.wrap(callback, unlock);

  batch = this.db.batch();

  batch.put(prefix + 't/t/' + hash, tx.toExtended());
  batch.put(prefix + 't/s/s/' + pad32(tx.ps) + '/' + hash, DUMMY);

  tx.getAddresses().forEach(function(address) {
    batch.put(prefix + 't/a/' + address + '/' + hash, DUMMY);
  });

  tx.inputs.forEach(function(input) {
    var key = input.prevout.hash + '/' + input.prevout.index;
    var address;

    if (tx.isCoinbase())
      return;

    assert(input.coin);
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

  return batch.write(callback);
};

Mempool.prototype._removeUnchecked = function removeUnchecked(hash, callback, force) {
  var self = this;
  var prefix = 'm/';
  var batch;

  var unlock = this.writeLock.lock(removeUnchecked, [hash, callback], force);
  if (!unlock)
    return;

  callback = utils.wrap(callback, unlock);

  if (hash.hash)
    hash = hash.hash('hex');

  this.getTX(hash, function(err, tx) {
    if (err)
      return callback(err);

    if (!tx)
      return callback();

    batch = self.db.batch();

    batch.del(prefix + 't/t/' + hash);
    batch.del(prefix + 't/s/s/' + pad32(tx.ps) + '/' + hash);

    tx.getAddresses().forEach(function(address) {
      batch.del(prefix + 't/a/' + address + '/' + hash);
    });

    utils.forEachSerial(tx.inputs, function(input, next) {
      var key = input.prevout.hash + '/' + input.prevout.index;
      var address;

      if (tx.isCoinbase())
        return next();

      if (!input.coin)
        return next();

      address = input.getAddress();

      batch.del(prefix + 's/t/' + key);

      self.hasTX(input.prevout.hash, function(err, result) {
        if (err)
          return next(err);

        if (result) {
          batch.put(prefix + 'u/t/' + key, input.coin.toRaw());
          if (address)
            batch.put(prefix + 'u/a/' + address + '/' + key, DUMMY);
        } else {
          batch.del(prefix + 'u/t/' + key);
          if (address)
            batch.del(prefix + 'u/a/' + address + '/' + key);
        }

        next();
      });
    }, function(err) {
      if (err)
        return callback(err);

      tx.outputs.forEach(function(output, i) {
        var key = hash + '/' + i;
        var address = output.getAddress();

        batch.del(prefix + 'u/t/' + key);

        if (address)
          batch.del(prefix + 'u/a/' + address + '/' + key);
      });

      return batch.write(callback);
    });
  });
};

/**
 * Expose
 */

return Mempool;
};
