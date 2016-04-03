/**
 * mempool.js - mempool for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var EventEmitter = require('events').EventEmitter;

var bcoin = require('../bcoin');
var bn = require('bn.js');
var constants = bcoin.protocol.constants;
var network = bcoin.protocol.network;
var utils = require('./utils');
var assert = utils.assert;
var BufferWriter = require('./writer');
var BufferReader = require('./reader');
var VerifyError = utils.VerifyError;

/**
 * Mempool
 */

function Mempool(node, options) {
  if (!(this instanceof Mempool))
    return new Mempool(node, options);

  EventEmitter.call(this);

  if (!options)
    options = {};

  this.options = options;
  this.node = node;
  this.chain = node.chain;

  this.loaded = false;

  this.locker = new bcoin.locker(this, this.add, 20 << 20);

  this.totalSize = 0;
  this.totalOrphans = 0;
  this.coins = {};
  this.txs = {};
  this.psIndex = new BinaryIndex();
  this.addressMap = new AddressMap();
  this.orphans = {};
  this.waiting = {};
  this.spent = {};

  this.freeCount = 0;
  this.lastTime = 0;

  this.limitFree = this.options.limitFree !== false;
  this.limitFreeRelay = this.options.limitFreeRelay || 15;
  this.relayPriority = this.options.relayPriority !== false;
  this.requireStandard = this.options.requireStandard !== false;
  this.rejectInsaneFees = this.options.rejectInsaneFees !== false;
  this.relay = this.options.relay || false;

  Mempool.global = this;

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

  assert(unlock);

  this.chain.open(function(err) {
    unlock();

    if (err)
      self.emit('error', err);

    self.loaded = true;
    self.emit('open');
  });
};

Mempool.prototype.open = function open(callback) {
  if (this.loaded)
    return utils.nextTick(callback);

  return this.once('open', callback);
};

Mempool.prototype.close =
Mempool.prototype.destroy = function destroy(callback) {
  return utils.nextTick(utils.ensure(callback));
};

Mempool.prototype.addBlock = function addBlock(block, callback, force) {
  var self = this;
  var unlock = this._lock(addBlock, [block, callback], force);
  if (!unlock)
    return;

  callback = utils.wrap(callback, unlock);

  utils.forEachSerial(block.txs, function(tx, next) {
    self.removeUnchecked(tx.hash('hex'), next);
  }, callback);
};

Mempool.prototype.removeBlock = function removeBlock(block, callback, force) {
  var self = this;
  var unlock = this._lock(removeBlock, [block, callback], force);
  if (!unlock)
    return;

  callback = utils.wrap(callback, unlock);

  utils.forEachSerial(block.txs.slice().reverse(), function(tx, next) {
    self.addUnchecked(tx, next);
  }, callback);
};

Mempool.prototype.limitMempoolSize = function limitMempoolSize(callback) {
  var self = this;

  if (this.size <= Mempool.MAX_MEMPOOL_SIZE)
    return callback(null, true);

  this.db.getRange({
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

        return callback(null, self.size <= Mempool.MAX_MEMPOOL_SIZE);
      });
    });
  });
};

Mempool.prototype.add =
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
            utils.debug('Added orphan %s to mempool.', tx.rhash);
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

// Use bitcoinj-style confidence calculation
Mempool.prototype.getConfidence = function getConfidence(hash, callback) {
  var self = this;
  var tx;

  callback = utils.asyncify(callback);

  if (hash instanceof bcoin.tx) {
    tx = hash;
    hash = tx.hash('hex');
  } else {
    try {
      tx = this.getTXSync(hash);
    } catch (e) {
      return callback(e);
    }
  }

  if (tx && this.isDoubleSpendSync(tx))
    return callback(null, constants.confidence.INCONFLICT);

  if (this.hasTXSync(hash))
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

      if (self.isSpentSync(hash, index)) {
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
    }, function(err) {
      if (err)
        return callback(err);

      return callback(null, tx, doubleSpend);
    });
  });
};

Mempool.prototype.addUnchecked = function addUnchecked(tx, callback) {
  var self = this;
  var hash = tx.hash();
  var hex = hash.toString('hex');
  var input, output, i, key, coin;

  this.txs[hex] = tx.toExtended();

  this.addressMap.addTX(tx);
  this.psIndex.insert(tx);

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    key = input.prevout.hash + '/' + input.prevout.index;
    delete this.coins[key];
    this.spent[key] = hash;
    this.addressMap.removeCoin(input);
  }

  for (i = 0; i < tx.outputs.length; i++) {
    output = tx.outputs[i];
    key = hex + '/' + i;
    coin = bcoin.coin(tx, i);
    this.coins[key] = coin.toRaw();
    this.addressMap.addCoin(coin);
  }

  this.totalSize += tx.getSize();

  this.emit('tx', tx);
  this.emit('add tx', tx);

  utils.debug('Added tx %s to the mempool.', tx.rhash);

  if (this.options.relay)
    this.node.broadcast(tx);

  this.resolveOrphans(tx, function(err, resolved) {
    if (err)
      return callback(err);

    utils.forEachSerial(resolved, function(tx, next) {
      self.addUnchecked(tx, function(err) {
        if (err)
          self.emit('error', err);
        utils.debug('Resolved orphan %s in mempool.', tx.rhash);
        next();
      }, true);
    }, callback);
  });
};

Mempool.prototype.removeUnchecked = function removeUnchecked(hash, callback) {
  var self = this;
  var tx, input, output, i, key, coin;

  if (hash instanceof bcoin.tx) {
    tx = hash;
    hash = tx.hash('hex');
  } else {
    try {
      tx = this.getTXSync(hash);
    } catch (e) {
      return utils.asyncify(callback)(e);
    }
  }

  if (!tx)
    return utils.nextTick(callback);

  this.fillAllTX(tx, function(err, tx) {
    if (err)
      return callback(err);

    delete self.txs[hash];

    try {
      self.removeOrphanSync(hash);
    } catch (e) {
      return callback(e);
    }

    self.addressMap.removeTX(tx);
    self.psIndex.remove(tx);

    for (i = 0; i < tx.inputs.length; i++) {
      inputs = tx.outputs[i];
      key = input.prevout.hash + '/' + input.prevout.index;
      delete self.spent[key];
      delete self.coins[key];
      self.addressMap.removeCoin(input);
      if (self.hasTXSync(input.prevout.hash)) {
        self.coins[key] = input.coin.toRaw();
        self.addressMap.addCoin(input.coin);
      }
    }

    for (i = 0; i < tx.outputs.length; i++) {
      output = tx.outputs[i];
      key = hash + '/' + i;
      delete self.coins[key];
      delete self.spent[key];
      self.addressMap.removeCoin(tx, i);
    }

    self.totalSize -= tx.getSize();
    self.emit('remove tx', tx);

    return callback();
  });
};

Mempool.prototype.removeOrphanSync = function removeOrphanSync(tx) {
  var prevout, i, hex, hash, prev, map, index;

  if (typeof tx === 'string')
    tx = this.getOrphanSync(tx);

  hash = tx.hash();
  hex = hash.toString('hex');
  prevout = tx.getPrevout();

  if (!this.orphans[hex])
    return false;

  delete this.orphans[hex];

  for (i = 0; i < prevout.length; i++) {
    prev = prevout[i];
    map = this.waiting[prev];

    if (!map)
      continue;

    index = binarySearch(map, hash);
    if (index !== -1) {
      map.splice(index, 1);
      if (map.length === 0)
        delete this.waiting[prev];
    }
  }

  return true;
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

Mempool.prototype.countAncestorsSync = function countAncestorsSync(tx) {
  var self = this;
  var max = 0
  var i, input, prev, count;

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    prev = this.getTXSync(input.prevout.hash);
    count = 0;

    if (!prev)
      continue;

    count += 1;
    count += this.countAncestorsSync(prev);

    if (count > max)
      max = count;
  }

  return max;
};

Mempool.prototype.hasOrphanSync = function hasOrphanSync(hash) {
  if (hash instanceof bcoin.tx)
    hash = hash.hash('hex');

  return this.orphans[hash] != null;
};

Mempool.prototype.getOrphanSync = function getOrphanSync(hash) {
  var orphan;

  if (hash instanceof bcoin.tx)
    hash = hash.hash('hex');

  orphan = this.orphans[hash];

  if (!orphan)
    return;

  return bcoin.tx.fromExtended(orphan, true);
};

Mempool.prototype.seenTX = function seenTX(tx, callback) {
  var hash = tx.hash('hex');

  if (this.hasOrphanSync(hash))
    return utils.asyncify(callback)(null, true);

  if (this.hasTXSync(hash))
    return utils.asyncify(callback)(null, true);

  return this.chain.db.hasTX(hash, callback);
};

Mempool.prototype.storeOrphanSync = function storeOrphanSync(tx) {
  var prevout = {};
  var hash = tx.hash();
  var i, input, key, map, index;

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    if (!input.coin)
      prevout[input.prevout.hash] = true;
  }

  prevout = Object.keys(prevout);

  assert(prevout.length > 0);

  for (i = 0; i < prevout.length; i++) {
    key = prevout[i];

    if (!this.waiting[key])
      this.waiting[key] = [];

    map = this.waiting[key];
    index = binarySearch(map, hash, true);
    map.splice(index + 1, 0, hash);
  }

  this.totalOrphans++;

  this.orphans[hash.toString('hex')] = tx.toExtended(true);

  if (this.totalOrphans > Mempool.MAX_ORPHAN_TX)
    this.purgeOrphansSync();

  return tx;
};

Mempool.prototype.getBalanceSync = function getBalanceSync() {
  var coins = [];
  var hashes = Object.keys(this.coins);
  var balance = new bn(0);
  var parts, hash, index, i, coin;

  for (i = 0; i < hashes.length; i++) {
    parts = hashes[i].split('/');
    hash = parts[0];
    index = +parts[1];
    coin = this.getCoinSync(hash, index);
    coins.push(coin);
  }

  for (i = 0; i < coins.length; i++)
    balance.iadd(coins[i].value);

  return {
    unconfirmed: balance,
    confirmed: new bn(0)
  };
};

Mempool.prototype.getAllSync = function getAllSync() {
  var txs = [];
  var hashes = Object.keys(this.txs);
  var i, tx;

  for (i = 0; i < hashes.length; i++) {
    tx = this.getTXSync(hashes[i]);
    if (tx)
      txs.push(tx);
  }

  return txs;
};

Mempool.prototype.resolveOrphans = function resolveOrphans(tx, callback) {
  var self = this;
  var hash = tx.hash('hex');
  var hashes = this.waiting[hash];
  var resolved = [];

  if (!hashes)
    return callback(null, resolved);

  utils.forEachSerial(hashes, function(orphanHash, next, i) {
    var orphan;

    orphanHash = orphanHash.toString('hex');
    orphan = self.orphans[orphanHash];

    if (!orphan)
      return next();

    try {
      orphan = bcoin.tx.fromExtended(orphan, true);
    } catch (e) {
      return next(e);
    }

    orphan.fillCoins(tx);

    if (orphan.hasCoins()) {
      self.totalOrphans--;
      delete self.orphans[orphanHash];
      return self.verify(orphan, function(err) {
        if (err) {
          if (err.type === 'VerifyError')
            return next();
          return next(err);
        }
        resolved.push(orphan);
        return next();
      });
    }

    self.orphans[orphanHash] = orphan.toExtended(true);

    next();
  }, function(err) {
    if (err)
      return callback(err);

    delete self.waiting[hash];

    return callback(null, resolved);
  });
};

Mempool.prototype.getSnapshotSync = function getSnapshotSync() {
  return Object.keys(this.txs);
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

/**
 * Async Wrappers
 */

Mempool.prototype.getRange = function getRange(options, callback) {
  var ret;

  callback = utils.asyncify(callback);

  try {
    ret = this.getRangeSync(options);
  } catch (e) {
    return callback(e);
  }

  return callback(null, ret);
};

Mempool.prototype.purgeOrphans = function purgeOrphans(callback) {
  var ret;

  callback = utils.asyncify(callback);

  try {
    ret = this.purgeOrphansSync();
  } catch (e) {
    return callback(e);
  }

  return callback(null, ret);
};

Mempool.prototype.get =
Mempool.prototype.getTX = function getTX(hash, callback) {
  var tx;

  callback = utils.asyncify(callback);

  try {
    tx = this.getTXSync(hash);
  } catch (e) {
    return callback(e);
  }

  return callback(null, tx);
};

Mempool.prototype.getCoin = function getCoin(hash, index, callback) {
  var coin;

  callback = utils.asyncify(callback);

  try {
    coin = this.getCoinSync(hash, index);
  } catch (e) {
    return callback(e);
  }

  return callback(null, coin);
};

Mempool.prototype.isSpent = function isSpent(hash, index, callback) {
  callback = utils.asyncify(callback);

  return callback(null, this.isSpentSync(hash, index));
};

Mempool.prototype.isDoubleSpend = function isDoubleSpend(tx, callback) {
  callback = utils.asyncify(callback);
  return callback(null, this.isDoubleSpendSync(tx));
};

Mempool.prototype.getCoinsByAddress = function getCoinsByAddress(addresses, callback) {
  var coins;

  callback = utils.asyncify(callback);

  try {
    coins = this.getCoinsByAddressSync(addresses);
  } catch (e) {
    return callback(e);
  }

  return callback(null, coins);
};

Mempool.prototype.getByAddress =
Mempool.prototype.getTXByAddress = function getTXByAddress(addresses, callback) {
  var txs;

  callback = utils.asyncify(callback);

  try {
    txs = this.getTXByAddressSync(addresses);
  } catch (e) {
    return callback(e);
  }

  return callback(null, txs);
};

Mempool.prototype.fillTX = function fillTX(tx, callback) {
  callback = utils.asyncify(callback);

  try {
    tx = this.fillTXSync(tx);
  } catch (e) {
    return callback(e);
  }

  return callback(null, tx);
};

Mempool.prototype.fillCoins = function fillCoins(tx, callback) {
  callback = utils.asyncify(callback);

  try {
    tx = this.fillCoinsSync(tx);
  } catch (e) {
    return callback(e);
  }

  return callback(null, tx);
};

Mempool.prototype.has =
Mempool.prototype.hasTX = function hasTX(hash, callback) {
  callback = utils.asyncify(callback);
  return callback(null, this.hasTXSync(hash));
};

Mempool.prototype.removeOrphan = function removeOrphan(tx, callback) {
  var ret;

  callback = utils.asyncify(callback);

  try {
    ret = this.removeOrphanSync(tx);
  } catch (e) {
    return callback(e);
  }

  return callback(null, ret);
};

Mempool.prototype.countAncestors = function countAncestors(tx, callback) {
  var count;

  callback = utils.asyncify(callback);

  try {
    count = this.countAncestorsSync(tx);
  } catch (e) {
    return callback(e);
  }

  return callback(null, count);
};

Mempool.prototype.hasOrphan = function hasOrphan(hash, callback) {
  callback = utils.asyncify(callback);
  return callback(null, this.hasOrphanSync(hash));
};

Mempool.prototype.getOrphan = function getOrphan(hash, callback) {
  var orphan;

  callback = utils.asyncify(callback);

  try {
    orphan = this.getOrphanSync(hash);
  } catch (e) {
    return callback(e);
  }

  return callback(null, orphan);
};

Mempool.prototype.storeOrphan = function storeOrphan(tx, callback) {
  var ret;

  callback = utils.asyncify(callback);

  try {
    ret = this.storeOrphanSync(tx);
  } catch (e) {
    return callback(e);
  }

  return callback(null, ret);
};

Mempool.prototype.getBalance = function getBalance(callback) {
  var balance;

  callback = utils.asyncify(callback);

  try {
    balance = this.getBalanceSync();
  } catch (e) {
    return callback(e);
  }

  return callback(null, balance);
};

Mempool.prototype.getAll = function getAll(callback) {
  var txs;

  callback = utils.asyncify(callback);

  try {
    txs = this.getAllSync();
  } catch (e) {
    return callback(e);
  }

  return callback(null, txs);
};

Mempool.prototype.getSnapshot = function getSnapshot(callback) {
  return utils.asyncify(callback)(null, this.getSnapshotSync());
};

/**
 * AddressMap
 */

function AddressMap() {
  this.map = { tx: {}, coin: {} };
}

AddressMap.prototype.getTX = function getTX(address) {
  var map = this.map.tx[address];
  var keys = [];
  var i, key;

  if (!map)
    return keys;

  for (i = 0; i < map.length; i++) {
    key = map[i];
    assert(key.length === 32);
    keys.push(key.toString('hex'));
  }

  return keys;
};

AddressMap.prototype.getCoins = function getCoins(address) {
  var map = this.map.coin[address];
  var keys = [];
  var i, p, key;

  if (!map)
    return keys;

  for (i = 0; i < map.length; i++) {
    key = map[i];

    assert(key.length === 36);

    p = new BufferReader(key);
    p.start();

    try {
      key = [p.readHash('hex'), p.readU32()];
    } catch (e) {
      continue;
    }

    p.end();

    keys.push(key);
  }

  return keys;
};

AddressMap.prototype.addTX = function addTX(tx) {
  var hash = tx.hash();
  var addresses = tx.getAddresses();
  var address, i, map, index;

  for (i = 0; i < addresses.length; i++) {
    address = addresses[i];
    if (!this.map.tx[address])
      this.map.tx[address] = [];
    map = this.map.tx[address];
    index = binarySearch(map, hash, true);
    map.splice(index + 1, 0, hash);
  }
};

AddressMap.prototype.removeTX = function removeTX(tx) {
  var hash = tx.hash();
  var addresses = tx.getAddresses();
  var address, map, index;

  for (i = 0; i < addresses.length; i++) {
    address = addresses[i];
    map = this.map.tx[address];

    if (map) {
      index = binarySearch(map, hash);
      if (index !== -1) {
        map.splice(index, 1);
        if (map.length === 0)
          delete this.map.tx[address];
      }
    }
  }
};

AddressMap.prototype.addCoin = function addCoin(coin) {
  var address = coin.getAddress();
  var key = this._coinKey(coin.hash, coin.index);
  var map, index;

  if (address) {
    if (!this.map.coin[address])
      this.map.coin[address] = [];
    map = this.map.coin[address];
    index = binarySearch(map, key, true);
    map.splice(index + 1, 0, key);
  }
};

AddressMap.prototype._coinKey = function _coinKey(hash, index) {
  var p = new BufferWriter();
  p.writeHash(hash);
  p.writeU32(index);
  return p.render();
};

AddressMap.prototype.removeCoin = function removeCoin(tx, i) {
  var address, key, map, index;

  if (tx instanceof bcoin.input) {
    address = tx.getAddress();
    key = this._coinKey(tx.prevout.hash, tx.prevout.index);
  } else {
    address = tx.outputs[i].getAddress();
    key = this._coinKey(tx.hash(), i);
  }

  map = this.map.coin[address];

  if (map) {
    index = binarySearch(map, key);
    if (index !== -1) {
      map.splice(index, 1);
      if (map.length === 0)
        delete this.map.coin[address];
    }
  }
};

/**
 * BinaryIndex
 */

function BinaryIndex() {
  this.index = [];
  this.data = [];
}

BinaryIndex.prototype.insert = function insert(tx) {
  var ps = new Buffer(4);
  var index;

  utils.writeU32BE(ps, tx.ps, 0);

  index = binarySearch(this.index, ps, true);

  this.index.splice(index + 1, 0, ps);
  this.data.splice(index + 1, 0, tx.hash());
};

BinaryIndex.prototype.remove = function remove(tx) {
  var ps = new Buffer(4);
  var index;

  utils.writeU32BE(ps, tx.ps, 0);

  index = binarySearch(this.index, ps);

  if (index !== -1) {
    this.index.splice(index, 1);
    this.data.splice(index, 1);
  }
};

BinaryIndex.prototype.range = function range(start, end) {
  var hashes = [];
  var ts = new Buffer(4);
  var i, ps;

  utils.writeU32BE(ts, start, 0);

  i = binarySearch(this.index, ts, true);

  for (; i < this.index.length; i++) {
    ps = utils.readU32BE(this.index[i], 0);
    if (ps < start || ps > end)
      return hashes;
    hashes.push(this.data[i].toString('hex'));
  }

  return hashes;
};

/**
 * Helpers
 */

function binarySearch(items, key, insert, compare) {
  var start = 0;
  var end = items.length - 1;
  var pos, cmp;

  if (!compare)
    compare = utils.cmp;

  while (start <= end) {
    pos = (start + end) >>> 1;
    cmp = compare(items[pos], key);

    if (cmp === 0)
      return pos;

    if (cmp < 0)
      start = pos + 1;
    else
      end = pos - 1;
  }

  if (!insert)
    return -1;

  return start - 1;
}

/**
 * Expose
 */

module.exports = Mempool;
