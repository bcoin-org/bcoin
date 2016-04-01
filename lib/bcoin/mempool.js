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
  this.addressMap = new AddressMap;
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

Mempool.prototype.dynamicMemoryUsage = function dynamicMemoryUsage(callback) {
  return utils.asyncify(callback)(null, this.totalSize);
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
    self.removeUnchecked(tx, next);
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

  if (this.totalSize <= Mempool.MAX_MEMPOOL_SIZE)
    return callback(null, true);

  this.getRange({
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

        return callback(self.totalSize <= Mempool.MAX_MEMPOOL_SIZE);
      });
    });
  });
};

Mempool.prototype.getRange = function getRange(options, callback) {
  return callback(null, []);
};

Mempool.prototype.purgeOrphans = function purgeOrphans(callback) {
  var self = this;
  var batch = this.db.batch();

  callback = utils.ensure(callback);

  this.waiting = {};
  this.totalOrphans = 0;

  Object.keys(this.orphans).forEach(function(key) {
    self.totalSize -= self.orphans[key].length;
    delete self.orphans[key];
  });

  return utils.nextTick(callback);
};

Mempool.prototype.getTXSync = function getTXSync(hash) {
  var tx;

  if (hash instanceof bcoin.tx)
    hash = hash.hash('hex');

  tx = this.txs[hash];

  if (!tx)
    return;

  return bcoin.tx.fromExtended(tx);
};

Mempool.prototype.getCoinSync = function getCoinSync(hash, index) {
  var key = hash + '/' + index;
  var coin;

  coin = this.coins[key];

  if (!coin)
    return;

  coin = bcoin.coin.fromRaw(coin);
  coin.hash = hash;
  coin.index = index;

  return coin;
};

Mempool.prototype.isSpentSync = function isSpentSync(hash, index) {
  var key = hash + '/' + index;

  return this.spent[key];
};

Mempool.prototype.isDoubleSpendSync = function isDoubleSpendSync(tx) {
  var i, input;

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    if (this.isSpentSync(input.prevout.hash, input.prevout.index))
      return true;
  }

  return false;
};

Mempool.prototype.get =
Mempool.prototype.getTX = function getTX(hash, callback) {
  callback = utils.asyncify(callback);

  try {
    return callback(null, this.getTXSync(hash));
  } catch (e) {
    return callback(e);
  }
};

Mempool.prototype.getCoin = function getCoin(hash, index, callback) {
  callback = utils.asyncify(callback);

  try {
    return callback(null, this.getCoinSync(hash, index));
  } catch (e) {
    return callback(e);
  }
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
  var uniq = {};
  var coins = [];
  var i, j, address, keys, key, coin, parts, hash, index;

  callback = utils.asyncify(callback);

  if (!Array.isArray(addresses))
    addresses = [addresses];

  addresses = utils.uniqs(addresses);

  for (i = 0; i < addresses.length; i++) {
    address = addresses[i];
    keys = this.addressMap.getKeys(address);
    for (j = 0; j < keys.length; j++) {
      key = keys[j];
      parts = key.split('/');
      hash = parts[0];
      index = +parts[1];

      try {
        coin = this.getCoinSync(hash, index);
      } catch (e) {
        return callback(e);
      }

      if (!coin)
        continue;

      coins.push(coin);
    }
  }

  return callback(null, coins);
};

Mempool.prototype.getByAddress =
Mempool.prototype.getTXByAddress = function getTXByAddress(addresses, callback) {
  var uniq = {};
  var txs = [];
  var i, j, address, hashes, hash, tx;

  callback = utils.asyncify(callback);

  if (!Array.isArray(addresses))
    addresses = [addresses];

  addresses = utils.uniqs(addresses);

  for (i = 0; i < addresses.length; i++) {
    address = addresses[i];
    hashes = this.addressMap.getKeys(address);
    for (j = 0; j < hashes.length; j++) {
      hash = hashes[j];

      if (uniq[hash])
        continue;

      try {
        tx = this.getTXSync(hash);
      } catch (e) {
        return callback(e);
      }

      if (!tx)
        continue;

      uniq[hash] = true;

      txs.push(tx);
    }
  }

  return callback(null, txs);
};

Mempool.prototype.fillTX = function fillTX(tx, callback) {
  var i, input, tx;

  callback = utils.asyncify(callback);

  if (tx.isCoinbase())
    return callback(null, tx);

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];

    if (input.coin)
      continue;

    try {
      tx = this.getTXSync(input.prevout.hash);
    } catch (e) {
      return callback(e);
    }

    if (!tx)
      continue;

    input.coin = bcoin.coin(tx, input.prevout.index);
  }

  return callback(null, tx);
};

Mempool.prototype.fillCoins = function fillCoins(tx, callback) {
  var input;

  callback = utils.asyncify(callback);

  if (tx.isCoinbase())
    return callback(null, tx);

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];

    if (input.coin)
      continue;

    try {
      input.coin = this.getCoinSync(input.prevout.hash, input.prevout.index);
    } catch (e) {
      return callback(e);
    }
  }

  return callback(null, tx);
};

Mempool.prototype.has =
Mempool.prototype.hasTX = function hasTX(hash, callback) {
  callback = utils.asyncify(callback);

  if (hash instanceof bcoin.tx)
    hash = hash.hash('hex');

  return callback(null, !!this.txs[hash]);
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

  self.chain.checkFinal(self.chain.tip, tx, lockFlags, function(err, isFinal) {
    if (err)
      return callback(err);

    if (!isFinal)
      return callback(new VerifyError(tx, 'nonstandard', 'non-final', 0));

    if (self.requireStandard) {
      if (!tx.isStandard(flags, ret))
        return callback(new VerifyError(tx, ret.reason, 0));
    }

    self._hasTX(tx, function(err, exists) {
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

        self.node.fillCoins(tx, function(err) {
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

function AddressMap() {
  this.map = {};
}

AddressMap.prototype.getKeys = function getKeys(address) {
  return this.map[address] || [];
};

AddressMap.prototype.addTX = function addTX(tx) {
  var hash = tx.hash('hex');
  var addresses = tx.getAddresses();
  var address;
  var i;

  for (i = 0; i < addresses.length; i++) {
    address = addresses[i];
    if (!this.map[address])
      this.map[address] = [];
    this.map[address].push(hash);
  }
};

function binarySearch(items, key, insert) {
  var start = 0;
  var end = items.length - 1;
  var pos, cmp;

  while (start <= end) {
    pos = (start + end) >>> 1;
    cmp = utils.cmp(items[pos], key);

    if (cmp === 0)
      return pos;

    if (cmp < 0)
      start = pos + 1;
    else
      end = pos - 1;
  }

  if (!insert)
    return -1;

  if (start === 0)
    return 0;

  return start - 1;
}

AddressMap.prototype.removeTX = function removeTX(tx) {
  var addresses = tx.getAddresses();
  var address;
  var map, i;

  for (i = 0; i < addresses.length; i++) {
    address = addresses[i];
    map = this.map[address];

    if (map) {
      i = map.indexOf(hash);
      if (i !== -1)
        map.splice(i , 1);
      if (map.length === 0)
        delete this.map[address];
    }
  }
};

AddressMap.prototype.addCoin = function addCoin(coin) {
  var address = coin.getAddress();
  var key = coin.hash + '/' + coin.index;

  if (address) {
    if (!this.map[address])
      this.map[address] = [];
    this.map[address].push(key);
  }
};

AddressMap.prototype.removeCoin = function removeCoin(tx, i) {
  var address, key, map, i;

  if (tx instanceof bcoin.input) {
    address = tx.getAddress();
    key = tx.prevout.hash + '/' + tx.prevout.index;
  } else {
    address = tx.outputs[i].getAddress();
    key = tx.hash('hex') + '/' + i;
  }

  map = this.map[address];

  if (map) {
    i = map.indexOf(key);
    if (i !== -1)
      map.splice(i, 1);
    if (map.length === 0)
      delete this.map[address];
  }
};

Mempool.prototype.addUnchecked = function addUnchecked(tx, callback) {
  var self = this;
  var hash = tx.hash('hex');

  this.txs[hash] = tx.toExtended();

  this.addressMap.addTX(tx);

  tx.inputs.forEach(function(input, i) {
    var key = input.prevout.hash + '/' + input.prevout.index;
    delete self.coins[key];
    self.spent[key] = hash;
    self.addressMap.removeCoin(input);
  });

  tx.outputs.forEach(function(output, i) {
    var coin = bcoin.coin(tx, i);
    var key = coin.hash + '/' + coin.index;
    self.coins[key] = coin.toRaw();
    self.addressMap.addCoin(coin);
  });

  self.totalSize += tx.getSize();
  self.emit('tx', tx);
  self.emit('add tx', tx);

  utils.debug('Added tx %s to the mempool.', tx.rhash);

  if (self.options.relay)
    self.node.broadcast(tx);

  self.resolveOrphans(tx, function(err, resolved) {
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

Mempool.prototype.removeUnchecked = function removeUnchecked(tx, callback) {
  var self = this;
  var hash;

  callback = utils.asyncify(callback);

  try {
    tx = this.getTXSync(tx);
  } catch (e) {
    return callback(e);
  }

  if (!tx)
    return callback();

  hash = tx.hash('hex');

  delete this.txs[hash];
  delete this.orphans[hash];

  this.addressMap.removeTX(tx);

  tx.inputs.forEach(function(input, i) {
    var key = input.prevout.hash + '/' + input.prevout.index;
    delete self.coins[key];
    delete self.spent[key];
    self.addressMap.removeCoin(input);
  });

  tx.outputs.forEach(function(output, i) {
    var address = output.getAddress();
    var key = hash + '/' + i;

    delete self.coins[key];
    delete self.spent[key];
    self.addressMap.removeCoin(tx, i);
  });

  self.totalSize -= tx.getSize();
  self.emit('remove tx', tx);

  return callback();
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
  var inputs = new Array(tx.inputs.length);
  var i, input, prev;

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    prev = self.getTXSync(input.prevout.hash);
    inputs[i] = 0;

    if (!prev)
      continue;

    inputs[i] += 1;
    inputs[i] += self.countAncestorsSync(prev);
  }

  return inputs.sort().pop();
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

Mempool.prototype.hasOrphanSync = function hasOrphanSync(hash) {
  if (hash instanceof bcoin.tx)
    hash = hash.hash('hex');

  return !!this.orphans[hash];
};

Mempool.prototype.getOrphanSync = function getOrphanSync(hash) {
  var orphan;

  if (hash instanceof bcoin.tx)
    hash = hash.hash('hex');

  orphan = this.orphans[hash];

  if (!orphan)
    return callback();

  return bcoin.tx.fromExtended(orphan, true);
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

Mempool.prototype._hasTX = function hasTX(tx, callback) {
  var self = this;
  var hash = tx.hash('hex');

  this.node.hasTX(hash, function(err, result) {
    if (err)
      return callback(err);

    if (result)
      return callback(null, result);

    self.hasOrphan(hash, function(err, result) {
      if (err)
        return callback(err);

      return callback(null, result);
    });
  });
};

Mempool.prototype.storeOrphan = function storeOrphan(tx, callback) {
  var self = this;
  var prevout = {};
  var hash = tx.hash('hex');
  var i, input, p;

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    if (!input.coin)
      prevout[input.prevout.hash] = true;
  }

  prevout = Object.keys(prevout);

  assert(prevout.length > 0);

  prevout.forEach(function(key) {
    if (!self.waiting[key])
      self.waiting[key] = [];

    self.waiting[key].push(hash);
  });

  self.totalOrphans++;

  self.orphans[hash] = tx.toExtended(true);

  if (self.totalOrphans > Mempool.MAX_ORPHAN_TX)
    return self.purgeOrphans(callback);

  return utils.nextTick(callback);
};

Mempool.prototype.getBalance = function getBalance(callback) {
  var coins = [];
  var hashes = Object.keys(this.coins);
  var parts, hash, index, i, coin;
  var unconfirmed = new bn(0);
  var confirmed = new bn(0);

  callback = utils.asyncify(callback);

  for (i = 0; i < hashes.length; i++) {
    parts = hashes[i].split('/');
    hash = parts[0];
    index = +parts[1];

    try {
      coin = this.getCoinSync(hash, index);
    } catch (e) {
      return callback(e);
    }

    coins.push(coin);
  }

  for (i = 0; i < coins.length; i++) {
    coin = coins[i];
    if (coin.height !== -1)
      confirmed.iadd(coin.value);
    unconfirmed.iadd(coin.value);
  }

  return callback(null, {
    unconfirmed: unconfirmed,
    confirmed: confirmed
  });
};

Mempool.prototype.getAll = function getAll(callback) {
  var txs = [];
  var hashes = Object.keys(this.txs);
  var i, tx;

  callback = utils.asyncify(callback);

  for (i = 0; i < hashes.length; i++) {
    try {
      tx = this.getTXSync(hashes[i]);
    } catch (e) {
      return callback(e);
    }

    txs.push(tx);
  }

  return callback(null, txs);
};

Mempool.prototype.resolveOrphans = function resolveOrphans(tx, callback) {
  var self = this;
  var hash = tx.hash('hex');
  var hashes = this.waiting[hash];
  var resolved = [];

  if (!hashes)
    return callback(null, resolved);

  utils.forEachSerial(hashes, function(orphanHash, next, i) {
    var orphan = self.orphans[orphanHash];

    if (!orphan)
      return next();

    try {
      orphan = bcoin.tx.fromExtended(orphan, true);
    } catch (e) {
      return next(e);
    }

    orphan.inputs.forEach(function(input) {
      if (!input.coin && input.prevout.hash === hash)
        input.coin = bcoin.coin(tx, input.prevout.index);
    });

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

Mempool.prototype.getSnapshot = function getSnapshot(callback) {
  return utils.asyncify(callback)(null, Object.keys(this.txs));
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
 * Expose
 */

module.exports = Mempool;
