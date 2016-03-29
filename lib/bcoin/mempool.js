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
var DUMMY_PEER = { sendReject: function() {} };

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

  Mempool.global = this;

  this._init();
}

utils.inherits(Mempool, EventEmitter);

Mempool.flags = constants.flags.STANDARD_VERIFY_FLAGS;
Mempool.mandatory = constants.flags.MANDATORY_VERIFY_FLAGS;

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

  bcoin.ldb.destroy('mempool', 'memdown', function(err) {
    if (err) {
      unlock();
      return self.emit('error', err);
    }

    self.db = bcoin.ldb('mempool', {
      db: 'memdown'
    });

    self.tx = new bcoin.txdb('m', self.db, {
      indexExtra: false,
      indexAddress: false,
      mapAddress: false,
      verify: false
    });

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

        unlock();
        self.loaded = true;
        self.emit('open');
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

Mempool.prototype.get =
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

Mempool.prototype.getByAddress =
Mempool.prototype.getTXByAddress = function getTXByAddress(addresses, callback) {
  return this.tx.getTXByAddress(addresses, callback);
};

Mempool.prototype.fillTX = function fillTX(tx, callback) {
  return this.tx.fillTX(tx, callback);
};

Mempool.prototype.fillCoins = function fillCoins(tx, callback) {
  return this.tx.fillCoins(tx, callback);
};

Mempool.prototype.has =
Mempool.prototype.hasTX = function hasTX(hash, callback) {
  return this.get(hash, function(err, tx) {
    if (err)
      return callback(err);
    return callback(null, !!tx);
  });
};

Mempool.prototype.add =
Mempool.prototype.addTX = function addTX(tx, peer, callback, force) {
  var self = this;
  var hash, ts, height, now;
  var ret = {};

  var unlock = this._lock(addTX, [tx, peer, callback], force);
  if (!unlock)
    return;

  if (typeof peer === 'function') {
    callback = peer;
    peer = null;
  }

  if (!peer)
    peer = DUMMY_PEER;

  hash = tx.hash('hex');

  assert(tx.ts === 0);

  callback = utils.wrap(callback, unlock);
  callback = utils.asyncify(callback);

  if (!this.chain.segwitActive) {
    if (tx.hasWitness())
      return callback(new VerifyError('nonstandard', 'no-witness-yet', 0));
  }

  if (!this.checkTX(tx, peer))
    return callback(new VerifyError('invalid', 'CheckTransaction failed', -1));

  if (tx.isCoinbase()) {
    peer.sendReject(tx, 'invalid', 'coinbase', 100);
    return callback(new VerifyError('invalid', 'coinbase', 100));
  }

  ts = utils.now();
  height = this.chain.height + 1;

  if (this.requireStandard && !tx.isStandard(Mempool.flags, ts, height, ret)) {
    peer.sendReject(tx, 'nonstandard', ret.reason, 0);
    return callback(new VerifyError(ret.reason, 0));
  }

  this._hasTX(tx, function(err, exists) {
    if (err)
      return callback(err);

    if (exists) {
      peer.sendReject(tx, 'alreadyknown', 'txn-already-in-mempool', 0);
      return callback();
    }

    self.tx.isDoubleSpend(tx, function(err, doubleSpend) {
      if (err)
        return callback(err);

      if (doubleSpend) {
        peer.sendReject(tx, 'duplicate', 'bad-txns-inputs-spent', 0);
        return callback(new VerifyError(
          'duplicate',
          'bad-txns-inputs-spent',
          0));
      }

      self.node.fillCoins(tx, function(err) {
        if (err)
          return callback(err);

        if (!tx.hasCoins()) {
          if (self.size > Mempool.MAX_MEMPOOL_SIZE) {
            return callback(new VerifyError(
              'insufficientfee',
              'mempool full',
              0));
          }
          return self.storeOrphan(tx, callback);
        }

        self.verify(tx, function(err) {
          if (err) {
            if (err.type === 'VerifyError' && err.score >= 0)
              peer.sendReject(tx, err.code, err.reason, err.score);
            return callback(err);
          }

          self.limitMempoolSize(function(err, result) {
            if (err)
              return callback(err);

            if (!result) {
              return callback(new VerifyError(
                'insufficientfee',
                'mempool full',
                0));
            }

            self.addUnchecked(tx, peer, callback);
          });
        });
      });
    });
  });
};

Mempool.prototype.addUnchecked = function addUnchecked(tx, peer, callback) {
  var self = this;
  this.tx.addUnchecked(tx, function(err) {
    if (err)
      return callback(err);

    self.size += tx.getSize();
    self.emit('tx', tx);
    self.emit('add tx', tx);

    utils.debug('Added tx %s to the mempool.', tx.rhash);

    self.resolveOrphans(tx, function(err, resolved) {
      if (err)
        return callback(err);

      utils.forEachSerial(resolved, function(tx, next) {
        self.addUnchecked(tx, peer, function(err) {
          if (err)
            self.emit('error', err);
          next();
        }, true);
      }, callback);
    });
  });
};

Mempool.prototype.removeUnchecked = function removeUnchecked(tx, callback) {
  var self = this;
  this.tx.removeUnchecked(tx, function(err) {
    if (err)
      return callback(err);
    self.size -= tx.getSize();
    self.emit('remove tx', tx);
    return callback();
  });
};

Mempool.prototype.verify = function verify(tx, callback) {
  var self = this;
  var height = this.chain.height + 1;
  var total, input, coin, i, fee, now, free, minFee;
  var flags = Mempool.flags;
  var mandatory = Mempool.mandatory;

  if (this.chain.segwitActive) {
    flags |= constants.flags.VERIFY_WITNESS;
    mandatory |= constants.flags.VERIFY_WITNESS;
  }

  this.checkMempoolLocks(tx, flags, function(err, result) {
    if (err)
      return callback(err);

    if (!result) {
      return callback(new VerifyError(
        'nonstandard',
        'non-BIP68-final',
        0));
    }

    if (self.requireStandard && !tx.isStandardInputs(flags)) {
      return callback(new VerifyError(
        'nonstandard',
        'bad-txns-nonstandard-inputs',
        0));
    }

    if (tx.getSigops(true) > constants.tx.maxSigops) {
      return callback(new VerifyError(
        'nonstandard',
        'bad-txns-too-many-sigops',
        0));
    }

    total = new bn(0);
    for (i = 0; i < tx.inputs.length; i++) {
      input = tx.inputs[i];
      coin = input.coin;

      if (coin.coinbase) {
        if (self.chain.height - coin.height < constants.tx.coinbaseMaturity) {
          return callback(new VerifyError(
            'invalid',
            'bad-txns-premature-spend-of-coinbase',
            0));
        }
      }

      if (coin.value.cmpn(0) < 0 || coin.value.cmp(constants.maxMoney) > 0) {
        return callback(new VerifyError(
          'invalid',
          'bad-txns-inputvalues-outofrange',
          100));
      }

      total.iadd(coin.value);
    }

    if (total.cmpn(0) < 0 || total.cmp(constants.maxMoney) > 0) {
      return callback(new VerifyError(
        'invalid',
        'bad-txns-inputvalues-outofrange',
        100));
    }

    if (tx.getOutputValue().cmp(total) > 0)
      return callback(new VerifyError('invalid', 'bad-txns-in-belowout', 100));

    fee = total.sub(tx.getOutputValue());

    if (fee.cmpn(0) < 0)
      return callback(new VerifyError('invalid', 'bad-txns-fee-negative', 100));

    if (fee.cmp(constants.maxMoney) > 0) {
      return callback(new VerifyError(
        'invalid',
        'bad-txns-fee-outofrange',
        100));
    }

    minFee = tx.getMinFee();
    if (fee.cmp(minFee) < 0) {
      if (self.relayPriority && fee.cmpn(0) === 0) {
        free = tx.isFree(height);
        if (!free) {
          return callback(new VerifyError(
            'insufficientfee',
            'insufficient priority',
            0));
        }
      } else {
        return callback(new VerifyError(
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
        return callback(new VerifyError(
          'insufficientfee',
          'rate limited free transaction',
          0));
      }

      self.freeCount += tx.getSize();
    }

    if (self.rejectInsaneFees && fee.cmp(minFee.muln(10000)) > 0)
      return callback(new VerifyError('highfee', 'absurdly-high-fee', 0));

    self.countAncestors(tx, function(err, count) {
      if (err)
        return callback(err);

      if (count > Mempool.ANCESTOR_LIMIT) {
        return callback(new VerifyError(
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
              return callback(new VerifyError(
                'nonstandard',
                'non-mandatory-script-verify-flag',
                0));
            }

            return callback(new VerifyError(
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
  var inputs = new Array(tx.inputs.length);
  utils.forEachSerial(tx.inputs, function(input, next, i) {
    inputs[i] = 0;
    self.getTX(input.prevout.hash, function(err, tx) {
      if (err)
        return next(err);

      if (!tx)
        return next();

      inputs[i] += 1;

      self.countAncestors(tx, function(err, max) {
        if (err)
          return next(err);

        inputs[i] += max;

        next();
      });
    });
  }, function(err) {
    if (err)
      return callback(err);

    return callback(null, inputs.sort().pop());
  });
};

Mempool.prototype._hasTX = function hasTX(tx, callback, force) {
  var self = this;
  var hash = tx.hash('hex');

  this.node.hasTX(hash, function(err, result) {
    if (err)
      return callback(err);

    if (result)
      return callback(null, result);

    self.db.get('m/D/' + hash, function(err, tx) {
      if (err && err.type !== 'NotFoundError')
        return callback(err);

      return callback(null, !!tx);
    });
  });
};

Mempool.prototype.storeOrphan = function storeOrphan(tx, callback, force) {
  var self = this;
  var outputs = {};
  var batch = this.db.batch();
  var hash = tx.hash('hex');
  var i, input, p;

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    if (!input.coin)
      outputs[input.prevout.hash] = true;
  }

  outputs = Object.keys(outputs);

  assert(outputs.length > 0);

  utils.forEachSerial(outputs, function(key, next) {
    self.db.get('m/d/' + key, function(err, buf) {
      if (err && err.type !== 'NotFoundError')
        return next(err);

      p = new BufferWriter();

      if (buf)
        p.writeBytes(buf);

      p.writeHash(hash);

      batch.put('m/d/' + key, p.render());

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

Mempool.prototype.resolveOrphans = function resolveOrphans(tx, callback, force) {
  var self = this;
  var hash = tx.hash('hex');
  var hashes = [];
  var resolved = [];
  var batch = this.db.batch();
  var p;

  this.db.get('m/d/' + hash, function(err, buf) {
    if (err && err.type !== 'NotFoundError')
      return callback(err);

    if (!buf)
      return callback(null, resolved);

    p = new BufferReader(buf);

    p.start();

    try {
      while (p.left())
        hashes.push(p.readHash('hex'));
    } catch (e) {
      return callback(e);
    }

    p.end();

    utils.forEachSerial(hashes, function(orphanHash, next, i) {
      self.db.get('m/D/' + orphanHash, function(err, orphan) {
        if (err && err.type !== 'NotFoundError')
          return next(err);

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
          self.orphans--;
          batch.del('m/D/' + orphanHash);
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

Mempool.prototype.getSnapshot = function getSnapshot(callback) {
  return this.tx.getAllHashes(callback);
};

Mempool.prototype.checkTX = function checkTX(tx, peer) {
  return Mempool.checkTX(tx, peer);
};

Mempool.checkTX = function checkTX(tx, peer) {
  var uniq = {};
  var total = new bn(0);
  var i, input, output, size;

  if (!peer)
    peer = DUMMY_PEER;

  if (tx.inputs.length === 0)
    return peer.sendReject(tx, 'invalid', 'bad-txns-vin-empty', 100);

  if (tx.outputs.length === 0)
    return peer.sendReject(tx, 'invalid', 'bad-txns-vout-empty', 100);

  if (tx.getVirtualSize() > constants.block.maxSize)
    return peer.sendReject(tx, 'invalid', 'bad-txns-oversize', 100);

  for (i = 0; i < tx.outputs.length; i++) {
    output = tx.outputs[i];

    if (output.value.cmpn(0) < 0)
      return peer.sendReject(tx, 'invalid', 'bad-txns-vout-negative', 100);

    if (output.value.cmp(constants.maxMoney) > 0)
      return peer.sendReject(tx, 'invalid', 'bad-txns-vout-toolarge', 100);

    total.iadd(output.value);

    if (total.cmpn(0) < 0 || total.cmp(constants.maxMoney) > 0) {
      return peer.sendReject(tx,
        'invalid',
        'bad-txns-txouttotal-toolarge',
        100);
    }
  }

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    if (uniq[input.prevout.hash])
      return peer.sendReject(tx, 'invalid', 'bad-txns-inputs-duplicate', 100);
    uniq[input.prevout.hash] = true;
  }

  if (tx.isCoinbase()) {
    size = tx.inputs[0].script.getSize();
    if (size < 2 || size > 100)
      return peer.sendReject(tx, 'invalid', 'bad-cb-length', 100);
  } else {
    for (i = 0; i < tx.inputs.length; i++) {
      input = tx.inputs[i];
      if (+input.prevout.hash === 0)
        return peer.sendReject(tx, 'invalid', 'bad-txns-prevout-null', 10);
    }
  }

  return true;
};

Mempool.prototype.getLocks = function getLocks(tx, flags, entry, callback) {
  var self = this;
  var mask = constants.sequenceLocktimeMask
  var granularity = constants.sequenceLocktimeGranularity;
  var disableFlag = constants.sequenceLocktimeDisableFlag;
  var typeFlag = constants.sequenceLocktimeTypeFlag;
  var hasFlag = flags & constants.flags.VERIFY_CHECKSEQUENCEVERIFY;
  var minHeight = -1;
  var minTime = -1;
  var coinHeight;

  if ((tx.version >>> 0) < 2 || !hasFlag)
    return utils.asyncify(callback)(null, minHeight, minTime);

  utils.forEachSerial(tx.inputs, function(input, next) {
    if (input.sequence & disableFlag)
      return next();

    coinHeight = coin.height === -1
      ? self.chain.tip + 1
      : coin.height;

    if ((input.sequence & typeFlag) === 0) {
      coinHeight += (input.sequence & mask) - 1;
      minHeight = Math.max(minHeight, coinHeight);
      return next();
    }

    entry.getAncestorByHeight(Math.max(coinHeight - 1, 0), function(err, entry) {
      if (err)
        return next(err);

      assert(entry, 'Database is corrupt.');

      entry.getMedianTimeAsync(function(err, coinTime) {
        if (err)
          return next(err);

        coinTime += ((input.sequence & mask) << granularity) - 1;
        minTime = Math.max(minTime, coinTime);

        next();
      });
    });
  }, function(err) {
    if (err)
      return callback(err);
    return callback(null, minHeight, minTime);
  });
};

Mempool.prototype.evalLocks = function evalLocks(entry, minHeight, minTime, callback) {
  if (minHeight >= entry.height)
    return utils.asyncify(callback)(null, false);

  if (minTime === -1)
    return utils.asyncify(callback)(null, true);

  entry.getMedianTimeAsync(function(err, medianTime) {
    if (err)
      return callback(err);

    if (minTime >= medianTime)
      return callback(null, false);

    return callback(null, true);
  });
}

Mempool.prototype.checkLocks = function checkLocks(tx, flags, entry, callback) {
  var self = this;
  this.getLocks(tx, flags, entry, function(err, minHeight, minTime) {
    if (err)
      return callback(err);

    self.evalLocks(entry, minHeight, minTime, callback);
  });
}

Mempool.prototype.checkMempoolLocks = function checkMempoolLocks(tx, flags, callback) {
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

  this.checkLocks(tx, flags, index, callback);
}

/**
 * VerifyError
 */

function VerifyError(code, reason, score) {
  Error.call(this);
  if (Error.captureStackTrace)
    Error.captureStackTrace(this, VerifyError);
  this.type = 'VerifyError';
  this.code = code;
  this.message = reason;
  this.reason = score === -1 ? null : reason;
  this.score = score;
}

utils.inherits(VerifyError, Error);

/**
 * Expose
 */

module.exports = Mempool;
