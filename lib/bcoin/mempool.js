/**
 * mempool.js - mempool for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var EventEmitter = require('events').EventEmitter;

var bcoin = require('../bcoin');
var bn = require('bn.js');
var constants = bcoin.protocol.constants;
var utils = require('./utils');
var assert = utils.assert;

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
  this.db = node.chain.db;
  this.tx = new bcoin.txdb('m', this.db, {
    indexSpent: true,
    indexExtra: false,
    indexAddress: false,
    mapAddress: false
  });

  this.txs = {};
  this.spent = {};
  this.addresses = {};
  this.size = 0;
  this.count = 0;
  this.locked = false;
  this.loaded = false;
  this.jobs = [];
  this.busy = false;
  this.pending = [];
  this.pendingTX = {};
  this.pendingSize = 0;
  this.pendingLimit = 20 << 20;
  this.freeCount = 0;
  this.lastTime = 0;
  this.limitFreeRelay = this.options.limitFreeRelay || 15;
  this.requireStandard = this.options.requireStandard !== false;
  this.limitFree = this.options.limitFree !== false;
  this.rejectInsaneFees = this.options.rejectInsaneFees !== false;

  Mempool.global = this;

  this._init();
}

utils.inherits(Mempool, EventEmitter);

Mempool.prototype._lock = function _lock(func, args, force) {
  var self = this;
  var block, called;

  if (force) {
    assert(this.busy);
    return function unlock() {
      assert(!called);
      called = true;
    };
  }

  if (this.busy) {
    if (func === Mempool.prototype.add) {
      tx = args[0];
      this.pending.push(tx);
      this.pendingTX[tx.hash('hex')] = true;
      this.pendingSize += tx.getSize();
      if (this.pendingSize > this.pendingLimit) {
        this.purgePending();
        return;
      }
    }
    this.jobs.push([func, args]);
    return;
  }

  this.busy = true;

  return function unlock() {
    var item, tx;

    assert(!called);
    called = true;

    self.busy = false;

    if (func === Chain.prototype.add) {
      if (self.pending.length === 0)
        self.emit('flush');
    }

    if (self.jobs.length === 0)
      return;

    item = self.jobs.shift();

    if (item[0] === Mempool.prototype.add) {
      tx = item[1][0];
      assert(tx === self.pending.shift());
      delete self.pendingTX[tx.hash('hex')];
      self.pendingSize -= tx.getSize();
    }

    item[0].apply(self, item[1]);
  };
};

Mempool.prototype.purgePending = function purgePending() {
  var self = this;

  utils.debug('Warning: %dmb of pending txs. Purging.',
    utils.mb(this.pendingSize));

  this.pending.forEach(function(tx) {
    delete self.pendingTX[tx.hash('hex')];
  });

  this.pending.length = 0;
  this.pendingSize = 0;

  this.jobs = this.jobs.filter(function(item) {
    return item[0] !== Mempool.prototype.add;
  });
};

Mempool.prototype._init = function _init() {
  var self = this;

  if (this.db.loaded) {
    this.loaded = true;
    return;
  }

  this.db.once('open', function() {
    self.loaded = true;
    self.emit('open');
  });
};

Mempool.prototype.open = function open(callback) {
  return this.db.open(callback);
};

Mempool.prototype.addBlock = function addBlock(block) {
  var self = this;
  callback = utils.ensure(callback);
  // Remove now-mined transactions
  // XXX should batch this
  utils.forEachSerial(block.txs.slice().reverse(), function(tx, next) {
    self.tx.remove(tx, next);
  }, callback);
};

Mempool.prototype.removeBlock = function removeBlock(block, callback) {
  var self = this;
  callback = utils.ensure(callback);
  // XXX should batch this
  utils.forEachSerial(block.txs, function(tx, next) {
    self.tx.add(tx, next);
  }, callback);
};

Mempool.prototype.get =
Mempool.prototype.getTX = function getTX(hash, callback) {
  if (hash instanceof bcoin.tx)
    hash = hash.hash('hex');
  return this.tx.getTX(hash, index, callback);
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
Mempool.prototype.getTXByAddress = function getTXByAddress(addresses) {
  return this.tx.getTXByAddress(addresses, callback);
};

Mempool.prototype.fillTX = function fillTX(tx, callback) {
  return this.tx.fillTX(tx, callback);
};

Mempool.prototype.fillCoin = function fillCoin(tx, callback) {
  return this.tx.fillCoin(tx, callback);
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
  var flags = constants.flags.STANDARD_VERIFY_FLAGS;
  var hash, ts, height, now;
  var ret = {};

  var unlock = this._lock(addTX, [tx, peer, callback], force);
  if (!unlock)
    return;

  hash = tx.hash('hex');

  assert(tx.ts === 0);

  callback = utils.wrap(callback, unlock);
  callback = utils.asyncify(callback);

  if (!this.checkTX(tx, peer))
    return callback(new Error('CheckTransaction failed'));

  if (tx.isCoinbase()) {
    this.reject(peer, tx, 'coinbase', 100);
    return callback(new Error('coinbase as individual tx'));
  }

  ts = utils.now();
  height = this.chain.height + 1;

  if (self.requireStandard && !tx.isStandard(flags, ts, height, ret)) {
    self.reject(peer, tx, ret.reason, 0);
    return callback(new Error('TX is not standard.'));
  }

  this.node.hasTX(tx, function(err, exists) {
    if (err)
      return callback(err);

    if (exists)
      return callback();

    self.node.fillCoin(tx, function(err) {
      var i, input, output, total, fee, coin;

      if (err)
        return callback(err);

      if (!tx.hasPrevout()) {
        // Store as orphan:
        // return self.tx.add(tx, callback);
        return callback(new Error('No prevouts yet.'));
      }

      if (self.requireStandard && !tx.isStandardInputs(flags))
        return callback(new Error('TX inputs are not standard.'));

      if (tx.getSigops(true) > constants.script.maxSigops) {
        self.reject(peer, tx, 'bad-txns-too-many-sigops', 0);
        return callback(new Error('TX has too many sigops.'));
      }

      total = new bn(0);
      for (i = 0; i < tx.inputs.length; i++) {
        input = tx.inputs[i];
        coin = input.coin;

        if (coin.isCoinbase()) {
          if (self.chain.height - coin.height < constants.tx.coinbaseMaturity) {
            self.reject(peer, tx, 'bad-txns-premature-spend-of-coinbase', 0);
            return callback(new Error('Tried to spend coinbase prematurely.'));
          }
        }

        if (coin.value.cmpn(0) < 0 || coin.value.cmp(constants.maxMoney) > 0)
          return self.reject(peer, tx, 'bad-txns-inputvalues-outofrange', 100);

        total.iadd(coin.value);
      }

      if (total.cmpn(0) < 0 || total.cmp(constants.maxMoney) > 0)
        return self.reject(peer, tx, 'bad-txns-inputvalues-outofrange', 100);

      if (tx.getOutputValue().cmp(total) > 0) {
        self.reject(peer, tx, 'bad-txns-in-belowout', 100);
        return callback(new Error('TX is spending coins it does not have.'));
      }

      fee = total.subn(tx.getOutputValue());

      if (fee.cmpn(0) < 0) {
        self.reject(peer, tx, 'bad-txns-fee-negative', 100);
        return callback(new Error('TX has a negative fee.'));
      }

      if (fee.cmp(constants.maxMoney) > 0) {
        return self.reject(peer, tx, 'bad-txns-fee-outofrange', 100);
        return callback(new Error('TX has a fee higher than max money.'));
      }

      if (self.limitFree && fee.cmp(tx.getMinFee(true)) < 0) {
        self.reject(peer, tx, 'insufficient fee', 0);
        return callback(new Error('Insufficient fee.'));
      }

      if (self.limitFree && fee.cmpn(tx.getMinFee()) < 0) {
        now = utils.now();

        if (!self.lastTime)
          self.lastTime = now;

        self.freeCount *= Math.pow(1 - 1 / 600, now - self.lastTime);
        self.lastTime = now;

        if (self.freeCount > self.limitFreeRelay * 10 * 1000) {
          self.reject(peer, tx, 'insufficient priority', 0);
          return callback(new Error('Too many free txs at once!'));
        }

        self.freeCount += tx.getVirtualSize();
      }

      if (self.rejectInsaneFees && fee.cmpn(tx.getMinFee().muln(10000)) > 0)
        return callback(new Error('TX has an insane fee.'));

      // Do this in the worker pool.
      tx.verifyAsync(null, true, flags, function(err, result) {
        if (err)
          return callback(err);

        if (!result) {
          // Just say it's non-mandatory for now.
          self.reject(peer, tx, 'non-mandatory-script-verify-flag', 0);
          return callback(new Error('TX did not verify.'));
        }

        self.tx.add(tx, function(err) {
          if (err) {
            if (err.message === 'Transaction is double-spending.') {
              self.reject(peer, tx, 'bad-txns-inputs-spent', 0);
            }
            return callback(err);
          }

          self.emit('tx', tx);

          return callback();
        });
      });
    });
  });
};

Mempool.prototype.getInv = function getInv(callback) {
  return this.tx.getAllHashes(callback);
};

Mempool.prototype.remove =
Mempool.prototype.removeTX = function removeTX(hash, callback, force) {
  var self = this;

  var unlock = this._lock(removeTX, [hash, callback], force);
  if (!unlock)
    return;

  function getTX() {
    if (hash.hash) {
      hash = hash.hash('hex');
      return self.getTX(hash, function(err, tx) {
        if (err)
          return callback(err);
        if (!tx)
          return callback();
        return self.node.fillTX(hash, callback);
      });
    }
    return callback(null, hash);
  }

  getTX(function(err, tx) {
    if (err)
      return callback(err);

    self.tx.remove(tx, function(err) {
      if (err)
        return callback(err);

      self.emit('remove tx', tx);
    });
  });
};

Mempool.prototype.checkTX = function checkTX(tx, peer) {
  var i, input, output, size;
  var total = new bn(0);
  var uniq = {};

  if (tx.inputs.length === 0)
    return this.reject(peer, tx, 'bad-txns-vin-empty', 100);

  if (tx.outputs.length === 0)
    return this.reject(peer, tx, 'bad-txns-vout-empty', 100);

  if (tx.getSize() > constants.block.maxSize)
    return this.reject(peer, tx, 'bad-txns-oversize', 100);

  for (i = 0; i < tx.outputs.length; i++) {
    output = tx.outputs[i];
    if (output.value.cmpn(0) < 0)
      return this.reject(peer, tx, 'bad-txns-vout-negative', 100);
    if (output.value.cmp(constants.maxMoney) > 0)
      return this.reject(peer, tx, 'bad-txns-vout-toolarge', 100);
    total.iadd(output.value);
    if (total.cmpn(0) < 0 || total.cmp(constants.maxMoney))
      return this.reject(peer, tx, 'bad-txns-txouttotal-toolarge', 100);
  }

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    if (uniq[input.out.hash])
      return this.reject(peer, tx, 'bad-txns-inputs-duplicate', 100);
    uniq[input.out.hash] = true;
  }

  if (tx.isCoinbase()) {
    size = bcoin.script.getSize(tx.inputs[0].script);
    if (size < 2 || size > 100)
      return this.reject(peer, tx, 'bad-cb-length', 100);
  } else {
    for (i = 0; i < tx.inputs.length; i++) {
      input = tx.inputs[i];
      if (+input.out.hash === 0)
        return this.reject(peer, tx, 'bad-txns-prevout-null', 10);
    }
  }

  return true;
};

Mempool.prototype.reject = function reject(peer, obj, reason, dos) {
  utils.debug('Rejecting TX %s. Reason=%s.', obj.hash('hex'), reason);

  if (dos != null)
    this.node.pool.setMisbehavior(peer, dos);

  if (!peer)
    return false;

  // peer.reject({
  //   reason: reason,
  //   data: obj.hash ? obj.hash() : []
  // });

  return false;
};

/**
 * Expose
 */

module.exports = Mempool;
