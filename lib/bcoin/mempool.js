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
  // this.db = node.chain.db.db;

  this.db = bcoin.ldb('mempool', {
    db: 'memdown'
  });

  this.tx = new bcoin.txdb('m', this.db, {
    indexSpent: true,
    indexExtra: false,
    indexAddress: false,
    mapAddress: false,
    verify: false
  });

  this.loaded = false;

  this.jobs = [];
  this.busy = false;

  this.pending = [];
  this.pendingTX = {};
  this.pendingSize = 0;
  this.pendingLimit = 20 << 20;
  this.locker = new bcoin.locker(this, this.add, this.pendingLimit);

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

Mempool.flags = constants.flags.STANDARD_VERIFY_FLAGS;
Mempool.mandatory = constants.flags.MANDATORY_VERIFY_FLAGS;

Mempool.prototype._lock = function _lock(func, args, force) {
  return this.locker.lock(func, args, force);
};

Mempool.prototype.purgePending = function purgePending() {
  return this.locker.purgePending();
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

Mempool.prototype.addBlock = function addBlock(block, callback) {
  var self = this;
  callback = utils.ensure(callback);
  // Remove now-mined transactions
  // XXX should batch this
  utils.forEachSerial(block.txs, function(tx, next) {
    self.tx.remove(tx, next);
  }, callback);
};

Mempool.prototype.removeBlock = function removeBlock(block, callback) {
  var self = this;
  callback = utils.ensure(callback);
  // XXX should batch this
  utils.forEachSerial(block.txs.slice().reverse(), function(tx, next) {
    self.tx.add(tx, next);
  }, callback);
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

  if (!this.checkTX(tx, peer))
    return callback(new VerifyError('CheckTransaction failed', -1));

  if (tx.isCoinbase()) {
    peer.sendReject(tx, 'coinbase', 100);
    return callback(new VerifyError('coinbase as individual tx', 100));
  }

  ts = utils.now();
  height = this.chain.height + 1;

  if (this.requireStandard && !tx.isStandard(Mempool.flags, ts, height, ret)) {
    peer.sendReject(tx, ret.reason, 0);
    return callback(new VerifyError(ret.reason, 0));
  }

  this._hasTX(tx, function(err, exists) {
    if (err)
      return callback(err);

    if (exists)
      return callback();

    self.node.fillCoin(tx, function(err) {
      if (err)
        return callback(err);

      if (!tx.hasPrevout()) {
        return self.tx.isDoubleSpend(tx, function(err, result) {
          if (err)
            return callback(err);

          if (result) {
            peer.sendReject(tx, 'bad-txns-inputs-spent', 0);
            return callback(new VerifyError('bad-txns-inputs-spent', 0));
          }

          return self.storeOrphan(tx, callback);
        });
      }

      self.verify(tx, function(err) {
        if (err) {
          if (err.type === 'VerifyError' && err.score >= 0)
            peer.sendReject(tx, err.reason, err.score);
          return callback(err);
        }

        self.addUnchecked(tx, peer, callback);
      });
    });
  });
};

Mempool.prototype.addUnchecked = function addUnchecked(tx, peer, callback) {
  var self = this;
  self.tx.add(tx, function(err) {
    if (err)
      return callback(err);

    self.emit('tx', tx);

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

Mempool.prototype.verify = function verify(tx, callback) {
  var self = this;
  var total, input, coin, i, fee, now;

  if (this.requireStandard && !tx.isStandardInputs(Mempool.flags))
    return callback(new VerifyError('TX inputs are not standard.', -1));

  if (tx.getSigops(true) > constants.script.maxSigops)
    return callback(new VerifyError('bad-txns-too-many-sigops', 0));

  total = new bn(0);
  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    coin = input.output;

    if (coin.coinbase) {
      if (this.chain.height - coin.height < constants.tx.coinbaseMaturity)
        return callback(new VerifyError('bad-txns-premature-spend-of-coinbase', 0));
    }

    if (coin.value.cmpn(0) < 0 || coin.value.cmp(constants.maxMoney) > 0)
      return callback(new VerifyError('bad-txns-inputvalues-outofrange', 100));

    total.iadd(coin.value);
  }

  if (total.cmpn(0) < 0 || total.cmp(constants.maxMoney) > 0)
    return callback(new VerifyError('bad-txns-inputvalues-outofrange', 100));

  if (tx.getOutputValue().cmp(total) > 0)
    return callback(new VerifyError('bad-txns-in-belowout', 100));

  fee = total.sub(tx.getOutputValue());

  if (fee.cmpn(0) < 0)
    return callback(new VerifyError('bad-txns-fee-negative', 100));

  if (fee.cmp(constants.maxMoney) > 0)
    return callback(new VerifyError('bad-txns-fee-outofrange', 100));

  if (this.limitFree && fee.cmp(tx.getMinFee(true)) < 0)
    return callback(new VerifyError('insufficient fee', 0));

  if (this.limitFree && fee.cmpn(tx.getMinFee()) < 0) {
    now = utils.now();

    if (!this.lastTime)
      this.lastTime = now;

    this.freeCount *= Math.pow(1 - 1 / 600, now - this.lastTime);
    this.lastTime = now;

    if (this.freeCount > this.limitFreeRelay * 10 * 1000)
      return callback(new VerifyError('insufficient priority', 0));

    this.freeCount += tx.getVirtualSize();
  }

  if (this.rejectInsaneFees && fee.cmpn(tx.getMinFee().muln(10000)) > 0)
    return callback(new VerifyError('TX has an insane fee.', -1));

  // Do this in the worker pool.
  tx.verifyAsync(null, true, Mempool.flags, function(err, result) {
    if (err)
      return callback(err);

    if (!result) {
      return tx.verifyAsync(null, true, Mempool.mandatory, function(err, result) {
        if (err)
          return callback(err);

        if (!result)
          return callback(new VerifyError('mandatory-script-verify-flag', 0));

        return callback(new VerifyError('non-mandatory-script-verify-flag', 0));
      });
    }

    return callback();
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

    self.db.get('D/' + hash, function(err, tx) {
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
    if (!input.output)
      outputs[input.prevout.hash] = true;
  }

  outputs = Object.keys(outputs);

  assert(outputs.length > 0);

  utils.forEachSerial(outputs, function(key, next) {
    self.db.get('d/' + key, function(err, buf) {
      if (err && err.type !== 'NotFoundError')
        return next(err);

      p = new BufferWriter();

      if (buf)
        p.writeBytes(buf);

      p.writeHash(hash);

      batch.put('d/' + key, p.render());

      next();
    });
  }, function(err) {
    if (err)
      return callback(err);

    batch.put('D/' + hash, tx.toExtended(true));
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

  this.db.get('d/' + hash, function(err, buf) {
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
      self.db.get('D/' + orphanHash, function(err, orphan) {
        if (err && err.type !== 'NotFoundError')
          return next(err);

        if (!orphan)
          return next();

        try {
          orphan = bcoin.tx.fromExtended(orphan, true);
        } catch (e) {
          return next(e);
        }

        orphan.fillPrevout(tx);

        if (orphan.hasPrevout()) {
          batch.del('D/' + orphanHash);
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

        batch.put('D/' + orphanHash, orphan.toExtended(true));
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

      batch.del('d/' + hash);

      return batch.write(done);
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
    if (hash instanceof bcoin.tx)
      return callback(null, hash);

    return self.getTX(hash, function(err, tx) {
      if (err)
        return callback(err);
      if (!tx)
        return callback();
      return self.node.fillTX(tx, callback);
    });
  }

  return getTX(function(err, tx) {
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
  return Mempool.checkTX(tx, peer);
};

Mempool.checkTX = function checkTX(tx, peer) {
  var i, input, output, size;
  var total = new bn(0);
  var uniq = {};

  if (!peer)
    peer = DUMMY_PEER;

  if (tx.inputs.length === 0)
    return peer.sendReject(tx, 'bad-txns-vin-empty', 100);

  if (tx.outputs.length === 0)
    return peer.sendReject(tx, 'bad-txns-vout-empty', 100);

  if (tx.getVirtualSize() > constants.block.maxSize)
    return peer.sendReject(tx, 'bad-txns-oversize', 100);

  for (i = 0; i < tx.outputs.length; i++) {
    output = tx.outputs[i];
    if (output.value.cmpn(0) < 0)
      return peer.sendReject(tx, 'bad-txns-vout-negative', 100);
    if (output.value.cmp(constants.maxMoney) > 0)
      return peer.sendReject(tx, 'bad-txns-vout-toolarge', 100);
    total.iadd(output.value);
    if (total.cmpn(0) < 0 || total.cmp(constants.maxMoney) > 0)
      return peer.sendReject(tx, 'bad-txns-txouttotal-toolarge', 100);
  }

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    if (uniq[input.prevout.hash])
      return peer.sendReject(tx, 'bad-txns-inputs-duplicate', 100);
    uniq[input.prevout.hash] = true;
  }

  if (tx.isCoinbase()) {
    size = tx.inputs[0].script.getSize();
    if (size < 2 || size > 100)
      return peer.sendReject(tx, 'bad-cb-length', 100);
  } else {
    for (i = 0; i < tx.inputs.length; i++) {
      input = tx.inputs[i];
      if (+input.prevout.hash === 0)
        return peer.sendReject(tx, 'bad-txns-prevout-null', 10);
    }
  }

  return true;
};

function VerifyError(reason, score) {
  Error.call(this);
  if (Error.captureStackTrace)
    Error.captureStackTrace(this, VerifyError);
  this.type = 'VerifyError';
  this.message = reason;
  this.reason = score === -1 ? null : reason;
  this.score = score;
}

utils.inherits(VerifyError, Error);

/**
 * Expose
 */

module.exports = Mempool;
