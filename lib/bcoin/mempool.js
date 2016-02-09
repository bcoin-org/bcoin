/**
 * mempool.js - mempool for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var inherits = require('inherits');
var EventEmitter = require('events').EventEmitter;

var bcoin = require('../bcoin');
var bn = require('bn.js');
var constants = bcoin.protocol.constants;
var network = bcoin.protocol.network;
var utils = bcoin.utils;
var assert = utils.assert;
var fs = bcoin.fs;

/**
 * Mempool
 */

function Mempool(pool, options) {
  if (!(this instanceof Mempool))
    return new Mempool(pool, options);

  if (!options)
    options = {};

  this.options = options;
  this.pool = pool;
  this.storage = bcoin.db;

  this.txs = {};
  this.prevout = {};
  this.size = 0;
  this.count = 0;
  this.locked = false;

  this._init();
}

Mempool.prototype._init = function _init() {
  var self = this;

  // Remove now-mined transactions
  this.pool.on('block', function(block) {
    block.txs.forEach(function(tx) {
      var mtx = self.get(tx);
      if (!mtx)
        return;

      mtx.ps = 0;
      mtx.ts = block.ts;
      mtx.block = block.hash('hex');

      self.remove(mtx);
    });
  });
};

Mempool.prototype.get = function get(hash) {
  if (hash instanceof bcoin.tx)
    hash = hash.hash('hex');
  return this.txs[hash];
};

Mempool.prototype.getAll = function getAll(hash) {
  return Object.keys(this.txs).map(function(key) {
    return this.txs[key];
  }, this);
};

Mempool.prototype.has = function has(hash) {
  return !!this.get(hash);
};

Mempool.prototype.add = function add(tx, peer, callback) {
  var self = this;
  var hash = tx.hash('hex');

  assert(tx.ts === 0);

  callback = utils.asyncify(callback);

  if (this.locked)
    return callback(new Error('Mempool is locked.'));

  if (this.count >= 50000)
    return callback(new Error('Mempool is full.'));

  if (this.size >= 20 * 1024 * 1024)
    return callback(new Error('Mempool is full.'));

  if (this.txs[hash])
    return callback(new Error('Already have TX.'));

  this._lockTX(tx);

  this.storage.fillTX(tx, function(err) {
    var i, input, dup, height, ts, priority;

    self._unlockTX(tx);

    if (err)
      return callback(err);

    if (!tx.hasPrevout()) {
      peer.reject({
        data: tx.hash(),
        reason: 'no-prevout'
      });
      pool.setMisbehavior(peer, 100);
      return callback(new Error('Previous outputs not found.'));
    }

    if (!tx.isStandard()) {
      peer.reject({
        data: tx.hash(),
        reason: 'non-standard'
      });
      pool.setMisbehavior(peer, 100);
      return callback(new Error('TX is not standard.'));
    }

    if (!tx.isStandardInputs()) {
      peer.reject({
        data: tx.hash(),
        reason: 'non-standard-inputs'
      });
      pool.setMisbehavior(peer, 100);
      return callback(new Error('TX inputs are not standard.'));
    }

    if (tx.getOutputValue().cmp(tx.getInputValue()) > 0) {
      peer.reject({
        data: tx.hash(),
        reason: 'nonexistent-coins'
      });
      pool.setMisbehavior(peer, 100);
      return callback(new Error('TX is spending coins that it does not have.'));
    }

    height = self.pool.chain.height() + 1;
    ts = utils.now();
    if (!tx.isFinal(height, ts)) {
      peer.reject({
        data: tx.hash(),
        reason: 'not-final'
      });
      pool.setMisbehavior(peer, 100);
      return callback(new Error('TX is not final.'));
    }

    for (i = 0; i < tx.inputs.length; i++) {
      input = tx.inputs[i];
      if (input.output.spent) {
        peer.reject({
          data: tx.hash(),
          reason: 'old-outputs'
        });
        pool.setMisbehavior(peer, 100);
        return callback(new Error('TX is spending old outputs.'));
      }
      dup = self.prevout[input.prevout.hash];
      if (dup) {
        // Replace-by-fee
        if (input.sequence === 0xffffffff - 1) {
          if (dup.getFee().cmp(tx.getFee()) < 0) {
            self.remove(dup);
            continue;
          }
        }
        peer.reject({
          data: tx.hash(),
          reason: 'double-spend'
        });
        pool.setMisbehavior(peer, 100);
        return callback(new Error('TX is double spending.'));
      }
    }

    for (i = 0; i < tx.outputs.length; i++) {
      output = tx.outputs[i];
      if (output.value.cmpn(0) < 0) {
        peer.reject({
          data: tx.hash(),
          reason: 'negative-value'
        });
        pool.setMisbehavior(peer, 100);
        return callback(new Error('TX is spending negative coins.'));
      }
    }

    if (!tx.verify(true)) {
      peer.reject({
        data: tx.hash(),
        reason: 'script-failed'
      });
      pool.setMisbehavior(peer, 100);
      return callback(new Error('TX did not verify.'));
    }

    for (i = 0; i < tx.inputs.length; i++) {
      input = tx.inputs[i];
      self.prevout[input.prevout.hash] = tx;
    }

    // Possibly do something bitcoinxt-like here with priority
    priority = tx.getPriority();

    self.txs[hash] = tx;
    self.count++;
    self.size += tx.getSize();

    self.storage.saveMempoolTX(tx, function(err) {
      if (err)
        return callback(err);

      return callback();
    });
  });
};

// Lock a tx to prevent race conditions
Mempool.prototype._lockTX = function _lockTX(tx) {
  var hash = tx.hash('hex');
  var i, input;

  if (!this.txs[hash])
    this.txs[hash] = tx;

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    if (!this.prevout[input.prevout.hash])
      this.prevout[input.prevout.hash] = tx;
  }
};

Mempool.prototype._unlockTX = function _unlockTX(tx) {
  var hash = tx.hash('hex');
  var i, input;

  if (this.txs[hash] === tx)
    delete this.txs[hash];

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    if (this.prevout[input.prevout.hash] === tx)
      delete this.prevout[input.prevout.hash];
  }
};

Mempool.prototype.remove = function remove(hash, callback) {
  var self = this;
  var tx, input;

  callback = utils.asyncify(callback);

  if (hash instanceof bcoin.tx)
    hash = hash.hash('hex');

  tx = this.txs[hash];

  if (!tx)
    return callback(new Error('TX does not exist in mempool.'));

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    if (this.prevout[input.prevout.hash] === tx)
      delete this.prevout[input.prevout.hash];
  }

  delete this.txs[hash];

  this.count--;
  this.size -= tx.getSize();

  this.storage.removeMempoolTX(tx, function(err) {
    if (err)
      return callback(err);

    return callback();
  });
};

// Need to lock the mempool when
// downloading a new block.
Mempool.prototype.lock = function lock() {
  this.locked = true;
};

Mempool.prototype.unlock = function unlock() {
  this.locked = false;
};

/**
 * Expose
 */

module.exports = Mempool;
