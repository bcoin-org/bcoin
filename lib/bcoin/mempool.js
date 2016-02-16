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

function Mempool(node, options) {
  if (!(this instanceof Mempool))
    return new Mempool(pool, options);

  if (!options)
    options = {};

  this.options = options;
  this.node = node;
  this.pool = node.pool;
  this.block = node.block;

  this.txs = {};
  this.spent = {};
  this.addresses = {};
  this.size = 0;
  this.count = 0;
  this.locked = false;

  this._init();
}

inherits(Mempool, EventEmitter);

Mempool.prototype._init = function _init() {
  ;
};

Mempool.prototype.addBlock = function addBlock(block) {
  var self = this;
  // Remove now-mined transactions
  block.txs.forEach(function(tx) {
    var mtx = self.get(tx);
    if (!mtx)
      return;

    mtx.ps = 0;
    mtx.ts = block.ts;
    mtx.block = block.hash('hex');
    mtx.network = true;

    self.removeTX(mtx);
  });
};

Mempool.prototype.removeBlock = function removeBlock(block) {
  var self = this;
  block.txs.forEach(function(tx) {
    var hash = tx.hash('hex');
    // Remove anything that tries to redeem these outputs
    tx.outputs.forEach(function(output, i) {
      var mtx = self.spent[hash + '/' + i];
      if (!mtx)
        return;

      self.removeTX(mtx);
    });
  });
};

Mempool.prototype.get =
Mempool.prototype.getTX = function getTX(hash) {
  if (hash instanceof bcoin.tx)
    hash = hash.hash('hex');
  return this.txs[hash];
};

Mempool.prototype.getCoin = function getCoin(hash, index) {
  var tx = this.get(hash);
  if (!tx)
    return;

  return bcoin.coin(tx, index);
};

Mempool.prototype.isSpent = function isSpent(hash, index) {
  return !!this.spent[hash + '/' + index];
};

Mempool.prototype.getCoinsByAddress = function getCoinsByAddress(addresses) {
  var txs = this.getByAddress(addresses);
  return txs.reduce(function(out, tx) {
    return out.concat(tx.outputs.map(function(output, i) {
      return bcoin.coin(tx, i);
    }));
  }, []);
};

Mempool.prototype.getByAddress =
Mempool.prototype.getTXByAddress = function getTXByAddress(addresses) {
  var self = this;
  var txs = [];
  var uniq = {};

  if (typeof addresses === 'string')
    addresses = [addresses];

  addresses = utils.uniqs(addresses);

  addresses.forEach(function(address) {
    var map = self.addresses[address];
    if (!map)
      return;

    Object.keys(map).forEach(function(hash) {
      var tx;

      if (uniq[hash])
        return;

      uniq[hash] = true;

      tx = self.get(hash);
      assert(tx);

      txs.push(tx);
    });
  });

  return txs;
};

Mempool.prototype.fillCoin =
Mempool.prototype.fillTX = function fillTX(tx) {
  var i, input, total;

  total = 0;

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];

    if (input.output) {
      total++;
      continue;
    }

    if (this.hasTX(input.prevout.hash)) {
      input.output = this.getCoin(input.prevout.hash, input.prevout.index);
      total++;
    }
  }

  return total === tx.inputs.length;
};

Mempool.prototype.getAll = function getAll(hash) {
  return Object.keys(this.txs).map(function(key) {
    return this.txs[key];
  }, this);
};

Mempool.prototype.has =
Mempool.prototype.hasTX = function hasTX(hash) {
  return !!this.get(hash);
};

Mempool.prototype.add =
Mempool.prototype.addTX = function addTX(tx, peer, callback) {
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

  this.block.fillCoin(tx, function(err) {
    var i, input, dup, height, ts, priority;

    self._unlockTX(tx);

    if (err)
      return callback(err);

    if (!tx.hasPrevout()) {
      return callback(new Error('Previous outputs not found.'));
      peer.reject({
        data: tx.hash(),
        reason: 'no-prevout'
      });
      pool.setMisbehavior(peer, 100);
      return callback(new Error('Previous outputs not found.'));
    }

    if (!tx.isStandard()) {
      return callback(new Error('TX is not standard.'));
      peer.reject({
        data: tx.hash(),
        reason: 'non-standard'
      });
      pool.setMisbehavior(peer, 100);
      return callback(new Error('TX is not standard.'));
    }

    if (!tx.isStandardInputs()) {
      return callback(new Error('TX inputs are not standard.'));
      peer.reject({
        data: tx.hash(),
        reason: 'non-standard-inputs'
      });
      pool.setMisbehavior(peer, 100);
      return callback(new Error('TX inputs are not standard.'));
    }

    if (tx.getOutputValue().cmp(tx.getInputValue()) > 0) {
      return callback(new Error('TX is spending coins that it does not have.'));
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
      return callback(new Error('TX is not final.'));
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
        return callback(new Error('TX is spending old outputs.'));
        peer.reject({
          data: tx.hash(),
          reason: 'old-outputs'
        });
        pool.setMisbehavior(peer, 100);
        return callback(new Error('TX is spending old outputs.'));
      }
      dup = self.spent[input.prevout.hash + '/' + input.prevout.index];
      if (dup) {
        // Replace-by-fee
        if (input.sequence === 0xffffffff - 1) {
          if (dup.getFee().cmp(tx.getFee()) < 0) {
            self.remove(dup);
            continue;
          }
        }
        return callback(new Error('TX is double spending.'));
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
        return callback(new Error('TX is spending negative coins.'));
        peer.reject({
          data: tx.hash(),
          reason: 'negative-value'
        });
        pool.setMisbehavior(peer, 100);
        return callback(new Error('TX is spending negative coins.'));
      }
    }

    if (!tx.verify(true)) {
      return callback(new Error('TX did not verify.'));
      peer.reject({
        data: tx.hash(),
        reason: 'script-failed'
      });
      pool.setMisbehavior(peer, 100);
      return callback(new Error('TX did not verify.'));
    }

    for (i = 0; i < tx.inputs.length; i++) {
      input = tx.inputs[i];
      self.spent[input.prevout.hash + '/' + input.prevout.index] = tx;
    }

    // Possibly do something bitcoinxt-like here with priority
    priority = tx.getPriority();

    self.txs[hash] = tx;
    self.count++;
    self.size += tx.getSize();

    tx.inputs.forEach(function(input) {
      var address = input.getAddress();

      if (!address)
        return;

      if (!self.addresses[address])
        self.addresses[address] = {};

      self.addresses[address][hash] = true;
    });

    tx.outputs.forEach(function(output) {
      var address = output.getAddress();

      if (!address)
        return;

      if (!self.addresses[address])
        self.addresses[address] = {};

      self.addresses[address][hash] = true;
    });
  });
};

// Lock a tx to prevent race conditions
Mempool.prototype._lockTX = function _lockTX(tx) {
  var hash = tx.hash('hex');
  var i, input, id;

  if (!this.txs[hash])
    this.txs[hash] = tx;

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    id = input.prevout.hash + '/' + input.prevout.index;
    if (!this.spent[id])
      this.spent[id] = tx;
  }
};

Mempool.prototype._unlockTX = function _unlockTX(tx) {
  var hash = tx.hash('hex');
  var i, input, id;

  if (this.txs[hash] === tx)
    delete this.txs[hash];

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    id = input.prevout.hash + '/' + input.prevout.index;
    if (this.spent[id] === tx)
      delete this.spent[id];
  }
};

Mempool.prototype.remove =
Mempool.prototype.removeTX = function removeTX(hash, callback) {
  var self = this;
  var tx, input, id;

  callback = utils.asyncify(callback);

  if (hash instanceof bcoin.tx)
    hash = hash.hash('hex');

  tx = this.txs[hash];

  if (!tx)
    return callback(new Error('TX does not exist in mempool.'));

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    id = input.prevout.hash + '/' + input.prevout.index;
    if (this.spent[id] === tx)
      delete this.spent[id];
  }

  delete this.txs[hash];

  this.count--;
  this.size -= tx.getSize();

  tx.inputs.forEach(function(input) {
    var address = input.getAddress();

    if (!address)
      return;

    if (self.addresses[address]) {
      delete self.addresses[address][hash];
      if (Object.keys(self.addresses[address]).length === 0)
        delete self.addresses[address];
    }
  });

  tx.outputs.forEach(function(output) {
    var address = output.getAddress();

    if (!address)
      return;

    if (self.addresses[address]) {
      delete self.addresses[address][hash];
      if (Object.keys(self.addresses[address]).length === 0)
        delete self.addresses[address];
    }
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
