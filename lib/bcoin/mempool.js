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

  this.txs = {};
  this.spent = {};
  this.addresses = {};
  this.size = 0;
  this.count = 0;
  this.locked = false;
  this.loaded = false;

  Mempool.global = this;

  this._init();
}

utils.inherits(Mempool, EventEmitter);

Mempool.prototype._init = function _init() {
  var self = this;
  utils.nextTick(function() {
    self.loaded = true;
    self.emit('load');
  });
};

Mempool.prototype.open = function open(callback) {
  if (this.loaded)
    return utils.nextTick(callback);

  this.once('load', callback);
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
    // Add transaction back into mempool
    // tx = tx.clone();
    tx.ps = utils.now();
    tx.ts = 0;
    tx.block = null;
    tx.network = true;
    self.addTX(tx);
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

Mempool.prototype.getAll = function getAll() {
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
  var flags = constants.flags.STANDARD_VERIFY_FLAGS;
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

  if (tx.isCoinbase())
    return callback(new Error('What?'));

  if (!this.checkTX(tx, peer))
    return callback(new Error('TX failed checkTX.'));

  assert(tx.ts === 0);

  this._lockTX(tx);

  this.chain.fillCoin(tx, function(err) {
    var i, input, output, dup, height, ts, priority;

    self._unlockTX(tx);

    if (err)
      return callback(err);

    // Do this in the future.
    // tx = self.fillCoin(tx);

    if (!tx.hasPrevout()) {
      return callback(new Error('Previous outputs not found.'));
      peer.reject({
        data: tx.hash(),
        reason: 'no-prevout'
      });
      return callback(new Error('Previous outputs not found.'));
    }

    if (!tx.isStandard(flags)) {
      return callback(new Error('TX is not standard.'));
      peer.reject({
        data: tx.hash(),
        reason: 'non-standard'
      });
      self.node.pool.setMisbehavior(peer, 100);
      return callback(new Error('TX is not standard.'));
    }

    if (!tx.isStandardInputs(flags)) {
      return callback(new Error('TX inputs are not standard.'));
      peer.reject({
        data: tx.hash(),
        reason: 'non-standard-inputs'
      });
      self.node.pool.setMisbehavior(peer, 100);
      return callback(new Error('TX inputs are not standard.'));
    }

    if (tx.getOutputValue().cmp(tx.getInputValue()) > 0) {
      return callback(new Error('TX is spending coins that it does not have.'));
      peer.reject({
        data: tx.hash(),
        reason: 'nonexistent-coins'
      });
      self.node.pool.setMisbehavior(peer, 100);
      return callback(new Error('TX is spending coins that it does not have.'));
    }

    height = self.node.pool.chain.height + 1;
    ts = utils.now();
    if (!tx.isFinal(height, ts)) {
      return callback(new Error('TX is not final.'));
      peer.reject({
        data: tx.hash(),
        reason: 'not-final'
      });
      self.node.pool.setMisbehavior(peer, 100);
      return callback(new Error('TX is not final.'));
    }

    for (i = 0; i < tx.inputs.length; i++) {
      input = tx.inputs[i];
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
        self.node.pool.setMisbehavior(peer, 100);
        return callback(new Error('TX is spending negative coins.'));
      }
    }

    if (!tx.verify(null, true, flags)) {
      return callback(new Error('TX did not verify.'));
      peer.reject({
        data: tx.hash(),
        reason: 'script-failed'
      });
      self.node.pool.setMisbehavior(peer, 100);
      return callback(new Error('TX did not verify.'));
    }

    for (i = 0; i < tx.inputs.length; i++) {
      input = tx.inputs[i];
      self.spent[input.prevout.hash + '/' + input.prevout.index] = tx;
      self.size += input.output.getSize();
    }

    // Possibly do something bitcoinxt-like here with priority
    priority = tx.getPriority();

    tx.inputs.forEach(function(input) {
      var type = input.getType();
      var address = input.getAddress();

      if (type === 'pubkey' || type === 'multisig')
        address = null;

      if (!address)
        return;

      if (!self.addresses[address])
        self.addresses[address] = {};

      self.addresses[address][hash] = true;
    });

    tx.outputs.forEach(function(output) {
      var type = output.getType();
      var address = output.getAddress();

      if (type === 'pubkey' || type === 'multisig')
        address = null;

      if (!address)
        return;

      if (!self.addresses[address])
        self.addresses[address] = {};

      self.addresses[address][hash] = true;
    });

    self.txs[hash] = tx;
    self.count++;
    self.size += tx.getSize();

    self.emit('tx', tx);
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
  var tx, input, id, i;

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

  tx.inputs.forEach(function(input) {
    var type = input.getType();
    var address = input.getAddress();

    if (type === 'pubkey' || type === 'multisig')
      address = null;

    if (!address)
      return;

    if (self.addresses[address]) {
      delete self.addresses[address][hash];
      if (Object.keys(self.addresses[address]).length === 0)
        delete self.addresses[address];
    }
  });

  tx.outputs.forEach(function(output) {
    var type = output.getType();
    var address = output.getAddress();

    if (type === 'pubkey' || type === 'multisig')
      address = null;

    if (!address)
      return;

    if (self.addresses[address]) {
      delete self.addresses[address][hash];
      if (Object.keys(self.addresses[address]).length === 0)
        delete self.addresses[address];
    }
  });

  delete this.txs[hash];
  this.count--;
  this.size -= tx.getSize();
  this.emit('remove tx', tx);
};

// Need to lock the mempool when
// downloading a new block.
Mempool.prototype.lock = function lock() {
  this.locked = true;
};

Mempool.prototype.unlock = function unlock() {
  this.locked = false;
};

Mempool.prototype.checkTX = function checkTX(tx, peer) {
  var i, input, output, size;
  var total = new bn(0);
  var uniq = {};

  if (tx.inputs.length === 0)
    return this.reject(peer, tx, 'bad-txns-vin-empty');

  if (tx.outputs.length === 0)
    return this.reject(peer, tx, 'bad-txns-vout-empty');

  if (tx.getSize() > constants.block.maxSize)
    return this.reject(peer, tx, 'bad-txns-oversize');

  for (i = 0; i < tx.outputs.length; i++) {
    output = tx.outputs[i];
    if (output.value.cmpn(0) < 0)
      return this.reject(peer, tx, 'bad-txns-vout-negative');
    if (output.value.cmp(constants.maxMoney) > 0)
      return this.reject(peer, tx, 'bad-txns-vout-toolarge');
    total.iadd(output.value);
    if (total.cmpn(0) < 0 || total.cmp(constants.maxMoney))
      return this.reject(peer, tx, 'bad-txns-txouttotal-toolarge');
  }

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    if (uniq[input.out.hash])
      return this.reject(peer, tx, 'bad-txns-inputs-duplicate');
    uniq[input.out.hash] = true;
  }

  if (tx.isCoinbase()) {
    size = bcoin.script.getSize(tx.inputs[0].script);
    if (size < 2 || size > 100)
      return this.reject(peer, tx, 'bad-cb-length');
  } else {
    for (i = 0; i < tx.inputs.length; i++) {
      input = tx.inputs[i];
      if (+input.out.hash === 0)
        return this.reject(peer, tx, 'bad-txns-prevout-null');
    }
  }

  return true;
};

Mempool.prototype.reject = function reject(peer, obj, reason) {
  return false;

  if (!peer)
    return false;

  peer.reject({
    reason: reason,
    data: obj.hash ? obj.hash() : []
  });

  return false;
};

/**
 * Expose
 */

module.exports = Mempool;
