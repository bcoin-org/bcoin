/**
 * tx-pool.js - transaction pool for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bn = require('bn.js');
var inherits = require('inherits');
var bcoin = require('../bcoin');
var utils = bcoin.utils;
var assert = bcoin.utils.assert;
var EventEmitter = require('events').EventEmitter;

/**
 * TXPool
 */

function TXPool(wallet) {
  if (!(this instanceof TXPool))
    return new TXPool(wallet);

  EventEmitter.call(this);

  this._wallet = wallet;
  this._storage = wallet.storage;
  this._prefix = wallet.prefix + 'tx/';
  this._all = {};
  this._unspent = {};
  this._orphans = {};
  this._lastTs = 0;
  this._loaded = false;

  // Load TXs from storage
  this._init();
}

inherits(TXPool, EventEmitter);

TXPool.prototype._init = function init() {
  var self = this;

  if (!this._storage) {
    this._loaded = true;
    return;
  }

  var s = this._storage.createReadStream({
    keys: false,
    start: this._prefix,
    end: this._prefix + 'z'
  });

  s.on('data', function(data) {
    self.add(bcoin.tx.fromJSON(data), true);
  });

  s.on('error', function(err) {
    self.emit('error', err);
  });

  s.on('end', function() {
    self._loaded = true;
    self.emit('load', self._lastTs);
  });
};

TXPool.prototype.add = function add(tx, noWrite) {
  var hash = tx.hash('hex');
  var updated;
  var i, input, key, unspent, index, orphan;
  var out, key, orphans, some;

  // Ignore stale pending transactions
  if (tx.ts === 0 && tx.ps + 2 * 24 * 3600 < utils.now()) {
    this._removeTX(tx, noWrite);
    return;
  }

  // Do not add TX two times
  if (this._all[hash]) {
    // Transaction was confirmed, update it in storage
    if (tx.ts !== 0 && this._all[hash].ts === 0) {
      this._all[hash].ts = tx.ts;
      this._all[hash].block = tx.block;
      this._storeTX(hash, tx, noWrite);
    }
    return false;
  }
  this._all[hash] = tx;

  updated = false;

  // Consume unspent money or add orphans
  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    key = input.out.hash + '/' + input.out.index;
    unspent = this._unspent[key];

    if (!input.out.tx && this._all[input.out.hash])
      input.out.tx = this._all[input.out.hash];

    if (unspent) {
      // Add TX to inputs and spend money
      index = tx._inputIndex(unspent.tx.hash('hex'), unspent.index);
      assert(index !== -1);
      assert(tx.inputs[index] === input);
      assert(tx.inputs[index].out.hash === unspent.tx.hash('hex'));
      assert(tx.inputs[index].out.index === unspent.index);
      input.out.tx = unspent.tx;

      // Skip invalid transactions
      if (!tx.verify(index))
        return;

      delete this._unspent[key];
      updated = true;
      continue;
    }

    // Only add orphans if this input is ours.
    // If there is no previous output, there's no way to truly
    // verify this is ours, so we assume it is. If we add the
    // signature checking code to ownInput for p2sh and p2pk,
    // we could in theory use ownInput here (and down below)
    // instead.
    // if (this._wallet.ownInput(input.out.tx, input.out.index))
    if (input.out.tx) {
      if (!this._wallet.ownOutput(input.out.tx, input.out.index))
        continue;
    }

    // Add orphan, if no parent transaction is yet known
    orphan = { tx: tx, index: input.out.index };
    if (this._orphans[key])
      this._orphans[key].push(orphan);
    else
      this._orphans[key] = [orphan];
  }

  if (!this._wallet.ownOutput(tx)) {
    if (updated)
      this.emit('update', this._lastTs, tx);

    // Save spending TXs without adding unspents
    // if (this._wallet.ownInput(tx))
    this._storeTX(hash, tx, noWrite);
    return;
  }

  function checkOrphan(orphan) {
    var index = orphan.tx._inputIndex(tx.hash('hex'), orphan.index);
    assert(index !== -1);
    assert(orphan.tx.inputs[index].out.hash === tx.hash('hex'));
    assert(orphan.tx.inputs[index].out.index === i);
    orphan.tx.inputs[index].out.tx = tx;

    // Verify that input script is correct, if not - add output to unspent
    // and remove orphan from storage
    if (!orphan.tx.verify(index)) {
      this._removeTX(orphan.tx, noWrite);
      return false;
    }
    return true;
  }

  // Add unspent outputs or fullfill orphans
  for (i = 0; i < tx.outputs.length; i++) {
    out = tx.outputs[i];

    // Do not add unspents for outputs that aren't ours.
    if (!this._wallet.ownOutput(tx, i))
      continue;

    key = hash + '/' + i;
    orphans = this._orphans[key];

    // Add input to orphan
    if (orphans) {
      some = orphans.some(checkOrphan, this);
      if (!some)
        orphans = null;
    }

    delete this._orphans[key];
    if (!orphans) {
      this._unspent[key] = { tx: tx, index: i };
      updated = true;
    }
  }

  this._lastTs = Math.max(tx.ts, this._lastTs);
  if (updated)
    this.emit('update', this._lastTs, tx);

  this._storeTX(hash, tx, noWrite);

  this.emit('tx', tx);

  return true;
};

TXPool.prototype._storeTX = function _storeTX(hash, tx, noWrite) {
  var self = this;

  if (!this._storage || noWrite)
    return;

  this._storage.put(this._prefix + hash, tx.toJSON(), function(err) {
    if (err)
      self.emit('error', err);
  });
};

TXPool.prototype._removeTX = function _removeTX(tx, noWrite) {
  var self = this;

  for (var i = 0; i < tx.outputs.length; i++)
    delete this._unspent[tx.hash('hex') + '/' + i];

  if (!this._storage || noWrite)
    return;

  this._storage.del(this._prefix + tx.hash('hex'), function(err) {
    if (err)
      self.emit('error', err);
  });
};

TXPool.prototype.all = function all() {
  return Object.keys(this._all).map(function(key) {
    return this._all[key];
  }, this).filter(function(tx) {
    return this._wallet.ownOutput(tx)
      || this._wallet.ownInput(tx);
  }, this);
};

TXPool.prototype.unspent = function unspent() {
  return Object.keys(this._unspent).map(function(key) {
    return this._unspent[key];
  }, this).filter(function(item) {
    return this._wallet.ownOutput(item.tx, item.index);
  }, this);
};

TXPool.prototype.hasUnspent = function hasUnspent(hash, unspent) {
  var has;

  if (utils.isBuffer(hash) && hash.length && typeof hash[0] !== 'number') {
    unspent = this.unspent();
    has = hash.map(function(hash) {
      var h = this.hasUnspent(hash, unspent);
      if (!h)
        return false;
      return h[0];
    }, this).filter(Boolean);
    if (has.length !== hash.length)
      return null;
    return has;
  }

  if (utils.isBuffer(hash))
    hash = utils.toHex(hash);
  else if (hash.out)
    hash = hash.out.hash;
  else if (hash.tx)
    hash = hash.tx.hash('hex');
  else if (hash instanceof bcoin.tx)
    hash = hash.hash('hex');

  unspent = unspent || this.unspent();

  has = unspent.filter(function(item) {
    return item.tx.hash('hex') === hash;
  });

  if (!has.length)
    return null;

  return has;
};

TXPool.prototype.pending = function pending() {
  return Object.keys(this._all).map(function(key) {
    return this._all[key];
  }, this).filter(function(tx) {
    return tx.ts === 0;
  });
};

TXPool.prototype.balance = function balance() {
  var acc = new bn(0);
  var unspent = this.unspent();
  if (unspent.length === 0)
    return acc;

  return unspent.reduce(function(acc, item) {
    return acc.iadd(item.tx.outputs[item.index].value);
  }, acc);
};

TXPool.prototype.toJSON = function toJSON() {
  return {
    v: 1,
    type: 'tx-pool',
    txs: Object.keys(this._all).map(function(hash) {
      return this._all[hash].toJSON();
    }, this)
  };
};

TXPool.prototype.fromJSON = function fromJSON(json) {
  assert.equal(json.v, 1);
  assert.equal(json.type, 'tx-pool');

  json.txs.forEach(function(tx) {
    this.add(bcoin.tx.fromJSON(tx));
  }, this);
};

/**
 * Expose
 */

module.exports = TXPool;
