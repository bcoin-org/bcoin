var assert = require('assert');
var bn = require('bn.js');
var util = require('util');
var bcoin = require('../bcoin');
var EventEmitter = require('events').EventEmitter;

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

  // Load TXs from storage
  this._init();
}
util.inherits(TXPool, EventEmitter);
module.exports = TXPool;

TXPool.prototype._init = function init() {
  if (!this._storage)
    return;

  var self = this;
  var s = this._storage.createReadStream({
    keys: false,
    start: this._prefix,
    end: this._prefix + 'z'
  })
  s.on('data', function(data) {
    self.add(bcoin.tx.fromJSON(data), true);
  });
  s.on('error', function(err) {
    self.emit('error', err);
  });
  s.on('end', function() {
    self.emit('load', self._lastTs);
  });
};

TXPool.prototype.add = function add(tx, noWrite) {
  var hash = tx.hash('hex');

  // Ignore stale pending transactions
  if (tx.ps + 2 * 24 * 3600 < +new Date / 1000) {
    this._removeTX(orphan.tx);
    return;
  }

  // Do not add TX two times
  if (this._all[hash]) {
    // Transaction was confirmed, update it in storage
    if (this._storage && tx.ts !== 0 && this._all[hash].ts === 0) {
      this._all[hash].ts = tx.ts;
      this._storeTX(hash, tx);
    }
    return false;
  }
  this._all[hash] = tx;

  var own = this._wallet.ownOutput(tx);
  var updated = false;

  // Consume unspent money or add orphans
  for (var i = 0; i < tx.inputs.length; i++) {
    var input = tx.inputs[i];
    var key = input.out.hash + '/' + input.out.index;
    var unspent = this._unspent[key];

    if (unspent) {
      // Add TX to inputs and spend money
      var index = tx._input(unspent.tx, unspent.index);

      // Skip invalid transactions
      if (!tx.verify(index))
        return;

      delete this._unspent[key];
      updated = true;
      continue;
    }

    if (!own)
      continue;

    // Add orphan, if no parent transaction is yet known
    var orphan = { tx: tx, index: input.out.index };
    if (this._orphans[key])
      this._orphans[key].push(orphan);
    else
      this._orphans[key] = [orphan];
  }

  if (!own) {
    if (updated)
      this.emit('update', this._lastTs);

    // Save spending TXs without adding unspents
    if (this._storage && this._wallet.ownInput(tx))
      this._storeTX(hash, tx);
    return;
  }

  // Add unspent outputs or fullfill orphans
  for (var i = 0; i < tx.outputs.length; i++) {
    var out = tx.outputs[i];

    var key = hash + '/' + i;
    var orphans = this._orphans[key];

    // Add input to orphan
    if (orphans) {
      var some = orphans.some(function(orphan) {
        var index = orphan.tx._input(tx, orphan.index);

        // Verify that input script is correct, if not - add output to unspent
        // and remove orphan from storage
        if (!orphan.tx.verify(index)) {
          this._removeTX(orphan.tx);
          return false;
        }
        return true;
      }, this);
      if (!some)
        orphans = null;
    }

    delete this._orphans[key];
    if (!orphans)
      this._unspent[key] = { tx: tx, index: i };
  }

  this._lastTs = Math.max(tx.ts, this._lastTs);
  if (updated)
    this.emit('update', this._lastTs);

  if (!noWrite)
    this._storeTX(hash, tx);

  this.emit('tx', tx);

  return true;
};

TXPool.prototype._storeTX = function _storeTX(hash, tx) {
  if (!this._storage)
    return;

  var self = this;
  this._storage.put(this._prefix + hash, tx.toJSON(), function(err) {
    if (err)
      self.emit('error', err);
  });
};

TXPool.prototype._removeTX = function _removeTX(tx) {
  for (var i = 0; i < tx.outputs.length; i++)
    delete this._unspent[tx.hash('hex') + '/' + i];

  if (!this._storage)
    return;
  var self = this;
  this._storage.del(this._prefix + tx.hash('hex'), function(err) {
    if (err)
      self.emit('error', err);
  });
};

TXPool.prototype.all = function all() {
  return Object.keys(this._all).map(function(key) {
    return this._all[key];
  }, this).filter(function(tx) {
    return this._wallet.ownOutput(tx) ||
           this._wallet.ownInput(tx);
  }, this);
};

TXPool.prototype.unspent = function unspent() {
  return Object.keys(this._unspent).map(function(key) {
    return this._unspent[key];
  }, this).filter(function(item) {
    return this._wallet.ownOutput(item.tx, item.index);
  }, this);
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
