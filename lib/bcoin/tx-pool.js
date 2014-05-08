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
  this._prefix = 'bt/' + wallet.getAddress() + '/tx/';
  this._all = {};
  this._unspent = {};
  this._orphans = {};

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
};

TXPool.prototype.add = function add(tx, noWrite) {
  var hash = tx.hash('hex');

  // Do not add TX two times
  if (this._all[hash])
    return false;
  this._all[hash] = tx;

  var own = this._wallet.own(tx);

  // Consume unspent money or add orphans
  for (var i = 0; i < tx.inputs.length; i++) {
    var input = tx.inputs[i];
    var key = input.out.hash + '/' + input.out.index;
    var unspent = this._unspent[key];

    if (unspent) {
      // Add TX to inputs and spend money
      tx.input(unspent.tx, unspent.index);
      delete this._unspent[key];
      this.emit('update');
      continue;
    }

    // Double-spend?!
    if (!own || this._orphans[key])
      continue;

    // Add orphan, if no parent transaction is yet known
    this._orphans[key] = { tx: tx, index: i };
  }

  if (!own)
    return;

  // Add unspent outputs or fullfill orphans
  for (var i = 0; i < tx.outputs.length; i++) {
    var out = tx.outputs[i];

    var key = hash + '/' + i;
    var orphan = this._orphans[key];
    if (!orphan) {
      this._unspent[key] = { tx: tx, index: i };
      this.emit('update');
      continue;
    }
    delete this._orphans[key];

    // Add input to orphan
    orphan.tx.input(tx, orphan.index);
  }

  if (!noWrite && this._storage) {
    var self = this;
    this._storage.put(this._prefix + hash, tx.toJSON(), function(err) {
      if (err)
        self.emit('error', err);
    });
  }

  return true;
};

TXPool.prototype.unspent = function unspent() {
  return Object.keys(this._unspent).map(function(key) {
    return this._unspent[key];
  }, this).filter(function(item) {
    return this._wallet.own(item.tx, item.index);
  }, this);
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
