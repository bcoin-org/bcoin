var assert = require('assert');
var bn = require('bn.js');
var bcoin = require('../bcoin');

function TXPool(wallet) {
  if (!(this instanceof TXPool))
    return new TXPool(wallet);

  this._wallet = wallet;
  this._all = {};
  this._unspent = {};
  this._orphans = {};
}
module.exports = TXPool;

TXPool.prototype.add = function add(tx) {
  var hash = tx.hash('hex');

  if (!this._wallet.own(tx))
    return;

  // Do not add TX two times
  if (this._all[hash])
    return false;
  this._all[hash] = tx;

  // Consume unspent money or add orphans
  for (var i = 0; i < tx.inputs.length; i++) {
    var input = tx.inputs[i];
    var key = input.out.hash + '/' + input.out.index;
    var unspent = this._unspent[key];

    if (unspent) {
      // Add TX to inputs and spend money
      tx.input(unspent.tx, unspent.index);
      delete this._unspent[key];
      continue;
    }

    // Double-spend?!
    if (this._orphans[key])
      continue;

    // Add orphan, if no parent transaction is yet known
    this._orphans[key] = { tx: tx, index: i };
  }

  // Add unspent outputs or fullfill orphans
  for (var i = 0; i < tx.outputs.length; i++) {
    var out = tx.outputs[i];

    var key = hash + '/' + i;
    var orphan = this._orphans[key];
    if (!orphan) {
      this._unspent[key] = { tx: tx, index: i };
      continue;
    }
    delete this._orphans[key];

    // Add input to orphan
    orphan.tx.input(tx, orphan.index);
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
