var bn = require('bn.js');

function TXPool() {
  if (!(this instanceof TXPool))
    return new TXPool();

  this._all = {};
  this._unspent = {};
  this._orphans = {};
}
module.exports = TXPool;

TXPool.prototype.add = function add(tx) {
  var hash = tx.hash('hex');

  // Do not add TX two times
  if (this._all[hash])
    return;
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
};

TXPool.prototype.unspent = function unspent(wallet) {
  return Object.keys(this._unspent).map(function(key) {
    return this._unspent[key];
  }, this).filter(function(item) {
    return wallet.own(item.tx, item.index);
  });
};

TXPool.prototype.balance = function balance(wallet) {
  var acc = new bn(0);
  var unspent = this.unspent(wallet);
  if (unspent.length === 0)
    return acc;

  return unspent.reduce(function(acc, item) {
    return acc.iadd(item.tx.outputs[item.index].value);
  }, acc);
};
