var bn = require('bn.js');
var inherits = require('inherits');
var bcoin = require('../bcoin');
var assert = bcoin.utils.assert;
var EventEmitter = require('events').EventEmitter;

function TXPool(options) {
  if (!(this instanceof TXPool))
    return new TXPool(options);

  EventEmitter.call(this);

  var options = options || {};
  var wallet;

  // Legacy:
  if (options instanceof bcoin.wallet)
    wallet = options;
  else if (options.wallet)
    wallet = options.wallet;

  this.options = options;
  this._wallet = wallet;
  this._storage = options.storage;
  this._prefix = (options.prefix || 'bt/') + 'tx/';
  this._all = {};
  this._unspent = {};
  this._orphans = {};
  this._lastTs = 0;
  this._loaded = false;

  // Load TXs from storage
  this._init();
}
inherits(TXPool, EventEmitter);
module.exports = TXPool;

TXPool.prototype._init = function init() {
  if (!this._storage) {
    this._loaded = true;
    return;
  }

  var self = this;
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

  // Ignore stale pending transactions
  if (tx.ts === 0 && tx.ps + 2 * 24 * 3600 < +new Date() / 1000) {
    this._removeTX(tx);
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

  var own = !this._wallet || this._wallet.ownOutput(tx);
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
      this.emit('update', this._lastTs, tx);

    // Save spending TXs without adding unspents
    if (this._storage && (!this._wallet || this._wallet.ownInput(tx)))
      this._storeTX(hash, tx);
    return;
  }

  function checkOrphan(orphan) {
    var index = orphan.tx._input(tx, orphan.index);

    // Verify that input script is correct, if not - add output to unspent
    // and remove orphan from storage
    if (!orphan.tx.verify(index)) {
      this._removeTX(orphan.tx);
      return false;
    }
    return true;
  }

  // Add unspent outputs or fullfill orphans
  for (var i = 0; i < tx.outputs.length; i++) {
    var out = tx.outputs[i];

    var key = hash + '/' + i;
    var orphans = this._orphans[key];

    // Add input to orphan
    if (orphans) {
      var some = orphans.some(checkOrphan, this);
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

  if (!noWrite)
    this._storeTX(hash, tx);

  this.emit('tx', tx);

  // Since we don't have a particular key's tx's to keep track of, these might
  // use a bit of memory. Free them up every so often.
  if (!this._wallet) {
    var memLimit = this.options.memLimit || 1000;
    if (Object.keys(this._all).length > memLimit) {
      this._all = {};
    }
    if (Object.keys(this._unspent).length > memLimit) {
      this._unspent = {};
    }
    if (Object.keys(this._orphans).length > memLimit) {
      this._orphans = {};
    }
  }

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

TXPool.prototype._getTX = function(hash, callback) {
  if (!this._storage)
    return callback(new Error('No storage.'));
  this._storage.get(this._prefix + hash, function(err, data) {
    if (err) return callback(err);
    var tx = bcoin.tx.fromJSON(data);
    // self.add(tx, true);
    return callback(null, tx);
  });
};

TXPool.prototype.get = function(hash, options, callback) {
  var self = this;

  if (!callback) {
    callback = options;
    options = {};
  }

  if (options.memory === false) {
    if (this._all[hash])
      return callback(null, this._all[hash]);
  }

  this._getTX(hash, function(err, tx) {
    if (err) return callback(err);
    if (options.add)
      self.add(tx, true);
    return callback(null, tx);
  });
};

TXPool.prototype.all = function all() {
  return Object.keys(this._all).map(function(key) {
    return this._all[key];
  }, this).filter(function(tx) {
    if (!this._wallet)
      return true;
    return this._wallet.ownOutput(tx) ||
           this._wallet.ownInput(tx);
  }, this);
};

TXPool.prototype.unspent = function unspent() {
  return Object.keys(this._unspent).map(function(key) {
    return this._unspent[key];
  }, this).filter(function(item) {
    if (!this._wallet)
      return true;
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
