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
  var self = this;

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
  this._lastHeight = 0;
  this._loaded = false;
  this._addresses = {};
  this._sent = new bn(0);
  this._received = new bn(0);
  this._balance = new bn(0);

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
    self.emit('load', self._lastTs, self._lastHeight);
  });
};

TXPool.prototype.add = function add(tx, noWrite, strict) {
  var hash = tx.hash('hex');
  var updated = false;
  var i, input, output, coin, unspent, index, orphan;
  var key, orphans, some;

  this._wallet.fillPrevout(tx);

  if (!this._wallet.ownInput(tx) && !this._wallet.ownOutput(tx))
    return false;

  // Ignore stale pending transactions
  if (tx.ts === 0 && tx.ps + 2 * 24 * 3600 < utils.now()) {
    this._removeTX(tx, noWrite);
    return;
  }

  // Do not add TX two times
  if (this._all[hash]) {
    // Transaction was confirmed, update it in storage
    if (tx.ts !== 0 && this._all[hash].ts === 0) {
      this._all[hash].ps = 0;
      this._all[hash].ts = tx.ts;
      this._all[hash].block = tx.block;
      this._all[hash].height = tx.height;
      this._all[hash].outputs.forEach(function(output, i) {
        var key = hash + '/' + i;
        if (this._unspent[key])
          this._unspent[key].height = tx.height;
      });
      this._storeTX(hash, tx, noWrite);
      this._lastTs = Math.max(tx.ts, this._lastTs);
      this._lastHeight = Math.max(tx.height, this._lastHeight);
      this.emit('update', this._lastTs, this._lastHeight, tx);
      this.emit('confirmed', tx);
    }
    return false;
  }

  this._all[hash] = tx;

  // Consume unspent money or add orphans
  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    key = input.prevout.hash + '/' + input.prevout.index;
    unspent = this._unspent[key];

    if (unspent) {
      // Add TX to inputs and spend money
      input.output = unspent;

      assert(input.prevout.hash === unspent.hash);
      assert(input.prevout.index === unspent.index);

      // Skip invalid transactions
      if (!tx.verify(i))
        return;

      this._addInput(tx, i);

      delete this._unspent[key];
      updated = true;
      continue;
    }

    // Only add orphans if this input is ours.
    if (!this._wallet.ownInput(input))
      continue;

    // Add orphan, if no parent transaction is yet known
    orphan = { tx: tx, index: i };
    if (this._orphans[key])
      this._orphans[key].push(orphan);
    else
      this._orphans[key] = [orphan];
  }

  function checkOrphan(orphan) {
    orphan.tx.inputs[orphan.index].output = coin;

    assert(orphan.tx.inputs[orphan.index].prevout.hash === hash);
    assert(orphan.tx.inputs[orphan.index].prevout.index === i);

    // Verify that input script is correct, if not - add output to unspent
    // and remove orphan from storage
    if (!orphan.tx.verify(orphan.index)) {
      this._removeTX(orphan.tx, noWrite);
      return false;
    }

    this._addInput(orphan.tx, orphan.index);
    return true;
  }

  // Add unspent outputs or fullfill orphans
  for (i = 0; i < tx.outputs.length; i++) {
    output = tx.outputs[i];

    // Do not add unspents for outputs that aren't ours.
    if (!this._wallet.ownOutput(tx, i))
      continue;

    coin = bcoin.coin(tx, i);

    this._addOutput(tx, i);

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
      this._unspent[key] = coin;
      updated = true;
    }
  }

  this._lastTs = Math.max(tx.ts, this._lastTs);
  this._lastHeight = Math.max(tx.height, this._lastHeight);
  if (updated)
    this.emit('update', this._lastTs, this._lastHeight, tx);

  this.emit('tx', tx);

  if (tx.ts !== 0)
    this.emit('confirmed', tx);

  this._storeTX(hash, tx, noWrite);

  return true;
};

TXPool.prototype.getTX = function getTX(hash) {
  return this._all[hash];
};

TXPool.prototype.getCoin = function getCoin(hash, index) {
  return this._unspent[hash + '/' + index];
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
  var key;

  for (var i = 0; i < tx.outputs.length; i++) {
    key = tx.hash('hex') + '/' + i;
    if (this._unspent[key]) {
      delete this._unspent[key];
      this._removeOutput(tx, i);
    }
  }

  if (!this._storage || noWrite)
    return;

  this._storage.del(this._prefix + tx.hash('hex'), function(err) {
    if (err)
      self.emit('error', err);
  });
};

TXPool.prototype._addOutput = function _addOutput(tx, i, remove) {
  var output, address;

  if ((tx instanceof bcoin.output) || (tx instanceof bcoin.coin))
    output = tx;
  else
    output = tx.outputs[i];

  if (!this._wallet.ownOutput(output))
    return;

  address = output.getAddress();

  if (!this._addresses[address]) {
    this._addresses[address] = {
      received: new bn(0),
      sent: new bn(0),
      balance: new bn(0)
    };
  }

  if (!remove) {
    this._addresses[address].balance.iadd(output.value);
    this._addresses[address].received.iadd(output.value);
  } else {
    this._addresses[address].balance.isub(output.value);
    this._addresses[address].received.isub(output.value);
  }

  if (!remove) {
    this._balance.iadd(output.value);
    this._received.iadd(output.value);
  } else {
    this._balance.isub(output.value);
    this._received.isub(output.value);
  }
};

TXPool.prototype._removeOutput = function _removeOutput(tx, i) {
  return this._addOutput(tx, i, true);
};

TXPool.prototype._addInput = function _addInput(tx, i, remove) {
  var input, prev, address;

  if (tx instanceof bcoin.input)
    input = tx;
  else
    input = tx.inputs[i];

  assert(input.output);

  if (!this._wallet.ownOutput(input.output))
    return;

  prev = input.output;
  address = prev.getAddress();

  if (!this._addresses[address]) {
    this._addresses[address] = {
      received: new bn(0),
      sent: new bn(0),
      balance: new bn(0)
    };
  }

  if (!remove) {
    this._addresses[address].balance.isub(prev.value);
    this._addresses[address].sent.iadd(prev.value);
  } else {
    this._addresses[address].balance.iadd(prev.value);
    this._addresses[address].sent.isub(prev.value);
  }

  if (!remove) {
    this._balance.isub(prev.value);
    this._sent.iadd(prev.value);
  } else {
    this._balance.iadd(prev.value);
    this._sent.isub(prev.value);
  }
};

TXPool.prototype._removeInput = function _removeInput(tx, i) {
  return this._addInput(tx, i, true);
};

TXPool.prototype.getAll = function getAll(address) {
  return Object.keys(this._all).map(function(key) {
    return this._all[key];
  }, this).filter(function(tx) {
    if (address) {
      if (!address.ownOutput(tx) && !address.ownInput(tx))
        return false;
    }
    return true;
  });
};

TXPool.prototype.getUnspent = function getUnspent(address) {
  return Object.keys(this._unspent).map(function(key) {
    return this._unspent[key];
  }, this).filter(function(item) {
    if (address) {
      if (!address.ownOutput(item))
        return false;
    }
    return true;
  });
};

TXPool.prototype.getPending = function getPending(address) {
  return Object.keys(this._all).map(function(key) {
    return this._all[key];
  }, this).filter(function(tx) {
    if (address) {
      if (!address.ownInput(tx) && !address.ownOutput(tx))
        return false;
    }
    return tx.ts === 0;
  });
};

TXPool.prototype.getSent = function getSent(address) {
  if (address) {
    if (typeof address !== 'string')
      address = address.getAddress();
    if (this._addresses[address])
      return this._addresses[address].sent.clone();
    return new bn(0);
  }
  return this._sent.clone();
};

TXPool.prototype.getReceived = function getReceived(address) {
  if (address) {
    if (typeof address !== 'string')
      address = address.getAddress();
    if (this._addresses[address])
      return this._addresses[address].received.clone();
    return new bn(0);
  }
  return this._sent.clone();
};

TXPool.prototype.getBalance = function getBalance(address) {
  if (address) {
    if (typeof address !== 'string')
      address = address.getAddress();
    if (this._addresses[address])
      return this._addresses[address].balance.clone();
    return new bn(0);
  }
  return this._balance.clone();
};

TXPool.prototype.getBalanceUnspent = function getBalanceUnspent(address) {
  var acc = new bn(0);
  var unspent = this.getUnspent(address);
  if (unspent.length === 0)
    return acc;

  return unspent.reduce(function(acc, coin) {
    return acc.iadd(coin.value);
  }, acc);
};

// Legacy
TXPool.prototype.all = TXPool.prototype.getAll;
TXPool.prototype.unspent = TXPool.prototype.getUnspent;
TXPool.prototype.pending = TXPool.prototype.getPending;
TXPool.prototype.balance = TXPool.prototype.getBalance;

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

TXPool.fromJSON = function fromJSON(wallet, json) {
  var txPool;

  assert.equal(json.v, 1);
  assert.equal(json.type, 'tx-pool');

  txPool = new TXPool(wallet);

  utils.nextTick(function() {
    json.txs.forEach(function(tx) {
      txPool.add(bcoin.tx.fromJSON(tx));
    });
  });

  return txPool;
};

/**
 * Expose
 */

module.exports = TXPool;
