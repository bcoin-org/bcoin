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
  this._loaded = false;
  this._addresses = {};
  this._sent = new bn(0);
  this._received = new bn(0);
  this._balance = new bn(0);

  this._wallet.on('remove address', function(address) {
    address = self._addresses[address.getAddress()];
    if (address) {
      self._balance.isub(address.balance);
      self._sent.isub(address.sent);
      self._received.isub(address.received);
      delete self._addresses[address];
    }
  });

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

TXPool.prototype.add = function add(tx, noWrite, strict) {
  var hash = tx.hash('hex');
  var updated;
  var i, input, key, unspent, index, orphan;
  var out, key, orphans, some;

  if (strict) {
    if (!this._wallet.ownInput(tx) && !this._wallet.ownOutput(tx))
      return false;
  }

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
      this._storeTX(hash, tx, noWrite);
      this.emit('tx', tx);
      this.emit('confirmed', tx);
    }
    return false;
  }
  this._all[hash] = tx;

  updated = false;

  // Consume unspent money or add orphans
  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    key = input.prevout.hash + '/' + input.prevout.index;
    unspent = this._unspent[key];

    if (!input.prevout.tx && this._all[input.prevout.hash])
      input.prevout.tx = this._all[input.prevout.hash];

    if (unspent) {
      // Add TX to inputs and spend money
      index = tx._inputIndex(unspent.tx.hash('hex'), unspent.index);
      assert(index !== -1);
      assert(tx.inputs[index] === input);
      assert(tx.inputs[index].prevout.hash === unspent.tx.hash('hex'));
      assert(tx.inputs[index].prevout.index === unspent.index);
      input.prevout.tx = unspent.tx;

      // Skip invalid transactions
      if (!tx.verify(index))
        return;

      this._addInput(tx, index);

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
    if (input.prevout.tx) {
      if (!this._wallet.ownOutput(input.prevout.tx, input.prevout.index))
        continue;
    }

    // Add orphan, if no parent transaction is yet known
    orphan = { tx: tx, index: input.prevout.index };
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
    assert(orphan.tx.inputs[index].prevout.hash === tx.hash('hex'));
    assert(orphan.tx.inputs[index].prevout.index === i);
    orphan.tx.inputs[index].prevout.tx = tx;

    // Verify that input script is correct, if not - add output to unspent
    // and remove orphan from storage
    if (!orphan.tx.verify(index)) {
      this._removeTX(orphan.tx, noWrite);
      return false;
    }
    this._addInput(orphan.tx, index);
    return true;
  }

  // Add unspent outputs or fullfill orphans
  for (i = 0; i < tx.outputs.length; i++) {
    out = tx.outputs[i];

    // Do not add unspents for outputs that aren't ours.
    if (!this._wallet.ownOutput(tx, i))
      continue;

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

TXPool.prototype.prune = function prune(pruneOrphans) {
  var unspent = Object.keys(this._unspent).reduce(function(key) {
    out[key.split('/')[0]] = true;
    return out;
  }, {});
  Object.keys(this._all).forEach(function(key) {
    if (!unspent[key])
      delete this._all[key];
  });
  if (pruneOrphans)
    this._orphans = {};
};

TXPool.prototype.getAll = function getAll(address) {
  if (!address)
    address = this._wallet;

  return Object.keys(this._all).map(function(key) {
    return this._all[key];
  }, this).filter(function(tx) {
    return address.ownOutput(tx)
      || address.ownInput(tx);
  });
};

TXPool.prototype._addOutput = function _addOutput(tx, i, remove) {
  var i, data, address, addr, output;

  output = tx.outputs[i];
  data = bcoin.script.getOutputData(output.script);

  if (!this._wallet.ownOutput(tx, i))
    return;

  if (data.scriptAddress)
    data.addresses = [data.scriptAddress];

  for (i = 0; i < data.addresses.length; i++) {
    addr = data.addresses[i];
    if (!this._addresses[addr]) {
      this._addresses[addr] = {
        received: new bn(0),
        sent: new bn(0),
        balance: new bn(0)
      };
    }
    if (!remove) {
      this._addresses[addr].balance.iadd(output.value);
      this._addresses[addr].received.iadd(output.value);
    } else {
      this._addresses[addr].balance.isub(output.value);
      this._addresses[addr].received.isub(output.value);
    }
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
  var i, input, prev, data, address, addr, output;

  input = tx.inputs[i];
  assert(input.prevout.tx);

  if (!this._wallet.ownOutput(input.prevout.tx, input.prevout.index))
    return;

  prev = input.prevout.tx.outputs[input.prevout.index];
  data = bcoin.script.getInputData(input.script, prev.script);

  if (data.scriptAddress)
    data.addresses = [data.scriptAddress];

  for (i = 0; i < data.addresses.length; i++) {
    addr = data.addresses[i];
    if (!this._addresses[addr]) {
      this._addresses[addr] = {
        received: new bn(0),
        sent: new bn(0),
        balance: new bn(0)
      };
    }
    if (!remove) {
      this._addresses[addr].balance.isub(prev.value);
      this._addresses[addr].sent.iadd(prev.value);
    } else {
      this._addresses[addr].balance.iadd(prev.value);
      this._addresses[addr].sent.isub(prev.value);
    }
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

TXPool.prototype.getAddressBalance = function getAddressBalance(address) {
  if (this._addresses[address])
    return this._addresses[address].balance.clone();

  return new bn(0);
};

TXPool.prototype.getUnspent = function getUnspent(address) {
  if (!address)
    address = this._wallet;

  return Object.keys(this._unspent).map(function(key) {
    return this._unspent[key];
  }, this).filter(function(item) {
    return address.ownOutput(item.tx, item.index);
  });
};

TXPool.prototype.getPending = function getPending() {
  return Object.keys(this._all).map(function(key) {
    return this._all[key];
  }, this).filter(function(tx) {
    return tx.ts === 0;
  });
};

TXPool.prototype.getBalance = function getBalance(address) {
  var acc = new bn(0);
  var unspent = this.getUnspent(address);
  if (unspent.length === 0)
    return acc;

  return unspent.reduce(function(acc, item) {
    return acc.iadd(item.tx.outputs[item.index].value);
  }, acc);
};

TXPool.prototype.getBalance = function getBalance(address) {
  if (address)
    return this.getAddressBalance(address);
  return this._balance.clone();
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
