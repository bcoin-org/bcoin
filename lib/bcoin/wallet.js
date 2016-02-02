/**
 * wallet.js - wallet object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bcoin = require('../bcoin');
var hash = require('hash.js');
var bn = require('bn.js');
var inherits = require('inherits');
var EventEmitter = require('events').EventEmitter;
var utils = bcoin.utils;
var assert = utils.assert;
var constants = bcoin.protocol.constants;
var network = bcoin.protocol.network;

/**
 * Wallet
 */

function Wallet(options) {
  var i;

  if (!(this instanceof Wallet))
    return new Wallet(options);

  EventEmitter.call(this);

  if (!options)
    options = {};

  this.options = options;
  this.addresses = [];
  this.master = options.master || null;
  this._addressTable = {};
  this._labelMap = {};

  this.accountIndex = options.accountIndex || 0;
  this.addressIndex = options.addressIndex || 0;
  this.changeIndex = options.changeIndex || 0;

  if (options.addresses && options.addresses.length > 0) {
    options.addresses.forEach(function(address) {
      this.addAddress(address);
    }, this);
  } else {
    this.createNewAddress(options);
  }

  // Create a non-master account address if we don't have one.
  // Might not be necessary now.
  if (this.master) {
    for (i = 0; i < this.addresses.length; i++) {
      if (this.addresses[i].key.hd && !this.addresses[i].change)
        break;
    }
    if (i === this.addresses.length)
      this.createNewAddress(options);
  }

  // Find the last change address if there is one.
  for (i = this.addresses.length - 1; i >= 0; i--) {
    if (this.addresses[i].change)
      break;
  }

  if (i === -1)
    this.changeAddress = this.createChangeAddress();
  else
    this.changeAddress = this.addresses[i];

  this.storage = options.storage;
  this.label = options.label || '';
  this.loaded = false;
  this.lastTs = 0;

  this.prefix = 'bt/wallet/' + this.getKeyAddress() + '/';

  this.tx = new bcoin.txPool(this);

  this._init();
}

inherits(Wallet, EventEmitter);

Wallet.prototype._init = function init() {
  var self = this;
  var prevBalance = null;

  if (this.tx._loaded) {
    this.loaded = true;
    return;
  }

  // Notify owners about new accepted transactions
  this.tx.on('update', function(lastTs, tx) {
    var b = this.getBalance();
    if (prevBalance && prevBalance.cmp(b) !== 0)
      self.emit('balance', b);
    self.emit('update', tx);
    prevBalance = b;
  });

  this.tx.on('tx', function(tx) {
    // TX using this change address was
    // confirmed. Allocate a new change address.
    if (self.changeAddress.ownOutput(tx))
      self.changeAddress = self.createChangeAddress();
    self.emit('tx', tx);
  });

  this.tx.once('load', function(ts) {
    self.loaded = true;
    self.lastTs = ts;
    self.emit('load', ts);
  });

  this.tx.on('error', function(err) {
    self.emit('error', err);
  });
};

Wallet.prototype.__defineGetter__('address', function() {
  return this.addresses[0];
});

Wallet.prototype._getAddressTable = function() {
  var addresses = {};
  var i, address;

  for (i = 0; i < this.addresses.length; i++) {
    address = this.addresses[i];
    if (address.type === 'scripthash')
      addresses[address.getScriptAddress()] = i;
    addresses[address.getKeyAddress()] = i;
  }

  return addresses;
};

// Faster than indexOf if we have tons of addresses
Wallet.prototype._addressIndex = function _addressIndex(address) {
  var addr;

  if (!(address instanceof bcoin.address))
    address = bcoin.address(address);

  if (address.type === 'scripthash') {
    addr = address.getScriptAddress();
    if (this._addressTable[addr] != null)
      return this._addressTable[addr];
  }

  addr = address.getKeyAddress();
  if (this._addressTable[addr] != null)
    return this._addressTable[addr];

  return -1;
};

Wallet.prototype.createChangeAddress = function createChangeAddress(options) {
  if (!options)
    options = {};

  options.change = true;

  if (this.master) {
    options.priv =
      this.master.key.hd.deriveChange(this.accountIndex, this.changeIndex++);
  }

  return this.addAddress(options);
};

Wallet.prototype.createNewAddress = function createNewAddress(options) {
  if (!options)
    options = {};

  if (this.master) {
    options.priv =
      this.master.key.hd.deriveAddress(this.accountIndex, this.addressIndex++);
  }

  return this.addAddress(options);
};

Wallet.prototype.hasAddress = function hasAddress(address) {
  return this._addressIndex(address) != -1;
};

Wallet.prototype.findAddress = function findAddress(address) {
  var i = this._addressIndex(address);

  if (i === -1)
    return;

  return this.addresses[i];
};

Wallet.prototype.addAddress = function addAddress(address) {
  var self = this;
  var index;

  if (!(address instanceof bcoin.address))
    address = bcoin.address(address);

  if (this._addressIndex(address) !== -1)
    return;

  if (address.key.hd && address.key.hd.isMaster) {
    assert(!this.master);
    this.master = address;
    return;
  }

  if (address._wallet)
    address._wallet.removeAddress(address);

  address._wallet = this;

  index = this.addresses.push(address) - 1;

  address.on('scriptaddress', address._onUpdate = function(old, cur) {
    self._addressTable[cur] = self._addressTable[old];
    delete self._addressTable[old];
    self.emit('add address', address);
  });

  if (address.type === 'scripthash')
    this._addressTable[address.getScriptAddress()] = index;

  this._addressTable[address.getKeyAddress()] = index;

  this.emit('add address', address);

  return address;
};

Wallet.prototype.removeAddress = function removeAddress(address) {
  var i;

  assert(address instanceof bcoin.address);

  i = this._addressIndex(address);

  if (i === -1)
    return;

  assert(address._wallet === this);
  assert(address._onUpdate);

  this.addresses.splice(i, 1);

  address.removeListener('scriptaddress', address._onUpdate);

  this._addressTable = this._getAddressTable();

  delete address._onUpdate;
  delete address._wallet;

  this.emit('remove address', address);

  return address;
};

Wallet.prototype.addKey = function addKey(key, i) {
  return this.address.addKey(key);
};

Wallet.prototype.removeKey = function removeKey(key) {
  return this.address.removeKey(key);
};

Wallet.prototype.getPrivateKey = function getPrivateKey(enc) {
  return this.address.getPrivateKey(enc);
};

Wallet.prototype.getScript = function getScript() {
  return this.address.getScript();
};

Wallet.prototype.getScriptHash = function getScriptHash() {
  return this.address.getScriptHash();
};

Wallet.prototype.getScriptAddress = function getScriptAddress() {
  return this.address.getScriptAddress();
};

Wallet.prototype.getPublicKey = function getPublicKey(enc) {
  return this.address.getPublicKey(enc);
};

Wallet.prototype.getKeyHash = function getKeyHash() {
  return this.address.getKeyHash();
};

Wallet.prototype.getKeyAddress = function getKeyAddress() {
  return this.address.getKeyAddress();
};

Wallet.prototype.getHash = function getHash() {
  return this.address.getHash();
};

Wallet.prototype.getAddress = function getAddress() {
  return this.address.getAddress();
};

Wallet.prototype.ownInput = function ownInput(tx, index) {
  this.fillPrevout(tx);
  return tx.testInputs(this._addressTable, index, true);
};

Wallet.prototype.ownOutput = function ownOutput(tx, index) {
  return tx.testOutputs(this._addressTable, index, true);
};

Wallet.prototype.fill = function fill(tx, address, fee) {
  var unspent, items, result;

  if (!address)
    address = this.changeAddress.getKeyAddress();

  unspent = this.getUnspent();

  // Avoid multisig if first address is not multisig
  items = unspent.filter(function(item) {
    var output = item.tx.outputs[item.index];
    if (bcoin.script.isScripthash(output.script)) {
      if (this.address.type === 'scripthash')
        return true;
      return false;
    }
    if (bcoin.script.isMultisig(output.script)) {
      if (this.address.n > 1)
        return true;
      return false;
    }
    return true;
  }, this);

  if (tx.getInputs(unspent, address, fee).inputs)
    unspent = items;

  result = tx.fill(unspent, address, fee);

  if (!result.inputs)
    return false;

  return true;
};

// Legacy
Wallet.prototype.fillUnspent = Wallet.prototype.fill;
Wallet.prototype.fillInputs = Wallet.prototype.fill;

Wallet.prototype.fillPrevout = function fillPrevout(tx) {
  return tx.fillPrevout(this);
};

// Legacy
Wallet.prototype.fillTX = Wallet.prototype.fillPrevout;

Wallet.prototype.createTX = function createTX(outputs, fee) {
  var tx = bcoin.tx();
  var target;

  if (!Array.isArray(outputs))
    outputs = [outputs];

  outputs.forEach(function(output) {
    tx.addOutput(output);
  });

  if (!this.fill(tx, null, fee))
    return;

  // Find the necessary locktime if there is
  // a checklocktimeverify script in the unspents.
  target = tx.getTargetTime();

  // No target value. The unspents have an
  // incompatible locktime type.
  if (!target)
    return;

  if (target.value > 0)
    tx.setLockTime(target.value);
  else
    tx.avoidFeeSnipping();

  this.sign(tx);

  return tx;
};

Wallet.prototype.scriptInputs = function scriptInputs(tx) {
  var self = this;

  return this.addresses.reduce(function(total, address) {
    var pub = address.getPublicKey();
    var redeem = address.getScript();

    tx.inputs.forEach(function(input, i) {
      if (!input.prevout.tx && self.tx._all[input.prevout.hash])
        input.prevout.tx = self.tx._all[input.prevout.hash];

      if (!input.prevout.tx)
        return;

      if (!address.ownOutput(input.prevout.tx, input.prevout.index))
        return;

      if (tx.scriptInput(i, pub, redeem))
        total++;
    });

    return total;
  }, 0);
};

Wallet.prototype.signInputs = function signInputs(tx, type) {
  var self = this;

  return this.addresses.reduce(function(total, address) {
    if (!address.key.priv)
      return total;

    tx.inputs.forEach(function(input, i) {
      if (!input.prevout.tx && self.tx._all[input.prevout.hash])
        input.prevout.tx = self.tx._all[input.prevout.hash];

      if (!input.prevout.tx)
        return;

      if (!address.ownOutput(input.prevout.tx, input.prevout.index))
        return;

      if (tx.signInput(i, address.key, type))
        total++;
    });

    return total;
  }, 0);
};

Wallet.prototype.sign = function sign(tx, type) {
  var self = this;

  return this.addresses.reduce(function(total, address) {
    var pub = address.getPublicKey();
    var redeem = address.getScript();
    var key = address.key;

    if (!key.priv)
      return total;

    // Add signature script to each input
    tx.inputs.forEach(function(input, i) {
      if (!input.prevout.tx && self.tx._all[input.prevout.hash])
        input.prevout.tx = self.tx._all[input.prevout.hash];

      // Filter inputs that this wallet own
      if (!input.prevout.tx)
        return;

      if (!address.ownOutput(input.prevout.tx, input.prevout.index))
        return;

      if (tx.scriptSig(i, key, pub, redeem, type))
        total++;
    });

    return total;
  }, 0);
};

Wallet.prototype.addTX = function addTX(tx, block) {
  return this.tx.add(tx);
};

Wallet.prototype.getAll = function getAll() {
  return this.tx.getAll();
};

Wallet.prototype.getUnspent = function getUnspent() {
  return this.tx.getUnspent();
};

Wallet.prototype.getPending = function getPending() {
  return this.tx.getPending();
};

Wallet.prototype.getBalance = function getBalance() {
  return this.tx.getBalance();
};

// Legacy
Wallet.prototype.all = Wallet.prototype.getAll;
Wallet.prototype.unspent = Wallet.prototype.getUnspent;
Wallet.prototype.pending = Wallet.prototype.getPending;
Wallet.prototype.balance = Wallet.prototype.getBalance;

Wallet.prototype.toAddress = function toAddress() {
  var self = this;
  var received = new bn(0);
  var sent = new bn(0);

  var txs = Object.keys(this.tx._all).reduce(function(out, hash) {
    out.push(self.tx._all[hash]);
    return out;
  }, []);

  txs.forEach(function(tx) {
    tx.inputs.forEach(function(input, i) {
      if (self.ownInput(tx, i))
        sent.iadd(input.value);
    });
    tx.outputs.forEach(function(output, i) {
      if (self.ownOutput(tx, i))
        received.iadd(output.value);
    });
  });

  return {
    address: this.getAddress(),
    hash: utils.toHex(this.getHash()),
    received: received,
    sent: sent,
    balance: this.getBalance(),
    txs: txs
  };
};

Wallet.prototype.toJSON = function toJSON(encrypt) {
  return {
    v: 3,
    name: 'wallet',
    network: network.type,
    label: this.label,
    accountIndex: this.accountIndex,
    addressIndex: this.addressIndex,
    changeIndex: this.changeIndex,
    master: this.master ? this.master.toJSON(encrypt) : null,
    addresses: this.addresses.filter(function(address) {
      if (!address.key.hd)
        return true;

      if (address.change)
        return false;

      return true;
    }).map(function(address) {
      return address.toJSON(encrypt);
    }),
    balance: utils.toBTC(this.getBalance()),
    tx: this.tx.toJSON()
  };
};

Wallet.fromJSON = function fromJSON(json, decrypt) {
  var priv, pub, xprivkey, multisig, compressed, key, w, i;

  assert.equal(json.v, 3);
  assert.equal(json.name, 'wallet');

  if (json.network)
    assert.equal(json.network, network.type);

  w = new Wallet({
    label: json.label,
    accountIndex: json.accountIndex,
    addressIndex: json.addressIndex,
    changeIndex: json.changeIndex,
    master: json.master
      ? bcoin.address.fromJSON(json.master, decrypt)
      : null,
    addresses: json.addresses.map(function(address) {
      return bcoin.address.fromJSON(address, decrypt);
    })
  });

  w.tx.fromJSON(json.tx);

  // Make sure we have all the change
  // addresses (we don't save them).
  if (w.master) {
    for (i = 0; i < w.changeIndex; i++) {
      w.addAddress({
        change: true,
        key: w.master.key.hd.deriveChange(w.accountIndex, i)
      });
    }
  }

  return w;
};

// Compat - Legacy
Wallet.toSecret = function toSecret(priv, compressed) {
  return bcoin.keypair.toSecret(priv, compressed);
};

Wallet.fromSecret = function fromSecret(priv) {
  return bcoin.keypair.fromSecret(priv);
};

Wallet.key2hash = function key2hash(key) {
  return bcoin.address.key2hash(key);
};

Wallet.hash2addr = function hash2addr(hash, prefix) {
  return bcoin.address.hash2addr(hash, prefix);
};

Wallet.addr2hash = function addr2hash(addr, prefix) {
  return bcoin.address.addr2hash(addr, prefix);
};

Wallet.validateAddress = function validateAddress(addr, prefix) {
  return bcoin.address.validateAddress(addr, prefix);
};

/**
 * Expose
 */

module.exports = Wallet;
