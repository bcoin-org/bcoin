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
  var key, receiving;

  if (!(this instanceof Wallet))
    return new Wallet(options);

  EventEmitter.call(this);

  if (!options)
    options = {};

  options = utils.merge({}, options);

  if (typeof options.master === 'string')
    options.master = { xkey: options.master };

  if (options.master
      && typeof options.master === 'object'
      && !(options.master instanceof bcoin.hd)) {
    options.master = bcoin.hd(options.master);
  }

  if (!options.master)
    options.master = bcoin.hd.privateKey();

  this.options = options;
  this.addresses = [];
  this.master = options.master || null;
  this.addressMap = options.addressMap || {};
  this.labelMap = {};
  this.change = [];
  this.receive = [];

  this.accountIndex = options.accountIndex || 0;
  this.receiveDepth = options.receiveDepth || 1;
  this.changeDepth = options.changeDepth || 1;
  this.copayBIP45 = options.copayBIP45 || false;
  this.lookahead = options.lookahead != null ? options.lookahead : 5;
  this.cosignerIndex = -1;

  this.type = options.type || 'pubkeyhash';
  this.derivation = options.derivation || 'bip44';
  this.compressed = options.compressed !== false;
  this.keys = [];
  this.m = options.m || 1;
  this.n = options.n || 1;

  if (this.n > 1)
    this.type = 'multisig';

  assert(this.type === 'pubkeyhash' || this.type === 'multisig');
  this.prefixType = this.type === 'multisig' ? 'scripthash' : 'pubkeyhash';

  if (network.prefixes[this.prefixType] == null)
    throw new Error('Unknown prefix: ' + this.prefixType);

  if (this.m < 1 || this.m > this.n)
    throw new Error('m ranges between 1 and n');

  if (this.derivation === 'bip45') {
    this.accountKey = this.master.isPurpose45()
      ? this.master
      : this.master.derivePurpose45();
  } else if (this.derivation === 'bip44') {
    this.accountKey = this.master.isAccount44()
      ? this.master
      : this.master.deriveAccount44(this.accountIndex);
  }

  this.storage = options.storage;
  this.loading = true;
  this.lastTs = 0;
  this.lastHeight = 0;

  this.addKey(this.accountKey);

  (options.keys || []).forEach(function(key) {
    this.addKey(key);
  }, this);
}

inherits(Wallet, EventEmitter);

Wallet.prototype._init = function _init() {
  var self = this;
  var prevBalance = null;
  var options = this.options;
  var addr, i;

  assert(!this._initialized);
  this._initialized = true;

  if (Object.keys(this.addressMap).length === 0) {
    for (i = 0; i < this.receiveDepth - 1; i++)
      this.deriveReceive(i);

    for (i = 0; i < this.changeDepth - 1; i++)
      this.deriveChange(i);

    for (i = this.receiveDepth; i < this.receiveDepth + this.lookahead; i++)
      this.deriveReceive(i);

    for (i = this.changeDepth; i < this.changeDepth + this.lookahead; i++)
      this.deriveChange(i);
  }

  this.receiveAddress = this.deriveReceive(this.receiveDepth - 1);
  this.changeAddress = this.deriveChange(this.changeDepth - 1);

  assert(this.receiveAddress);
  assert(!this.receiveAddress.change);
  assert(this.changeAddress.change);

  this.prefix = 'bt/wallet/' + this.getID() + '/';

  this.tx = options.tx || bcoin.txPool(this);

  if (this.tx._loaded) {
    this.loading = false;
    return;
  }

  // Notify owners about new accepted transactions
  this.tx.on('update', function(lastTs, lastHeight, tx) {
    var b = this.getBalance();
    if (prevBalance && prevBalance.cmp(b) !== 0)
      self.emit('balance', b);
    if (tx)
      self.emit('update', tx);
    self.lastTs = Math.max(lastTs, self.lastTs);
    self.lastHeight = Math.max(lastHeight, self.lastHeight);
    prevBalance = b;
  });

  this.tx.on('tx', function(tx) {
    self.emit('tx', tx);
  });

  this.tx.on('confirmed', function(tx) {
    // TX using this address was confirmed.
    // Allocate a new address.
    self.syncOutputDepth(tx);
    self.emit('confirmed', tx);
  });

  this.tx.once('load', function(ts, height) {
    self.loading = false;
    self.lastTs = ts;
    self.lastHeight = height;
    self.emit('load', ts);
  });

  this.tx.on('error', function(err) {
    self.emit('error', err);
  });
};

Wallet.prototype.addKey = function addKey(key) {
  var has, i;

  if (key instanceof bcoin.wallet) {
    assert(key.derivation === this.derivation);
    key = key.accountKey;
  }

  if (bcoin.hd.privateKey.isExtended(key))
    key = bcoin.hd.privateKey(key);
  else if (bcoin.hd.publicKey.isExtended(key))
    key = bcoin.hd.publicKey(key);

  if (key instanceof bcoin.hd.privateKey)
    key = key.hdpub;

  if (this.derivation === 'bip44') {
    if (!key || !key.isAccount44())
      throw new Error('Must add HD account keys to BIP44 wallet.');
  } else if (this.derivation === 'bip45') {
    if (!key || !key.isPurpose45())
      throw new Error('Must add HD purpose keys to BIP45 wallet.');
  }

  has = this.keys.some(function(k) {
    return k.xpubkey === key.xpubkey;
  });

  if (has)
    return;

  assert(!this._keysFinalized);

  this.keys.push(key);

  if (this.keys.length === this.n)
    this._finalizeKeys();
};

Wallet.prototype.removeKey = function removeKey(key) {
  var index;

  assert(!this._keysFinalized);

  if (key instanceof bcoin.wallet) {
    assert(key.derivation === this.derivation);
    key = key.accountKey;
  }

  if (bcoin.hd.privateKey.isExtended(key))
    key = bcoin.hd.privateKey(key);
  else if (bcoin.hd.publicKey.isExtended(key))
    key = bcoin.hd.publicKey(key);

  if (key instanceof bcoin.keypair)
    key = key.hd;

  if (key instanceof bcoin.hd.privateKey)
    key = key.hdpub;

  if (this.derivation === 'bip44') {
    if (!key || !key.isAccount44())
      throw new Error('Must add HD account keys to BIP44 wallet.');
  } else if (this.derivation === 'bip45') {
    if (!key || !key.isPurpose45())
      throw new Error('Must add HD purpose keys to BIP45 wallet.');
  }

  index = this.keys.map(function(k, i) {
    return k.xpubkey === key.xpubkey ? i : null;
  }).filter(function(i) {
    return i !== null;
  })[0];

  if (index == null)
    return;

  this.keys.splice(index, 1);
};

Wallet.prototype._finalizeKeys = function _finalizeKeys(key) {
  assert(!this._keysFinalized);
  this._keysFinalized = true;

  this.keys = utils.sortHDKeys(this.keys);

  for (i = 0; i < this.keys.length; i++) {
    if (this.keys[i].xpubkey === this.accountKey.xpubkey) {
      this.cosignerIndex = i;
      break;
    }
  }

  assert(this.cosignerIndex !== -1);

  this._init();
};

// Wallet ID:
// bip45: Purpose key address
// bip44: Account key address
Wallet.prototype.getID = function getID() {
  return bcoin.address.compile(this.accountKey.publicKey);
};

Wallet.prototype.createReceive = function createReceive() {
  return this.createAddress(false);
};

Wallet.prototype.createChange = function createChange() {
  return this.createAddress(true);
};

Wallet.prototype.createAddress = function createAddress(change) {
  var address;

  if (typeof change === 'string')
    change = this.parsePath(change).change;

  if (change) {
    address = this.deriveChange(this.changeDepth);
    this.deriveChange(this.changeDepth + this.lookahead);
    this.changeDepth++;
  } else {
    address = this.deriveReceive(this.receiveDepth);
    this.deriveReceive(this.receiveDepth + this.lookahead);
    this.receiveDepth++;
  }

  return address;
};

Wallet.prototype.deriveReceive = function deriveReceive(index) {
  if (typeof index === 'string')
    index = this.parsePath(index).index;

  return this.deriveAddress(false, index);
};

Wallet.prototype.deriveChange = function deriveChange(index) {
  if (typeof index === 'string')
    index = this.parsePath(index).index;

  return this.deriveAddress(true, index);
};

Wallet.prototype.deriveAddress = function deriveAddress(change, index) {
  var path, data, key, options, address;

  assert(this._initialized);

  if (typeof change === 'string')
    path = change;

  if (path) {
    // Map address to path
    if (path.indexOf('/') === -1) {
      path = this.addressMap[path];
      if (!path)
        return;
    }
    data = this.parsePath(path);
  } else {
    data = {
      path: this.createPath(this.cosignerIndex, change, index),
      cosignerIndex: this.cosignerIndex,
      change: change,
      index: index
    };
  }

  key = this.accountKey.derive(data.path);

  options = {
    privateKey: key.privateKey,
    publicKey: key.publicKey,
    compressed: key.compressed,
    change: data.change,
    index: data.index,
    path: data.path,
    type: this.type,
    m: this.m,
    n: this.n,
    keys: [],
    derived: true
  };

  this.keys.forEach(function(key, cosignerIndex) {
    var path = this.createPath(cosignerIndex, data.change, data.index);
    key = key.derive(path);
    options.keys.push(key.publicKey);
  }, this);

  address = bcoin.address(options);

  this.addressMap[address.getAddress()] = data.path;

  return address;
};

Wallet.prototype.hasAddress = function hasAddress(address) {
  return this.addressMap[address] != null;
};

Wallet.prototype.createPath = function createPath(cosignerIndex, change, index) {
  if (this.copayBIP45)
    cosignerIndex = constants.hd.hardened - 1;

  return 'm'
    + (this.derivation === 'bip45' ? '/' + cosignerIndex : '')
    + '/' + (change ? 1 : 0)
    + '/' + index;
};

Wallet.prototype.parsePath = function parsePath(path) {
  var parts;

  if (this.derivation === 'bip45')
    assert(/^m\/\d+\/\d+\/\d+$/.test(path));
  else
    assert(/^m\/\d+\/\d+$/.test(path));

  parts = path.split('/');

  if (this.derivation === 'bip45' && this.copayBIP45)
    assert(+parts[parts.length - 3] === constants.hd.hardened - 1);

  return {
    path: path,
    cosignerIndex: this.derivation === 'bip45'
      ? +parts[parts.length - 3]
      : null,
    change: +parts[parts.length - 2] === 1,
    index: +parts[parts.length - 1]
  };
};

Wallet.prototype.setReceiveDepth = function setReceiveDepth(depth) {
  var i;

  if (depth <= this.receiveDepth)
    return false;

  for (i = this.receiveDepth; i < depth; i++)
    this.receiveAddress = this.deriveReceive(i);

  for (i = this.receiveDepth + this.lookahead; i < depth + this.lookahead; i++)
    this.deriveReceive(i);

  this.receiveDepth = depth;

  return true;
};

Wallet.prototype.setChangeDepth = function setChangeDepth(depth) {
  var i;

  if (depth <= this.changeDepth)
    return false;

  for (i = this.changeDepth; i < depth; i++)
    this.changeAddress = this.deriveChange(i);

  for (i = this.changeDepth + this.lookahead; i < depth + this.lookahead; i++)
    this.deriveChange(i);

  this.changeDepth = depth;

  return true;
};

Wallet.prototype.getPrivateKey = function getPrivateKey(enc) {
  return this.receiveAddress.getPrivateKey(enc);
};

Wallet.prototype.getScript = function getScript() {
  return this.receiveAddress.getScript();
};

Wallet.prototype.getScriptHash = function getScriptHash() {
  return this.receiveAddress.getScriptHash();
};

Wallet.prototype.getScriptAddress = function getScriptAddress() {
  return this.receiveAddress.getScriptAddress();
};

Wallet.prototype.getPublicKey = function getPublicKey(enc) {
  return this.receiveAddress.getPublicKey(enc);
};

Wallet.prototype.getKeyHash = function getKeyHash() {
  return this.receiveAddress.getKeyHash();
};

Wallet.prototype.getKeyAddress = function getKeyAddress() {
  return this.receiveAddress.getKeyAddress();
};

Wallet.prototype.getHash = function getHash() {
  return this.receiveAddress.getHash();
};

Wallet.prototype.getAddress = function getAddress() {
  return this.receiveAddress.getAddress();
};

Wallet.prototype.ownInput = function ownInput(tx, index) {
  if (tx instanceof bcoin.input)
    return tx.test(this.addressMap) ? [tx] : false;

  this.fillPrevout(tx);

  return tx.testInputs(this.addressMap, index, true);
};

Wallet.prototype.ownOutput = function ownOutput(tx, index) {
  if ((tx instanceof bcoin.output) || (tx instanceof bcoin.coin))
    return tx.test(this.addressMap) ? [tx] : false;

  return tx.testOutputs(this.addressMap, index, true);
};

Wallet.prototype.fill = function fill(tx, options) {
  var address, unspent;

  if (!options)
    options = {};

  assert(this._initialized);

  address = this.changeAddress.getAddress();

  unspent = this.getUnspent();

  result = tx.fill(unspent, address, options.fee);

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

  // Add the outputs
  outputs.forEach(function(output) {
    tx.addOutput(output);
  });

  // Fill the inputs with unspents
  if (!this.fill(tx, null, fee))
    return;

  // Sort members a la BIP69
  tx.sortMembers();

  // Find the necessary locktime if there is
  // a checklocktimeverify script in the unspents.
  target = tx.getTargetLocktime();

  // No target value. The unspents have an
  // incompatible locktime type.
  if (!target)
    return;

  // Set the locktime to target value or
  // `height - whatever` to avoid fee snipping.
  if (target.value > 0)
    tx.setLocktime(target.value);
  else
    tx.avoidFeeSnipping();

  return tx;
};

Wallet.prototype.deriveInputs = function deriveInputs(tx) {
  var paths = this.getInputPaths(tx);
  var addresses = [];
  var i;

  for (i = 0; i < paths.length; i++)
    addresses.push(this.deriveAddress(paths[i]));

  return addresses;
};

Wallet.prototype.getPath = function getPath(address) {
  if (!address || typeof address !== 'string')
    return;
  return this.addressMap[address];
};

Wallet.prototype.getInputPaths = function getInputPaths(tx) {
  var paths = [];
  var i, input, output, address, path;

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    output = input.output;
    assert(output);

    address = output.getAddress();
    path = this.getPath(address);

    if (!path)
      continue;

    paths.push(path);
  }

  return utils.uniqs(paths);
};

Wallet.prototype.getOutputPaths = function getOutputPaths(tx) {
  var paths = [];
  var i, output, address, path;

  for (i = 0; i < tx.outputs.length; i++) {
    output = tx.outputs[i];

    address = output.getAddress();
    path = this.getPath(address);

    if (!path)
      continue;

    paths.push(path);
  }

  return utils.uniqs(paths);
};

Wallet.prototype.getOutputDepth = function getOutputDepth(tx) {
  var paths = this.getOutputPaths(tx);
  var depth = { change: -1, receive: -1 };
  var i, path;

  for (i = 0; i < paths.length; i++) {
    path = this.parsePath(path);
    if (path.change) {
      if (path.index > depth.change)
        depth.change = path.index;
    } else {
      if (path.index > depth.receive)
        depth.receive = path.index;
    }
  }

  depth.change++;
  depth.receive++;

  return depth;
};

Wallet.prototype.syncOutputDepth = function syncOutputDepth(tx) {
  var depth = this.getOutputDepth(tx);
  if (depth.change >= this.changeDepth)
    this.setChangeDepth(depth.change + 1);
  if (depth.receive >= this.receiveDepth)
    this.setReceiveDepth(depth.receive + 1);
};

Wallet.prototype.scriptInputs = function scriptInputs(tx, index) {
  this.fillPrevout(tx);
  var addresses = this.deriveInputs(tx);
  return addresses.reduce(function(total, address) {
    return total + address.scriptInputs(tx, index);
  }, 0);
};

Wallet.prototype.signInputs = function signInputs(tx, type, index) {
  this.fillPrevout(tx);
  var addresses = this.deriveInputs(tx);
  return addresses.reduce(function(total, address) {
    return total + address.signInputs(tx, type, index);
  }, 0);
};

Wallet.prototype.sign = function sign(tx, type, index) {
  this.fillPrevout(tx);
  var addresses = this.deriveInputs(tx);
  return addresses.reduce(function(total, address) {
    return total + address.sign(tx, type, index);
  }, 0);
};

Wallet.prototype.addTX = function addTX(tx, block) {
  return this.tx.add(tx);
};

Wallet.prototype.getAll = function getAll(address) {
  return this.tx.getAll(address);
};

Wallet.prototype.getUnspent = function getUnspent(address) {
  return this.tx.getUnspent(address);
};

Wallet.prototype.getPending = function getPending(address) {
  return this.tx.getPending(address);
};

Wallet.prototype.getSent = function getSent(address) {
  return this.tx.getSent(address);
};

Wallet.prototype.getReceived = function getReceived(address) {
  return this.tx.getReceived(address);
};

Wallet.prototype.getBalance = function getBalance(address) {
  return this.tx.getBalance(address);
};

// Legacy
Wallet.prototype.all = Wallet.prototype.getAll;
Wallet.prototype.unspent = Wallet.prototype.getUnspent;
Wallet.prototype.pending = Wallet.prototype.getPending;
Wallet.prototype.balance = Wallet.prototype.getBalance;

Wallet.prototype.__defineGetter__('script', function() {
  return this.getScript();
});

Wallet.prototype.__defineGetter__('scriptHash', function() {
  return this.getScriptHash();
});

Wallet.prototype.__defineGetter__('scriptAddress', function() {
  return this.getScriptAddress();
});

Wallet.prototype.__defineGetter__('privateKey', function() {
  return this.getPrivateKey();
});

Wallet.prototype.__defineGetter__('publicKey', function() {
  return this.getPublicKey();
});

Wallet.prototype.__defineGetter__('keyHash', function() {
  return this.getKeyHash();
});

Wallet.prototype.__defineGetter__('keyAddress', function() {
  return this.getKeyAddress();
});

Wallet.prototype.__defineGetter__('hash', function() {
  return this.getHash();
});

Wallet.prototype.__defineGetter__('address', function() {
  return this.getAddress();
});

Wallet.prototype.toJSON = function toJSON(encrypt) {
  return {
    v: 3,
    name: 'wallet',
    network: network.type,
    type: this.type,
    m: this.m,
    n: this.n,
    derivation: this.derivation,
    copayBIP45: this.copayBIP45,
    accountIndex: this.accountIndex,
    receiveDepth: this.receiveDepth,
    changeDepth: this.changeDepth,
    master: this.master ? this.master.toJSON(encrypt) : null,
    addressMap: this.addressMap,
    keys: this.keys.map(function(key) {
      return key.xpubkey;
    }),
    balance: utils.btc(this.getBalance()),
    tx: this.tx.toJSON()
  };
};

Wallet.fromJSON = function fromJSON(json, decrypt) {
  var wallet;

  assert.equal(json.v, 3);
  assert.equal(json.name, 'wallet');

  if (json.network)
    assert.equal(json.network, network.type);

  wallet = new Wallet({
    type: json.type,
    m: json.m,
    n: json.n,
    derivation: json.derivation,
    copayBIP45: json.copayBIP45,
    accountIndex: json.accountIndex,
    receiveDepth: json.receiveDepth,
    changeDepth: json.changeDepth,
    master: json.master
      ? bcoin.hd.fromJSON(json.master, decrypt)
      : null,
    addressMap: json.addressMap,
    keys: json.keys
  });

  wallet.tx.fromJSON(json.tx);

  return wallet;
};

/**
 * Expose
 */

module.exports = Wallet;
