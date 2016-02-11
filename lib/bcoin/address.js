/**
 * address.js - address object for bcoin
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
 * Address
 */

function Address(options) {
  if (!(this instanceof Address))
    return new Address(options);

  if (options instanceof Address)
    return options;

  EventEmitter.call(this);

  if (!options)
    options = {};

  this.options = options;
  this.storage = options.storage;
  this.label = options.label || '';
  this.derived = !!options.derived;

  this.key = bcoin.keypair(options);
  this.path = options.path;
  this.change = !!options.change;
  this.index = options.index;

  this.type = options.type || 'pubkeyhash';
  this.keys = [];
  this.m = options.m || 1;
  this.n = options.n || 1;
  this.redeem = null;

  if (this.n > 1)
    this.type = 'multisig';

  assert(this.type === 'pubkeyhash' || this.type === 'multisig');
  this.prefixType = this.type === 'multisig' ? 'scripthash' : 'pubkeyhash';

  if (network.prefixes[this.prefixType] == null)
    throw new Error('Unknown prefix: ' + this.prefixType);

  if (this.m < 1 || this.m > this.n)
    throw new Error('m ranges between 1 and n');

  this.addKey(this.getPublicKey());

  (options.keys || []).forEach(function(key) {
    this.addKey(key);
  }, this);

  if (options.redeem || options.script)
    this.setRedeem(options.redeem || options.script);

  this.prefix = 'bt/address/' + this.getID() + '/';
}

inherits(Address, EventEmitter);

Address.prototype.__defineGetter__('balance', function() {
  return this.getBalance();
});

Address.prototype.getID = function getID() {
  return this.getKeyAddress();
};

Address.prototype.getAll = function getAll() {
  return this._wallet.getAll(this);
};

Address.prototype.getUnspent = function getUnspent() {
  return this._wallet.getUnspent(this);
};

Address.prototype.getPending = function getPending() {
  return this._wallet.getPending(this);
};

Address.prototype.getSent = function getSent() {
  return this._wallet.getSent(this);
};

Address.prototype.getReceived = function getReceived() {
  return this._wallet.getReceived(this);
};

Address.prototype.getBalance = function getBalance() {
  return this._wallet.getBalance(this);
};

Address.prototype.setRedeem = function setRedeem(redeem) {
  var old = this.getScriptAddress();

  if (!utils.isBytes(redeem))
    redeem = bcoin.script.encode(redeem);

  this.type = 'multisig';
  this.prefixType = 'scripthash';
  this.redeem = redeem;
  this.emit('update script', old, this.getScriptAddress());
};

Address.prototype.addKey = function addKey(key) {
  var old = this.getScriptAddress();
  var cur;

  key = utils.toBuffer(key);

  var has = this.keys.some(function(k) {
    return utils.isEqual(k, key);
  });

  if (has)
    return;

  this.keys.push(key);

  this.keys = utils.sortKeys(this.keys);

  delete this._scriptAddress;
  delete this._scriptHash;
  delete this._script;
  this.getScriptAddress();

  cur = this.getScriptAddress();

  if (old !== cur)
    this.emit('update script', old, cur);
};

Address.prototype.removeKey = function removeKey(key) {
  var old = this.getScriptAddress();
  var cur;

  key = utils.toBuffer(key);

  var index = this.keys.map(function(k, i) {
    return utils.isEqual(k, key) ? i : null;
  }).filter(function(i) {
    return i !== null;
  })[0];

  if (index == null)
    return;

  this.keys.splice(index, 1);

  this.keys = utils.sortKeys(this.keys);

  delete this._scriptAddress;
  delete this._scriptHash;
  delete this._script;
  this.getScriptAddress();

  cur = this.getScriptAddress();

  if (old !== cur)
    this.emit('update script', old, cur);
};

Address.prototype.getPrivateKey = function getPrivateKey(enc) {
  return this.key.getPrivateKey(enc);
};

Address.toSecret = function toSecret(privateKey, compressed) {
  return bcoin.keypair.toSecret(privateKey, compressed);
};

Address.fromSecret = function fromSecret(privateKey) {
  return bcoin.keypair.fromSecret(privateKey);
};

Address.prototype.getScript = function getScript() {
  var redeem;

  if (this.prefixType !== 'scripthash')
    return;

  if (this._script)
    return this._script;

  if (this.redeem) {
    redeem = this.redeem.slice();
    assert(utils.isBytes(redeem));
  } else if (this.keys.length < this.n) {
    redeem = bcoin.script.createPubkeyhash(this.getKeyHash());
    redeem = bcoin.script.encode(redeem);
  } else {
    redeem = bcoin.script.createMultisig(this.keys, this.m, this.n);
    redeem = bcoin.script.encode(redeem);
  }

  if (redeem.length > 520)
    throw new Error('Redeem script too large (520 byte limit).');

  this._script = redeem;

  return this._script;
};

Address.prototype.getScriptHash = function getScriptHash() {
  if (this.prefixType !== 'scripthash')
    return;

  if (this._scriptHash)
    return this._scriptHash;

  this._scriptHash = Address.hash160(this.getScript());

  return this._scriptHash;
};

Address.prototype.getScriptAddress = function getScriptAddress() {
  if (this.prefixType !== 'scripthash')
    return;

  if (this._scriptAddress)
    return this._scriptAddress;

  this._scriptAddress = Address.toAddress(this.getScriptHash(), this.prefixType);

  return this._scriptAddress;
};

Address.prototype.getPublicKey = function getPublicKey(enc) {
  if (!enc) {
    if (this._pub)
      return this._pub;

    this._pub = this.key.getPublicKey();

    return this._pub;
  }

  return this.key.getPublicKey(enc);
};

Address.prototype.getKeyHash = function getKeyHash() {
  if (this._hash)
    return this._hash;

  this._hash = Address.hash160(this.getPublicKey());

  return this._hash;
};

Address.prototype.getKeyAddress = function getKeyAddress() {
  if (this._address)
    return this._address;

  this._address = Address.toAddress(this.getKeyHash(), 'pubkeyhash');

  return this._address;
};

Address.prototype.getHash = function getHash() {
  if (this.prefixType === 'scripthash')
    return this.getScriptHash();
  return this.getKeyHash();
};

Address.prototype.getAddress = function getAddress() {
  if (this.prefixType === 'scripthash')
    return this.getScriptAddress();
  return this.getKeyAddress();
};

Address.prototype.ownOutput = function ownOutput(tx, index) {
  var address = this.getAddress();
  var outputs = tx.outputs;

  if ((tx instanceof bcoin.output) || (tx instanceof bcoin.coin)) {
    outputs = [tx];
    tx = null;
  }

  outputs = outputs.filter(function(output, i) {
    if (index != null && index !== i)
      return false;

    return output.test(address);
  }, this);

  if (outputs.length === 0)
    return false;

  return outputs;
};

Address.prototype.ownInput = function ownInput(tx, index) {
  var address = this.getAddress();
  var inputs = tx.inputs;

  if (tx instanceof bcoin.input) {
    inputs = [tx];
    tx = null;
  }

  if (tx)
    this._wallet.fillPrevout(tx);

  inputs = inputs.filter(function(input, i) {
    if (index != null && index !== i)
      return false;

    if (input.output)
      return input.output.test(address);

    return input.test(address);
  }, this);

  if (inputs.length === 0)
    return false;

  return inputs;
};

Address.prototype.scriptInputs = function scriptInputs(tx, index) {
  var self = this;
  var publicKey = this.getPublicKey();
  var redeem = this.getScript();

  if (index && typeof index === 'object')
    index = tx.inputs.indexOf(index);

  return tx.inputs.reduce(function(total, input, i) {
    if (index != null && index !== i)
      return total;

    if (!input.output)
      return total;

    if (!self.ownOutput(input.output))
      return total;

    if (tx.scriptInput(i, publicKey, redeem))
      total++;

    return total;
  }, 0);
};

Address.prototype.signInputs = function signInputs(tx, type, index) {
  var self = this;
  var key = this.key;
  var total = 0;

  if (index && typeof index === 'object')
    index = tx.inputs.indexOf(index);

  if (!key.privateKey)
    return 0;

  return tx.inputs.reduce(function(total, input, i) {
    if (index != null && index !== i)
      return total;

    if (!input.output)
      return total;

    if (!self.ownOutput(input.output))
      return total;

    if (tx.signInput(i, key, type))
      total++;

    return total;
  }, 0);
};

Address.prototype.sign = function sign(tx, type, index) {
  var self = this;
  var redeem = this.getScript();
  var key = this.key;

  if (index && typeof index === 'object')
    index = tx.inputs.indexOf(index);

  if (!key.privateKey)
    return 0;

  // Add signature script to each input
  return tx.inputs.reduce(function(total, input, i) {
    if (index != null && index !== i)
      return total;

    // Filter inputs that this wallet own
    if (!input.output)
      return total;

    if (!self.ownOutput(input.output))
      return total;

    if (tx.sign(i, key, redeem, type))
      total++;

    return total;
  }, 0);
};

Address.prototype.__defineGetter__('script', function() {
  return this.getScript();
});

Address.prototype.__defineGetter__('scriptHash', function() {
  return this.getScriptHash();
});

Address.prototype.__defineGetter__('scriptAddress', function() {
  return this.getScriptAddress();
});

Address.prototype.__defineGetter__('privateKey', function() {
  return this.getPrivateKey();
});

Address.prototype.__defineGetter__('publicKey', function() {
  return this.getPublicKey();
});

Address.prototype.__defineGetter__('keyHash', function() {
  return this.getKeyHash();
});

Address.prototype.__defineGetter__('keyAddress', function() {
  return this.getKeyAddress();
});

Address.prototype.__defineGetter__('hash', function() {
  return this.getHash();
});

Address.prototype.__defineGetter__('address', function() {
  return this.getAddress();
});

Address.prototype.toExplore = function toExplore() {
  return {
    address: this.getAddress(),
    hash160: utils.toHex(this.getHash()),
    received: this.getReceived(),
    sent: this.getSent(),
    balance: this.getBalance(),
    txs: this.getAll()
  };
};

Address.hash160 = function hash160(key) {
  key = utils.toBuffer(key);
  return utils.ripesha(key);
};

Address.toAddress = function toAddress(hash, prefix) {
  var addr;

  hash = utils.toArray(hash, 'hex');

  prefix = network.prefixes[prefix || 'pubkeyhash'];
  hash = [prefix].concat(hash);

  addr = hash.concat(utils.checksum(hash));

  return utils.toBase58(addr);
};

Address.compile = function compile(key, prefix) {
  return Address.toAddress(Address.hash160(key), prefix);
};

Address.toHash = function toHash(addr, prefix) {
  var chk;

  if (prefix == null && typeof addr === 'string')
    prefix = Address.prefixes[addr[0]];

  if (!utils.isBuffer(addr))
    addr = utils.fromBase58(addr);

  prefix = network.prefixes[prefix || 'pubkeyhash'];

  if (addr.length !== 25)
    return [];

  if (addr[0] !== prefix)
    return [];

  chk = utils.checksum(addr.slice(0, -4));

  if (utils.readU32(chk, 0) !== utils.readU32(addr, 21))
    return [];

  return addr.slice(1, -4);
};

Address.__defineGetter__('prefixes', function() {
  if (Address._prefixes)
    return Address._prefixes;

  Address._prefixes = ['pubkeyhash', 'scripthash'].reduce(function(out, prefix) {
    var ch = Address.compile([], prefix)[0];
    out[ch] = prefix;
    return out;
  }, {});

  return Address._prefixes;
});

Address.validate = function validate(addr, prefix) {
  if (!addr || typeof addr !== 'string')
    return false;

  var p = Address.toHash(addr, prefix);

  return p.length !== 0;
};

Address.validateAddress = Address.validate;

Address.prototype.toJSON = function toJSON(encrypt) {
  return {
    v: 1,
    name: 'address',
    network: network.type,
    label: this.label,
    change: this.change,
    derived: this.derived,
    index: this.index,
    path: this.path,
    address: this.getAddress(),
    key: this.key.toJSON(encrypt),
    type: this.type,
    redeem: this.redeem ? utils.toHex(this.redeem) : null,
    keys: this.keys.map(utils.toBase58),
    m: this.m,
    n: this.n
  };
};

Address.fromJSON = function fromJSON(json, decrypt) {
  var w;

  assert.equal(json.v, 1);
  assert.equal(json.name, 'address');

  if (json.network)
    assert.equal(json.network, network.type);

  w = new Address({
    label: json.label,
    change: json.change,
    derived: json.derived,
    index: json.index,
    path: json.path,
    key: bcoin.keypair.fromJSON(json.key, decrypt),
    type: json.type,
    redeem: json.redeem ? utils.toArray(json.redeem, 'hex') : null,
    keys: json.keys.map(utils.fromBase58),
    m: json.m,
    n: json.n
  });

  return w;
};

/**
 * Expose
 */

module.exports = Address;
