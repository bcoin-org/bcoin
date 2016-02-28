/**
 * address.js - address object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bcoin = require('../bcoin');
var bn = require('bn.js');
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
  this.label = options.label || '';
  this.derived = !!options.derived;
  this.addressMap = null;

  this.key = options.key || bcoin.keypair(options);
  this.path = options.path;
  this.change = !!options.change;
  this.index = options.index;

  this.type = options.type || 'pubkeyhash';
  this.keys = [];
  this.m = options.m || 1;
  this.n = options.n || 1;

  if (this.n > 1)
    this.type = 'multisig';

  assert(this.type === 'pubkeyhash' || this.type === 'multisig');

  if (this.m < 1 || this.m > this.n)
    throw new Error('m ranges between 1 and n');

  this.addKey(this.getPublicKey());

  (options.keys || []).forEach(function(key) {
    this.addKey(key);
  }, this);
}

utils.inherits(Address, EventEmitter);

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

Address.prototype.addKey = function addKey(key) {
  key = utils.ensureBuffer(key);

  var has = this.keys.some(function(k) {
    return utils.isEqual(k, key);
  });

  if (has)
    return;

  this.keys.push(key);

  this.keys = utils.sortKeys(this.keys);
};

Address.prototype.removeKey = function removeKey(key) {
  key = utils.ensureBuffer(key);

  var index = this.keys.map(function(k, i) {
    return utils.isEqual(k, key) ? i : null;
  }).filter(function(i) {
    return i !== null;
  })[0];

  if (index == null)
    return;

  this.keys.splice(index, 1);

  this.keys = utils.sortKeys(this.keys);
};

Address.prototype.getPrivateKey = function getPrivateKey(enc) {
  return this.key.getPrivateKey(enc);
};

Address.prototype.getScript = function getScript() {
  var redeem;

  if (this.type !== 'multisig')
    return;

  if (this._script)
    return this._script;

  assert(this.keys.length === this.n, 'Not all keys have been added.');

  redeem = bcoin.script.createMultisig(this.keys, this.m, this.n);
  redeem = bcoin.script.encode(redeem);

  if (this.options.program) {
    if (redeem.length > 10000)
      throw new Error('Redeem script too large (10000 byte limit).');
  } else {
    if (redeem.length > 520)
      throw new Error('Redeem script too large (520 byte limit).');
  }

  this._script = redeem;

  return this._script;
};

Address.prototype.getProgram = function getProgram() {
  var program;

  if (!this.options.program)
    return;

  if (this._program)
    return this._program;

  if (this.type === 'pubkeyhash') {
    program = bcoin.script.createWitnessProgram(
      0, Address.hash160(this.getPublicKey()));
  } else if (this.type === 'multisig') {
    program = bcoin.script.createWitnessProgram(
      0, utils.sha256(this.getScript()));
  }

  assert(program);

  this._program = bcoin.script.encode(program);

  return this._program;
};

Address.prototype.getProgramHash = function getProgramHash() {
  if (!this.options.program)
    return;

  if (this._programHash)
    return this._programHash;

  this._programHash = Address.hash160(this.getProgram());

  return this._programHash;
};

Address.prototype.getProgramAddress = function getProgramAddress() {
  if (!this.options.program)
    return;

  if (this._programAddress)
    return this._programAddress;

  this._programAddress = Address.compileHash(this.getProgramHash(), 'scripthash');

  return this._programAddress;
};

Address.prototype.getScriptHash = function getScriptHash() {
  return this.getScriptHash160();
};

Address.prototype.getScriptHash160 = function getScriptHash256() {
  if (this.type !== 'multisig')
    return;

  if (this._scriptHash160)
    return this._scriptHash160;

  this._scriptHash160 = Address.hash160(this.getScript());

  return this._scriptHash160;
};

Address.prototype.getScriptHash256 = function getScriptHash256() {
  if (this.type !== 'multisig')
    return;

  if (this._scriptHash256)
    return this._scriptHash256;

  this._scriptHash256 = Address.sha256(this.getScript());

  return this._scriptHash256;
};

Address.prototype.getScriptAddress = function getScriptAddress() {
  if (this.type !== 'multisig')
    return;

  if (this._scriptAddress)
    return this._scriptAddress;

  if (this.options.program)
    this._scriptAddress = Address.compileHash(this.getScriptHash256(), 'witnessscripthash');
  else
    this._scriptAddress = Address.compileHash(this.getScriptHash160(), 'scripthash');

  return this._scriptAddress;
};

Address.prototype.getPublicKey = function getPublicKey(enc) {
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

  if (this.options.program)
    this._address = Address.compileHash(this.getKeyHash(), 'witnesspubkeyhash');
  else
    this._address = Address.compileHash(this.getKeyHash(), 'pubkeyhash');

  return this._address;
};

Address.prototype.getHash = function getHash() {
  if (this.type === 'multisig')
    return this.getScriptHash();
  return this.getKeyHash();
};

Address.prototype.getAddress = function getAddress() {
  if (this.type === 'multisig')
    return this.getScriptAddress();
  return this.getKeyAddress();
};

Address.prototype._getAddressMap = function _getAddressMap() {
  if (this.addressMap)
    return this.addressMap;

  this.addressMap = {};

  this.addressMap[this.getKeyAddress()] = true;

  if (this.type === 'multisig')
    this.addressMap[this.getScriptAddress()] = true;

  if (this.options.program)
    this.addressMap[this.getProgramAddress()] = true;

  return this.addressMap;
};

Address.prototype.ownOutput = function ownOutput(tx, index) {
  var addressMap = this._getAddressMap();
  var outputs = tx.outputs;

  if ((tx instanceof bcoin.output) || (tx instanceof bcoin.coin)) {
    outputs = [tx];
    tx = null;
  }

  outputs = outputs.filter(function(output, i) {
    if (index != null && index !== i)
      return false;

    return output.test(addressMap);
  }, this);

  if (outputs.length === 0)
    return false;

  return outputs;
};

Address.prototype.ownInput = function ownInput(tx, index) {
  var addressMap = this._getAddressMap();
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
      return input.output.test(addressMap);

    return input.test(addressMap);
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

    if (tx.scriptInput(i, self))
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

    if (tx.signInput(i, self, type))
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

    if (tx.sign(i, self, type))
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

Address.prototype.__defineGetter__('scriptHash160', function() {
  return this.getScriptHash160();
});

Address.prototype.__defineGetter__('scriptHash256', function() {
  return this.getScriptHash256();
});

Address.prototype.__defineGetter__('scriptAddress', function() {
  return this.getScriptAddress();
});

Address.prototype.__defineGetter__('program', function() {
  return this.getProgram();
});

Address.prototype.__defineGetter__('programHash', function() {
  return this.getProgramHash();
});

Address.prototype.__defineGetter__('programAddress', function() {
  return this.getProgramAddress();
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
  key = utils.ensureBuffer(key);
  return utils.ripesha(key);
};

Address.sha256 = function sha256(key) {
  key = utils.ensureBuffer(key);
  return utils.sha256(key);
};

Address.compileHash = function compileHash(hash, prefixType) {
  var prefix, version, size, off, addr;

  if (!Buffer.isBuffer(hash))
    hash = new Buffer(hash, 'hex');

  if (!prefixType)
    prefixType = 'pubkeyhash';

  prefix = network.address.prefixes[prefixType];
  version = network.address.versions[prefixType];

  assert(prefix != null);
  assert(hash.length === 20 || hash.length === 32);

  size = 1 + hash.length + 4;

  if (version != null)
    size += 2;

  addr = new Buffer(size);

  off = 0;

  off += utils.writeU8(addr, prefix, off);
  if (version != null) {
    off += utils.writeU8(addr, version, off);
    off += utils.writeU8(addr, 0, off);
  }
  off += utils.copy(hash, addr, off);
  off += utils.copy(utils.checksum(addr.slice(0, off)), addr, off);

  return utils.toBase58(addr);
};

Address.compileData = function compileData(key, prefix) {
  if (prefix === 'witnessscripthash')
    key = Address.sha256(key);
  else
    key = Address.hash160(key);

  return Address.compileHash(key, prefix);
};

Address.parse = function parse(addr, prefixType) {
  var chk, prefix, version, size, hash;

  if (!Buffer.isBuffer(addr))
    addr = utils.fromBase58(addr);

  if (prefixType == null)
    prefixType = network.address.prefixesByVal[addr[0]];

  if (!prefixType)
    prefixType = 'pubkeyhash';

  prefix = network.address.prefixes[prefixType];
  version = network.address.versions[prefixType];

  assert(prefix != null);

  // prefix
  size = 1;

  // version + nul byte
  if (version != null)
    size += 2;

  hash = addr.slice(size, -4);

  // hash
  if (prefixType === 'witnessscripthash')
    size += 32;
  else
    size += 20;

  if (addr.length !== size + 4) {
    utils.debug('Address is not the right length.');
    return;
  }

  if (addr[0] !== prefix) {
    utils.debug('Address is not the right prefix.');
    return;
  }

  if (version != null && (addr[1] !== version || addr[2] !== 0)) {
    utils.debug('Address is not the right program version.');
    return;
  }

  chk = utils.checksum(addr.slice(0, -4));

  if (utils.readU32(chk, 0) !== utils.readU32(addr, size)) {
    utils.debug('Address checksum failed.');
    return;
  }

  return {
    type: prefixType,
    hash: hash,
    version: version == null ? -1 : version
  };
};

Address.validate = function validate(addr, prefix) {
  if (!addr)
    return false;

  if (!Address.parse(addr, prefix))
    return false;

  return true;
};

Address.getType = function getType(addr) {
  var prefix;

  if (!addr)
    return 'unknown';

  if (!Buffer.isBuffer(addr))
    addr = utils.fromBase58(addr);

  prefix = network.address.prefixes[addr[0]];

  if (!Address.validate(addr, prefix))
    return 'unknown';

  return prefix;
};

Address.prototype.toJSON = function toJSON(passphrase) {
  var key = this.key;

  if (!(key instanceof bcoin.keypair))
    key = new bcoin.keypair({ privateKey: key.getPrivateKey() });

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
    key: key.toJSON(passphrase),
    type: this.type,
    redeem: this.redeem ? utils.toHex(this.redeem) : null,
    keys: this.keys.map(utils.toBase58),
    m: this.m,
    n: this.n
  };
};

Address.fromJSON = function fromJSON(json, passphrase) {
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
    key: bcoin.keypair.fromJSON(json.key, passphrase),
    type: json.type,
    redeem: json.redeem ? new Buffer(json.redeem, 'hex') : null,
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
