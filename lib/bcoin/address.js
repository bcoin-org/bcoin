/**
 * address.js - address object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bcoin = require('../bcoin');
var utils = bcoin.utils;
var assert = utils.assert;
var network = bcoin.protocol.network;
var BufferWriter = require('./writer');
var BufferReader = require('./reader');

/**
 * Address
 */

function Address(options) {
  if (!(this instanceof Address))
    return new Address(options);

  if (options instanceof Address)
    return options;

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
  this.witness = options.witness || false;

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

Address.isAddress = function isAddress(obj) {
  return obj
    && Array.isArray(obj.keys)
    && typeof obj._getAddressMap === 'function';
};

Address.prototype.getID = function getID() {
  return this.getKeyAddress();
};

Address.prototype.addKey = function addKey(key) {
  if (utils.indexOf(this.keys, key) !== -1)
    return;

  this.keys.push(key);

  this.keys = utils.sortKeys(this.keys);
};

Address.prototype.removeKey = function removeKey(key) {
  var index = utils.indexOf(this.keys, key);

  if (index === -1)
    return;

  this.keys.splice(index, 1);

  this.keys = utils.sortKeys(this.keys);
};

Address.prototype.getPrivateKey = function getPrivateKey(enc) {
  return this.key.getPrivateKey(enc);
};

Address.prototype.getPublicKey = function getPublicKey(enc) {
  return this.key.getPublicKey(enc);
};

Address.prototype.getScript = function getScript() {
  var redeem;

  if (this.type !== 'multisig')
    return;

  if (this._script)
    return this._script;

  assert(this.keys.length === this.n, 'Not all keys have been added.');

  redeem = bcoin.script.createMultisig(this.keys, this.m, this.n);

  if (this.witness) {
    if (redeem.getSize() > 10000)
      throw new Error('Redeem script too large (10000 byte limit).');
  } else {
    if (redeem.getSize() > 520)
      throw new Error('Redeem script too large (520 byte limit).');
  }

  this._script = redeem;

  return this._script;
};

Address.prototype.getProgram = function getProgram() {
  var program;

  if (!this.witness)
    return;

  if (this._program)
    return this._program;

  if (this.type === 'pubkeyhash') {
    program = bcoin.script.createWitnessProgram(
      0, Address.hash160(this.getPublicKey()));
  } else if (this.type === 'multisig') {
    program = bcoin.script.createWitnessProgram(
      0, Address.sha256(this.getScript().encode()));
  }

  assert(program);

  this._program = program;

  return this._program;
};

Address.prototype.getProgramHash = function getProgramHash() {
  if (!this.witness)
    return;

  if (this._programHash)
    return this._programHash;

  this._programHash = Address.hash160(this.getProgram().encode());

  return this._programHash;
};

Address.prototype.getProgramAddress = function getProgramAddress() {
  if (!this.witness)
    return;

  if (this._programAddress)
    return this._programAddress;

  this._programAddress =
    Address.compileHash(this.getProgramHash(), 'scripthash');

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

  this._scriptHash160 = Address.hash160(this.getScript().encode());

  return this._scriptHash160;
};

Address.prototype.getScriptHash256 = function getScriptHash256() {
  if (this.type !== 'multisig')
    return;

  if (this._scriptHash256)
    return this._scriptHash256;

  this._scriptHash256 = Address.sha256(this.getScript().encode());

  return this._scriptHash256;
};

Address.prototype.getScriptAddress = function getScriptAddress() {
  if (this.type !== 'multisig')
    return;

  if (this._scriptAddress)
    return this._scriptAddress;

  if (this.witness) {
    this._scriptAddress =
      Address.compileHash(this.getScriptHash256(), 'witnessscripthash', 0);
  } else {
    this._scriptAddress =
      Address.compileHash(this.getScriptHash160(), 'scripthash');
  }

  return this._scriptAddress;
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

  if (this.witness)
    this._address = Address.compileHash(this.getKeyHash(), 'witnesspubkeyhash', 0);
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

  if (this.witness)
    this.addressMap[this.getProgramAddress()] = true;

  return this.addressMap;
};

Address.prototype.ownInput = function ownInput(tx, index) {
  var addressMap = this._getAddressMap();

  if (tx instanceof bcoin.input)
    return tx.test(addressMap);

  return tx.testInputs(addressMap, index);
};

Address.prototype.ownOutput = function ownOutput(tx, index) {
  var addressMap = this._getAddressMap();

  if (tx instanceof bcoin.output)
    return tx.test(addressMap);

  return tx.testOutputs(addressMap, index);
};

Address.prototype.scriptInputs = function scriptInputs(tx, index) {
  var self = this;

  if (index && typeof index === 'object')
    index = tx.inputs.indexOf(index);

  return tx.inputs.reduce(function(total, input, i) {
    if (index != null && index !== i)
      return total;

    if (!input.coin)
      return total;

    if (!self.ownOutput(input.coin))
      return total;

    if (tx.scriptInput(i, self))
      total++;

    return total;
  }, 0);
};

Address.prototype.signInputs = function signInputs(tx, type, index) {
  var self = this;

  if (index && typeof index === 'object')
    index = tx.inputs.indexOf(index);

  if (!this.key.privateKey)
    return 0;

  return tx.inputs.reduce(function(total, input, i) {
    if (index != null && index !== i)
      return total;

    if (!input.coin)
      return total;

    if (!self.ownOutput(input.coin))
      return total;

    if (tx.signInput(i, self, type))
      total++;

    return total;
  }, 0);
};

Address.prototype.sign = function sign(tx, type, index) {
  var self = this;

  if (index && typeof index === 'object')
    index = tx.inputs.indexOf(index);

  if (!this.key.privateKey)
    return 0;

  // Add signature script to each input
  return tx.inputs.reduce(function(total, input, i) {
    if (index != null && index !== i)
      return total;

    // Filter inputs that this wallet own
    if (!input.coin)
      return total;

    if (!self.ownOutput(input.coin))
      return total;

    if (tx.sign(i, self, type))
      total++;

    return total;
  }, 0);
};

Address.prototype.__defineGetter__('privateKey', function() {
  return this.getPrivateKey();
});

Address.prototype.__defineGetter__('publicKey', function() {
  return this.getPublicKey();
});

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

Address.hash160 = function hash160(key) {
  return utils.ripesha(key);
};

Address.sha256 = function sha256(key) {
  return utils.sha256(key);
};

Address.compileHash = function compileHash(hash, type, version) {
  var p, prefix;

  if (!Buffer.isBuffer(hash))
    hash = new Buffer(hash, 'hex');

  if (!type)
    type = 'pubkeyhash';

  prefix = network.address.prefixes[type];

  if (version == null)
    version = network.address.versions[type];

  assert(prefix != null, 'Not a valid address prefix.');

  if (version == null)
    assert(hash.length === 20, 'Hash is the wrong size.');
  else if (version === 0 && type === 'witnesspubkeyhash')
    assert(hash.length === 20, 'Hash is the wrong size.');
  else if (version === 0 && type === 'witnessscripthash')
    assert(hash.length === 32, 'Hash is the wrong size.');

  p = new BufferWriter();

  p.writeU8(prefix);
  if (version != null) {
    p.writeU8(version);
    p.writeU8(0)
  }
  p.writeBytes(hash);
  p.writeChecksum();

  return utils.toBase58(p.render());
};

Address.compileData = function compileData(data, type, version) {
  if (type === 'witnessscripthash')
    data = Address.sha256(data);
  else
    data = Address.hash160(data);

  return Address.compileHash(data, type, version);
};

Address.parse = function parse(address) {
  var prefix, type, version, hash;

  if (!Buffer.isBuffer(address))
    address = utils.fromBase58(address);

  p = new BufferReader(address, true);
  prefix = p.readU8();

  type = network.address.prefixesByVal[prefix];
  version = network.address.versions[type];

  assert(type != null, 'Not a valid address prefix.');

  if (version != null) {
    version = p.readU8();
    assert(version >= 0 && version <= 16, 'Bad program version.');
    assert(p.readU8() === 0, 'Address version padding is non-zero.');
  }

  if (type === 'witnessscripthash')
    hash = p.readBytes(32);
  else
    hash = p.readBytes(20);

  p.verifyChecksum();

  return {
    type: type,
    hash: hash,
    version: version == null ? -1 : version
  };
};

Address.validate = function validate(address, type) {
  if (!address)
    return false;

  if (!Buffer.isBuffer(address) && typeof address !== 'string')
    return false;

  try {
    address = Address.parse(address);
  } catch (e) {
    return false;
  }

  if (type && address.type !== type)
    return false;

  return true;
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
    witness: this.witness,
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
    witness: json.witness,
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
