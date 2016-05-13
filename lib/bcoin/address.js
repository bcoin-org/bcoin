/*!
 * address.js - address object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

var bcoin = require('../bcoin');
var utils = bcoin.utils;
var assert = utils.assert;
var network = bcoin.protocol.network;
var BufferWriter = require('./writer');
var BufferReader = require('./reader');

/**
 * Represents a key ring which amounts to an address. Used for {@link Wallet}.
 * @exports Address
 * @constructor
 * @param {Object} options
 * @param {String?} options.label
 * @param {Boolean?} options.derived
 * @param {HDPrivateKey|HDPublicKey} options.key
 * @param {String?} options.path
 * @param {Boolean?} options.change
 * @param {Number?} options.index
 * @param {String?} options.type - `"pubkeyhash"` or `"multisig"`.
 * @param {Buffer[]} options.keys - Shared multisig keys.
 * @param {Number?} options.m - Multisig `m` value.
 * @param {Number?} options.n - Multisig `n` value.
 * @param {Boolean?} options.witness - Whether witness programs are enabled.
 */

function Address(options) {
  var i;

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

  if (options.keys) {
    for (i = 0; i < options.keys.length; i++)
      this.addKey(options.keys[i]);
  }
}

/**
 * Test an object to see if it is an Address.
 * @param {Object} obj
 * @returns {Boolean}
 */

Address.isAddress = function isAddress(obj) {
  return obj
    && Array.isArray(obj.keys)
    && typeof obj._getAddressMap === 'function';
};

/**
 * Return address ID (pubkeyhash address of pubkey).
 * @returns {Base58Address}
 */

Address.prototype.getID = function getID() {
  return this.getKeyAddress();
};

/**
 * Add a key to shared keys.
 * @param {Buffer} key
 */

Address.prototype.addKey = function addKey(key) {
  if (utils.indexOf(this.keys, key) !== -1)
    return;

  this.keys.push(key);

  this.keys = utils.sortKeys(this.keys);
};

/**
 * Remove a key from shared keys.
 * @param {Buffer} key
 */

Address.prototype.removeKey = function removeKey(key) {
  var index = utils.indexOf(this.keys, key);

  if (index === -1)
    return;

  this.keys.splice(index, 1);

  this.keys = utils.sortKeys(this.keys);
};

/**
 * Get private key.
 * @param {String?} enc - `"hex"` or `null`.
 * @returns {Buffer}
 */

Address.prototype.getPrivateKey = function getPrivateKey(enc) {
  return this.key.getPrivateKey(enc);
};

/**
 * Get public key.
 * @param {String?} enc - `"hex"` or `null`.
 * @returns {Buffer}
 */

Address.prototype.getPublicKey = function getPublicKey(enc) {
  return this.key.getPublicKey(enc);
};

/**
 * Get redeem script.
 * @returns {Script}
 */

Address.prototype.getScript = function getScript() {
  var redeem;

  if (this.type !== 'multisig')
    return;

  if (!this._script) {
    assert(this.keys.length === this.n, 'Not all keys have been added.');

    redeem = bcoin.script.createMultisig(this.keys, this.m, this.n);

    if (redeem.getSize() > 520)
      throw new Error('Redeem script too large (520 byte limit).');

    this._script = redeem;
  }

  return this._script;
};

/**
 * Get witness program.
 * @returns {Buffer}
 */

Address.prototype.getProgram = function getProgram() {
  var hash, program;

  if (!this.witness)
    return;

  if (!this._program) {
    if (this.type === 'pubkeyhash') {
      hash = Address.hash160(this.getPublicKey());
      program = bcoin.script.createWitnessProgram(0, hash);
    } else if (this.type === 'multisig') {
      hash = Address.sha256(this.getScript().encode());
      program = bcoin.script.createWitnessProgram(0, hash);
    } else {
      assert(false, 'Unknown address type.');
    }
    this._program = program;
  }

  return this._program;
};

/**
 * Get address' ripemd160 program scripthash
 * (for witness programs behind a scripthash).
 * @param {String?} enc - `"hex"` or `null`.
 * @returns {Buffer}
 */

Address.prototype.getProgramHash = function getProgramHash(enc) {
  if (!this.witness)
    return;

  if (!this._programHash)
    this._programHash = Address.hash160(this.getProgram().encode());

  return enc === 'hex'
    ? this._programHash.toString('hex')
    : this._programHash;
};

/**
 * Get address' scripthash address for witness program.
 * @returns {Base58Address}
 */

Address.prototype.getProgramAddress = function getProgramAddress() {
  var hash, address;

  if (!this.witness)
    return;

  if (!this._programAddress) {
    hash = this.getProgramHash();
    address = this.compileHash(hash, 'scripthash');
    this._programAddress = address;
  }

  return this._programAddress;
};

/**
 * Get scripthash.
 * @param {String?} enc - `"hex"` or `null`.
 * @returns {Buffer}
 */

Address.prototype.getScriptHash = function getScriptHash(enc) {
  if (this.witness)
    return this.getScriptHash256(enc);
  return this.getScriptHash160(enc);
};

/**
 * Get ripemd160 scripthash.
 * @param {String?} enc - `"hex"` or `null`.
 * @returns {Buffer}
 */

Address.prototype.getScriptHash160 = function getScriptHash256(enc) {
  if (this.type !== 'multisig')
    return;

  if (!this._scriptHash160)
    this._scriptHash160 = Address.hash160(this.getScript().encode());

  return enc === 'hex'
    ? this._scriptHash160.toString('hex')
    : this._scriptHash160;
};

/**
 * Get sha256 scripthash.
 * @param {String?} enc - `"hex"` or `null`.
 * @returns {Buffer}
 */

Address.prototype.getScriptHash256 = function getScriptHash256(enc) {
  if (this.type !== 'multisig')
    return;

  if (!this._scriptHash256)
    this._scriptHash256 = Address.sha256(this.getScript().encode());

  return enc === 'hex'
    ? this._scriptHash256.toString('hex')
    : this._scriptHash256;
};

/**
 * Get scripthash address.
 * @returns {Base58Address}
 */

Address.prototype.getScriptAddress = function getScriptAddress() {
  var hash, address;

  if (this.type !== 'multisig')
    return;

  if (!this._scriptAddress) {
    if (this.witness) {
      hash = this.getScriptHash256();
      address = this.compileHash(hash, 'witnessscripthash', 0);
    } else {
      hash = this.getScriptHash160();
      address = this.compileHash(hash, 'scripthash');
    }
    this._scriptAddress = address;
  }

  return this._scriptAddress;
};

/**
 * Get public key hash.
 * @param {String?} enc - `"hex"` or `null`.
 * @returns {Buffer}
 */

Address.prototype.getKeyHash = function getKeyHash(enc) {
  if (!this._hash)
    this._hash = Address.hash160(this.getPublicKey());

  return enc === 'hex'
    ? this._hash.toString('hex')
    : this._hash;
};

/**
 * Get pubkeyhash address.
 * @returns {Base58Address}
 */

Address.prototype.getKeyAddress = function getKeyAddress() {
  var hash, address;

  if (!this._address) {
    hash = this.getKeyHash();
    if (this.witness)
      address = this.compileHash(hash, 'witnesspubkeyhash', 0);
    else
      address = this.compileHash(hash, 'pubkeyhash');
    this._address = address;
  }

  return this._address;
};

/**
 * Get hash.
 * @param {String?} enc - `"hex"` or `null`.
 * @returns {Buffer}
 */

Address.prototype.getHash = function getHash(enc) {
  if (this.type === 'multisig')
    return this.getScriptHash(enc);
  return this.getKeyHash(enc);
};

/**
 * Get base58 address.
 * @returns {Base58Address}
 */

Address.prototype.getAddress = function getAddress() {
  if (this.type === 'multisig')
    return this.getScriptAddress();
  return this.getKeyAddress();
};

Address.prototype._getAddressMap = function _getAddressMap() {
  if (!this.addressMap) {
    this.addressMap = {};

    this.addressMap[this.getKeyAddress()] = true;

    if (this.type === 'multisig')
      this.addressMap[this.getScriptAddress()] = true;

    if (this.witness)
      this.addressMap[this.getProgramAddress()] = true;
  }

  return this.addressMap;
};

/**
 * Check whether transaction input belongs to this address.
 * @param {TX|Output} tx - Transaction or Output.
 * @param {Number?} index - Output index.
 * @returns {Boolean}
 */

Address.prototype.ownInput = function ownInput(tx, index) {
  var addressMap = this._getAddressMap();

  if (tx instanceof bcoin.input)
    return tx.test(addressMap);

  return tx.testInputs(addressMap, index);
};

/**
 * Check whether transaction output belongs to this address.
 * @param {TX|Output} tx - Transaction or Output.
 * @param {Number?} index - Output index.
 * @returns {Boolean}
 */

Address.prototype.ownOutput = function ownOutput(tx, index) {
  var addressMap = this._getAddressMap();

  if (tx instanceof bcoin.output)
    return tx.test(addressMap);

  return tx.testOutputs(addressMap, index);
};

/**
 * Build input scripts templates for a transaction (does not
 * sign, only creates signature slots). Only builds scripts
 * for inputs that are redeemable by this address.
 * @param {MTX} tx
 * @param {Number?} index - Index of input. If not present,
 * it will attempt to sign all redeemable inputs.
 * @returns {Number} Total number of scripts built.
 */

Address.prototype.scriptInputs = function scriptInputs(tx, index) {
  var total = 0;
  var i, input;

  if (index && typeof index === 'object')
    index = tx.inputs.indexOf(index);

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];

    if (index != null && index !== i)
      continue;

    if (!input.coin)
      continue;

    if (!this.ownOutput(input.coin))
      continue;

    if (tx.scriptInput(i, this))
      total++;
  }

  return total;
};

/**
 * Sign inputs for a transaction. Only attempts to sign inputs
 * that are redeemable by this address.
 * @param {MTX} tx
 * @param {Number?} index - Index of input. If not present,
 * it will attempt to sign all redeemable inputs.
 * @param {SighashType?} type
 * @returns {Number} Total number of inputs signed.
 */

Address.prototype.signInputs = function signInputs(tx, index, type) {
  var total = 0;
  var i, input;

  if (index && typeof index === 'object')
    index = tx.inputs.indexOf(index);

  if (!this.key.privateKey)
    return 0;

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];

    if (index != null && index !== i)
      continue;

    if (!input.coin)
      continue;

    if (!this.ownOutput(input.coin))
      continue;

    if (tx.signInput(i, this, type))
      total++;
  }

  return total;
};

/**
 * Build input scripts and sign inputs for a transaction. Only attempts
 * to build/sign inputs that are redeemable by this address.
 * @param {MTX} tx
 * @param {Number?} index - Index of input. If not present,
 * it will attempt to build and sign all redeemable inputs.
 * @param {SighashType?} type
 * @returns {Number} Total number of inputs scripts built and signed.
 */

Address.prototype.sign = function sign(tx, index, type) {
  var total = 0;
  var i, input;

  if (index && typeof index === 'object')
    index = tx.inputs.indexOf(index);

  if (!this.key.privateKey)
    return 0;

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];

    if (index != null && index !== i)
      continue;

    if (!input.coin)
      continue;

    if (!this.ownOutput(input.coin))
      continue;

    if (tx.sign(i, this, type))
      total++;
  }

  return total;
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

/**
 * Perform a hash160 (sha256 + ripemd160)
 * @param {Buffer} key
 * @returns {Buffer}
 */

Address.hash160 = function hash160(key) {
  return utils.ripesha(key);
};

/**
 * @param {Buffer} key
 * @returns {Buffer}
 */

Address.sha256 = function sha256(key) {
  return utils.sha256(key);
};

/**
 * Compile a hash to an address.
 * @param {Hash|Buffer} hash
 * @param {AddressType?} type
 * @param {Number?} version - Witness version.
 * @returns {Base58Address}
 * @throws Error on bad hash/prefix.
 */

Address.compileHash = function compileHash(hash, type, version, network) {
  var p, prefix;

  if (!Buffer.isBuffer(hash))
    hash = new Buffer(hash, 'hex');

  if (!type)
    type = 'pubkeyhash';

  network = bcoin.network.get(network);

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

/**
 * Hash data and compile hash to an address.
 * @param {Hash|Buffer} hash
 * @param {AddressType?} type
 * @param {Number?} version - Witness program version.
 * @returns {Base58Address}
 */

Address.compileData = function compileData(data, type, version, network) {
  if (type === 'witnessscripthash')
    data = Address.sha256(data);
  else
    data = Address.hash160(data);

  return Address.compileHash(data, type, version, network);
};

/**
 * Parse a base58 address.
 * @param {Base58Address} address
 * @returns {ParsedAddress}
 * @throws Parse error
 */

Address.parse = function parse(address, network) {
  var prefix, type, version, hash;

  if (!Buffer.isBuffer(address))
    address = utils.fromBase58(address);

  p = new BufferReader(address, true);
  prefix = p.readU8();

  network = bcoin.network.get(network);

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

/**
 * Validate an address, optionally test against a type.
 * @param {String} address - Can be of any type in reality.
 * @param {AddressType}
 * @returns {Boolean}
 */

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

Address.prototype.compileHash = function compileHash(hash, type, version) {
  return Address.compileHash(hash, type, version, this.network);
};

/**
 * Convert an Address to a more json-friendly object.
 * @param {String?} passphrase - Address passphrase
 * @returns {Object}
 */

Address.prototype.toJSON = function toJSON(passphrase) {
  var key = this.key;

  if (!(key instanceof bcoin.keypair))
    key = new bcoin.keypair({ privateKey: key.getPrivateKey() });

  return {
    v: 1,
    name: 'address',
    network: this.network.type,
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

/**
 * Instantiate an Address from a jsonified transaction object.
 * @param {Object} json - The jsonified transaction object.
 * @param {String?} passphrase - Address passphrase
 * @returns {Address}
 */

Address.fromJSON = function fromJSON(json, passphrase) {
  var w;

  assert.equal(json.v, 1);
  assert.equal(json.name, 'address');

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

module.exports = Address;
