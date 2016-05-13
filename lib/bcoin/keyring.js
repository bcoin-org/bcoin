/*!
 * address.js - address object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

var bcoin = require('./env');
var utils = bcoin.utils;
var assert = utils.assert;
var networks = bcoin.protocol.network;
var BufferWriter = require('./writer');
var BufferReader = require('./reader');

/**
 * Represents a key ring which amounts to an address. Used for {@link Wallet}.
 * @exports KeyRing
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

function KeyRing(options) {
  var i;

  if (!(this instanceof KeyRing))
    return new KeyRing(options);

  if (options instanceof KeyRing)
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
 * Test an object to see if it is an KeyRing.
 * @param {Object} obj
 * @returns {Boolean}
 */

KeyRing.isKeyRing = function isKeyRing(obj) {
  return obj
    && Array.isArray(obj.keys)
    && typeof obj._getAddressMap === 'function';
};

/**
 * Return address ID (pubkeyhash address of pubkey).
 * @returns {Base58Address}
 */

KeyRing.prototype.getID = function getID() {
  return this.getKeyAddress();
};

/**
 * Add a key to shared keys.
 * @param {Buffer} key
 */

KeyRing.prototype.addKey = function addKey(key) {
  if (utils.indexOf(this.keys, key) !== -1)
    return;

  this.keys.push(key);

  this.keys = utils.sortKeys(this.keys);
};

/**
 * Remove a key from shared keys.
 * @param {Buffer} key
 */

KeyRing.prototype.removeKey = function removeKey(key) {
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

KeyRing.prototype.getPrivateKey = function getPrivateKey(enc) {
  return this.key.getPrivateKey(enc);
};

/**
 * Get public key.
 * @param {String?} enc - `"hex"` or `null`.
 * @returns {Buffer}
 */

KeyRing.prototype.getPublicKey = function getPublicKey(enc) {
  return this.key.getPublicKey(enc);
};

/**
 * Get redeem script.
 * @returns {Script}
 */

KeyRing.prototype.getScript = function getScript() {
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

KeyRing.prototype.getProgram = function getProgram() {
  var hash, program;

  if (!this.witness)
    return;

  if (!this._program) {
    if (this.type === 'pubkeyhash') {
      hash = KeyRing.hash160(this.getPublicKey());
      program = bcoin.script.createWitnessProgram(0, hash);
    } else if (this.type === 'multisig') {
      hash = KeyRing.sha256(this.getScript().encode());
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

KeyRing.prototype.getProgramHash = function getProgramHash(enc) {
  if (!this.witness)
    return;

  if (!this._programHash)
    this._programHash = KeyRing.hash160(this.getProgram().encode());

  return enc === 'hex'
    ? this._programHash.toString('hex')
    : this._programHash;
};

/**
 * Get address' scripthash address for witness program.
 * @returns {Base58Address}
 */

KeyRing.prototype.getProgramAddress = function getProgramAddress() {
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

KeyRing.prototype.getScriptHash = function getScriptHash(enc) {
  if (this.witness)
    return this.getScriptHash256(enc);
  return this.getScriptHash160(enc);
};

/**
 * Get ripemd160 scripthash.
 * @param {String?} enc - `"hex"` or `null`.
 * @returns {Buffer}
 */

KeyRing.prototype.getScriptHash160 = function getScriptHash256(enc) {
  if (this.type !== 'multisig')
    return;

  if (!this._scriptHash160)
    this._scriptHash160 = KeyRing.hash160(this.getScript().encode());

  return enc === 'hex'
    ? this._scriptHash160.toString('hex')
    : this._scriptHash160;
};

/**
 * Get sha256 scripthash.
 * @param {String?} enc - `"hex"` or `null`.
 * @returns {Buffer}
 */

KeyRing.prototype.getScriptHash256 = function getScriptHash256(enc) {
  if (this.type !== 'multisig')
    return;

  if (!this._scriptHash256)
    this._scriptHash256 = KeyRing.sha256(this.getScript().encode());

  return enc === 'hex'
    ? this._scriptHash256.toString('hex')
    : this._scriptHash256;
};

/**
 * Get scripthash address.
 * @returns {Base58Address}
 */

KeyRing.prototype.getScriptAddress = function getScriptAddress() {
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

KeyRing.prototype.getKeyHash = function getKeyHash(enc) {
  if (!this._hash)
    this._hash = KeyRing.hash160(this.getPublicKey());

  return enc === 'hex'
    ? this._hash.toString('hex')
    : this._hash;
};

/**
 * Get pubkeyhash address.
 * @returns {Base58Address}
 */

KeyRing.prototype.getKeyAddress = function getKeyAddress() {
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

KeyRing.prototype.getHash = function getHash(enc) {
  if (this.type === 'multisig')
    return this.getScriptHash(enc);
  return this.getKeyHash(enc);
};

/**
 * Get base58 address.
 * @returns {Base58Address}
 */

KeyRing.prototype.getAddress = function getAddress() {
  if (this.type === 'multisig')
    return this.getScriptAddress();
  return this.getKeyAddress();
};

KeyRing.prototype._getAddressMap = function _getAddressMap() {
  if (!this.addressMap) {
    this.addressMap = {};

    this.addressMap[this.getKeyHash('hex')] = true;

    if (this.type === 'multisig')
      this.addressMap[this.getScriptHash('hex')] = true;

    if (this.witness)
      this.addressMap[this.getProgramHash('hex')] = true;
  }

  return this.addressMap;
};

/**
 * Check whether transaction input belongs to this address.
 * @param {TX|Output} tx - Transaction or Output.
 * @param {Number?} index - Output index.
 * @returns {Boolean}
 */

KeyRing.prototype.ownInput = function ownInput(tx, index) {
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

KeyRing.prototype.ownOutput = function ownOutput(tx, index) {
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

KeyRing.prototype.scriptInputs = function scriptInputs(tx, index) {
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

KeyRing.prototype.signInputs = function signInputs(tx, index, type) {
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

KeyRing.prototype.sign = function sign(tx, index, type) {
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

KeyRing.prototype.__defineGetter__('privateKey', function() {
  return this.getPrivateKey();
});

KeyRing.prototype.__defineGetter__('publicKey', function() {
  return this.getPublicKey();
});

KeyRing.prototype.__defineGetter__('script', function() {
  return this.getScript();
});

KeyRing.prototype.__defineGetter__('scriptHash', function() {
  return this.getScriptHash();
});

KeyRing.prototype.__defineGetter__('scriptHash160', function() {
  return this.getScriptHash160();
});

KeyRing.prototype.__defineGetter__('scriptHash256', function() {
  return this.getScriptHash256();
});

KeyRing.prototype.__defineGetter__('scriptAddress', function() {
  return this.getScriptAddress();
});

KeyRing.prototype.__defineGetter__('program', function() {
  return this.getProgram();
});

KeyRing.prototype.__defineGetter__('programHash', function() {
  return this.getProgramHash();
});

KeyRing.prototype.__defineGetter__('programAddress', function() {
  return this.getProgramAddress();
});

KeyRing.prototype.__defineGetter__('keyHash', function() {
  return this.getKeyHash();
});

KeyRing.prototype.__defineGetter__('keyAddress', function() {
  return this.getKeyAddress();
});

KeyRing.prototype.__defineGetter__('hash', function() {
  return this.getHash();
});

KeyRing.prototype.__defineGetter__('address', function() {
  return this.getAddress();
});

/**
 * Perform a hash160 (sha256 + ripemd160)
 * @param {Buffer} key
 * @returns {Buffer}
 */

KeyRing.hash160 = function hash160(key) {
  return utils.ripesha(key);
};

/**
 * @param {Buffer} key
 * @returns {Buffer}
 */

KeyRing.sha256 = function sha256(key) {
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

KeyRing.compileHash = function compileHash(hash, type, version, network) {
  return bcoin.script.Address.toBase58(hash, type, version, network);
};

/**
 * Hash data and compile hash to an address.
 * @param {Hash|Buffer} hash
 * @param {AddressType?} type
 * @param {Number?} version - Witness program version.
 * @returns {Base58Address}
 */

KeyRing.compileData = function compileData(data, type, version, network) {
  if (type === 'witnessscripthash')
    data = KeyRing.sha256(data);
  else
    data = KeyRing.hash160(data);

  return KeyRing.compileHash(data, type, version, network);
};

/**
 * Parse a base58 address.
 * @param {Base58Address} address
 * @returns {ParsedAddress}
 * @throws Parse error
 */

KeyRing.parse = function parse(address) {
  return bcoin.script.Address.parseBase58(address);
};

/**
 * Validate an address, optionally test against a type.
 * @param {String} address - Can be of any type in reality.
 * @param {AddressType}
 * @returns {Boolean}
 */

KeyRing.validate = function validate(address, type) {
  return bcoin.script.Address.validate(address, type);
};

KeyRing.prototype.compileHash = function compileHash(hash, type, version) {
  return KeyRing.compileHash(hash, type, version, this.network);
};

/**
 * Convert an KeyRing to a more json-friendly object.
 * @param {String?} passphrase - KeyRing passphrase
 * @returns {Object}
 */

KeyRing.prototype.toJSON = function toJSON(passphrase) {
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
 * Instantiate an KeyRing from a jsonified transaction object.
 * @param {Object} json - The jsonified transaction object.
 * @param {String?} passphrase - KeyRing passphrase
 * @returns {KeyRing}
 */

KeyRing.fromJSON = function fromJSON(json, passphrase) {
  var w;

  assert.equal(json.v, 1);
  assert.equal(json.name, 'address');

  w = new KeyRing({
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

module.exports = KeyRing;
