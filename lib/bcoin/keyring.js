/*!
 * keyring.js - keyring object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

var bcoin = require('./env');
var utils = bcoin.utils;
var assert = utils.assert;

/**
 * Represents a key ring which amounts to an address. Used for {@link Wallet}.
 * @exports KeyRing
 * @constructor
 * @param {Object} options
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
  this.addressMap = null;

  this.network = bcoin.network.get(options.network);
  this.key = options.key;
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

  this.addKey(this.key);

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
 * Get public key.
 * @param {String?} enc - `"hex"` or `null`.
 * @returns {Buffer}
 */

KeyRing.prototype.getPublicKey = function getPublicKey(enc) {
  if (enc === 'base58')
    return utils.toBase58(this.key);

  if (enc === 'hex')
    return this.key.toString('hex');

  return this.key;
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
      hash = utils.ripesha(this.getPublicKey());
      program = bcoin.script.createWitnessProgram(0, hash);
    } else if (this.type === 'multisig') {
      hash = utils.sha256(this.getScript().encode());
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
    this._programHash = utils.ripesha(this.getProgram().encode());

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
    address = this.compile(hash, 'scripthash');
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
    this._scriptHash160 = utils.ripesha(this.getScript().encode());

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
    this._scriptHash256 = utils.sha256(this.getScript().encode());

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
      address = this.compile(hash, 'witnessscripthash', 0);
    } else {
      hash = this.getScriptHash160();
      address = this.compile(hash, 'scripthash');
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
    this._hash = utils.ripesha(this.getPublicKey());

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
      address = this.compile(hash, 'witnesspubkeyhash', 0);
    else
      address = this.compile(hash, 'pubkeyhash');
    this._address = address;
  }

  return this._address;
};

/**
 * Compile a hash to an address.
 * @param {Hash|Buffer} hash
 * @param {AddressType?} type
 * @param {Number?} version - Witness version.
 * @returns {Base58Address}
 * @throws Error on bad hash/prefix.
 */

KeyRing.prototype.compile = function compile(hash, type, version) {
  return bcoin.address.toBase58(hash, type, version, this.network);
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
 * Build input scripts and sign inputs for a transaction. Only attempts
 * to build/sign inputs that are redeemable by this address.
 * @param {MTX} tx
 * @param {HDPrivateKey|KeyPair|Buffer} key - Private key.
 * @param {Number?} index - Index of input. If not present,
 * it will attempt to build and sign all redeemable inputs.
 * @param {SighashType?} type
 * @returns {Number} Total number of inputs scripts built and signed.
 */

KeyRing.prototype.sign = function sign(tx, key, index, type) {
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

    if (tx.sign(i, this, key, type))
      total++;
  }

  return total;
};

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
 * Convert an KeyRing to a more json-friendly object.
 * @param {String?} passphrase - KeyRing passphrase
 * @returns {Object}
 */

KeyRing.prototype.toJSON = function toJSON() {
  return {
    v: 1,
    name: 'address',
    address: this.getAddress(),
    network: this.network.type,
    change: this.change,
    index: this.index,
    path: this.path,
    key: utils.toBase58(this.key),
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

KeyRing.fromJSON = function fromJSON(json) {
  assert.equal(json.v, 1);
  assert.equal(json.name, 'address');
  return new KeyRing({
    nework: json.network,
    change: json.change,
    index: json.index,
    path: json.path,
    key: utils.fromBase58(json.key),
    type: json.type,
    witness: json.witness,
    keys: json.keys.map(utils.fromBase58),
    m: json.m,
    n: json.n
  });
};

/*
 * Expose
 */

module.exports = KeyRing;
