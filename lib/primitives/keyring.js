/*!
 * keyring.js - keyring object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var bcoin = require('../env');
var constants = bcoin.constants;
var utils = bcoin.utils;
var crypto = require('../crypto/crypto');
var assert = utils.assert;
var networks = bcoin.networks;
var BufferReader = require('../utils/reader');
var BufferWriter = require('../utils/writer');
var scriptTypes = constants.scriptTypes;
var Address = require('./address');
var ec = require('../crypto/ec');

/**
 * Represents a key ring which amounts to an address.
 * @exports KeyRing
 * @constructor
 * @param {Object} options
 * @param {HDPrivateKey|HDPublicKey|Buffer} options.key
 * @param {Buffer[]} options.keys - Shared multisig keys.
 * @param {Number?} options.m - Multisig `m` value.
 * @param {Number?} options.n - Multisig `n` value.
 * @param {Boolean?} options.witness - Whether witness programs are enabled.
 */

function KeyRing(options, network) {
  if (!(this instanceof KeyRing))
    return new KeyRing(options, network);

  this.network = bcoin.network.get();
  this.witness = false;
  this.publicKey = constants.ZERO_KEY;
  this.privateKey = null;
  this.script = null;

  this._keyHash = null;
  this._keyAddress = null;
  this._program = null;
  this._nestedHash = null;
  this._nestedAddress = null;
  this._scriptHash160 = null;
  this._scriptHash256 = null;
  this._scriptAddress = null;

  if (options)
    this.fromOptions(options, network);
}

/**
 * Inject properties from options object.
 * @private
 * @param {Object} options
 */

KeyRing.prototype.fromOptions = function fromOptions(options, network) {
  var key = toKey(options);
  var script = options.script;
  var compressed = options.compressed;
  var network = options.network;

  if (Buffer.isBuffer(key))
    return this.fromKey(key, network);

  key = toKey(options.key);

  if (options.publicKey)
    key = toKey(options.publicKey);

  if (options.privateKey)
    key = toKey(options.privateKey);

  if (options.witness != null) {
    assert(typeof options.witness === 'boolean');
    this.witness = options.witness;
  }

  if (script)
    return this.fromScript(key, script, compressed, network);

  this.fromKey(key, compressed, network);
};

/**
 * Instantiate key ring from options.
 * @param {Object} options
 * @returns {KeyRing}
 */

KeyRing.fromOptions = function fromOptions(options) {
  return new KeyRing().fromOptions(options);
};

/**
 * Inject data from private key.
 * @private
 * @param {Buffer} key
 * @param {Boolean?} compressed
 * @param {(NetworkType|Network}) network
 */

KeyRing.prototype.fromPrivate = function fromPrivate(key, compressed, network) {
  assert(Buffer.isBuffer(key), 'Private key must be a buffer.');
  assert(ec.privateKeyVerify(key), 'Not a valid private key.');

  if (typeof compressed !== 'boolean') {
    network = compressed;
    compressed = null;
  }

  this.network = bcoin.network.get(network);
  this.privateKey = key;
  this.publicKey = ec.publicKeyCreate(key, compressed !== false);

  return this;
};

/**
 * Instantiate keyring from a private key.
 * @param {Buffer} key
 * @param {Boolean?} compressed
 * @param {(NetworkType|Network}) network
 * @returns {KeyRing}
 */

KeyRing.fromPrivate = function fromPrivate(key, compressed, network) {
  return new KeyRing().fromPrivate(key, compressed, network);
};

/**
 * Inject data from public key.
 * @private
 * @param {Buffer} key
 * @param {(NetworkType|Network}) network
 */

KeyRing.prototype.fromPublic = function fromPublic(key, network) {
  assert(Buffer.isBuffer(key), 'Public key must be a buffer.');
  assert(ec.publicKeyVerify(key), 'Not a valid public key.');
  this.network = bcoin.network.get(network);
  this.publicKey = key;
  return this;
};

/**
 * Generate a keyring.
 * @private
 * @param {(Network|NetworkType)?} network
 * @returns {KeyRing}
 */

KeyRing.prototype.generate = function(compressed, network) {
  var key;

  if (typeof compressed !== 'boolean') {
    network = compressed;
    compressed = null;
  }

  key = ec.generatePrivateKey();

  return this.fromKey(key, compressed, network);
};

/**
 * Generate a keyring.
 * @param {(Network|NetworkType)?} network
 * @returns {KeyRing}
 */

KeyRing.generate = function(compressed, network) {
  return new KeyRing().generate(compressed, network);
};

/**
 * Instantiate keyring from a public key.
 * @param {Buffer} publicKey
 * @param {(NetworkType|Network}) network
 * @returns {KeyRing}
 */

KeyRing.fromPublic = function fromPublic(key, network) {
  return new KeyRing().fromPublic(key, network);
};

/**
 * Inject data from public key.
 * @private
 * @param {Buffer} privateKey
 * @param {(NetworkType|Network}) network
 */

KeyRing.prototype.fromKey = function fromKey(key, compressed, network) {
  assert(Buffer.isBuffer(key), 'Key must be a buffer.');

  if (typeof compressed !== 'boolean') {
    network = compressed;
    compressed = null;
  }

  if (key.length === 32)
    return this.fromPrivate(key, compressed !== false, network);

  return this.fromPublic(key, network);
};

/**
 * Instantiate keyring from a public key.
 * @param {Buffer} publicKey
 * @param {(NetworkType|Network}) network
 * @returns {KeyRing}
 */

KeyRing.fromKey = function fromKey(key, compressed, network) {
  return new KeyRing().fromKey(key, compressed, network);
};

/**
 * Inject data from script.
 * @private
 * @param {Buffer} key
 * @param {Script} script
 * @param {(NetworkType|Network}) network
 */

KeyRing.prototype.fromScript = function fromScript(key, script, compressed, network) {
  assert(script instanceof bcoin.script, 'Non-script passed into KeyRing.');

  if (typeof compressed !== 'boolean') {
    network = compressed;
    compressed = null;
  }

  this.fromKey(key, compressed, network);
  this.script = script;

  return this;
};

/**
 * Instantiate keyring from script.
 * @param {Buffer} key
 * @param {Script} script
 * @param {(NetworkType|Network}) network
 * @returns {KeyRing}
 */

KeyRing.fromScript = function fromScript(key, script, compressed, network) {
  return new KeyRing().fromScript(key, script, compressed, network);
};

/**
 * Convert key to a CBitcoinSecret.
 * @param {(Network|NetworkType)?} network
 * @returns {Base58String}
 */

KeyRing.prototype.toSecret = function toSecret() {
  var p = new BufferWriter();

  assert(this.privateKey, 'Cannot serialize without private key.');

  p.writeU8(this.network.keyPrefix.privkey);
  p.writeBytes(this.privateKey);

  if (this.publicKey.length === 33)
    p.writeU8(1);

  p.writeChecksum();

  return utils.toBase58(p.render());
};

/**
 * Inject properties from serialized CBitcoinSecret.
 * @private
 * @param {Base58String} secret
 */

KeyRing.prototype.fromSecret = function fromSecret(data) {
  var p = new BufferReader(utils.fromBase58(data), true);
  var i, prefix, version, type, key, compressed;

  version = p.readU8();

  for (i = 0; i < networks.types.length; i++) {
    type = networks.types[i];
    prefix = networks[type].keyPrefix.privkey;
    if (version === prefix)
      break;
  }

  assert(i < networks.types.length, 'Network not found.');

  key = p.readBytes(32);

  if (p.left() > 4) {
    assert(p.readU8() === 1, 'Bad compression flag.');
    compressed = true;
  } else {
    compressed = false;
  }

  p.verifyChecksum();

  return this.fromPrivate(key, compressed, type);
};

/**
 * Instantiate a keyring from a serialized CBitcoinSecret.
 * @param {Base58String} secret
 * @returns {KeyRing}
 */

KeyRing.fromSecret = function fromSecret(data) {
  return new KeyRing().fromSecret(data);
};

/**
 * Get private key.
 * @param {String?} enc - Can be `"hex"`, `"base58"`, or `null`.
 * @returns {Buffer} Private key.
 */

KeyRing.prototype.getPrivateKey = function getPrivateKey(enc) {
  if (!this.privateKey)
    return;

  if (enc === 'base58')
    return this.toSecret();

  if (enc === 'hex')
    return this.privateKey.toString('hex');

  return this.privateKey;
};

/**
 * Get public key.
 * @param {String?} enc - `"hex"` or `null`.
 * @returns {Buffer}
 */

KeyRing.prototype.getPublicKey = function getPublicKey(enc) {
  if (enc === 'base58')
    return utils.toBase58(this.publicKey);

  if (enc === 'hex')
    return this.publicKey.toString('hex');

  return this.publicKey;
};

/**
 * Get redeem script.
 * @returns {Script}
 */

KeyRing.prototype.getScript = function getScript() {
  return this.script;
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
    if (!this.script) {
      hash = crypto.hash160(this.publicKey);
      program = bcoin.script.fromProgram(0, hash);
    } else {
      hash = this.script.sha256();
      program = bcoin.script.fromProgram(0, hash);
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

KeyRing.prototype.getNestedHash = function getNestedHash(enc) {
  if (!this.witness)
    return;

  if (!this._nestedHash)
    this._nestedHash = this.getProgram().hash160();

  return enc === 'hex'
    ? this._nestedHash.toString('hex')
    : this._nestedHash;
};

/**
 * Get address' scripthash address for witness program.
 * @param {String?} enc - `"base58"` or `null`.
 * @returns {Address|Base58Address}
 */

KeyRing.prototype.getNestedAddress = function getNestedAddress(enc) {
  var hash, address;

  if (!this.witness)
    return;

  if (!this._nestedAddress) {
    hash = this.getNestedHash();
    address = this.compile(hash, scriptTypes.SCRIPTHASH);
    this._nestedAddress = address;
  }

  if (enc === 'base58')
    return this._nestedAddress.toBase58();

  return this._nestedAddress;
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
  if (!this.script)
    return;

  if (!this._scriptHash160)
    this._scriptHash160 = this.script.hash160();

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
  if (!this.script)
    return;

  if (!this._scriptHash256)
    this._scriptHash256 = this.script.sha256();

  return enc === 'hex'
    ? this._scriptHash256.toString('hex')
    : this._scriptHash256;
};

/**
 * Get scripthash address.
 * @param {String?} enc - `"base58"` or `null`.
 * @returns {Address|Base58Address}
 */

KeyRing.prototype.getScriptAddress = function getScriptAddress(enc) {
  var hash, address;

  if (!this.script)
    return;

  if (!this._scriptAddress) {
    if (this.witness) {
      hash = this.getScriptHash256();
      address = this.compile(hash, scriptTypes.WITNESSSCRIPTHASH, 0);
    } else {
      hash = this.getScriptHash160();
      address = this.compile(hash, scriptTypes.SCRIPTHASH);
    }
    this._scriptAddress = address;
  }

  if (enc === 'base58')
    return this._scriptAddress.toBase58();

  return this._scriptAddress;
};

/**
 * Get public key hash.
 * @param {String?} enc - `"hex"` or `null`.
 * @returns {Buffer}
 */

KeyRing.prototype.getKeyHash = function getKeyHash(enc) {
  if (!this._keyHash)
    this._keyHash = crypto.hash160(this.publicKey);

  return enc === 'hex'
    ? this._keyHash.toString('hex')
    : this._keyHash;
};

/**
 * Get pubkeyhash address.
 * @param {String?} enc - `"base58"` or `null`.
 * @returns {Address|Base58Address}
 */

KeyRing.prototype.getKeyAddress = function getKeyAddress(enc) {
  var hash, address;

  if (!this._keyAddress) {
    hash = this.getKeyHash();
    if (this.witness)
      address = this.compile(hash, scriptTypes.WITNESSPUBKEYHASH, 0);
    else
      address = this.compile(hash, scriptTypes.PUBKEYHASH);
    this._keyAddress = address;
  }

  if (enc === 'base58')
    return this._keyAddress.toBase58();

  return this._keyAddress;
};

/**
 * Compile a hash to an address.
 * @private
 * @param {Hash|Buffer} hash
 * @param {AddressType?} type
 * @param {Number?} version - Witness version.
 * @returns {Address}
 * @throws Error on bad hash/prefix.
 */

KeyRing.prototype.compile = function compile(hash, type, version) {
  return Address.fromHash(hash, type, version, this.network);
};

/**
 * Get hash.
 * @param {String?} enc - `"hex"` or `null`.
 * @returns {Buffer}
 */

KeyRing.prototype.getHash = function getHash(enc) {
  if (this.script)
    return this.getScriptHash(enc);
  return this.getKeyHash(enc);
};

/**
 * Get base58 address.
 * @param {String?} enc - `"base58"` or `null`.
 * @returns {Address|Base58Address}
 */

KeyRing.prototype.getAddress = function getAddress(enc) {
  if (this.script)
    return this.getScriptAddress(enc);
  return this.getKeyAddress(enc);
};

/**
 * Test an address hash against hash and program hash.
 * @param {Buffer} hash
 * @returns {Boolean}
 */

KeyRing.prototype.ownHash = function ownHash(hash) {
  if (!hash)
    return false;

  if (utils.equal(hash, this.keyHash))
    return true;

  if (utils.equal(hash, this.scriptHash))
    return true;

  if (this.witness) {
    if (utils.equal(hash, this.nestedHash))
      return true;
  }

  return false;
};

/**
 * Check whether transaction input belongs to this address.
 * @param {TX|Output} tx - Transaction or Output.
 * @param {Number?} index - Output index.
 * @returns {Boolean}
 */

KeyRing.prototype.ownInput = function ownInput(tx, index) {
  var input;

  if (tx instanceof bcoin.input) {
    input = tx;
  } else {
    input = tx.inputs[index];
    assert(input, 'Input does not exist.');
  }

  return this.ownHash(input.getHash());
};

/**
 * Check whether transaction output belongs to this address.
 * @param {TX|Output} tx - Transaction or Output.
 * @param {Number?} index - Output index.
 * @returns {Boolean}
 */

KeyRing.prototype.ownOutput = function ownOutput(tx, index) {
  var output;

  if (tx instanceof bcoin.output) {
    output = tx;
  } else {
    output = tx.outputs[index];
    assert(output, 'Output does not exist.');
  }

  return this.ownHash(output.getHash());
};

/**
 * Test a hash against script hashes to
 * find the correct redeem script, if any.
 * @param {Buffer} hash
 * @returns {Script|null}
 */

KeyRing.prototype.getRedeem = function(hash) {
  if (this.program) {
    if (utils.equal(hash, this.nestedHash))
      return this.program;
  }

  if (this.script) {
    if (utils.equal(hash, this.scriptHash160))
      return this.script;

    if (utils.equal(hash, this.scriptHash256))
      return this.script;
  }

  return null;
};

/**
 * Sign a message.
 * @param {Buffer} msg
 * @returns {Buffer} Signature in DER format.
 */

KeyRing.prototype.sign = function sign(msg) {
  assert(this.privateKey, 'Cannot sign without private key.');
  return ec.sign(msg, this.privateKey);
};

/**
 * Verify a message.
 * @param {Buffer} msg
 * @param {Buffer} sig - Signature in DER format.
 * @returns {Boolean}
 */

KeyRing.prototype.verify = function verify(msg, sig) {
  return ec.verify(msg, sig, this.publicKey);
};

/**
 * Get script type.
 * @returns {ScriptType}
 */

KeyRing.prototype.getType = function getType() {
  if (this.program)
    return this.program.getType();

  if (this.script)
    return this.script.getType();

  return scriptTypes.PUBKEYHASH;
};

/**
 * Get address type.
 * @returns {ScriptType}
 */

KeyRing.prototype.getAddressType = function getAddressType() {
  if (this.witness) {
    if (this.script)
      return scriptTypes.WITNESSSCRIPTHASH;
    return scriptTypes.WITNESSPUBKEYHASH;
  }
  if (this.script)
    return scriptTypes.SCRIPTHASH;
  return scriptTypes.PUBKEYHASH;
};

/*
 * Getters
 */

KeyRing.prototype.__defineGetter__('type', function() {
  return this.getType();
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

KeyRing.prototype.__defineGetter__('nestedHash', function() {
  return this.getNestedHash();
});

KeyRing.prototype.__defineGetter__('nestedAddress', function() {
  return this.getNestedAddress();
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
 * Inspect keyring.
 * @returns {Object}
 */

KeyRing.prototype.inspect = function inspect() {
  return this.toJSON();
};

/**
 * Convert an KeyRing to a more json-friendly object.
 * @returns {Object}
 */

KeyRing.prototype.toJSON = function toJSON() {
  return {
    network: this.network.type,
    witness: this.witness,
    publicKey: this.publicKey.toString('hex'),
    script: this.script ? this.script.toRaw().toString('hex') : null,
    type: constants.scriptTypesByVal[this.type].toLowerCase(),
    address: this.getAddress('base58'),
    nestedAddress: this.getNestedAddress('base58')
  };
};

/**
 * Inject properties from json object.
 * @private
 * @param {Object} json
 */

KeyRing.prototype.fromJSON = function fromJSON(json) {
  assert(json);
  assert(typeof json.network === 'string');
  assert(typeof json.witness === 'boolean');
  assert(typeof json.publicKey === 'string');
  assert(!json.script || typeof json.script === 'string');

  this.nework = bcoin.network.get(json.network);
  this.witness = json.witness;
  this.publicKey = new Buffer(json.publicKey, 'hex');

  if (json.script)
    this.script = new Buffer(json.script, 'hex');

  return this;
};

/**
 * Instantiate an KeyRing from a jsonified transaction object.
 * @param {Object} json - The jsonified transaction object.
 * @returns {KeyRing}
 */

KeyRing.fromJSON = function fromJSON(json) {
  return new KeyRing().fromJSON(json);
};

/**
 * Serialize the keyring.
 * @returns {Buffer}
 */

KeyRing.prototype.toRaw = function toRaw(writer) {
  var p = new BufferWriter(writer);

  p.writeU8(this.witness ? 1 : 0);

  if (this.privateKey) {
    p.writeVarBytes(this.privateKey);
    p.writeU8(this.publicKey.length === 33);
  } else {
    p.writeVarBytes(this.publicKey);
  }

  if (this.script)
    p.writeVarBytes(this.script.toRaw());
  else
    p.writeVarint(0);

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

KeyRing.prototype.fromRaw = function fromRaw(data, network) {
  var p = new BufferReader(data);
  var compressed, key, script;

  this.network = bcoin.network.get(network);
  this.witness = p.readU8() === 1;

  key = p.readVarBytes();

  if (key.length === 32) {
    compressed = p.readU8() === 1;
    this.privateKey = key;
    this.publicKey = ec.publicKeyCreate(key, compressed);
  } else {
    this.publicKey = key;
    assert(ec.publicKeyVerify(key), 'Invalid public key.');
  }

  script = p.readVarBytes();

  if (script.length > 0)
    this.script = bcoin.script.fromRaw(script);

  return this;
};

/**
 * Instantiate a keyring from serialized data.
 * @param {Buffer} data
 * @returns {KeyRing}
 */

KeyRing.fromRaw = function fromRaw(data) {
  return new KeyRing().fromRaw(data);
};

/**
 * Test whether an object is a KeyRing.
 * @param {Object} obj
 * @returns {Boolean}
 */

KeyRing.isKeyRing = function isKeyRing(obj) {
  return obj
    && Buffer.isBuffer(obj.publicKey)
    && typeof obj.toSecret === 'function';
};

/*
 * Helpers
 */

function toKey(opt) {
  if (!opt)
    return opt;

  if (opt.privateKey)
    return opt.privateKey;

  if (opt.publicKey)
    return opt.publicKey;

  return opt;
}

/*
 * Expose
 */

module.exports = KeyRing;
