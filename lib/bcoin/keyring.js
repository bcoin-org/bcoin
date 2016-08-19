/*!
 * keyring.js - keyring object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var bcoin = require('./env');
var constants = bcoin.protocol.constants;
var utils = bcoin.utils;
var assert = utils.assert;
var BufferReader = require('./reader');
var BufferWriter = require('./writer');
var scriptTypes = constants.scriptTypes;

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
  this.publicKey = null;
  this.privateKey = null;
  this.script = null;
  this.path = null;

  this._keyHash = null;
  this._keyAddress = null;
  this._program = null;
  this._programHash = null;
  this._programAddress = null;
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

  if (Buffer.isBuffer(key))
    return this.fromKey(key, network);

  key = toKey(options.key);

  if (options.privateKey)
    key = toKey(options.privateKey);

  if (options.publicKey)
    key = toKey(options.publicKey);

  if (options.network)
    this.network = bcoin.network.get(options.network);

  if (options.witness != null) {
    assert(typeof options.witness === 'boolean');
    this.witness = options.witness;
  }

  if (options.keys)
    return this.fromKeys(key, options.m, options.n, options.keys, this.network);

  if (options.script)
    return this.fromScript(key, options.script, this.network);

  this.fromKey(key, this.network);
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
 * @param {Buffer} privateKey
 * @param {Boolean?} compressed
 * @param {(NetworkType|Network}) network
 */

KeyRing.prototype.fromPrivate = function fromPrivate(privateKey, network) {
  assert(Buffer.isBuffer(privateKey), 'Private key must be a buffer.');
  assert(bcoin.ec.privateKeyVerify(privateKey), 'Not a valid private key.');
  this.network = bcoin.network.get(network);
  this.privateKey = privateKey;
  this.publicKey = bcoin.ec.publicKeyCreate(this.privateKey, true);
  return this;
};

/**
 * Instantiate keyring from a private key.
 * @param {Buffer} privateKey
 * @param {Boolean?} compressed
 * @param {(NetworkType|Network}) network
 * @returns {KeyRing}
 */

KeyRing.fromPrivate = function fromPrivate(privateKey, network) {
  return new KeyRing().fromPrivate(privateKey, network);
};

/**
 * Inject data from public key.
 * @private
 * @param {Buffer} privateKey
 * @param {(NetworkType|Network}) network
 */

KeyRing.prototype.fromPublic = function fromPublic(publicKey, network) {
  assert(Buffer.isBuffer(publicKey), 'Public key must be a buffer.');
  assert(bcoin.ec.publicKeyVerify(publicKey), 'Not a valid public key.');
  this.network = bcoin.network.get(network);
  this.publicKey = publicKey;
  return this;
};

/**
 * Generate a keyring.
 * @param {(Network|NetworkType)?} network
 * @returns {KeyRing}
 */

KeyRing.generate = function(witness, network) {
  var key = new KeyRing();
  key.network = bcoin.network.get(network);
  key.privateKey = bcoin.ec.generatePrivateKey();
  key.publicKey = bcoin.ec.publicKeyCreate(key.privateKey, true);
  key.witness = !!witness;
  return key;
};

/**
 * Instantiate keyring from a public key.
 * @param {Buffer} publicKey
 * @param {(NetworkType|Network}) network
 * @returns {KeyRing}
 */

KeyRing.fromPublic = function fromPublic(publicKey, network) {
  return new KeyRing().fromPublic(publicKey, network);
};

/**
 * Inject data from public key.
 * @private
 * @param {Buffer} privateKey
 * @param {(NetworkType|Network}) network
 */

KeyRing.prototype.fromKey = function fromKey(key, network) {
  assert(Buffer.isBuffer(key), 'Key must be a buffer.');
  assert(key.length === 32 || key.length === 33, 'Not a key.');

  if (key.length === 33)
    return this.fromPublic(key, network);

  return this.fromPrivate(key, network);
};

/**
 * Instantiate keyring from a public key.
 * @param {Buffer} publicKey
 * @param {(NetworkType|Network}) network
 * @returns {KeyRing}
 */

KeyRing.fromKey = function fromKey(key, network) {
  return new KeyRing().fromKey(key, network);
};

/**
 * Inject data from public key.
 * @private
 * @param {Buffer} key
 * @param {Number} m
 * @param {Number} n
 * @param {Buffer[]} keys
 * @param {(NetworkType|Network}) network
 */

KeyRing.prototype.fromKeys = function fromKeys(key, m, n, keys, network) {
  var script = bcoin.script.fromMultisig(m, n, keys);
  this.fromScript(key, script, network);
  return this;
};

/**
 * Instantiate keyring from keys.
 * @param {Buffer} key
 * @param {Number} m
 * @param {Number} n
 * @param {Buffer[]} keys
 * @param {(NetworkType|Network}) network
 * @returns {KeyRing}
 */

KeyRing.fromKeys = function fromKeys(key, m, n, keys, network) {
  return new KeyRing().fromKeys(key, m, n, keys, network);
};

/**
 * Inject data from script.
 * @private
 * @param {Buffer} key
 * @param {Script} script
 * @param {(NetworkType|Network}) network
 */

KeyRing.prototype.fromScript = function fromScript(key, script, network) {
  assert(script instanceof bcoin.script, 'Non-script passed into KeyRing.');
  this.fromKey(key, network);
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

KeyRing.fromScript = function fromScript(key, script, network) {
  return new KeyRing().fromScript(key, script, network);
};

/**
 * Convert key to a CBitcoinSecret.
 * @param {(Network|NetworkType)?} network
 * @returns {Base58String}
 */

KeyRing.prototype.toSecret = function toSecret(network) {
  var p = new BufferWriter();

  assert(this.privateKey, 'Cannot serialize without private key.');

  if (!network)
    network = this.network;

  network = bcoin.network.get(network);

  p.writeU8(network.keyPrefix.privkey);
  p.writeBytes(this.privateKey);

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

  for (i = 0; i < network.types.length; i++) {
    type = network.types[i];
    prefix = network[type].keyPrefix.privkey;
    if (version === prefix)
      break;
  }

  assert(i < network.types.length, 'Network not found.');

  key = p.readBytes(32);

  if (p.left() > 4) {
    assert(p.readU8() === 1, 'Bad compression flag.');
    compressed = true;
  } else {
    compressed = false;
  }

  p.verifyChecksum();

  assert(compressed === false, 'Cannot handle uncompressed.');

  return this.fromPrivate(key, type);
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
      hash = utils.hash160(this.publicKey);
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

KeyRing.prototype.getProgramHash = function getProgramHash(enc) {
  if (!this.witness)
    return;

  if (!this._programHash)
    this._programHash = this.getProgram().hash160();

  return enc === 'hex'
    ? this._programHash.toString('hex')
    : this._programHash;
};

/**
 * Get address' scripthash address for witness program.
 * @param {String?} enc - `"base58"` or `null`.
 * @returns {Address|Base58Address}
 */

KeyRing.prototype.getProgramAddress = function getProgramAddress(enc) {
  var hash, address;

  if (!this.witness)
    return;

  if (!this._programAddress) {
    hash = this.getProgramHash();
    address = this.compile(hash, scriptTypes.SCRIPTHASH);
    this._programAddress = address;
  }

  if (enc === 'base58')
    return this._programAddress.toBase58();

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
    this._keyHash = utils.hash160(this.publicKey);

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
  return bcoin.address.fromHash(hash, type, version, this.network);
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
    if (utils.equal(hash, this.programHash))
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
    if (utils.equal(hash, this.programHash))
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
  return bcoin.ec.sign(msg, this.privateKey);
};

/**
 * Verify a message.
 * @param {Buffer} msg
 * @param {Buffer} sig - Signature in DER format.
 * @returns {Boolean}
 */

KeyRing.prototype.verify = function verify(msg, sig) {
  return bcoin.ec.verify(msg, sig, this.publicKey);
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
    key: this.publicKey.toString('hex'),
    script: this.script ? this.script.toRaw().toString('hex') : null,
    type: constants.scriptTypesByVal[this.type].toLowerCase(),
    wid: this.path ? this.path.wid : undefined,
    id: this.path ? this.path.id : undefined,
    name: this.path ? this.path.name : undefined,
    account: this.path ? this.path.account : undefined,
    change: this.path ? this.path.change : undefined,
    index: this.path ? this.path.index : undefined,
    address: this.getAddress('base58'),
    programAddress: this.getProgramAddress('base58')
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

  assert(!json.wid || utils.isNumber(json.wid));
  assert(!json.id || utils.isName(json.id));
  assert(!json.name || utils.isName(json.name));
  assert(utils.isNumber(json.account));
  assert(utils.isNumber(json.change));
  assert(utils.isNumber(json.index));

  this.nework = bcoin.network.get(json.network);
  this.witness = json.witness;
  this.publicKey = new Buffer(json.publicKey, 'hex');

  if (json.script)
    this.script = new Buffer(json.script, 'hex');

  this.wid = json.wid;
  this.name = json.name;
  this.account = json.account;
  this.change = json.change;
  this.index = json.index;

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
  var i;

  p.writeU8(this.witness ? 1 : 0);

  if (this.privateKey)
    p.writeVarBytes(this.privateKey);
  else
    p.writeVarBytes(this.publicKey);

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

KeyRing.prototype.fromRaw = function fromRaw(data) {
  var p = new BufferReader(data);
  var i, count, key;

  this.witness = p.readU8() === 1;

  key = p.readVarBytes();

  if (key.length === 32) {
    this.privateKey = key;
    this.publicKey = bcoin.ec.publicKeyCreate(key, true);
  } else {
    this.publicKey = key;
  }

  this.script = p.readVarBytes();

  if (this.script.length === 0)
    this.script = null;

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

  if (opt.getPrivateKey)
    return opt.getPrivateKey();

  if (opt.getPublicKey)
    return opt.getPublicKey();

  return opt;
}

/*
 * Expose
 */

module.exports = KeyRing;
