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
 * Represents a key ring which amounts to an address. Used for {@link Wallet}.
 * @exports KeyRing
 * @constructor
 * @param {Object} options
 * @param {HDPrivateKey|HDPublicKey|KeyPair|Buffer} options.key
 * @param {String?} options.name
 * @param {Number?} options.account
 * @param {Number?} options.change
 * @param {Number?} options.index
 * @param {String?} options.type - `"pubkeyhash"` or `"multisig"`.
 * @param {Buffer[]} options.keys - Shared multisig keys.
 * @param {Number?} options.m - Multisig `m` value.
 * @param {Number?} options.n - Multisig `n` value.
 * @param {Boolean?} options.witness - Whether witness programs are enabled.
 */

function KeyRing(options) {
  if (!(this instanceof KeyRing))
    return new KeyRing(options);

  this.network = bcoin.network.get();
  this.type = KeyRing.types.PUBKEYHASH;
  this.m = 1;
  this.n = 1;
  this.witness = false;
  this.wid = 0;
  this.id = null;
  this.name = null;
  this.account = 0;
  this.change = 0;
  this.index = 0;
  this.key = null;
  this.keys = [];

  this._keyHash = null;
  this._keyAddress = null;
  this._program = null;
  this._programHash = null;
  this._programAddress = null;
  this._script = null;
  this._scriptHash160 = null;
  this._scriptHash256 = null;
  this._scriptAddress = null;
  this._addressMap = null;

  if (options)
    this.fromOptions(options);
}

/**
 * KeyRing types.
 * @enum {Number}
 * @default
 */

KeyRing.types = {
  PUBKEYHASH: 0,
  MULTISIG: 1
};

/**
 * KeyRing types by value.
 * @const {RevMap}
 */

KeyRing.typesByVal = {
  0: 'pubkeyhash',
  1: 'multisig'
};

/**
 * Inject properties from options object.
 * @private
 * @param {Object} options
 */

KeyRing.prototype.fromOptions = function fromOptions(options) {
  var i;

  assert(options.key);

  if (options.network)
    this.network = bcoin.network.get(options.network);

  if (options.type != null) {
    if (typeof options.type === 'string') {
      this.type = KeyRing.types[options.type.toUpperCase()];
      assert(this.type != null);
    } else {
      assert(typeof options.type === 'number');
      this.type = options.type;
      assert(KeyRing.typesByVal[this.type]);
    }
  }

  if (options.m != null) {
    assert(utils.isNumber(options.m));
    this.m = options.m;
  }

  if (options.n != null) {
    assert(utils.isNumber(options.n));
    this.n = options.n;
  }

  if (options.witness != null) {
    assert(typeof options.witness === 'boolean');
    this.witness = options.witness;
  }

  if (options.wid) {
    assert(utils.isNumber(options.wid));
    this.wid = options.wid;
  }

  if (options.id) {
    assert(utils.isName(options.id));
    this.id = options.id;
  }

  if (options.name) {
    assert(utils.isName(options.name));
    this.name = options.name;
  }

  if (options.account != null) {
    assert(utils.isNumber(options.account));
    this.account = options.account;
  }

  if (options.change != null) {
    assert(utils.isNumber(options.change));
    this.change = options.change;
  }

  if (options.index != null) {
    assert(utils.isNumber(options.index));
    this.index = options.index;
  }

  this.key = options.key;

  if (this.key.getPublicKey)
    this.key = this.key.getPublicKey();

  assert(Buffer.isBuffer(this.key));

  if (this.n > 1)
    this.type = KeyRing.types.MULTISIG;

  if (this.m < 1 || this.m > this.n)
    throw new Error('m ranges between 1 and n');

  this.addKey(this.key);

  if (options.keys) {
    assert(Array.isArray(options.keys));
    for (i = 0; i < options.keys.length; i++)
      this.addKey(options.keys[i]);
  }

  return this;
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
 * Inject properties from account object.
 * @private
 * @param {Account} account
 * @param {Buffer} key
 * @param {Buffer[]} keys
 * @param {Number} change
 * @param {Number} index
 */

KeyRing.prototype.fromAccount = function fromAccount(account, key, keys, change, index) {
  var i;

  this.network = account.network;
  this.key = key.publicKey;
  this.wid = account.wid;
  this.id = account.id;
  this.name = account.name;
  this.account = account.accountIndex;
  this.change = change;
  this.index = index;
  this.type = account.type;
  this.witness = account.witness;
  this.m = account.m;
  this.n = account.n;

  this.addKey(this.key);

  for (i = 0; i < keys.length; i++)
    this.addKey(keys[i]);

  return this;
};

/**
 * Instantiate key ring from an account.
 * @param {Account} account
 * @param {Buffer} key
 * @param {Buffer[]} keys
 * @param {Number} change
 * @param {Number} index
 * @returns {KeyRing}
 */

KeyRing.fromAccount = function fromAccount(account, key, keys, change, index) {
  return new KeyRing().fromAccount(account, key, keys, change, index);
};

/**
 * Add a key to shared keys.
 * @param {Buffer} key
 */

KeyRing.prototype.addKey = function addKey(key) {
  assert(Buffer.isBuffer(key));

  if (utils.indexOf(this.keys, key) !== -1)
    return;

  if (this.keys.length === this.n)
    throw new Error('Cannot add more keys.');

  utils.binaryInsert(this.keys, key, utils.cmp);
};

/**
 * Remove a key from shared keys.
 * @param {Buffer} key
 */

KeyRing.prototype.removeKey = function removeKey(key) {
  assert(Buffer.isBuffer(key));

  if (this.keys.length === this.n)
    throw new Error('Cannot remove key.');

  utils.binaryRemove(this.keys, key, utils.cmp);
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

  if (this.type !== KeyRing.types.MULTISIG)
    return;

  if (!this._script) {
    assert(this.keys.length === this.n, 'Not all keys have been added.');

    redeem = bcoin.script.fromMultisig(this.m, this.n, this.keys);

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
    if (this.type === KeyRing.types.PUBKEYHASH) {
      hash = utils.hash160(this.getPublicKey());
      program = bcoin.script.fromProgram(0, hash);
    } else if (this.type === KeyRing.types.MULTISIG) {
      hash = utils.sha256(this.getScript().toRaw());
      program = bcoin.script.fromProgram(0, hash);
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
    this._programHash = utils.hash160(this.getProgram().toRaw());

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
  if (this.type !== KeyRing.types.MULTISIG)
    return;

  if (!this._scriptHash160)
    this._scriptHash160 = utils.hash160(this.getScript().toRaw());

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
  if (this.type !== KeyRing.types.MULTISIG)
    return;

  if (!this._scriptHash256)
    this._scriptHash256 = utils.sha256(this.getScript().toRaw());

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

  if (this.type !== KeyRing.types.MULTISIG)
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
    this._keyHash = utils.hash160(this.getPublicKey());

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
  if (this.type === KeyRing.types.MULTISIG)
    return this.getScriptHash(enc);
  return this.getKeyHash(enc);
};

/**
 * Get base58 address.
 * @param {String?} enc - `"base58"` or `null`.
 * @returns {Address|Base58Address}
 */

KeyRing.prototype.getAddress = function getAddress(enc) {
  if (this.type === KeyRing.types.MULTISIG)
    return this.getScriptAddress(enc);
  return this.getKeyAddress(enc);
};

/**
 * Create the address map for testing txs.
 * @returns {AddressMap}
 */

KeyRing.prototype.getAddressMap = function getAddressMap() {
  if (!this._addressMap) {
    this._addressMap = {};
    this._addressMap[this.getHash('hex')] = true;
    if (this.witness)
      this._addressMap[this.getProgramHash('hex')] = true;
  }

  return this._addressMap;
};

/**
 * Check whether transaction input belongs to this address.
 * @param {TX|Output} tx - Transaction or Output.
 * @param {Number?} index - Output index.
 * @returns {Boolean}
 */

KeyRing.prototype.ownInput = function ownInput(tx, index) {
  var addressMap = this.getAddressMap();
  var input, hash;

  if (tx instanceof bcoin.input) {
    input = tx;
  } else {
    input = tx.inputs[index];
    assert(input, 'Input does not exist.');
  }

  hash = input.getHash('hex');

  if (!hash)
    return false;

  return addressMap[hash] === true;
};

/**
 * Check whether transaction output belongs to this address.
 * @param {TX|Output} tx - Transaction or Output.
 * @param {Number?} index - Output index.
 * @returns {Boolean}
 */

KeyRing.prototype.ownOutput = function ownOutput(tx, index) {
  var addressMap = this.getAddressMap();
  var output, hash;

  if (tx instanceof bcoin.output) {
    output = tx;
  } else {
    output = tx.outputs[index];
    assert(output, 'Output does not exist.');
  }

  hash = output.getHash('hex');

  if (!hash)
    return false;

  return addressMap[hash] === true;
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

/**
 * Derive to address index.
 * @param {HDPrivateKey} key
 * @returns {HDPrivateKey}
 */

KeyRing.prototype.derive = function derive(key) {
  if (key.isMaster())
    key = key.deriveAccount44(this.account);
  return key.derive(this.change).derive(this.index);
};

/**
 * Get script type.
 * @returns {ScriptType}
 */

KeyRing.prototype.getScriptType = function getScriptType() {
  switch (this.type) {
    case KeyRing.types.PUBKEYHASH:
      return this.witness
        ? scriptTypes.WITNESSPUBKEYHASH
        : scriptTypes.PUBKEYHASH;
    case KeyRing.types.MULTISIG:
      return this.witness
        ? scriptTypes.WITNESSSCRIPTHASH
        : scriptTypes.SCRIPTHASH;
    default:
      assert(false, 'Bad keyring type.');
      break;
  }
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
 * @returns {Object}
 */

KeyRing.prototype.toJSON = function toJSON() {
  return {
    network: this.network.type,
    type: KeyRing.typesByVal[this.type].toLowerCase(),
    m: this.m,
    n: this.n,
    witness: this.witness,
    wid: this.wid,
    id: this.id,
    name: this.name,
    account: this.account,
    change: this.change,
    index: this.index,
    key: this.key.toString('hex'),
    keys: this.keys.map(function(key) {
      return key.toString('hex');
    }),
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
  var i;

  assert(json);
  assert(typeof json.network === 'string');
  assert(typeof json.type === 'string');
  assert(utils.isNumber(json.m));
  assert(utils.isNumber(json.n));
  assert(typeof json.witness === 'boolean');
  assert(!json.wid || utils.isNumber(json.wid));
  assert(!json.id || utils.isName(json.id));
  assert(!json.name || utils.isName(json.name));
  assert(utils.isNumber(json.account));
  assert(utils.isNumber(json.change));
  assert(utils.isNumber(json.index));
  assert(typeof json.key === 'string');
  assert(Array.isArray(json.keys));

  this.nework = bcoin.network.get(json.network);
  this.type = KeyRing.types[json.type.toUpperCase()];
  this.m = json.m;
  this.n = json.n;
  this.witness = json.witness;
  this.wid = json.wid;
  this.name = json.name;
  this.account = json.account;
  this.change = json.change;
  this.index = json.index;
  this.key = new Buffer(json.key, 'hex');

  assert(this.type != null);

  for (i = 0; i < json.keys.length; i++)
    this.keys.push(new Buffer(json.keys[i], 'hex'));

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

  p.writeU32(this.network.magic);
  p.writeU8(this.type);
  p.writeU8(this.m);
  p.writeU8(this.n);
  p.writeU8(this.witness ? 1 : 0);
  p.writeU32(this.wid);
  p.writeVarString(this.id, 'utf8');
  p.writeVarString(this.name, 'utf8');
  p.writeU32(this.account);
  p.writeU32(this.change);
  p.writeU32(this.index);
  p.writeVarBytes(this.key);
  p.writeU8(this.keys.length);

  for (i = 0; i < this.keys.length; i++)
    p.writeVarBytes(this.keys[i]);

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
  var i, count;

  this.network = bcoin.network.fromMagic(p.readU32());
  this.type = p.readU8();
  this.m = p.readU8();
  this.n = p.readU8();
  this.witness = p.readU8() === 1;
  this.wid = p.readU32();
  this.id = p.readVarString('utf8');
  this.name = p.readVarString('utf8');
  this.account = p.readU32();
  this.change = p.readU32();
  this.index = p.readU32();
  this.key = p.readVarBytes();

  assert(KeyRing.typesByVal[this.type]);

  count = p.readU8();

  for (i = 0; i < count; i++)
    this.keys.push(p.readVarBytes());

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
    && Array.isArray(obj.keys)
    && typeof obj.getAddressMap === 'function';
};

/*
 * Expose
 */

module.exports = KeyRing;
