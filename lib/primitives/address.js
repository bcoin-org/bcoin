/*!
 * address.js - address object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var Network = require('../protocol/network');
var networks = require('../protocol/networks');
var constants = require('../protocol/constants');
var util = require('../utils/util');
var crypto = require('../crypto/crypto');
var assert = require('assert');
var BufferWriter = require('../utils/writer');
var BufferReader = require('../utils/reader');
var base58 = require('../utils/base58');
var scriptTypes = constants.scriptTypes;

/**
 * Represents an address.
 * @exports Address
 * @constructor
 * @param {Object} options
 * @param {Buffer|Hash} options.hash - Address hash.
 * @param {AddressType} options.type - Address type
 * `{witness,}{pubkeyhash,scripthash}`.
 * @param {Number} [options.version=-1] - Witness program version.
 * @param {(Network|NetworkType)?} options.network - Network name.
 * @property {Buffer} hash
 * @property {AddressType} type
 * @property {Number} version
 * @property {Network} network
 */

function Address(options) {
  if (!(this instanceof Address))
    return new Address(options);

  this.hash = constants.ZERO_HASH160;
  this.type = scriptTypes.PUBKEYHASH;
  this.version = -1;
  this.network = Network.primary;

  if (options)
    this.fromOptions(options);
}

/**
 * Inject properties from options object.
 * @private
 * @param {Object} options
 */

Address.prototype.fromOptions = function fromOptions(options) {
  if (typeof options === 'string')
    return this.fromBase58(options);

  if (Buffer.isBuffer(options))
    return this.fromRaw(options);

  return this.fromHash(
    options.hash,
    options.type,
    options.version,
    options.network
  );
};

/**
 * Insantiate address from options.
 * @param {Object} options
 * @returns {Address}
 */

Address.fromOptions = function fromOptions(options) {
  return new Address().fromOptions(options);
};

/**
 * Get the address hash.
 * @param {String?} enc - Can be `"hex"` or `null`.
 * @returns {Hash|Buffer}
 */

Address.prototype.getHash = function getHash(enc) {
  if (enc === 'hex')
    return this.hash.toString(enc);
  return this.hash;
};

/**
 * Get the address type as a string.
 * @returns {AddressType}
 */

Address.prototype.getType = function getType() {
  return constants.scriptTypesByVal[this.type].toLowerCase();
};

/**
 * Compile the address object to its raw serialization.
 * @param {{NetworkType|Network)?} network
 * @returns {Buffer}
 * @throws Error on bad hash/prefix.
 */

Address.prototype.toRaw = function toRaw(network) {
  var bw = new BufferWriter();
  var prefix;

  if (!network)
    network = this.network;

  network = Network.get(network);
  prefix = Address.getPrefix(this.type, network);

  assert(prefix !== -1, 'Not a valid address prefix.');

  bw.writeU8(prefix);
  if (this.version !== -1) {
    bw.writeU8(this.version);
    bw.writeU8(0);
  }
  bw.writeBytes(this.hash);
  bw.writeChecksum();

  return bw.render();
};

/**
 * Compile the address object to a base58 address.
 * @param {{NetworkType|Network)?} network
 * @returns {Base58Address}
 * @throws Error on bad hash/prefix.
 */

Address.prototype.toBase58 = function toBase58(network) {
  return base58.encode(this.toRaw(network));
};

/**
 * Convert the Address to a string.
 * @returns {Base58String}
 */

Address.prototype.toString = function toString(enc) {
  if (enc === 'hex')
    return this.getHash('hex');

  if (enc === 'base58')
    enc = null;

  return this.toBase58(enc);
};

/**
 * Inspect the Address.
 * @returns {Object}
 */

Address.prototype.inspect = function inspect() {
  return '<Address:'
    + ' type=' + this.getType()
    + ' version=' + this.version
    + ' base58=' + this.toBase58()
    + '>';
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 * @throws Parse error
 */

Address.prototype.fromRaw = function fromRaw(data) {
  var i, br, prefix, network, type, version, hash;

  assert(Buffer.isBuffer(data));

  br = new BufferReader(data, true);
  prefix = br.readU8();

  for (i = 0; i < networks.types.length; i++) {
    network = networks[networks.types[i]];
    type = Address.getType(prefix, network);
    if (type !== -1)
      break;
  }

  assert(i < networks.types.length, 'Unknown address prefix.');

  if (data.length > 25) {
    version = br.readU8();
    assert(br.readU8() === 0, 'Address version padding is non-zero.');
  } else {
    version = -1;
  }

  hash = br.readBytes(br.left() - 4);

  br.verifyChecksum();

  return this.fromHash(hash, type, version, network.type);
};

/**
 * Create an address object from a serialized address.
 * @param {Buffer} data
 * @returns {Address}
 * @throws Parse error.
 */

Address.fromRaw = function fromRaw(data) {
  return new Address().fromRaw(data);
};

/**
 * Inject properties from base58 address.
 * @private
 * @param {Base58Address} data
 * @throws Parse error
 */

Address.prototype.fromBase58 = function fromBase58(data) {
  assert(typeof data === 'string');
  return this.fromRaw(base58.decode(data));
};

/**
 * Create an address object from a base58 address.
 * @param {Base58Address} address
 * @returns {Address}
 * @throws Parse error.
 */

Address.fromBase58 = function fromBase58(address) {
  return new Address().fromBase58(address);
};

/**
 * Inject properties from output script.
 * @private
 * @param {Script} script
 */

Address.prototype.fromScript = function fromScript(script) {
  if (script.isPubkey()) {
    this.hash = crypto.hash160(script.get(0));
    this.type = scriptTypes.PUBKEYHASH;
    this.version = -1;
    return this;
  }

  if (script.isPubkeyhash()) {
    this.hash = script.get(2);
    this.type = scriptTypes.PUBKEYHASH;
    this.version = -1;
    return this;
  }

  if (script.isScripthash()) {
    this.hash = script.get(1);
    this.type = scriptTypes.SCRIPTHASH;
    this.version = -1;
    return this;
  }

  if (script.isWitnessPubkeyhash()) {
    this.hash = script.get(1);
    this.type = scriptTypes.WITNESSPUBKEYHASH;
    this.version = 0;
    return this;
  }

  if (script.isWitnessScripthash()) {
    this.hash = script.get(1);
    this.type = scriptTypes.WITNESSSCRIPTHASH;
    this.version = 0;
    return this;
  }

  if (script.isWitnessMasthash()) {
    this.hash = script.get(1);
    this.type = scriptTypes.WITNESSSCRIPTHASH;
    this.version = 1;
    return this;
  }

  // Put this last: it's the slowest to check.
  if (script.isMultisig()) {
    this.hash = script.hash160();
    this.type = scriptTypes.SCRIPTHASH;
    this.version = -1;
    return this;
  }
};

/**
 * Inject properties from witness.
 * @private
 * @param {Witness} witness
 */

Address.prototype.fromWitness = function fromWitness(witness) {
  // We're pretty much screwed here
  // since we can't get the version.
  if (witness.isPubkeyhashInput()) {
    this.hash = crypto.hash160(witness.get(1));
    this.type = scriptTypes.WITNESSPUBKEYHASH;
    this.version = 0;
    return this;
  }

  if (witness.isScripthashInput()) {
    this.hash = crypto.sha256(witness.get(witness.length - 1));
    this.type = scriptTypes.WITNESSSCRIPTHASH;
    this.version = 0;
    return this;
  }
};

/**
 * Inject properties from input script.
 * @private
 * @param {Script} script
 */

Address.prototype.fromInputScript = function fromInputScript(script) {
  if (script.isPubkeyhashInput()) {
    this.hash = crypto.hash160(script.get(1));
    this.type = scriptTypes.PUBKEYHASH;
    this.version = -1;
    return this;
  }

  if (script.isScripthashInput()) {
    this.hash = crypto.hash160(script.get(script.length - 1));
    this.type = scriptTypes.SCRIPTHASH;
    this.version = -1;
    return this;
  }
};

/**
 * Create an Address from a witness.
 * Attempt to extract address
 * properties from a witness.
 * @param {Witness}
 * @returns {Address|null}
 */

Address.fromWitness = function fromWitness(witness) {
  return new Address().fromWitness(witness);
};

/**
 * Create an Address from an input script.
 * Attempt to extract address
 * properties from an input script.
 * @param {Script}
 * @returns {Address|null}
 */

Address.fromInputScript = function fromInputScript(script) {
  return new Address().fromInputScript(script);
};

/**
 * Create an Address from an output script.
 * Parse an output script and extract address
 * properties. Converts pubkey and multisig
 * scripts to pubkeyhash and scripthash addresses.
 * @param {Script}
 * @returns {Address|null}
 */

Address.fromScript = function fromScript(script) {
  return new Address().fromScript(script);
};

/**
 * Inject properties from a hash.
 * @private
 * @param {Buffer|Hash} hash
 * @param {AddressType} type
 * @param {Number} [version=-1]
 * @param {(Network|NetworkType)?} network
 * @throws on bad hash size
 */

Address.prototype.fromHash = function fromHash(hash, type, version, network) {
  if (typeof hash === 'string')
    hash = new Buffer(hash, 'hex');

  if (typeof type === 'string')
    type = scriptTypes[type.toUpperCase()];

  if (type == null)
    type = scriptTypes.PUBKEYHASH;

  if (version == null)
    version = -1;

  network = Network.get(network);

  assert(Buffer.isBuffer(hash));
  assert(util.isNumber(type));
  assert(util.isNumber(version));

  assert(Address.getPrefix(type, network) !== -1, 'Not a valid address type.');

  if (version === -1) {
    assert(!Address.isWitness(type), 'Wrong version (witness)');
    assert(hash.length === 20, 'Hash is the wrong size.');
  } else {
    assert(Address.isWitness(type), 'Wrong version (non-witness).');
    assert(version >= 0 && version <= 16, 'Bad program version.');
    if (version === 0 && type === scriptTypes.WITNESSPUBKEYHASH)
      assert(hash.length === 20, 'Hash is the wrong size.');
    else if (version === 0 && type === scriptTypes.WITNESSSCRIPTHASH)
      assert(hash.length === 32, 'Hash is the wrong size.');
    else if (version === 1 && type === scriptTypes.WITNESSSCRIPTHASH)
      assert(hash.length === 32, 'Hash is the wrong size.');
  }

  this.hash = hash;
  this.type = type;
  this.version = version;
  this.network = network;

  return this;
};

/**
 * Create a naked address from hash/type/version.
 * @param {Buffer|Hash} hash
 * @param {AddressType} type
 * @param {Number} [version=-1]
 * @param {(Network|NetworkType)?} network
 * @returns {Address}
 * @throws on bad hash size
 */

Address.fromHash = function fromHash(hash, type, version, network) {
  return new Address().fromHash(hash, type, version, network);
};

/**
 * Inject properties from data.
 * @private
 * @param {Buffer|Buffer[]} data
 * @param {AddressType} type
 * @param {Number} [version=-1]
 * @param {(Network|NetworkType)?} network
 */

Address.prototype.fromData = function fromData(data, type, version, network) {
  if (typeof type === 'string')
    type = scriptTypes[type.toUpperCase()];

  if (type === scriptTypes.WITNESSSCRIPTHASH) {
    if (version === 0) {
      assert(Buffer.isBuffer(data));
      data = crypto.sha256(data);
    } else if (version === 1) {
      assert(Array.isArray(data));
      throw new Error('MASTv2 creation not implemented.');
    } else {
      throw new Error('Cannot create from version=' + version);
    }
  } else if (type === scriptTypes.WITNESSPUBKEYHASH) {
    if (version !== 0)
      throw new Error('Cannot create from version=' + version);
    assert(Buffer.isBuffer(data));
    data = crypto.hash160(data);
  } else {
    data = crypto.hash160(data);
  }

  return this.fromHash(data, type, version, network);
};

/**
 * Create an Address from data/type/version.
 * @param {Buffer|Buffer[]} data - Data to be hashed.
 * Normally a buffer, but can also be an array of
 * buffers for MAST.
 * @param {AddressType} type
 * @param {Number} [version=-1]
 * @param {(Network|NetworkType)?} network
 * @returns {Address}
 * @throws on bad hash size
 */

Address.fromData = function fromData(data, type, version, network) {
  return new Address().fromData(data, type, version, network);
};

/**
 * Validate an address, optionally test against a type.
 * @param {Base58Address} address
 * @param {AddressType}
 * @returns {Boolean}
 */

Address.validate = function validate(address, type) {
  if (!address)
    return false;

  if (!Buffer.isBuffer(address) && typeof address !== 'string')
    return false;

  try {
    address = Address.fromBase58(address);
  } catch (e) {
    return false;
  }

  if (typeof type === 'string')
    type = scriptTypes[type.toUpperCase()];

  if (type && address.type !== type)
    return false;

  return true;
};

/**
 * Get the hex hash of a base58
 * address or address object.
 * @param {Base58Address|Address} data
 * @returns {Hash|null}
 */

Address.getHash = function getHash(data, enc) {
  var hash;

  if (typeof data === 'string') {
    if (data.length === 40 || data.length === 64)
      return enc === 'hex' ? data : new Buffer(data, 'hex');

    try {
      hash = Address.fromBase58(data).hash;
    } catch (e) {
      return;
    }
  } else if (Buffer.isBuffer(data)) {
    hash = data;
  } else if (data instanceof Address) {
    hash = data.hash;
  } else {
    return;
  }

  return enc === 'hex'
    ? hash.toString('hex')
    : hash;
};

/**
 * Get a network address prefix for a specified address type.
 * @param {AddressType} type
 * @param {Network} network
 * @returns {Number}
 */

Address.getPrefix = function getPrefix(type, network) {
  var prefixes = network.addressPrefix;
  switch (type) {
    case scriptTypes.PUBKEYHASH:
      return prefixes.pubkeyhash;
    case scriptTypes.SCRIPTHASH:
      return prefixes.scripthash;
    case scriptTypes.WITNESSPUBKEYHASH:
      return prefixes.witnesspubkeyhash;
    case scriptTypes.WITNESSSCRIPTHASH:
      return prefixes.witnessscripthash;
    default:
      return -1;
  }
};

/**
 * Get an address type for a specified network address prefix.
 * @param {Number} prefix
 * @param {Network} network
 * @returns {AddressType}
 */

Address.getType = function getType(prefix, network) {
  var prefixes = network.addressPrefix;
  switch (prefix) {
    case prefixes.pubkeyhash:
      return scriptTypes.PUBKEYHASH;
    case prefixes.scripthash:
      return scriptTypes.SCRIPTHASH;
    case prefixes.witnesspubkeyhash:
      return scriptTypes.WITNESSPUBKEYHASH;
    case prefixes.witnessscripthash:
      return scriptTypes.WITNESSSCRIPTHASH;
    default:
      return -1;
  }
};

/**
 * Test whether an address type is a witness program.
 * @param {AddressType} type
 * @returns {Boolean}
 */

Address.isWitness = function isWitness(type) {
  switch (type) {
    case scriptTypes.WITNESSPUBKEYHASH:
      return true;
    case scriptTypes.WITNESSSCRIPTHASH:
      return true;
    default:
      return false;
  }
};

/*
 * Expose
 */

module.exports = Address;
