/*!
 * address.js - address object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var Network = require('../protocol/network');
var networks = require('../protocol/networks');
var common = require('../script/common');
var encoding = require('../utils/encoding');
var util = require('../utils/util');
var crypto = require('../crypto/crypto');
var BufferReader = require('../utils/reader');
var StaticWriter = require('../utils/staticwriter');
var base58 = require('../utils/base58');

/**
 * Represents an address.
 * @alias module:primitives.Address
 * @constructor
 * @param {Object} options
 * @param {Buffer|Hash} options.hash - Address hash.
 * @param {AddressPrefix} options.type - Address type
 * `{witness,}{pubkeyhash,scripthash}`.
 * @param {Number} [options.version=-1] - Witness program version.
 * @param {(Network|NetworkType)?} options.network - Network name.
 * @property {Buffer} hash
 * @property {AddressPrefix} type
 * @property {Number} version
 * @property {Network} network
 */

function Address(options) {
  if (!(this instanceof Address))
    return new Address(options);

  this.hash = encoding.ZERO_HASH160;
  this.type = Address.types.PUBKEYHASH;
  this.version = -1;
  this.network = Network.primary;

  if (options)
    this.fromOptions(options);
}

/**
 * Address types. Note that the values
 * have a direct mapping to script types.
 * These also represent the "prefix type"
 * as a network-agnostic version of the
 * prefix byte. They DO NOT represent the
 * script type. For example, script type
 * `WITNESSMASTHASH` would be prefix type
 * `WITNESSSCRIPTHASH` with a `version`
 * of 1.
 * @enum {Number}
 */

Address.types = {
  PUBKEYHASH: common.types.PUBKEYHASH,
  SCRIPTHASH: common.types.SCRIPTHASH,
  WITNESSSCRIPTHASH: common.types.WITNESSSCRIPTHASH,
  WITNESSPUBKEYHASH: common.types.WITNESSPUBKEYHASH
};

/**
 * Address types by value.
 * @const {RevMap}
 */

Address.typesByVal = util.revMap(Address.types);

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
 * Get a network address prefix for the address.
 * @param {Network?} network
 * @returns {Number}
 */

Address.prototype.getPrefix = function getPrefix(network) {
  if (!network)
    network = this.network;
  network = Network.get(network);
  return Address.getPrefix(this.type, network);
};

/**
 * Verify an address network (compares prefixes).
 * @param {Network} network
 * @returns {Boolean}
 */

Address.prototype.verifyNetwork = function verifyNetwork(network) {
  assert(network);
  return this.getPrefix() === this.getPrefix(network);
};

/**
 * Test whether the address is null.
 * @returns {Boolean}
 */

Address.prototype.isNull = function isNull() {
  return util.equal(this.hash, encoding.ZERO_HASH160);
};

/**
 * Get the address type as a string.
 * @returns {AddressPrefix}
 */

Address.prototype.getType = function getType() {
  return Address.typesByVal[this.type].toLowerCase();
};

/**
 * Calculate size of serialized address.
 * @returns {Number}
 */

Address.prototype.getSize = function getSize() {
  var size = 5 + this.hash.length;

  if (this.version !== -1)
    size += 2;

  return size;
};

/**
 * Compile the address object to its raw serialization.
 * @param {{NetworkType|Network)?} network
 * @returns {Buffer}
 * @throws Error on bad hash/prefix.
 */

Address.prototype.toRaw = function toRaw(network) {
  var size = this.getSize();
  var bw = new StaticWriter(size);
  var prefix = this.getPrefix(network);

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
 * @returns {Base58Address}
 */

Address.prototype.toString = function toString() {
  return this.toBase58();
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
  var br = new BufferReader(data, true);
  var i, prefix, network, type, version, hash;

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
 * @param {Network?} network
 * @throws Parse error
 */

Address.prototype.fromBase58 = function fromBase58(data, network) {
  assert(typeof data === 'string');

  this.fromRaw(base58.decode(data));

  if (network && !this.verifyNetwork(network))
    throw new Error('Network mismatch for address.');

  return this;
};

/**
 * Create an address object from a base58 address.
 * @param {Base58Address} address
 * @param {Network?} network
 * @returns {Address}
 * @throws Parse error.
 */

Address.fromBase58 = function fromBase58(address, network) {
  return new Address().fromBase58(address, network);
};

/**
 * Inject properties from output script.
 * @private
 * @param {Script} script
 */

Address.prototype.fromScript = function fromScript(script) {
  if (script.isPubkey()) {
    this.hash = crypto.hash160(script.get(0));
    this.type = Address.types.PUBKEYHASH;
    this.version = -1;
    return this;
  }

  if (script.isPubkeyhash()) {
    this.hash = script.get(2);
    this.type = Address.types.PUBKEYHASH;
    this.version = -1;
    return this;
  }

  if (script.isScripthash()) {
    this.hash = script.get(1);
    this.type = Address.types.SCRIPTHASH;
    this.version = -1;
    return this;
  }

  if (script.isWitnessPubkeyhash()) {
    this.hash = script.get(1);
    this.type = Address.types.WITNESSPUBKEYHASH;
    this.version = 0;
    return this;
  }

  if (script.isWitnessScripthash()) {
    this.hash = script.get(1);
    this.type = Address.types.WITNESSSCRIPTHASH;
    this.version = 0;
    return this;
  }

  if (script.isWitnessMasthash()) {
    this.hash = script.get(1);
    this.type = Address.types.WITNESSSCRIPTHASH;
    this.version = 1;
    return this;
  }

  // Put this last: it's the slowest to check.
  if (script.isMultisig()) {
    this.hash = script.hash160();
    this.type = Address.types.SCRIPTHASH;
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
    this.type = Address.types.WITNESSPUBKEYHASH;
    this.version = 0;
    return this;
  }

  if (witness.isScripthashInput()) {
    this.hash = crypto.sha256(witness.get(witness.length - 1));
    this.type = Address.types.WITNESSSCRIPTHASH;
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
    this.type = Address.types.PUBKEYHASH;
    this.version = -1;
    return this;
  }

  if (script.isScripthashInput()) {
    this.hash = crypto.hash160(script.get(script.length - 1));
    this.type = Address.types.SCRIPTHASH;
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
 * @param {AddressPrefix} type
 * @param {Number} [version=-1]
 * @param {(Network|NetworkType)?} network
 * @throws on bad hash size
 */

Address.prototype.fromHash = function fromHash(hash, type, version, network) {
  if (typeof hash === 'string')
    hash = new Buffer(hash, 'hex');

  if (typeof type === 'string') {
    type = Address.types[type.toUpperCase()];
    assert(type != null, 'Not a valid address type.');
  }

  if (type == null)
    type = Address.types.PUBKEYHASH;

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
    if (version === 0 && type === Address.types.WITNESSPUBKEYHASH)
      assert(hash.length === 20, 'Hash is the wrong size.');
    else if (version === 0 && type === Address.types.WITNESSSCRIPTHASH)
      assert(hash.length === 32, 'Hash is the wrong size.');
    else if (version === 1 && type === Address.types.WITNESSSCRIPTHASH)
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
 * @param {Hash} hash
 * @param {AddressPrefix} type
 * @param {Number} [version=-1]
 * @param {(Network|NetworkType)?} network
 * @returns {Address}
 * @throws on bad hash size
 */

Address.fromHash = function fromHash(hash, type, version, network) {
  return new Address().fromHash(hash, type, version, network);
};

/**
 * Inject properties from pubkeyhash.
 * @private
 * @param {Buffer} hash
 * @param {Network?} network
 * @returns {Address}
 */

Address.prototype.fromPubkeyhash = function fromPubkeyhash(hash, network) {
  var type = Address.types.PUBKEYHASH;
  return this.fromHash(hash, type, -1, network);
};

/**
 * Instantiate address from pubkeyhash.
 * @param {Buffer} hash
 * @param {Network?} network
 * @returns {Address}
 */

Address.fromPubkeyhash = function fromPubkeyhash(hash, network) {
  return new Address().fromPubkeyhash(hash, network);
};

/**
 * Inject properties from scripthash.
 * @private
 * @param {Buffer} hash
 * @param {Network?} network
 * @returns {Address}
 */

Address.prototype.fromScripthash = function fromScripthash(hash, network) {
  var type = Address.types.SCRIPTHASH;
  return this.fromHash(hash, type, -1, network);
};

/**
 * Instantiate address from scripthash.
 * @param {Buffer} hash
 * @param {Network?} network
 * @returns {Address}
 */

Address.fromScripthash = function fromScripthash(hash, network) {
  return new Address().fromScripthash(hash, network);
};

/**
 * Inject properties from witness pubkeyhash.
 * @private
 * @param {Buffer} hash
 * @param {Network?} network
 * @returns {Address}
 */

Address.prototype.fromWitnessPubkeyhash = function fromWitnessPubkeyhash(hash, network) {
  var type = Address.types.WITNESSPUBKEYHASH;
  return this.fromHash(hash, type, 0, network);
};

/**
 * Instantiate address from witness pubkeyhash.
 * @param {Buffer} hash
 * @param {Network?} network
 * @returns {Address}
 */

Address.fromWitnessPubkeyhash = function fromWitnessPubkeyhash(hash, network) {
  return new Address().fromWitnessPubkeyhash(hash, network);
};

/**
 * Inject properties from witness scripthash.
 * @private
 * @param {Buffer} hash
 * @param {Network?} network
 * @returns {Address}
 */

Address.prototype.fromWitnessScripthash = function fromWitnessScripthash(hash, network) {
  var type = Address.types.WITNESSSCRIPTHASH;
  return this.fromHash(hash, type, 0, network);
};

/**
 * Instantiate address from witness scripthash.
 * @param {Buffer} hash
 * @param {Network?} network
 * @returns {Address}
 */

Address.fromWitnessScripthash = function fromWitnessScripthash(hash, network) {
  return new Address().fromWitnessScripthash(hash, network);
};

/**
 * Inject properties from witness program.
 * @private
 * @param {Number} version
 * @param {Buffer} hash
 * @param {Network?} network
 * @returns {Address}
 */

Address.prototype.fromProgram = function fromProgram(version, hash, network) {
  var type;

  assert(version >= 0, 'Bad version for witness program.');

  if (typeof hash === 'string')
    hash = new Buffer(hash, 'hex');

  switch (hash.length) {
    case 20:
      type = Address.types.WITNESSPUBKEYHASH;
      break;
    case 32:
      type = Address.types.WITNESSSCRIPTHASH;
      break;
    default:
      assert(false, 'Unknown witness program data length.');
      break;
  }

  return this.fromHash(hash, type, version, network);
};

/**
 * Instantiate address from witness program.
 * @param {Number} version
 * @param {Buffer} hash
 * @param {Network?} network
 * @returns {Address}
 */

Address.fromProgram = function fromProgram(version, hash, network) {
  return new Address().fromProgram(version, hash, network);
};

/**
 * Test whether the address is pubkeyhash.
 * @returns {Boolean}
 */

Address.prototype.isPubkeyhash = function isPubkeyhash() {
  return this.type === Address.types.PUBKEYHASH;
};

/**
 * Test whether the address is scripthash.
 * @returns {Boolean}
 */

Address.prototype.isScripthash = function isScripthash() {
  return this.type === Address.types.SCRIPTHASH;
};

/**
 * Test whether the address is witness pubkeyhash.
 * @returns {Boolean}
 */

Address.prototype.isWitnessPubkeyhash = function isWitnessPubkeyhash() {
  return this.version === 0 && this.type === Address.types.WITNESSPUBKEYHASH;
};

/**
 * Test whether the address is witness scripthash.
 * @returns {Boolean}
 */

Address.prototype.isWitnessScripthash = function isWitnessScripthash() {
  return this.version === 0 && this.type === Address.types.WITNESSSCRIPTHASH;
};

/**
 * Test whether the address is witness masthash.
 * @returns {Boolean}
 */

Address.prototype.isWitnessMasthash = function isWitnessMasthash() {
  return this.version === 1 && this.type === Address.types.WITNESSSCRIPTHASH;
};

/**
 * Test whether the address is a witness program.
 * @returns {Boolean}
 */

Address.prototype.isProgram = function isProgram() {
  return this.version !== -1;
};

/**
 * Get the hash of a base58 address or address-related object.
 * @param {Base58Address|Address|Hash} data
 * @param {String} enc
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
 * @param {AddressPrefix} type
 * @param {Network} network
 * @returns {Number}
 */

Address.getPrefix = function getPrefix(type, network) {
  var prefixes = network.addressPrefix;
  switch (type) {
    case Address.types.PUBKEYHASH:
      return prefixes.pubkeyhash;
    case Address.types.SCRIPTHASH:
      return prefixes.scripthash;
    case Address.types.WITNESSPUBKEYHASH:
      return prefixes.witnesspubkeyhash;
    case Address.types.WITNESSSCRIPTHASH:
      return prefixes.witnessscripthash;
    default:
      return -1;
  }
};

/**
 * Get an address type for a specified network address prefix.
 * @param {Number} prefix
 * @param {Network} network
 * @returns {AddressPrefix}
 */

Address.getType = function getType(prefix, network) {
  var prefixes = network.addressPrefix;
  switch (prefix) {
    case prefixes.pubkeyhash:
      return Address.types.PUBKEYHASH;
    case prefixes.scripthash:
      return Address.types.SCRIPTHASH;
    case prefixes.witnesspubkeyhash:
      return Address.types.WITNESSPUBKEYHASH;
    case prefixes.witnessscripthash:
      return Address.types.WITNESSSCRIPTHASH;
    default:
      return -1;
  }
};

/**
 * Test whether an address type is a witness program.
 * @param {AddressPrefix} type
 * @returns {Boolean}
 */

Address.isWitness = function isWitness(type) {
  switch (type) {
    case Address.types.WITNESSPUBKEYHASH:
      return true;
    case Address.types.WITNESSSCRIPTHASH:
      return true;
    default:
      return false;
  }
};

/*
 * Expose
 */

module.exports = Address;
