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
var encoding = require('../utils/encoding');
var util = require('../utils/util');
var crypto = require('../crypto/crypto');
var BufferReader = require('../utils/reader');
var StaticWriter = require('../utils/staticwriter');
var base58 = require('../utils/base58');
var bech32 = require('../utils/bech32');

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
 * Address types.
 * @enum {Number}
 */

Address.types = {
  PUBKEYHASH: 2,
  SCRIPTHASH: 3,
  WITNESS: 4
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
  return Address.getPrefix(this.type, this.hash, network);
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
  var i;

  if (this.hash.length === 20)
    return util.equal(this.hash, encoding.ZERO_HASH160);

  if (this.hash.length === 32)
    return util.equal(this.hash, encoding.ZERO_HASH);

  for (i = 0; i < this.hash.length; i++) {
    if (this.hash[i] !== 0)
      return false;
  }

  return true;
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
 * Compile the address object to a bech32 address.
 * @param {{NetworkType|Network)?} network
 * @returns {String}
 * @throws Error on bad hash/prefix.
 */

Address.prototype.toBech32 = function toBech32(network) {
  var version = this.version;
  var hash = this.hash;
  var hrp, data;

  assert(version !== -1,
    'Cannot convert non-segwit address to bech32.');

  if (!network)
    network = this.network;

  network = Network.get(network);
  hrp = network.addressPrefix.bech32;

  data = bech32.bitsify(hash, 65, 8, 5, version, 0);

  return bech32.encode(hrp, data);
};

/**
 * Inject properties from string.
 * @private
 * @param {String} addr
 * @param {(Network|NetworkType)?} network
 * @returns {Address}
 */

Address.prototype.fromString = function fromString(addr, network) {
  var i, type, hrp;

  assert(typeof addr === 'string');
  assert(addr.length > 2);

  if (network) {
    network = Network.get(network);
    hrp = network.addressPrefix.bech32;
    if (util.startsWith(addr, hrp))
      return this.fromBech32(addr, network);
  } else {
    for (i = 0; i < networks.types.length; i++) {
      type = networks.types[i];
      hrp = networks[type].addressPrefix.bech32;
      if (util.startsWith(addr, hrp))
        return this.fromBech32(addr, type);
    }
  }

  return this.fromBase58(addr, network);
};

/**
 * Instantiate address from string.
 * @param {String} addr
 * @param {(Network|NetworkType)?} network
 * @returns {Address}
 */

Address.fromString = function fromString(addr, network) {
  return new Address().fromString(addr, network);
};

/**
 * Convert the Address to a string.
 * @param {(Network|NetworkType)?} network
 * @returns {Base58Address}
 */

Address.prototype.toString = function toString(network) {
  if (this.version !== -1)
    return this.toBech32(network);
  return this.toBase58(network);
};

/**
 * Inspect the Address.
 * @returns {Object}
 */

Address.prototype.inspect = function inspect() {
  return '<Address:'
    + ' type=' + this.getType()
    + ' version=' + this.version
    + ' base58=' + this.toString()
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
 * Inject properties from bech32 address.
 * @private
 * @param {String} data
 * @param {Network?} network
 * @throws Parse error
 */

Address.prototype.fromBech32 = function fromBech32(data, network) {
  var type = Address.types.WITNESS;
  var i, addr, hash, version;

  assert(typeof data === 'string');

  addr = bech32.decode(data);

  if (addr.data.length < 1)
    throw new Error('Invalid bech32 data length.');

  version = addr.data[0];

  if (network) {
    network = Network.get(network);
    if (addr.hrp !== network.addressPrefix.bech32)
      throw new Error('Network mismatch for bech32 address.');
  } else {
    for (i = 0; i < networks.types.length; i++) {
      network = networks[networks.types[i]];
      if (addr.hrp === network.addressPrefix.bech32)
        break;
    }

    assert(i < networks.types.length, 'Unknown bech32 address prefix.');
  }

  hash = bech32.bitsify(addr.data, 84, 5, 8, -1, 1);

  return this.fromHash(hash, type, version, network.type);
};

/**
 * Create an address object from a bech32 address.
 * @param {String} address
 * @param {Network?} network
 * @returns {Address}
 * @throws Parse error.
 */

Address.fromBech32 = function fromBech32(address, network) {
  return new Address().fromBech32(address, network);
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
    this.type = Address.types.WITNESS;
    this.version = 0;
    return this;
  }

  if (script.isWitnessScripthash()) {
    this.hash = script.get(1);
    this.type = Address.types.WITNESS;
    this.version = 0;
    return this;
  }

  if (script.isWitnessMasthash()) {
    this.hash = script.get(1);
    this.type = Address.types.WITNESS;
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
    this.type = Address.types.WITNESS;
    this.version = 0;
    return this;
  }

  if (witness.isScripthashInput()) {
    this.hash = crypto.sha256(witness.get(witness.length - 1));
    this.type = Address.types.WITNESS;
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

  assert(type >= Address.types.PUBKEYHASH && type <= Address.types.WITNESS,
    'Not a valid address type.');

  if (version === -1) {
    assert(type !== Address.types.WITNESS, 'Wrong version (witness)');
    assert(hash.length === 20, 'Hash is the wrong size.');
  } else {
    assert(type === Address.types.WITNESS, 'Wrong version (non-witness).');
    assert(version >= 0 && version <= 16, 'Bad program version.');
    if (version === 0 && type === Address.types.WITNESS) {
      assert(hash.length === 20 || hash.length === 32,
        'Witness program hash is the wrong size.');
    }
    assert(hash.length >= 2 && hash.length <= 40, 'Hash is the wrong size.');
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
  var type = Address.types.WITNESS;
  assert(hash.length === 20, 'P2WPKH must be 20 bytes.');
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
  var type = Address.types.WITNESS;
  assert(hash.length === 32, 'P2WPKH must be 32 bytes.');
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
  var type = Address.types.WITNESS;

  assert(version >= 0, 'Bad version for witness program.');

  if (typeof hash === 'string')
    hash = new Buffer(hash, 'hex');

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
  return this.version === 0 && this.hash.length === 20;
};

/**
 * Test whether the address is witness scripthash.
 * @returns {Boolean}
 */

Address.prototype.isWitnessScripthash = function isWitnessScripthash() {
  return this.version === 0 && this.hash.length === 32;
};

/**
 * Test whether the address is witness masthash.
 * @returns {Boolean}
 */

Address.prototype.isWitnessMasthash = function isWitnessMasthash() {
  return this.version === 1 && this.hash.length === 32;
};

/**
 * Test whether the address is a witness program.
 * @returns {Boolean}
 */

Address.prototype.isProgram = function isProgram() {
  return this.version !== -1;
};

/**
 * Test whether the address is an unknown witness program.
 * @returns {Boolean}
 */

Address.prototype.isUnknown = function isUnknown() {
  if (this.version === -1)
    return false;

  if (this.version > 0)
    return true;

  return this.hash.length !== 20 && this.hash.length !== 32;
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
      hash = Address.fromString(data).hash;
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
 * @param {Buffer} hash
 * @param {Network} network
 * @returns {Number}
 */

Address.getPrefix = function getPrefix(type, hash, network) {
  var prefixes = network.addressPrefix;
  switch (type) {
    case Address.types.PUBKEYHASH:
      return prefixes.pubkeyhash;
    case Address.types.SCRIPTHASH:
      return prefixes.scripthash;
    case Address.types.WITNESS:
      if (hash.length === 20)
        return prefixes.witnesspubkeyhash;
      if (hash.length === 32)
        return prefixes.witnessscripthash;
      assert(false, 'No witness prefix defined.');
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
      return Address.types.WITNESS;
    case prefixes.witnessscripthash:
      return Address.types.WITNESS;
    default:
      return -1;
  }
};

/*
 * Expose
 */

module.exports = Address;
