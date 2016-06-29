/*!
 * address.js - address object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var bcoin = require('./env');
var networks = bcoin.protocol.network;
var constants = bcoin.protocol.constants;
var utils = require('./utils');
var assert = utils.assert;
var BufferWriter = require('./writer');
var BufferReader = require('./reader');
var Script = bcoin.script;

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
 * @property {NetworkType} network
 */

function Address(options) {
  if (!(this instanceof Address))
    return new Address(options);

  this.hash = constants.ZERO_HASH160;
  this.type = 'pubkeyhash';
  this.version = -1;
  this.network = bcoin.network.get().type;

  if (options)
    this.fromOptions(options);
}

/**
 * Inject properties from options object.
 * @private
 * @param {Object} options
 */

Address.prototype.fromOptions = function fromOptions(options) {
  assert(options.hash);

  this.hash = options.hash;

  if (options.type)
    this.type = options.type;

  if (options.version != null)
    this.version = options.version;

  if (options.network)
    this.network = bcoin.network.get(options.network).type;

  if (typeof this.hash === 'string')
    this.hash = new Buffer(this.hash, 'hex');

  return this;
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
 * Compile the address object to a base58 address.
 * @param {{NetworkType|Network)?} network
 * @returns {Base58Address}
 * @throws Error on bad hash/prefix.
 */

Address.prototype.toBase58 = function toBase58(network) {
  var p = new BufferWriter();
  var prefix;

  if (!network)
    network = this.network;

  network = bcoin.network.get(network);
  prefix = network.address.prefixes[this.type];

  assert(prefix != null, 'Not a valid address prefix.');

  p.writeU8(prefix);
  if (this.version !== -1) {
    p.writeU8(this.version);
    p.writeU8(0);
  }
  p.writeBytes(this.hash);
  p.writeChecksum();

  return utils.toBase58(p.render());
};

/**
 * Convert the address to an output script.
 * @returns {Script}
 */

Address.prototype.toScript = function toScript() {
  return Script.fromAddress(this);
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
    + ' type=' + this.type
    + ' version=' + this.version
    + ' base58=' + this.toBase58()
    + '>';
};

/**
 * Inject properties from base58 address.
 * @private
 * @param {Base58Address} data
 * @throws Parse error
 */

Address.prototype.fromBase58 = function fromBase58(data) {
  var i, prefix, type, version, hash, network, p;

  if (typeof data === 'string')
    data = utils.fromBase58(data);

  p = new BufferReader(data, true);
  prefix = p.readU8();

  for (i = 0; i < networks.types.length; i++) {
    network = networks[networks.types[i]];
    type = network.address.prefixesByVal[prefix];
    if (type != null)
      break;
  }

  assert(type != null, 'Unknown address prefix.');

  if (data.length > 25) {
    version = p.readU8();
    assert(data.length === 27 || data.length === 39);
    assert(version >= 0 && version <= 16, 'Bad program version.');
    assert(p.readU8() === 0, 'Address version padding is non-zero.');
  } else {
    version = -1;
    assert(data.length === 25);
  }

  if (data.length === 39)
    hash = p.readBytes(32);
  else
    hash = p.readBytes(20);

  p.verifyChecksum();

  this.network = network.type;
  this.type = type;
  this.hash = hash;
  this.version = version;

  return this;
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
  var program;

  if (script.isProgram()) {
    program = script.toProgram();
    // TODO: MAST support
    if (program.isUnknown())
      return;
    this.hash = program.data;
    this.type = program.type;
    this.version = program.version;
    return this;
  }

  // Fast case
  if (script.isPubkey()) {
    this.hash = utils.hash160(script.raw.slice(1, script.raw[0] + 1));
    this.type = 'pubkeyhash';
    this.version = -1;
    return this;
  }

  if (script.isPubkeyhash()) {
    this.hash = script.raw.slice(3, 23);
    this.type = 'pubkeyhash';
    this.version = -1;
    return this;
  }

  if (script.isScripthash()) {
    this.hash = script.raw.slice(2, 22);
    this.type = 'scripthash';
    this.version = -1;
    return this;
  }

  // Slow case (allow non-minimal data and parse script)
  if (script.isPubkey(true)) {
    this.hash = utils.hash160(script.code[0].data);
    this.type = 'pubkeyhash';
    this.version = -1;
    return this;
  }

  if (script.isPubkeyhash(true)) {
    this.hash = script.code[2].data;
    this.type = 'pubkeyhash';
    this.version = -1;
    return this;
  }

  if (script.isMultisig()) {
    this.hash = utils.hash160(script.raw);
    this.type = 'scripthash';
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
  if (witness.isPubkeyhashInput()) {
    this.hash = utils.hash160(witness.items[1]);
    this.type = 'witnesspubkeyhash';
    this.version = 0;
    return this;
  }

  if (witness.isScripthashInput()) {
    this.hash = utils.sha256(witness.items[witness.items.length - 1]);
    this.type = 'witnessscripthash';
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
    this.hash = utils.hash160(script.code[1].data);
    this.type = 'pubkeyhash';
    this.version = -1;
    return this;
  }

  if (script.isScripthashInput()) {
    this.hash = utils.hash160(script.code[script.code.length - 1].data);
    this.type = 'scripthash';
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
 * @throws on bad hash size
 */

Address.prototype.fromHash = function fromHash(hash, type, version, network) {
  var prefix;

  if (typeof hash === 'string')
    hash = new Buffer(hash, 'hex');

  if (!type)
    type = 'pubkeyhash';

  if (version == null)
    version = -1;

  network = bcoin.network.get(network);
  prefix = network.address.prefixes[type];

  assert(prefix != null, 'Not a valid address prefix.');

  if (version === -1)
    assert(hash.length === 20, 'Hash is the wrong size.');
  else if (version === 0 && type === 'witnesspubkeyhash')
    assert(hash.length === 20, 'Hash is the wrong size.');
  else if (version === 0 && type === 'witnessscripthash')
    assert(hash.length === 32, 'Hash is the wrong size.');
  else if (version === 1 && type === 'witnessscripthash')
    assert(hash.length === 32, 'Hash is the wrong size.');

  this.hash = hash;
  this.type = type;
  this.version = version;
  this.network = network.type;

  return this;
};

/**
 * Create a naked address from hash/type/version.
 * @param {Buffer|Hash} hash
 * @param {AddressType} type
 * @param {Number} [version=-1]
 * @returns {Address}
 * @throws on bad hash size
 */

Address.fromHash = function fromHash(hash, type, version, network) {
  return new Address().fromHash(hash, type, version, network);
};

/**
 * Inject properties from hash.
 * @param {Hash|Buffer} hash
 * @param {AddressType?} type
 * @param {Number?} version - Witness program version.
 * @throws on bad hash size
 */

Address.prototype.fromData = function fromData(data, type, version, network) {
  if (type === 'witnessscripthash') {
    assert(version === 0);
    data = utils.sha256(data);
  } else if (type === 'witnesspubkeyhash') {
    assert(version === 0);
    data = utils.hash160(data);
  } else {
    data = utils.hash160(data);
  }
  return this.fromHash(data, type, version, network);
};

/**
 * Create an Address from data/type/version.
 * @param {Buffer} data - Data to be hashed.
 * @param {AddressType} type
 * @param {Number} [version=-1]
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

  if (utils.isHex(data))
    return enc === 'hex' ? data : new Buffer(data, 'hex');

  if (Buffer.isBuffer(data)) {
    hash = data;
  } else if (data instanceof Address) {
    hash = data.hash;
  } else {
    try {
      hash = Address.fromBase58(data).hash;
    } catch (e) {
      return;
    }
  }

  return enc === 'hex'
    ? hash.toString('hex')
    : hash;
};

/*
 * Expose
 */

module.exports = Address;
