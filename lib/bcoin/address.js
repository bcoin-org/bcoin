/*!
 * address.js - address object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var bcoin = require('./env');
var networks = bcoin.protocol.network;
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

  this.hash = null;
  this.type = null;
  this.version = null;
  this.network = bcoin.network.get().type;

  if (options)
    this.fromOptions(options);
}

Address.prototype.fromOptions = function fromOptions(options) {
  this.hash = options.hash;
  this.type = options.type || 'pubkeyhash';
  this.version = options.version == null ? -1 : options.version;
  this.network = bcoin.network.get(options.network).type;

  if (!Buffer.isBuffer(this.hash))
    this.hash = new Buffer(this.hash, 'hex');
};

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
  if (!network)
    network = this.network;

  return Address.toBase58(this.hash, this.type, this.version, network);
};

/**
 * Convert the address to an output script.
 * @returns {Script}
 */

Address.prototype.toScript = function toScript() {
  if (this.type === 'pubkeyhash')
    return Script.createPubkeyhash(this.hash);
  if (this.type === 'scripthash')
    return Script.createScripthash(this.hash);
  if (this.version !== -1)
    return Script.createWitnessProgram(this.version, this.hash);
  assert(false, 'Bad type.');
};

/**
 * Convert the Address to a string.
 * @returns {Base58String}
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
    + ' type=' + this.type
    + ' version=' + this.version
    + ' base58=' + this.toBase58()
    + '>';
};

/**
 * Compile a hash to an address.
 * @param {Hash|Buffer} hash
 * @param {AddressType?} type
 * @param {Number?} version - Witness version.
 * @returns {Base58Address}
 * @throws Error on bad hash/prefix.
 */

Address.toBase58 = function toBase58(hash, type, version, network) {
  var p, prefix;

  if (!Buffer.isBuffer(hash))
    hash = new Buffer(hash, 'hex');

  if (!type)
    type = 'pubkeyhash';

  network = bcoin.network.get(network);

  prefix = network.address.prefixes[type];

  if (!(version >= 0))
    version = network.address.versions[type];

  assert(prefix != null, 'Not a valid address prefix.');

  if (!(version >= 0))
    assert(hash.length === 20, 'Hash is the wrong size.');
  else if (version === 0 && type === 'witnesspubkeyhash')
    assert(hash.length === 20, 'Hash is the wrong size.');
  else if (version === 0 && type === 'witnessscripthash')
    assert(hash.length === 32, 'Hash is the wrong size.');

  p = new BufferWriter();

  p.writeU8(prefix);
  if (version != null) {
    p.writeU8(version);
    p.writeU8(0);
  }
  p.writeBytes(hash);
  p.writeChecksum();

  return utils.toBase58(p.render());
};

/**
 * Parse a base58 address.
 * @param {Base58Address} address
 * @returns {ParsedAddress}
 * @throws Parse error
 */

Address.prototype.fromBase58 = function fromBase58(address) {
  var i, prefix, type, version, hash, network, p;

  if (!Buffer.isBuffer(address))
    address = utils.fromBase58(address);

  p = new BufferReader(address, true);
  prefix = p.readU8();

  for (i = 0; i < networks.types.length; i++) {
    network = networks[networks.types[i]];
    type = network.address.prefixesByVal[prefix];
    if (type != null)
      break;
  }

  assert(type != null, 'Unknown address prefix.');

  version = network.address.versions[type];

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

  this.network = network.type;
  this.type = type;
  this.hash = hash;
  this.version = version == null ? -1 : version;

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
 * Parse an output script and extract address
 * properties. Converts pubkey and multisig
 * scripts to pubkeyhash and scripthash addresses.
 * @param {Script} script
 * @returns {ParsedAddress|null}
 */

Address.prototype.fromScript = function fromScript(script) {
  var program;

  if (script.isWitnessProgram()) {
    program = script.toProgram();
    if (program.isUnknown())
      return;
    this.hash = program.data;
    this.type = program.type;
    this.version = program.version;
    return this;
  }

  // Fast case
  if (script.isPubkey()) {
    this.hash = utils.ripesha(script.raw.slice(1, script.raw[0] + 1));
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
    this.hash = utils.ripesha(script.code[0].data);
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
    this.hash = utils.ripesha(script.raw);
    this.type = 'scripthash';
    this.version = -1;
    return this;
  }
};

/**
 * Attempt to extract address
 * properties from a witness.
 * @param {Witness} witness
 * @returns {ParsedAddress|null}
 */

Address.prototype.fromWitness = function fromWitness(witness) {
  if (witness.isPubkeyhashInput()) {
    this.hash = utils.ripesha(witness.items[1]);
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
 * Attempt to extract address
 * properties from an input script.
 * @param {Witness} witness
 * @returns {ParsedAddress|null}
 */

Address.prototype.fromInputScript = function fromInputScript(script) {
  if (script.isPubkeyhashInput()) {
    this.hash = utils.ripesha(script.code[1].data);
    this.type = 'pubkeyhash';
    this.version = -1;
    return this;
  }

  if (script.isScripthashInput()) {
    this.hash = utils.ripesha(script.code[script.code.length - 1].data);
    this.type = 'scripthash';
    this.version = -1;
    return this;
  }
};

/**
 * Create an Address from a witness.
 * @param {Witness}
 * @returns {ParsedAddress|null}
 */

Address.fromWitness = function fromWitness(witness) {
  return new Address().fromWitness(witness);
};

/**
 * Create an Address from an input script.
 * @param {Script}
 * @returns {ParsedAddress|null}
 */

Address.fromInputScript = function fromInputScript(script) {
  return new Address().fromInputScript(script);
};

/**
 * Create an Address from an output script.
 * @param {Script}
 * @returns {ParsedAddress|null}
 */

Address.fromScript = function fromScript(script) {
  return new Address().fromScript(script);
};

/**
 * Create a naked address from hash/type/version.
 * @param {Buffer|Hash} hash
 * @param {AddressType} type
 * @param {Number} [version=-1]
 * @returns {ParsedAddress}
 */

Address.prototype.fromHash = function fromHash(hash, type, version, network) {
  if (typeof hash === 'string')
    hash = new Buffer(hash, 'hex');

  this.hash = hash;
  this.type = type || 'pubkeyhash';
  this.version = version == null ? -1 : version;
  this.network = bcoin.network.get(network).type;

  return this;
};

/**
 * Create an Address from hash/type/version.
 * @param {Buffer|Hash} hash
 * @param {AddressType} type
 * @param {Number} [version=-1]
 * @returns {Address}
 */

Address.fromHash = function fromHash(hash, type, version, network) {
  return new Address().fromHash(hash, type, version, network);
};

/**
 * Hash data and compile hash to an address.
 * @param {Hash|Buffer} hash
 * @param {AddressType?} type
 * @param {Number?} version - Witness program version.
 * @returns {ParsedAddress}
 */

Address.prototype.fromData = function fromData(data, type, version, network) {
  if (type === 'witnessscripthash')
    data = utils.sha256(data);
  else
    data = utils.ripesha(data);

  return this.fromHash(data, type, version, network);
};

/**
 * Create an Address from data/type/version.
 * @param {Buffer} data - Data to be hashed.
 * @param {AddressType} type
 * @param {Number} [version=-1]
 * @returns {Address}
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
