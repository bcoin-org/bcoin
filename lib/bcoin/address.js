/*!
 * address.js - address object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

var bcoin = require('./env');
var bn = require('bn.js');
var constants = bcoin.protocol.constants;
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

  this.hash = options.hash;
  this.type = options.type || 'pubkeyhash';
  this.version = options.version == null ? -1 : options.version;
  this.network = bcoin.network.get(options.network).type;

  if (!Buffer.isBuffer(this.hash))
    this.hash = new Buffer(this.hash, 'hex');
}

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
    p.writeU8(0)
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

Address.parseBase58 = function parseBase58(address) {
  var i, prefix, type, version, hash, network;

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

  return {
    network: network.type,
    type: type,
    hash: hash,
    version: version == null ? -1 : version
  };
};

/**
 * Create an address object from a base58 address.
 * @param {Base58Address} address
 * @returns {Address}
 * @throws Parse error.
 */

Address.fromBase58 = function fromBase58(address) {
  return new Address(Address.parseBase58(address));
};

/**
 * Parse an output script and extract address
 * properties. Converts pubkey and multisig
 * scripts to pubkeyhash and scripthash addresses.
 * @param {Script} script
 * @returns {ParsedAddress|null}
 */

Address.parseScript = function parseScript(script) {
  var program;

  if (script.isWitnessProgram()) {
    program = script.getWitnessProgram();
    if (!program.type || program.type === 'unknown')
      return;
    return {
      hash: program.data,
      type: program.type,
      version: program.version
    };
  }

  if (script.isPubkey()) {
    hash = utils.ripesha(script.code[0]);
    return { hash: hash, type: 'pubkeyhash', version: -1 };
  }

  if (script.isPubkeyhash()) {
    hash = script.code[2];
    return { hash: hash, type: 'pubkeyhash', version: -1 };
  }

  if (script.isMultisig()) {
    hash = utils.ripesha(script.encode());
    return { hash: hash, type: 'scripthash', version: -1 };
  }

  if (script.isScripthash()) {
    hash = script.code[1];
    return { hash: hash, type: 'scripthash', version: -1 };
  }
};

/**
 * Parse input data (witness or input script) and
 * attempt extract address properties by "guessing"
 * the script type. Only works for pubkeyhash and
 * scripthash.
 * @param {Array} code
 * @returns {ParsedAddress|null}
 */

Address.parseInput = function parseInput(code, witness) {
  var hash;

  if (Script.isPubkeyInput(code))
    return;

  if (Script.isPubkeyhashInput(code)) {
    hash = utils.ripesha(code[1]);
    if (witness)
      return { hash: hash, type: 'witnesspubkeyhash', version: 0 };
    return { hash: hash, type: 'pubkeyhash', version: -1 };
  }

  if (Script.isMultisigInput(code, witness))
    return;

  if (Script.isScripthashInput(code)) {
    if (witness) {
      hash = utils.sha256(code[code.length - 1]);
      return { hash: hash, type: 'witnessscripthash', version: 0 };
    }
    hash = utils.ripesha(code[code.length - 1]);
    return { hash: hash, type: 'scripthash', version: -1 };
  }
};

/**
 * Attempt to extract address
 * properties from a witness.
 * @param {Witness} witness
 * @returns {ParsedAddress|null}
 */

Address.parseWitness = function parseWitness(witness) {
  return Address.parseInput(witness.items, true);
};

/**
 * Attempt to extract address
 * properties from an input script.
 * @param {Witness} witness
 * @returns {ParsedAddress|null}
 */

Address.parseInputScript = function parseInputScript(script) {
  return Address.parseInput(script.code, false);
};

/**
 * Create an Address from a witness.
 * @param {Witness}
 * @returns {ParsedAddress|null}
 */

Address.fromWitness = function fromWitness(witness) {
  var data = Address.parseWitness(witness);

  if (!data)
    return;

  return new Address(data);
};

/**
 * Create an Address from an input script.
 * @param {Script}
 * @returns {ParsedAddress|null}
 */

Address.fromInputScript = function fromInputScript(script) {
  var data = Address.parseInputScript(script);

  if (!data)
    return;

  return new Address(data);
};

/**
 * Create an Address from an output script.
 * @param {Script}
 * @returns {ParsedAddress|null}
 */

Address.fromScript = function fromScript(script) {
  var data = Address.parseScript(script);

  if (!data)
    return;

  return new Address(data);
};

/**
 * Create a naked address from hash/type/version.
 * @param {Buffer|Hash} hash
 * @param {AddressType} type
 * @param {Number} [version=-1]
 * @returns {ParsedAddress}
 */

Address.parseHash = function parseHash(hash, type, version) {
  if (!Buffer.isBuffer(hash))
    hash = new Buffer(hash, 'hex');

  return {
    hash: hash,
    type: type || 'pubkeyhash',
    version: version == null ? -1 : version
  };
};

/**
 * Create an Address from hash/type/version.
 * @param {Buffer|Hash} hash
 * @param {AddressType} type
 * @param {Number} [version=-1]
 * @returns {Address}
 */

Address.fromHash = function fromHash(hash, type, version) {
  return new Address(Address.parseHash(hash, type, version));
};

/**
 * Hash data and compile hash to an address.
 * @param {Hash|Buffer} hash
 * @param {AddressType?} type
 * @param {Number?} version - Witness program version.
 * @returns {ParsedAddress}
 */

Address.parseData = function parseData(data, type, version) {
  if (type === 'witnessscripthash')
    data = utils.sha256(data);
  else
    data = utils.ripesha(data);

  return Address.parseHash(data, type, version);
};

/**
 * Create an Address from data/type/version.
 * @param {Buffer} data - Data to be hashed.
 * @param {AddressType} type
 * @param {Number} [version=-1]
 * @returns {Address}
 */

Address.fromData = function fromData(data, type, version) {
  return new Address(Address.parseData(data, type, version));
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
    address = Address.parseBase58(address);
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

Address.getHash = function getHash(data) {
  var hash;

  if (data instanceof Address) {
    hash = data.hash;
  } else {
    try {
      hash = Address.parseBase58(data).hash;
    } catch (e) {
      return;
    }
  }

  return hash.toString('hex');
};

/*
 * Expose
 */

module.exports = Address;
