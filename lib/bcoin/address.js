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
 * @param {String?} options.hash
 * @param {String?} options.type
 * @param {String?} options.version
 * @param {String?} options.network
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

Address.prototype.getHash = function getHash(enc) {
  if (enc === 'hex')
    return this.hash.toString(enc);
  return this.hash;
};

Address.prototype.toBase58 = function toBase58(network) {
  if (!network)
    network = this.network;

  return Address.toBase58(this.hash, this.type, this.version, network);
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

Address.fromBase58 = function fromBase58(addr) {
  return new Address(Address.parseBase58(addr));
};

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

Address.parseWitness = function parseWitness(witness) {
  return Address.parseInput(witness.items, true);
};

Address.parseInputScript = function parseInputScript(script) {
  return Address.parseInput(script.code, false);
};

Address.fromWitness = function fromWitness(witness) {
  var data = Address.parseWitness(witness);

  if (!data)
    return;

  return new Address(data);
};

Address.fromInputScript = function fromInputScript(script) {
  var data = Address.parseInputScript(script);

  if (!data)
    return;

  return new Address(data);
};

Address.fromScript = function fromScript(script) {
  var data = Address.parseScript(script);

  if (!data)
    return;

  return new Address(data);
};

Address.parseHash = function parseHash(hash, type, version) {
  return {
    hash: hash,
    type: type || 'pubkeyhash',
    version: version == null ? -1 : version
  };
};

Address.fromHash = function fromHash(hash, type, version) {
  return new Address(Address.parseHash(hash, type, version));
};

/**
 * Hash data and compile hash to an address.
 * @param {Hash|Buffer} hash
 * @param {AddressType?} type
 * @param {Number?} version - Witness program version.
 * @returns {Base58Address}
 */

Address.parseData = function parseData(data, type, version) {
  if (type === 'witnessscripthash')
    data = utils.sha256(data);
  else
    data = utils.ripesha(data);
  return Address.parseHash(data, type, version);
};

Address.fromData = function fromData(data, type, version) {
  return new Address(Address.parseData(data, type, version));
};

Address.toScript = function toScript() {
  if (this.type === 'pubkeyhash')
    return Script.createPubkeyhash(this.hash);
  if (this.type === 'scripthash')
    return Script.createScripthash(this.hash);
  if (this.version !== -1)
    return Script.createWitnessProgram(this.version, this.hash);
  assert(false, 'Bad type.');
};

/**
 * Validate an address, optionally test against a type.
 * @param {String} address - Can be of any type in reality.
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

// Address.prototype.toString = function toString() {
//   return this.toBase58();
// };

Address.prototype.inspect = function inspect() {
  return {
    hash: this.getHash('hex'),
    type: this.type,
    version: this.version,
    address: this.toBase58()
  };
};

module.exports = Address;
