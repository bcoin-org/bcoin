/*!
 * path.js - path object for wallets
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const BufferReader = require('../utils/reader');
const StaticWriter = require('../utils/staticwriter');
const encoding = require('../utils/encoding');
const Address = require('../primitives/address');

/**
 * Path
 * @alias module:wallet.Path
 * @constructor
 * @property {WalletID} wid
 * @property {String} name - Account name.
 * @property {Number} account - Account index.
 * @property {Number} branch - Branch index.
 * @property {Number} index - Address index.
 * @property {Address|null} address
 */

function Path(options) {
  if (!(this instanceof Path))
    return new Path(options);

  this.keyType = Path.types.HD;

  this.id = null; // Passed in by caller.
  this.wid = -1; // Passed in by caller.
  this.name = null; // Passed in by caller.
  this.account = 0;
  this.branch = -1;
  this.index = -1;

  this.encrypted = false;
  this.data = null;

  // Currently unused.
  this.type = Address.types.PUBKEYHASH;
  this.version = -1;
  this.hash = null; // Passed in by caller.

  if (options)
    this.fromOptions(options);
}

/**
 * Path types.
 * @enum {Number}
 * @default
 */

Path.types = {
  HD: 0,
  KEY: 1,
  ADDRESS: 2
};

/**
 * Instantiate path from options object.
 * @private
 * @param {Object} options
 * @returns {Path}
 */

Path.prototype.fromOptions = function fromOptions(options) {
  this.keyType = options.keyType;

  this.id = options.id;
  this.wid = options.wid;
  this.name = options.name;
  this.account = options.account;
  this.branch = options.branch;
  this.index = options.index;

  this.encrypted = options.encrypted;
  this.data = options.data;

  this.type = options.type;
  this.version = options.version;
  this.hash = options.hash;

  return this;
};

/**
 * Instantiate path from options object.
 * @param {Object} options
 * @returns {Path}
 */

Path.fromOptions = function fromOptions(options) {
  return new Path().fromOptions(options);
};

/**
 * Clone the path object.
 * @returns {Path}
 */

Path.prototype.clone = function clone() {
  let path = new Path();

  path.keyType = this.keyType;

  path.id = this.id;
  path.wid = this.wid;
  path.name = this.name;
  path.account = this.account;
  path.branch = this.branch;
  path.index = this.index;

  path.encrypted = this.encrypted;
  path.data = this.data;

  path.type = this.type;
  path.version = this.version;
  path.hash = this.hash;

  return path;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

Path.prototype.fromRaw = function fromRaw(data) {
  let br = new BufferReader(data);

  this.account = br.readU32();
  this.keyType = br.readU8();

  switch (this.keyType) {
    case Path.types.HD:
      this.branch = br.readU32();
      this.index = br.readU32();
      break;
    case Path.types.KEY:
      this.encrypted = br.readU8() === 1;
      this.data = br.readVarBytes();
      break;
    case Path.types.ADDRESS:
      // Hash will be passed in by caller.
      break;
    default:
      assert(false);
      break;
  }

  this.version = br.read8();
  this.type = br.readU8();

  if (this.type === 129 || this.type === 130)
    this.type = 4;

  return this;
};

/**
 * Instantiate path from serialized data.
 * @param {Buffer} data
 * @returns {Path}
 */

Path.fromRaw = function fromRaw(data) {
  return new Path().fromRaw(data);
};

/**
 * Calculate serialization size.
 * @returns {Number}
 */

Path.prototype.getSize = function getSize() {
  let size = 0;

  size += 5;

  switch (this.keyType) {
    case Path.types.HD:
      size += 8;
      break;
    case Path.types.KEY:
      size += 1;
      size += encoding.sizeVarBytes(this.data);
      break;
  }

  size += 2;

  return size;
};

/**
 * Serialize path.
 * @returns {Buffer}
 */

Path.prototype.toRaw = function toRaw() {
  let size = this.getSize();
  let bw = new StaticWriter(size);

  bw.writeU32(this.account);
  bw.writeU8(this.keyType);

  switch (this.keyType) {
    case Path.types.HD:
      assert(!this.data);
      assert(this.index !== -1);
      bw.writeU32(this.branch);
      bw.writeU32(this.index);
      break;
    case Path.types.KEY:
      assert(this.data);
      assert(this.index === -1);
      bw.writeU8(this.encrypted ? 1 : 0);
      bw.writeVarBytes(this.data);
      break;
    case Path.types.ADDRESS:
      assert(!this.data);
      assert(this.index === -1);
      break;
    default:
      assert(false);
      break;
  }

  bw.write8(this.version);
  bw.writeU8(this.type);

  return bw.render();
};

/**
 * Inject properties from address.
 * @private
 * @param {Account} account
 * @param {Address} address
 */

Path.prototype.fromAddress = function fromAddress(account, address) {
  this.keyType = Path.types.ADDRESS;
  this.id = account.id;
  this.wid = account.wid;
  this.name = account.name;
  this.account = account.accountIndex;
  this.version = address.version;
  this.type = address.type;
  this.hash = address.getHash('hex');
  return this;
};

/**
 * Instantiate path from address.
 * @param {Account} account
 * @param {Address} address
 * @returns {Path}
 */

Path.fromAddress = function fromAddress(account, address) {
  return new Path().fromAddress(account, address);
};

/**
 * Convert path object to string derivation path.
 * @returns {String}
 */

Path.prototype.toPath = function toPath() {
  if (this.keyType !== Path.types.HD)
    return null;

  return `m/${this.account}'/${this.branch}/${this.index}`;
};

/**
 * Convert path object to an address (currently unused).
 * @returns {Address}
 */

Path.prototype.toAddress = function toAddress(network) {
  return Address.fromHash(this.hash, this.type, this.version, network);
};

/**
 * Convert path to a json-friendly object.
 * @returns {Object}
 */

Path.prototype.toJSON = function toJSON() {
  return {
    name: this.name,
    account: this.account,
    change: this.branch === 1,
    derivation: this.toPath()
  };
};

/**
 * Inspect the path.
 * @returns {String}
 */

Path.prototype.inspect = function inspect() {
  return `<Path: ${this.id}(${this.wid})/${this.name}:${this.toPath()}>`;
};

/**
 * Expose
 */

module.exports = Path;
