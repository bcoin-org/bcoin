/*!
 * path.js - path object for wallets
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var bcoin = require('../env');
var utils = require('../utils/utils');
var assert = utils.assert;
var constants = bcoin.constants;
var BufferReader = require('../utils/reader');
var BufferWriter = require('../utils/writer');
var Address = require('../primitives/address');

/**
 * Path
 * @constructor
 * @private
 * @property {WalletID} wid
 * @property {String} name - Account name.
 * @property {Number} account - Account index.
 * @property {Number} change - Change index.
 * @property {Number} index - Address index.
 * @property {Address|null} address
 */

function Path() {
  if (!(this instanceof Path))
    return new Path();

  this.keyType = Path.types.HD;

  this.id = null; // Passed in by caller.
  this.wid = -1; // Passed in by caller.
  this.name = null; // Passed in by caller.
  this.account = 0;
  this.change = -1;
  this.index = -1;

  this.encrypted = false;
  this.data = null;

  // Currently unused.
  this.type = bcoin.script.types.PUBKEYHASH;
  this.version = -1;
  this.hash = null; // Passed in by caller.
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
 * Clone the path object.
 * @returns {Path}
 */

Path.prototype.clone = function clone() {
  var path = new Path();

  path.keyType = this.keyType;

  path.id = this.id;
  path.wid = this.wid;
  path.name = this.name;
  path.account = this.account;
  path.change = this.change;
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
  var p = new BufferReader(data);

  this.account = p.readU32();
  this.keyType = p.readU8();

  switch (this.keyType) {
    case Path.types.HD:
      this.change = p.readU32();
      this.index = p.readU32();
      break;
    case Path.types.KEY:
      this.encrypted = p.readU8() === 1;
      this.data = p.readVarBytes();
      break;
    case Path.types.ADDRESS:
      // Hash will be passed in by caller.
      break;
    default:
      assert(false);
      break;
  }

  this.version = p.read8();
  this.type = p.readU8();

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
 * Serialize path.
 * @returns {Buffer}
 */

Path.prototype.toRaw = function toRaw(writer) {
  var p = new BufferWriter(writer);

  p.writeU32(this.account);
  p.writeU8(this.keyType);

  switch (this.keyType) {
    case Path.types.HD:
      assert(!this.data);
      assert(this.index !== -1);
      p.writeU32(this.change);
      p.writeU32(this.index);
      break;
    case Path.types.KEY:
      assert(this.data);
      assert(this.index === -1);
      p.writeU8(this.encrypted ? 1 : 0);
      p.writeVarBytes(this.data);
      break;
    case Path.types.ADDRESS:
      assert(!this.data);
      assert(this.index === -1);
      break;
    default:
      assert(false);
      break;
  }

  p.write8(this.version);
  p.writeU8(this.type);

  if (!writer)
    p = p.render();

  return p;
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

  return 'm/' + this.account
    + '\'/' + this.change
    + '/' + this.index;
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
    change: this.change === 1,
    derivation: this.toPath()
  };
};

/**
 * Inspect the path.
 * @returns {String}
 */

Path.prototype.inspect = function() {
  return '<Path: ' + this.id
    + '(' + this.wid + ')'
    + '/' + this.name
    + ': ' + this.toPath()
    + '>';
};

/**
 * Expose
 */

module.exports = Path;
