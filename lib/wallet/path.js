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

  this.wid = null;
  this.name = null;
  this.account = 0;
  this.change = -1;
  this.index = -1;

  this.encrypted = false;
  this.imported = null;
  this.script = null;

  // Currently unused.
  this.type = bcoin.script.types.PUBKEYHASH;
  this.version = -1;

  // Passed in by caller.
  this.id = null;
  this.hash = null;
}

/**
 * Clone the path object.
 * @returns {Path}
 */

Path.prototype.clone = function clone() {
  var path = new Path();

  path.wid = this.wid;
  path.name = this.name;
  path.account = this.account;
  path.change = this.change;
  path.index = this.index;

  path.encrypted = this.encrypted;
  path.imported = this.imported;
  path.script = this.script;

  path.type = this.type;
  path.version = this.version;

  path.id = this.id;
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

  this.wid = p.readU32();
  this.name = p.readVarString('utf8');
  this.account = p.readU32();

  switch (p.readU8()) {
    case 0:
      this.change = p.readU32();
      this.index = p.readU32();
      if (p.readU8() === 1)
        this.script = p.readVarBytes();
      break;
    case 1:
      this.encrypted = p.readU8() === 1;
      this.imported = p.readVarBytes();
      this.change = -1;
      this.index = -1;
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

  p.writeU32(this.wid);
  p.writeVarString(this.name, 'utf8');
  p.writeU32(this.account);

  if (this.index !== -1) {
    assert(!this.imported);
    p.writeU8(0);
    p.writeU32(this.change);
    p.writeU32(this.index);
    if (this.script) {
      p.writeU8(1);
      p.writeVarBytes(this.script);
    } else {
      p.writeU8(0);
    }
  } else {
    assert(this.imported);
    p.writeU8(1);
    p.writeU8(this.encrypted ? 1 : 0);
    p.writeVarBytes(this.imported);
  }

  p.write8(this.version);
  p.writeU8(this.type);

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Inject properties from account.
 * @private
 * @param {WalletID} wid
 * @param {KeyRing} ring
 */

Path.prototype.fromAccount = function fromAccount(account, ring, change, index) {
  this.wid = account.wid;
  this.name = account.name;
  this.account = account.accountIndex;

  if (change != null)
    this.change = change;

  if (index != null)
    this.index = index;

  this.version = ring.witness ? 0 : -1;
  this.type = ring.getType();

  this.id = account.id;
  this.hash = ring.getHash('hex');

  return this;
};

/**
 * Instantiate path from keyring.
 * @param {WalletID} wid
 * @param {KeyRing} ring
 * @returns {Path}
 */

Path.fromAccount = function fromAccount(account, ring, change, index) {
  return new Path().fromAccount(account, ring, change, index);
};

/**
 * Convert path object to string derivation path.
 * @returns {String}
 */

Path.prototype.toPath = function toPath() {
  return 'm/' + this.account
    + '\'/' + this.change
    + '/' + this.index;
};

/**
 * Convert path object to an address (currently unused).
 * @returns {Address}
 */

Path.prototype.toAddress = function toAddress(network) {
  return bcoin.address.fromHash(this.hash, this.type, this.version, network);
};

/**
 * Convert path to a json-friendly object.
 * @returns {Object}
 */

Path.prototype.toJSON = function toJSON() {
  return {
    name: this.name,
    change: this.change === 1,
    path: this.toPath()
  };
};

/**
 * Inject properties from json object.
 * @private
 * @param {Object} json
 */

Path.prototype.fromJSON = function fromJSON(json) {
  var indexes = bcoin.hd.parsePath(json.path, constants.hd.MAX_INDEX);

  assert(indexes.length === 3);
  assert(indexes[0] >= constants.hd.HARDENED);
  indexes[0] -= constants.hd.HARDENED;

  this.wid = json.wid;
  this.id = json.id;
  this.name = json.name;
  this.account = indexes[0];
  this.change = indexes[1];
  this.index = indexes[2];

  return this;
};

/**
 * Instantiate path from json object.
 * @param {Object} json
 * @returns {Path}
 */

Path.fromJSON = function fromJSON(json) {
  return new Path().fromJSON(json);
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
