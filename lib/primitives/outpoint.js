/*!
 * outpoint.js - outpoint object for bcoin
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var util = require('../utils/util');
var assert = require('assert');
var constants = require('../protocol/constants');
var BufferWriter = require('../utils/writer');
var BufferReader = require('../utils/reader');

/**
 * Represents a COutPoint.
 * @exports Outpoint
 * @constructor
 * @param {Hash?} hash
 * @param {Number?} index
 * @property {Hash} hash
 * @property {Number} index
 */

function Outpoint(hash, index) {
  if (!(this instanceof Outpoint))
    return new Outpoint(hash, index);

  this.hash = hash || constants.NULL_HASH;
  this.index = index != null ? index : 0xffffffff;
}

/**
 * Inject properties from options object.
 * @private
 * @param {Object} options
 */

Outpoint.prototype.fromOptions = function fromOptions(options) {
  assert(typeof options.hash === 'string');
  assert(util.isNumber(options.index));
  this.hash = options.hash;
  this.index = options.index;
  return this;
};

/**
 * Instantate outpoint from options object.
 * @param {Object} options
 * @returns {Outpoint}
 */

Outpoint.fromOptions = function fromOptions(options) {
  return new Outpoint().fromOptions(options);
};

/**
 * Test whether the outpoint is null (hash of zeroes
 * with max-u32 index). Used to detect coinbases.
 * @returns {Boolean}
 */

Outpoint.prototype.isNull = function isNull() {
  return this.index === 0xffffffff && this.hash === constants.NULL_HASH;
};

/**
 * Serialize outpoint.
 * @returns {Buffer}
 */

Outpoint.prototype.toRaw = function toRaw(writer) {
  var bw = BufferWriter(writer);

  bw.writeHash(this.hash);
  bw.writeU32(this.index);

  if (!writer)
    bw = bw.render();

  return bw;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

Outpoint.prototype.fromRaw = function fromRaw(data) {
  var br = BufferReader(data);
  this.hash = br.readHash('hex');
  this.index = br.readU32();
  return this;
};

/**
 * Instantiate outpoint from serialized data.
 * @param {Buffer} data
 * @returns {Outpoint}
 */

Outpoint.fromRaw = function fromRaw(data) {
  return new Outpoint().fromRaw(data);
};

/**
 * Inject properties from json object.
 * @private
 * @params {Object} json
 */

Outpoint.prototype.fromJSON = function fromJSON(json) {
  assert(typeof json.hash === 'string');
  assert(util.isNumber(json.index));
  this.hash = util.revHex(json.hash);
  this.index = json.index;
  return this;
};

/**
 * Convert the outpoint to an object suitable
 * for JSON serialization. Note that the hash
 * will be reversed to abide by bitcoind's legacy
 * of little-endian uint256s.
 * @returns {Object}
 */

Outpoint.prototype.toJSON = function toJSON() {
  return {
    hash: util.revHex(this.hash),
    index: this.index
  };
};

/**
 * Instantiate outpoint from json object.
 * @param {Object} json
 * @returns {Outpoint}
 */

Outpoint.fromJSON = function fromJSON(json) {
  return new Outpoint().fromJSON(json);
};

/**
 * Inject properties from tx.
 * @private
 * @param {TX} tx
 * @param {Number} index
 */

Outpoint.prototype.fromTX = function fromTX(tx, index) {
  assert(util.isNumber(index));
  this.hash = tx.hash('hex');
  this.index = index;
  return this;
};

/**
 * Instantiate outpoint from tx.
 * @param {TX} tx
 * @param {Number} index
 * @returns {Outpoint}
 */

Outpoint.fromTX = function fromTX(tx, index) {
  return new Outpoint().fromTX(tx, index);
};

/**
 * Convert the outpoint to a user-friendly string.
 * @returns {String}
 */

Outpoint.prototype.inspect = function inspect() {
  return '<Outpoint: ' + util.revHex(this.hash) + '/' + this.index + '>';
};

/*
 * Expose
 */

module.exports = Outpoint;
