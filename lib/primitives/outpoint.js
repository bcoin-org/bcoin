/*!
 * outpoint.js - outpoint object for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const util = require('../utils/util');
const assert = require('assert');
const StaticWriter = require('../utils/writer');
const BufferReader = require('../utils/reader');
const encoding = require('../utils/encoding');

/**
 * Represents a COutPoint.
 * @alias module:primitives.Outpoint
 * @constructor
 * @param {Hash?} hash
 * @param {Number?} index
 * @property {Hash} hash
 * @property {Number} index
 */

function Outpoint(hash, index) {
  if (!(this instanceof Outpoint))
    return new Outpoint(hash, index);

  this.hash = encoding.NULL_HASH;
  this.index = 0xffffffff;

  if (hash != null) {
    assert(typeof hash === 'string', 'Hash must be a string.');
    assert(util.isUInt32(index), 'Index must be a uint32.');
    this.hash = hash;
    this.index = index;
  }
}

/**
 * Inject properties from options object.
 * @private
 * @param {Object} options
 */

Outpoint.prototype.fromOptions = function fromOptions(options) {
  assert(options, 'Outpoint data is required.');
  assert(typeof options.hash === 'string', 'Hash must be a string.');
  assert(util.isUInt32(options.index), 'Index must be a uint32.');
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
  return this.index === 0xffffffff && this.hash === encoding.NULL_HASH;
};

/**
 * Get little-endian hash.
 * @returns {Hash}
 */

Outpoint.prototype.rhash = function rhash() {
  return util.revHex(this.hash);
};

/**
 * Get little-endian hash.
 * @returns {Hash}
 */

Outpoint.prototype.txid = function txid() {
  return this.rhash();
};

/**
 * Serialize outpoint to a key
 * suitable for a hash table.
 * @returns {String}
 */

Outpoint.prototype.toKey = function toKey() {
  return Outpoint.toKey(this.hash, this.index);
};

/**
 * Inject properties from hash table key.
 * @private
 * @param {String} key
 * @returns {Outpoint}
 */

Outpoint.prototype.fromKey = function fromKey(key) {
  assert(key.length > 64);
  this.hash = key.slice(0, 64);
  this.index = +key.slice(64);
  return this;
};

/**
 * Instantiate outpoint from hash table key.
 * @param {String} key
 * @returns {Outpoint}
 */

Outpoint.fromKey = function fromKey(key) {
  return new Outpoint().fromKey(key);
};

/**
 * Write outpoint to a buffer writer.
 * @param {BufferWriter} bw
 */

Outpoint.prototype.toWriter = function toWriter(bw) {
  bw.writeHash(this.hash);
  bw.writeU32(this.index);
  return bw;
};

/**
 * Calculate size of outpoint.
 * @returns {Number}
 */

Outpoint.prototype.getSize = function getSize() {
  return 36;
};

/**
 * Serialize outpoint.
 * @returns {Buffer}
 */

Outpoint.prototype.toRaw = function toRaw() {
  return this.toWriter(new StaticWriter(36)).render();
};

/**
 * Inject properties from buffer reader.
 * @private
 * @param {BufferReader} br
 */

Outpoint.prototype.fromReader = function fromReader(br) {
  this.hash = br.readHash('hex');
  this.index = br.readU32();
  return this;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

Outpoint.prototype.fromRaw = function fromRaw(data) {
  return this.fromReader(new BufferReader(data));
};

/**
 * Instantiate outpoint from a buffer reader.
 * @param {BufferReader} br
 * @returns {Outpoint}
 */

Outpoint.fromReader = function fromReader(br) {
  return new Outpoint().fromReader(br);
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
  assert(json, 'Outpoint data is required.');
  assert(typeof json.hash === 'string', 'Hash must be a string.');
  assert(util.isUInt32(json.index), 'Index must be a uint32.');
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
  assert(tx);
  assert(typeof index === 'number');
  assert(index >= 0);
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
 * Serialize outpoint to a key
 * suitable for a hash table.
 * @param {Hash} hash
 * @param {Number} index
 * @returns {String}
 */

Outpoint.toKey = function toKey(hash, index) {
  assert(typeof hash === 'string');
  assert(hash.length === 64);
  assert(index >= 0);
  return hash + index;
};

/**
 * Convert the outpoint to a user-friendly string.
 * @returns {String}
 */

Outpoint.prototype.inspect = function inspect() {
  return `<Outpoint: ${this.rhash()}/${this.index}>`;
};

/**
 * Test an object to see if it is an outpoint.
 * @param {Object} obj
 * @returns {Boolean}
 */

Outpoint.isOutpoint = function isOutpoint(obj) {
  return obj
    && typeof obj.hash === 'string'
    && typeof obj.index === 'number'
    && typeof obj.toKey === 'function';
};

/*
 * Expose
 */

module.exports = Outpoint;
