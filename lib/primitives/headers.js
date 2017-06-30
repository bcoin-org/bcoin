/*!
 * headers.js - headers object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const util = require('../utils/util');
const AbstractBlock = require('./abstractblock');
const StaticWriter = require('../utils/staticwriter');
const BufferReader = require('../utils/reader');

/**
 * Represents block headers obtained from the network via `headers`.
 * @alias module:primitives.Headers
 * @constructor
 * @extends AbstractBlock
 * @param {NakedBlock} options
 */

function Headers(options) {
  if (!(this instanceof Headers))
    return new Headers(options);

  AbstractBlock.call(this);

  if (options)
    this.parseOptions(options);
}

util.inherits(Headers, AbstractBlock);

/**
 * Do non-contextual verification on the headers.
 * @param {Object?} ret - Return object, may be
 * set with properties `reason` and `score`.
 * @returns {Boolean}
 */

Headers.prototype.verifyBody = function verifyBody(ret) {
  return true;
};

/**
 * Get size of the headers.
 * @returns {Number}
 */

Headers.prototype.getSize = function getSize() {
  return 81;
};

/**
 * Serialize the headers to a buffer writer.
 * @param {BufferWriter} bw
 */

Headers.prototype.toWriter = function toWriter(bw) {
  this.writeAbbr(bw);
  bw.writeVarint(0);
  return bw;
};

/**
 * Serialize the headers.
 * @returns {Buffer|String}
 */

Headers.prototype.toRaw = function toRaw() {
  let size = this.getSize();
  return this.toWriter(new StaticWriter(size)).render();
};

/**
 * Inject properties from buffer reader.
 * @private
 * @param {Buffer} data
 */

Headers.prototype.fromReader = function fromReader(br) {
  this.parseAbbr(br);
  br.readVarint();
  return this;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

Headers.prototype.fromRaw = function fromRaw(data) {
  return this.fromReader(new BufferReader(data));
};

/**
 * Instantiate headers from buffer reader.
 * @param {BufferReader} br
 * @returns {Headers}
 */

Headers.fromReader = function fromReader(br) {
  return new Headers().fromReader(br);
};

/**
 * Instantiate headers from serialized data.
 * @param {Buffer} data
 * @param {String?} enc - Encoding, can be `'hex'` or null.
 * @returns {Headers}
 */

Headers.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = Buffer.from(data, enc);
  return new Headers().fromRaw(data);
};

/**
 * Inject properties from buffer reader.
 * @private
 * @param {BufferReader} br
 */

Headers.prototype.fromAbbrReader = function fromAbbrReader(br) {
  return this.parseAbbr(br);
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

Headers.prototype.fromAbbr = function fromAbbr(data) {
  return this.fromAbbrReader(new BufferReader(data));
};

/**
 * Instantiate headers from buffer reader.
 * @param {BufferReader} br
 * @returns {Headers}
 */

Headers.fromAbbrReader = function fromAbbrReader(br) {
  return new Headers().fromAbbrReader(br);
};

/**
 * Instantiate headers from serialized data.
 * @param {Buffer} data
 * @param {String?} enc - Encoding, can be `'hex'` or null.
 * @returns {Headers}
 */

Headers.fromAbbr = function fromAbbr(data, enc) {
  if (typeof data === 'string')
    data = Buffer.from(data, enc);
  return new Headers().fromAbbr(data);
};

/**
 * Instantiate headers from a chain entry.
 * @param {ChainEntry} entry
 * @returns {Headers}
 */

Headers.fromEntry = function fromEntry(entry) {
  let headers = new Headers(entry);
  headers._hash = Buffer.from(entry.hash, 'hex');
  return headers;
};

/**
 * Convert the block to a headers object.
 * @returns {Headers}
 */

Headers.prototype.toHeaders = function toHeaders() {
  return this;
};

/**
 * Convert the block to a headers object.
 * @param {Block|MerkleBlock} block
 * @returns {Headers}
 */

Headers.fromBlock = function fromBlock(block) {
  let headers = new Headers(block);
  headers._hash = block._hash;
  headers._hhash = block._hhash;
  return headers;
};

/**
 * Convert the block to an object suitable
 * for JSON serialization.
 * @returns {Object}
 */

Headers.prototype.toJSON = function toJSON() {
  return this.getJSON();
};

/**
 * Convert the block to an object suitable
 * for JSON serialization. Note that the hashes
 * will be reversed to abide by bitcoind's legacy
 * of little-endian uint256s.
 * @param {Network} network
 * @param {CoinView} view
 * @param {Number} height
 * @returns {Object}
 */

Headers.prototype.getJSON = function getJSON(network, view, height) {
  return {
    hash: this.rhash(),
    height: height,
    version: this.version,
    prevBlock: util.revHex(this.prevBlock),
    merkleRoot: util.revHex(this.merkleRoot),
    ts: this.ts,
    bits: this.bits,
    nonce: this.nonce
  };
};

/**
 * Inject properties from json object.
 * @private
 * @param {Object} json
 */

Headers.prototype.fromJSON = function fromJSON(json) {
  this.parseJSON(json);
  return this;
};

/**
 * Instantiate a merkle block from a jsonified block object.
 * @param {Object} json - The jsonified block object.
 * @returns {Headers}
 */

Headers.fromJSON = function fromJSON(json) {
  return new Headers().fromJSON(json);
};

/**
 * Inspect the headers and return a more
 * user-friendly representation of the data.
 * @returns {Object}
 */

Headers.prototype.inspect = function inspect() {
  return this.format();
};

/**
 * Inspect the headers and return a more
 * user-friendly representation of the data.
 * @param {CoinView} view
 * @param {Number} height
 * @returns {Object}
 */

Headers.prototype.format = function format(view, height) {
  return {
    hash: this.rhash(),
    height: height != null ? height : -1,
    date: util.date(this.ts),
    version: util.hex32(this.version),
    prevBlock: util.revHex(this.prevBlock),
    merkleRoot: util.revHex(this.merkleRoot),
    ts: this.ts,
    bits: this.bits,
    nonce: this.nonce
  };
};

/**
 * Test an object to see if it is a Headers object.
 * @param {Object} obj
 * @returns {Boolean}
 */

Headers.isHeaders = function isHeaders(obj) {
  return obj
    && !obj.txs
    && typeof obj.abbr === 'function'
    && typeof obj.toBlock !== 'function';
};

/*
 * Expose
 */

module.exports = Headers;
