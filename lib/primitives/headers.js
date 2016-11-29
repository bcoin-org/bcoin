/*!
 * headers.js - headers object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var util = require('../utils/util');
var AbstractBlock = require('./abstractblock');
var BufferWriter = require('../utils/writer');
var BufferReader = require('../utils/reader');

/**
 * Represents block headers obtained from the network via `headers`.
 * @exports Headers
 * @constructor
 * @extends AbstractBlock
 * @param {NakedBlock} options
 */

function Headers(options) {
  if (!(this instanceof Headers))
    return new Headers(options);

  AbstractBlock.call(this, options);
}

util.inherits(Headers, AbstractBlock);

/**
 * Do non-contextual verification on the headers.
 * @alias Headers#verify
 * @param {Number|null} - Adjusted time.
 * @param {Object?} ret - Return object, may be
 * set with properties `reason` and `score`.
 * @returns {Boolean}
 */

Headers.prototype._verify = function _verify(now, ret) {
  return this.verifyHeaders(now, ret);
};

/**
 * Get size of the headers.
 * @returns {Number}
 */

Headers.prototype.getSize = function getSize() {
  var writer = new BufferWriter();
  this.toRaw(writer);
  return writer.written;
};

/**
 * Inspect the headers and return a more
 * user-friendly representation of the data.
 * @returns {Object}
 */

Headers.prototype.inspect = function inspect() {
  return {
    type: 'headers',
    hash: this.rhash,
    height: this.height,
    date: util.date(this.ts),
    version: util.hex32(this.version),
    prevBlock: util.revHex(this.prevBlock),
    merkleRoot: util.revHex(this.merkleRoot),
    ts: this.ts,
    bits: this.bits,
    nonce: this.nonce,
    totalTX: this.totalTX
  };
};

/**
 * Serialize the headers.
 * @param {String?} enc - Encoding, can be `'hex'` or null.
 * @returns {Buffer|String}
 */

Headers.prototype.toRaw = function toRaw(writer) {
  var bw = BufferWriter(writer);

  bw.writeU32(this.version);
  bw.writeHash(this.prevBlock);
  bw.writeHash(this.merkleRoot);
  bw.writeU32(this.ts);
  bw.writeU32(this.bits);
  bw.writeU32(this.nonce);
  bw.writeVarint(this.totalTX);

  if (!writer)
    bw = bw.render();

  return bw;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

Headers.prototype.fromRaw = function fromRaw(data) {
  var br = BufferReader(data);

  this.version = br.readU32(); // Technically signed
  this.prevBlock = br.readHash('hex');
  this.merkleRoot = br.readHash('hex');
  this.ts = br.readU32();
  this.bits = br.readU32();
  this.nonce = br.readU32();
  this.totalTX = br.readVarint();

  return this;
};

/**
 * Instantiate headers from serialized data.
 * @param {Buffer} data
 * @param {String?} enc - Encoding, can be `'hex'` or null.
 * @returns {Headers}
 */

Headers.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = new Buffer(data, enc);
  return new Headers().fromRaw(data);
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

Headers.prototype.fromAbbr = function fromAbbr(data) {
  var br = BufferReader(data);

  this.version = br.readU32(); // Technically signed
  this.prevBlock = br.readHash('hex');
  this.merkleRoot = br.readHash('hex');
  this.ts = br.readU32();
  this.bits = br.readU32();
  this.nonce = br.readU32();

  return this;
};

/**
 * Instantiate headers from serialized data.
 * @param {Buffer} data
 * @param {String?} enc - Encoding, can be `'hex'` or null.
 * @returns {Headers}
 */

Headers.fromAbbr = function fromAbbr(data, enc) {
  if (typeof data === 'string')
    data = new Buffer(data, enc);
  return new Headers().fromAbbr(data);
};

/**
 * Instantiate headers from a chain entry.
 * @param {ChainEntry} entry
 * @returns {Headers}
 */

Headers.fromEntry = function fromEntry(entry) {
  var headers = new Headers(entry);
  headers._hash = new Buffer(entry.hash, 'hex');
  headers._valid = true;
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
  var headers = new Headers(block);
  headers._hash = block._hash;
  headers._valid = true;
  return headers;
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
