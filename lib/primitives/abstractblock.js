/*!
 * abstractblock.js - abstract block object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const util = require('../utils/util');
const digest = require('../crypto/digest');
const BufferReader = require('../utils/reader');
const StaticWriter = require('../utils/staticwriter');
const InvItem = require('./invitem');
const encoding = require('../utils/encoding');
const consensus = require('../protocol/consensus');

/**
 * The class which all block-like objects inherit from.
 * @alias module:primitives.AbstractBlock
 * @constructor
 * @abstract
 * @property {Number} version - Block version. Note
 * that Bcoin reads versions as unsigned despite
 * them being signed on the protocol level. This
 * number will never be negative.
 * @property {Hash} prevBlock - Previous block hash.
 * @property {Hash} merkleRoot - Merkle root hash.
 * @property {Number} time - Timestamp.
 * @property {Number} bits
 * @property {Number} nonce
 */

function AbstractBlock() {
  if (!(this instanceof AbstractBlock))
    return new AbstractBlock();

  this.version = 1;
  this.prevBlock = encoding.NULL_HASH;
  this.merkleRoot = encoding.NULL_HASH;
  this.time = 0;
  this.bits = 0;
  this.nonce = 0;

  this.mutable = false;

  this._hash = null;
  this._hhash = null;
}

/**
 * Inject properties from options object.
 * @private
 * @param {NakedBlock} options
 */

AbstractBlock.prototype.parseOptions = function parseOptions(options) {
  assert(options, 'Block data is required.');
  assert(util.isU32(options.version));
  assert(typeof options.prevBlock === 'string');
  assert(typeof options.merkleRoot === 'string');
  assert(util.isU32(options.time));
  assert(util.isU32(options.bits));
  assert(util.isU32(options.nonce));

  this.version = options.version;
  this.prevBlock = options.prevBlock;
  this.merkleRoot = options.merkleRoot;
  this.time = options.time;
  this.bits = options.bits;
  this.nonce = options.nonce;

  if (options.mutable != null)
    this.mutable = Boolean(options.mutable);

  return this;
};

/**
 * Inject properties from json object.
 * @private
 * @param {Object} json
 */

AbstractBlock.prototype.parseJSON = function parseJSON(json) {
  assert(json, 'Block data is required.');
  assert(util.isU32(json.version));
  assert(typeof json.prevBlock === 'string');
  assert(typeof json.merkleRoot === 'string');
  assert(util.isU32(json.time));
  assert(util.isU32(json.bits));
  assert(util.isU32(json.nonce));

  this.version = json.version;
  this.prevBlock = util.revHex(json.prevBlock);
  this.merkleRoot = util.revHex(json.merkleRoot);
  this.time = json.time;
  this.bits = json.bits;
  this.nonce = json.nonce;

  return this;
};

/**
 * Test whether the block is a memblock.
 * @returns {Boolean}
 */

AbstractBlock.prototype.isMemory = function isMemory() {
  return false;
};

/**
 * Clear any cached values (abstract).
 */

AbstractBlock.prototype._refresh = function _refresh() {
  this._hash = null;
  this._hhash = null;
};

/**
 * Clear any cached values.
 */

AbstractBlock.prototype.refresh = function refresh() {
  return this._refresh();
};

/**
 * Hash the block headers.
 * @param {String?} enc - Can be `'hex'` or `null`.
 * @returns {Hash|Buffer} hash
 */

AbstractBlock.prototype.hash = function hash(enc) {
  let h = this._hash;

  if (!h) {
    h = digest.hash256(this.toHead());
    if (!this.mutable)
      this._hash = h;
  }

  if (enc === 'hex') {
    let hex = this._hhash;
    if (!hex) {
      hex = h.toString('hex');
      if (!this.mutable)
        this._hhash = hex;
    }
    h = hex;
  }

  return h;
};

/**
 * Serialize the block headers.
 * @returns {Buffer}
 */

AbstractBlock.prototype.toHead = function toHead() {
  return this.writeHead(new StaticWriter(80)).render();
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

AbstractBlock.prototype.fromHead = function fromHead(data) {
  return this.readHead(new BufferReader(data));
};

/**
 * Serialize the block headers.
 * @param {BufferWriter} bw
 */

AbstractBlock.prototype.writeHead = function writeHead(bw) {
  bw.writeU32(this.version);
  bw.writeHash(this.prevBlock);
  bw.writeHash(this.merkleRoot);
  bw.writeU32(this.time);
  bw.writeU32(this.bits);
  bw.writeU32(this.nonce);
  return bw;
};

/**
 * Parse the block headers.
 * @param {BufferReader} br
 */

AbstractBlock.prototype.readHead = function readHead(br) {
  this.version = br.readU32();
  this.prevBlock = br.readHash('hex');
  this.merkleRoot = br.readHash('hex');
  this.time = br.readU32();
  this.bits = br.readU32();
  this.nonce = br.readU32();
  return this;
};

/**
 * Verify the block.
 * @returns {Boolean}
 */

AbstractBlock.prototype.verify = function verify() {
  if (!this.verifyPOW())
    return false;

  if (!this.verifyBody())
    return false;

  return true;
};

/**
 * Verify proof-of-work.
 * @returns {Boolean}
 */

AbstractBlock.prototype.verifyPOW = function verifyPOW() {
  return consensus.verifyPOW(this.hash(), this.bits);
};

/**
 * Verify the block.
 * @returns {Boolean}
 */

AbstractBlock.prototype.verifyBody = function verifyBody() {
  throw new Error('Abstract method.');
};

/**
 * Get little-endian block hash.
 * @returns {Hash}
 */

AbstractBlock.prototype.rhash = function rhash() {
  return util.revHex(this.hash('hex'));
};

/**
 * Convert the block to an inv item.
 * @returns {InvItem}
 */

AbstractBlock.prototype.toInv = function toInv() {
  return new InvItem(InvItem.types.BLOCK, this.hash('hex'));
};

/*
 * Expose
 */

module.exports = AbstractBlock;
