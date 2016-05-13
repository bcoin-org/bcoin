/*!
 * abstractblock.js - abstract block object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

var bcoin = require('../bcoin');
var utils = bcoin.utils;
var assert = utils.assert;

/**
 * The class which all block-like objects inherit from.
 * @exports AbstractBlock
 * @constructor
 * @abstract
 * @param {NakedBlock} data
 * @property {Number} version - Block version. Note
 * that BCoin reads versions as unsigned despite
 * them being signed on the protocol level. This
 * number will never be negative.
 * @property {Hash} prevBlock - Previous block hash.
 * @property {Hash} merkleRoot - Merkle root hash.
 * @property {Number} ts - Timestamp.
 * @property {Number} bits
 * @property {Number} nonce
 * @property {Number} totalTX - Transaction count.
 * @property {Number} height - Block height (-1 if not present).
 * @property {TX[]} txs - Transaction vector.
 * @property {ReversedHash} rhash - Reversed block hash (uint256le).
 */

function AbstractBlock(data) {
  if (!(this instanceof AbstractBlock))
    return new AbstractBlock(data);

  assert(data, 'Block data is required.');
  assert(typeof data.version === 'number');
  assert(typeof data.prevBlock === 'string');
  assert(typeof data.merkleRoot === 'string');
  assert(typeof data.ts === 'number');
  assert(typeof data.bits === 'number');
  assert(typeof data.nonce === 'number');

  this.version = data.version;
  this.prevBlock = data.prevBlock;
  this.merkleRoot = data.merkleRoot;
  this.ts = data.ts;
  this.bits = data.bits;
  this.nonce = data.nonce;
  this.totalTX = data.totalTX || 0;
  this.height = data.height != null ? data.height : -1;

  this.txs = null;
  this.valid = null;

  this._hash = null;
  this._size = data._size || 0;
}

/**
 * Hash the block headers.
 * @param {String?} enc - Can be `'hex'` or `null`.
 * @returns {Hash|Buffer} hash
 */

AbstractBlock.prototype.hash = function hash(enc) {
  if (!this._hash)
    this._hash = utils.dsha256(this.abbr());

  return enc === 'hex' ? this._hash.toString('hex') : this._hash;
};

/**
 * Serialize the block headers.
 * @returns {Buffer}
 */

AbstractBlock.prototype.abbr = function abbr() {
  return bcoin.protocol.framer.blockHeaders(this);
};

/**
 * Get the full block size (this may be cached).
 * @returns {Number}
 */

AbstractBlock.prototype.getSize = function getSize() {
  return this._size || this.render().length;
};

/**
 * Verify the block.
 * @param {Object?} ret - Return object, may be
 * set with properties `reason` and `score`.
 * @returns {Boolean}
 */

AbstractBlock.prototype.verify = function verify(ret) {
  if (this.valid == null)
    this.valid = this._verify(ret);
  return this.valid;
};

/**
 * Verify the block headers (called by `verify()` in
 * all objects which inherit from AbstractBlock).
 * @param {Object?} ret - Return object, may be
 * set with properties `reason` and `score`.
 * @returns {Boolean}
 */

AbstractBlock.prototype.verifyHeaders = function verifyHeaders(ret) {
  if (!ret)
    ret = {};

  // Check proof of work
  if (!utils.testTarget(this.bits, this.hash())) {
    ret.reason = 'high-hash';
    ret.score = 50;
    return false;
  }

  // Check timestamp against now + 2 hours
  if (this.ts > bcoin.now() + 2 * 60 * 60) {
    ret.reason = 'time-too-new';
    ret.score = 0;
    return false;
  }

  return true;
};

/**
 * Set the `height` property and the `height`
 * property of all transactions within the block.
 * @param {Number} height
 */

AbstractBlock.prototype.setHeight = function setHeight(height) {
  var i;

  this.height = height;

  if (!this.txs)
    return;

  for (i = 0; i < this.txs.length; i++)
    this.txs[i].height = height;
};

AbstractBlock.prototype.__defineGetter__('rhash', function() {
  return utils.revHex(this.hash('hex'));
});

module.exports = AbstractBlock;
