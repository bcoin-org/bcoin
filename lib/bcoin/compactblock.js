/*!
 * compactblock.js - compact block object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

var bcoin = require('./env');
var bn = require('bn.js');
var utils = require('./utils');
var assert = utils.assert;

/**
 * A block object which is essentially a "placeholder"
 * for a full {@link Block} object. The v8 garbage
 * collector's head will explode if there is too much
 * data on the javascript heap. Blocks can currently
 * be up to 1mb in size. In the future, they may be
 * 2mb, 8mb, or maybe 20mb, who knows? A CompactBlock
 * is an optimization in BCoin which defers parsing of
 * the serialized transactions (the block Buffer) until
 * the block has passed through the chain queue and
 * is about to enter the chain. This keeps a lot data
 * off of the javascript heap for most of the time a
 * block even exists in memory, and manages to keep a
 * lot of strain off of the garbage collector. Having
 * 500mb of blocks on the js heap would not be a good
 * thing.
 * @exports CompactBlock
 * @constructor
 * @param {Object} data
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
 * @property {Boolean} compact - Always true.
 * @property {Number} coinbaseHeight - The coinbase height which
 * was extracted by the parser (the coinbase is the only
 * transaction we parse ahead of time).
 * @property {Buffer} raw - The raw block data.
 * @property {ReversedHash} rhash - Reversed block hash (uint256le).
 */

function CompactBlock(data) {
  if (!(this instanceof CompactBlock))
    return new CompactBlock(data);

  bcoin.abstractblock.call(this, data);

  this.compact = true;
  this.coinbaseHeight = data.coinbaseHeight;
  this.raw = data.raw;
}

utils.inherits(CompactBlock, bcoin.abstractblock);

/**
 * Get the full block size.
 * @returns {Number}
 */

CompactBlock.prototype.getSize = function getSize() {
  return this.raw.length;
};

/**
 * Verify the block headers.
 * @alias CompactBlock#verify
 * @param {Object?} ret - Return object, may be
 * set with properties `reason` and `score`.
 * @returns {Boolean}
 */

CompactBlock.prototype._verify = function _verify(ret) {
  return this.verifyHeaders(ret);
};

/**
 * Retrieve the coinbase height from the coinbase input script (already
 * extracted in actuality).
 * @returns {Number} height (-1 if not present).
 */

CompactBlock.prototype.getCoinbaseHeight = function getCoinbaseHeight() {
  return this.coinbaseHeight;
};

/**
 * Parse the serialized block data and create an actual {@link Block}.
 * @returns {Block}
 * @throws Parse error
 */

CompactBlock.prototype.toBlock = function toBlock() {
  var data = bcoin.protocol.parser.parseBlock(this.raw);
  delete this.raw;
  assert(!data.raw);
  assert(!data._raw);
  return new bcoin.block(data);
};

/**
 * Test an object to see if it is a CompactBlock.
 * @param {Object} obj
 * @returns {Boolean}
 */

CompactBlock.isCompactBlock = function isCompactBlock(obj) {
  return obj && typeof obj.toBlock === 'function';
};

/*
 * Expose
 */

module.exports = CompactBlock;
