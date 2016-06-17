/*!
 * memblock.js - memblock block object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var bcoin = require('./env');
var utils = require('./utils');

/**
 * A block object which is essentially a "placeholder"
 * for a full {@link Block} object. The v8 garbage
 * collector's head will explode if there is too much
 * data on the javascript heap. Blocks can currently
 * be up to 1mb in size. In the future, they may be
 * 2mb, 8mb, or maybe 20mb, who knows? A MemBlock
 * is an optimization in BCoin which defers parsing of
 * the serialized transactions (the block Buffer) until
 * the block has passed through the chain queue and
 * is about to enter the chain. This keeps a lot data
 * off of the javascript heap for most of the time a
 * block even exists in memory, and manages to keep a
 * lot of strain off of the garbage collector. Having
 * 500mb of blocks on the js heap would not be a good
 * thing.
 * @exports MemBlock
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
 * @property {Boolean} memory - Always true.
 * @property {Number} coinbaseHeight - The coinbase height which
 * was extracted by the parser (the coinbase is the only
 * transaction we parse ahead of time).
 * @property {Buffer} raw - The raw block data.
 * @property {ReversedHash} rhash - Reversed block hash (uint256le).
 */

function MemBlock(data) {
  if (!(this instanceof MemBlock))
    return new MemBlock(data);

  bcoin.abstractblock.call(this, data);

  this.memory = true;
  this.coinbaseHeight = null;
  this.raw = null;

  if (data)
    this.fromOptions(data);
}

utils.inherits(MemBlock, bcoin.abstractblock);

MemBlock.prototype.fromOptions = function fromOptions(data) {
  this.coinbaseHeight = data.coinbaseHeight;
  this.raw = data.raw;
  return this;
};

MemBlock.fromOptions = function fromOptions(data) {
  return new MemBlock().fromOptions(data);
};

/**
 * Get the full block size.
 * @returns {Number}
 */

MemBlock.prototype.getSize = function getSize() {
  return this.raw.length;
};

/**
 * Verify the block headers.
 * @alias MemBlock#verify
 * @param {Object?} ret - Return object, may be
 * set with properties `reason` and `score`.
 * @returns {Boolean}
 */

MemBlock.prototype._verify = function _verify(ret) {
  return this.verifyHeaders(ret);
};

/**
 * Retrieve the coinbase height from the coinbase input script (already
 * extracted in actuality).
 * @returns {Number} height (-1 if not present).
 */

MemBlock.prototype.getCoinbaseHeight = function getCoinbaseHeight() {
  return this.coinbaseHeight;
};

MemBlock.prototype.fromRaw = function fromRaw(data) {
  var p = bcoin.reader(data);
  var height = -1;
  var inCount, input;

  this.version = p.readU32(); // Technically signed
  this.prevBlock = p.readHash('hex');
  this.merkleRoot = p.readHash('hex');
  this.ts = p.readU32();
  this.bits = p.readU32();
  this.nonce = p.readU32();
  this.totalTX = p.readVarint();

  if (this.version > 1 && this.totalTX > 0) {
    p.readU32(); // Technically signed
    inCount = p.readVarint();

    if (inCount === 0) {
      if (p.readU8() !== 0)
        inCount = p.readVarint();
    }

    if (inCount > 0)
      input = bcoin.input.fromRaw(p);
  }

  if (input)
    height = bcoin.script.getCoinbaseHeight(input.script.raw);

  this.coinbaseHeight = height;
  this.raw = p.data;

  return this;
};

MemBlock.fromRaw = function fromRaw(data) {
  return new MemBlock().fromRaw(data);
};

MemBlock.prototype.toRaw = function toRaw() {
  return this.raw;
};

/**
 * Parse the serialized block data
 * and create an actual {@link Block}.
 * @returns {Block}
 * @throws Parse error
 */

MemBlock.prototype.toBlock = function toBlock() {
  var block = bcoin.block.fromRaw(this.raw);
  this.raw = null;
  return block;
};

/**
 * Test whether an object is a MemBlock.
 * @param {Object} obj
 * @returns {Boolean}
 */

MemBlock.isMemBlock = function isMemBlock(obj) {
  return obj && typeof obj.toBlock === 'function';
};

/*
 * Expose
 */

module.exports = MemBlock;
