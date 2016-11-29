/*!
 * memblock.js - memblock block object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var util = require('../utils/util');
var AbstractBlock = require('./abstractblock');
var Block = require('./block');
var Script = require('../script/script');
var Headers = require('./headers');
var BufferReader = require('../utils/reader');

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
 * @param {NakedBlock} options
 * @property {Boolean} memory - Always true.
 * @property {Number} coinbaseHeight - The coinbase height which
 * was extracted by the parser (the coinbase is the only
 * transaction we parse ahead of time).
 * @property {Buffer} raw - The raw block data.
 */

function MemBlock(options) {
  if (!(this instanceof MemBlock))
    return new MemBlock(options);

  AbstractBlock.call(this, options);

  this.memory = true;
  this.coinbaseHeight = -1;
  this.raw = null;

  if (options)
    this.fromOptions(options);
}

util.inherits(MemBlock, AbstractBlock);

/**
 * Inject properties from options object.
 * @private
 * @param {NakedBlock} options
 */

MemBlock.prototype.fromOptions = function fromOptions(options) {
  this.coinbaseHeight = options.coinbaseHeight;
  this.raw = options.raw;
  return this;
};

/**
 * Instantiate memblock from options object.
 * @param {NakedBlock} options
 * @returns {MemBlock}
 */

MemBlock.fromOptions = function fromOptions(options) {
  return new MemBlock().fromOptions(options);
};

/**
 * Serialize the block headers.
 * @returns {Buffer}
 */

MemBlock.prototype.abbr = function abbr(writer) {
  var data = this.raw.slice(0, 80);

  if (writer) {
    writer.writeBytes(data);
    return writer;
  }

  return data;
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
 * @param {Number|null} - Adjusted time.
 * @param {Object?} ret - Return object, may be
 * set with properties `reason` and `score`.
 * @returns {Boolean}
 */

MemBlock.prototype._verify = function _verify(now, ret) {
  return this.verifyHeaders(now, ret);
};

/**
 * Retrieve the coinbase height from the coinbase input script (already
 * extracted in actuality).
 * @returns {Number} height (-1 if not present).
 */

MemBlock.prototype.getCoinbaseHeight = function getCoinbaseHeight() {
  return this.coinbaseHeight;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

MemBlock.prototype.fromRaw = function fromRaw(data) {
  var br = BufferReader(data, true);
  var height = -1;
  var inCount, input;

  this.version = br.readU32(); // Technically signed
  this.prevBlock = br.readHash('hex');
  this.merkleRoot = br.readHash('hex');
  this.ts = br.readU32();
  this.bits = br.readU32();
  this.nonce = br.readU32();
  this.totalTX = br.readVarint();

  if (this.version > 1 && this.totalTX > 0) {
    br.seek(4);
    inCount = br.readVarint();

    if (inCount === 0) {
      if (br.readU8() !== 0)
        inCount = br.readVarint();
    }

    if (inCount > 0) {
      br.seek(36);
      input = br.readVarBytes();
      height = Script.getCoinbaseHeight(input);
    }
  }

  this.coinbaseHeight = height;
  this.raw = br.data;

  return this;
};

/**
 * Insantiate a memblock from serialized data.
 * @param {Buffer} data
 * @returns {MemBlock}
 */

MemBlock.fromRaw = function fromRaw(data) {
  return new MemBlock().fromRaw(data);
};

/**
 * Return serialized block data.
 * @returns {Buffer}
 */

MemBlock.prototype.toRaw = function toRaw() {
  return this.raw;
};

/**
 * Return serialized block data.
 * @returns {Buffer}
 */

MemBlock.prototype.toNormal = function toNormal() {
  return this.raw;
};

/**
 * Parse the serialized block data
 * and create an actual {@link Block}.
 * @returns {Block}
 * @throws Parse error
 */

MemBlock.prototype.toBlock = function toBlock() {
  var block = Block.fromRaw(this.raw);
  block._hash = this._hash;
  block._cbHeight = this.coinbaseHeight;
  this.raw = null;
  return block;
};

/**
 * Convert the block to a headers object.
 * @returns {Headers}
 */

MemBlock.prototype.toHeaders = function toHeaders() {
  return Headers.fromBlock(this);
};

/**
 * Test whether an object is a MemBlock.
 * @param {Object} obj
 * @returns {Boolean}
 */

MemBlock.isMemBlock = function isMemBlock(obj) {
  return obj && obj.memory && typeof obj.toBlock === 'function';
};

/*
 * Expose
 */

module.exports = MemBlock;
