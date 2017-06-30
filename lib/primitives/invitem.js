/*!
 * invitem.js - inv item object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const BufferReader = require('../utils/reader');
const StaticWriter = require('../utils/staticwriter');
const util = require('../utils/util');

/**
 * Inv Item
 * @alias module:primitives.InvItem
 * @constructor
 * @param {Number} type
 * @param {Hash} hash
 * @property {InvType} type
 * @property {Hash} hash
 */

function InvItem(type, hash) {
  if (!(this instanceof InvItem))
    return new InvItem(type, hash);

  this.type = type;
  this.hash = hash;
}

/**
 * Inv types.
 * @enum {Number}
 * @default
 */

InvItem.types = {
  ERROR: 0,
  TX: 1,
  BLOCK: 2,
  FILTERED_BLOCK: 3,
  WITNESS_TX: 1 | (1 << 30),
  WITNESS_BLOCK: 2 | (1 << 30),
  WITNESS_FILTERED_BLOCK: 3 | (1 << 30),
  CMPCT_BLOCK: 4
};

/**
 * Inv types by value.
 * @const {RevMap}
 */

InvItem.typesByVal = util.revMap(InvItem.types);

/**
 * Witness bit for inv types.
 * @const {Number}
 * @default
 */

InvItem.WITNESS_FLAG = 1 << 30;

/**
 * Write inv item to buffer writer.
 * @param {BufferWriter} bw
 */

InvItem.prototype.getSize = function getSize() {
  return 36;
};

/**
 * Write inv item to buffer writer.
 * @param {BufferWriter} bw
 */

InvItem.prototype.toWriter = function toWriter(bw) {
  bw.writeU32(this.type);
  bw.writeHash(this.hash);
  return bw;
};

/**
 * Serialize inv item.
 * @returns {Buffer}
 */

InvItem.prototype.toRaw = function toRaw() {
  return this.toWriter(new StaticWriter(36)).render();
};

/**
 * Inject properties from buffer reader.
 * @private
 * @param {BufferReader} br
 */

InvItem.prototype.fromReader = function fromReader(br) {
  this.type = br.readU32();
  this.hash = br.readHash('hex');
  return this;
};

/**
 * Inject properties from serialized data.
 * @param {Buffer} data
 */

InvItem.prototype.fromRaw = function fromRaw(data) {
  return this.fromReader(new BufferReader(data));
};

/**
 * Instantiate inv item from buffer reader.
 * @param {BufferReader} br
 * @returns {InvItem}
 */

InvItem.fromReader = function fromReader(br) {
  return new InvItem().fromReader(br);
};

/**
 * Instantiate inv item from serialized data.
 * @param {Buffer} data
 * @param {String?} enc
 * @returns {InvItem}
 */

InvItem.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = Buffer.from(data, enc);
  return new InvItem().fromRaw(data);
};

/**
 * Test whether the inv item is a block.
 * @returns {Boolean}
 */

InvItem.prototype.isBlock = function isBlock() {
  switch (this.type) {
    case InvItem.types.BLOCK:
    case InvItem.types.WITNESS_BLOCK:
    case InvItem.types.FILTERED_BLOCK:
    case InvItem.types.WITNESS_FILTERED_BLOCK:
    case InvItem.types.CMPCT_BLOCK:
      return true;
    default:
      return false;
  }
};

/**
 * Test whether the inv item is a tx.
 * @returns {Boolean}
 */

InvItem.prototype.isTX = function isTX() {
  switch (this.type) {
    case InvItem.types.TX:
    case InvItem.types.WITNESS_TX:
      return true;
    default:
      return false;
  }
};

/**
 * Test whether the inv item has the witness bit set.
 * @returns {Boolean}
 */

InvItem.prototype.hasWitness = function hasWitness() {
  return (this.type & InvItem.WITNESS_FLAG) !== 0;
};

/**
 * Get little-endian hash.
 * @returns {Hash}
 */

InvItem.prototype.rhash = function rhash() {
  return util.revHex(this.hash);
};

/*
 * Expose
 */

module.exports = InvItem;
