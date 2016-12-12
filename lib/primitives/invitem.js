/*!
 * invitem.js - inv item object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var constants = require('../protocol/constants');
var BufferReader = require('../utils/reader');
var StaticWriter = require('../utils/staticwriter');

/**
 * Inv Item
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
    data = new Buffer(data, enc);
  return new InvItem().fromRaw(data);
};

/**
 * Test whether the inv item is a block.
 * @returns {Boolean}
 */

InvItem.prototype.isBlock = function isBlock() {
  switch (this.type) {
    case constants.inv.BLOCK:
    case constants.inv.WITNESS_BLOCK:
    case constants.inv.FILTERED_BLOCK:
    case constants.inv.WITNESS_FILTERED_BLOCK:
    case constants.inv.CMPCT_BLOCK:
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
    case constants.inv.TX:
    case constants.inv.WITNESS_TX:
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
  return (this.type & constants.WITNESS_MASK) !== 0;
};

/*
 * Expose
 */

module.exports = InvItem;
