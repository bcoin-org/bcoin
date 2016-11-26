/*!
 * invitem.js - inv item object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var constants = require('../protocol/constants');
var BufferWriter = require('../utils/writer');
var BufferReader = require('../utils/reader');

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
 * Serialize inv item.
 * @returns {Buffer}
 */

InvItem.prototype.toRaw = function toRaw(writer) {
  var bw = BufferWriter(writer);

  bw.writeU32(this.type);
  bw.writeHash(this.hash);

  if (!writer)
    bw = bw.render();

  return bw;
};

/**
 * Inject properties from serialized data.
 * @param {Buffer} data
 */

InvItem.prototype.fromRaw = function fromRaw(data) {
  var br = BufferReader(data);
  this.type = br.readU32();
  this.hash = br.readHash('hex');
  return this;
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
