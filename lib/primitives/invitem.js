/*!
 * invitem.js - inv item object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const bio = require('bufio');
const util = require('../utils/util');

/**
 * Inv Item
 * @alias module:primitives.InvItem
 * @constructor
 * @property {InvType} type
 * @property {Hash} hash
 */

class InvItem {
  /**
   * Create an inv item.
   * @constructor
   * @param {Number} type
   * @param {Hash} hash
   */

  constructor(type, hash) {
    this.type = type;
    this.hash = hash;
  }

  /**
   * Write inv item to buffer writer.
   * @param {BufferWriter} bw
   */

  getSize() {
    return 36;
  }

  /**
   * Write inv item to buffer writer.
   * @param {BufferWriter} bw
   */

  toWriter(bw) {
    bw.writeU32(this.type);
    bw.writeHash(this.hash);
    return bw;
  }

  /**
   * Serialize inv item.
   * @returns {Buffer}
   */

  toRaw() {
    return this.toWriter(bio.write(36)).render();
  }

  /**
   * Inject properties from buffer reader.
   * @private
   * @param {BufferReader} br
   */

  fromReader(br) {
    this.type = br.readU32();
    this.hash = br.readHash('hex');
    return this;
  }

  /**
   * Inject properties from serialized data.
   * @param {Buffer} data
   */

  fromRaw(data) {
    return this.fromReader(bio.read(data));
  }

  /**
   * Instantiate inv item from buffer reader.
   * @param {BufferReader} br
   * @returns {InvItem}
   */

  static fromReader(br) {
    return new this().fromReader(br);
  }

  /**
   * Instantiate inv item from serialized data.
   * @param {Buffer} data
   * @param {String?} enc
   * @returns {InvItem}
   */

  static fromRaw(data, enc) {
    if (typeof data === 'string')
      data = Buffer.from(data, enc);
    return new this().fromRaw(data);
  }

  /**
   * Test whether the inv item is a block.
   * @returns {Boolean}
   */

  isBlock() {
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
  }

  /**
   * Test whether the inv item is a tx.
   * @returns {Boolean}
   */

  isTX() {
    switch (this.type) {
      case InvItem.types.TX:
      case InvItem.types.WITNESS_TX:
        return true;
      default:
        return false;
    }
  }

  /**
   * Test whether the inv item has the witness bit set.
   * @returns {Boolean}
   */

  hasWitness() {
    return (this.type & InvItem.WITNESS_FLAG) !== 0;
  }

  /**
   * Get little-endian hash.
   * @returns {Hash}
   */

  rhash() {
    return util.revHex(this.hash);
  }
}

/**
 * Inv types.
 * @enum {Number}
 * @default
 */

InvItem.types = {
  TX: 1,
  BLOCK: 2,
  FILTERED_BLOCK: 3,
  CMPCT_BLOCK: 4,
  WITNESS_TX: 1 | (1 << 30),
  WITNESS_BLOCK: 2 | (1 << 30),
  WITNESS_FILTERED_BLOCK: 3 | (1 << 30)
};

/**
 * Inv types by value.
 * @const {Object}
 */

InvItem.typesByVal = {
  1: 'TX',
  2: 'BLOCK',
  3: 'FILTERED_BLOCK',
  4: 'CMPCT_BLOCK',
  [1 | (1 << 30)]: 'WITNESS_TX',
  [2 | (1 << 30)]: 'WITNESS_BLOCK',
  [3 | (1 << 30)]: 'WITNESS_FILTERED_BLOCK'
};

/**
 * Witness bit for inv types.
 * @const {Number}
 * @default
 */

InvItem.WITNESS_FLAG = 1 << 30;

/*
 * Expose
 */

module.exports = InvItem;
