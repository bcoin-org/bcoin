/*!
 * records.js - walletdb records
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/**
 * @module wallet/records
 */

const assert = require('assert');
const bio = require('bufio');
const util = require('../utils/util');
const TX = require('../primitives/tx');
const consensus = require('../protocol/consensus');

/**
 * Chain State
 */

class ChainState {
  /**
   * Create a chain state.
   * @constructor
   */

  constructor() {
    this.startHeight = 0;
    this.startHash = consensus.NULL_HASH;
    this.height = 0;
    this.marked = false;
  }

  /**
   * Clone the state.
   * @returns {ChainState}
   */

  clone() {
    const state = new ChainState();
    state.startHeight = this.startHeight;
    state.startHash = this.startHash;
    state.height = this.height;
    state.marked = this.marked;
    return state;
  }

  /**
   * Inject properties from serialized data.
   * @private
   * @param {Buffer} data
   */

  fromRaw(data) {
    const br = bio.read(data);

    this.startHeight = br.readU32();
    this.startHash = br.readHash('hex');
    this.height = br.readU32();
    this.marked = br.readU8() === 1;

    return this;
  }

  /**
   * Instantiate chain state from serialized data.
   * @param {Hash} hash
   * @param {Buffer} data
   * @returns {ChainState}
   */

  static fromRaw(data) {
    return new this().fromRaw(data);
  }

  /**
   * Serialize the chain state.
   * @returns {Buffer}
   */

  toRaw() {
    const bw = bio.write(41);

    bw.writeU32(this.startHeight);
    bw.writeHash(this.startHash);
    bw.writeU32(this.height);
    bw.writeU8(this.marked ? 1 : 0);

    return bw.render();
  }
}

/**
 * Block Meta
 */

class BlockMeta {
  /**
   * Create block meta.
   * @constructor
   * @param {Hash} hash
   * @param {Number} height
   * @param {Number} time
   */

  constructor(hash, height, time) {
    this.hash = hash || consensus.NULL_HASH;
    this.height = height != null ? height : -1;
    this.time = time || 0;
  }

  /**
   * Clone the block.
   * @returns {BlockMeta}
   */

  clone() {
    return new this.constructor(this.hash, this.height, this.time);
  }

  /**
   * Get block meta hash as a buffer.
   * @returns {Buffer}
   */

  toHash() {
    return Buffer.from(this.hash, 'hex');
  }

  /**
   * Instantiate block meta from chain entry.
   * @private
   * @param {ChainEntry} entry
   */

  fromEntry(entry) {
    this.hash = entry.hash;
    this.height = entry.height;
    this.time = entry.time;
    return this;
  }

  /**
   * Instantiate block meta from json object.
   * @private
   * @param {Object} json
   */

  fromJSON(json) {
    this.hash = util.revHex(json.hash);
    this.height = json.height;
    this.time = json.time;
    return this;
  }

  /**
   * Instantiate block meta from serialized tip data.
   * @private
   * @param {Buffer} data
   */

  fromRaw(data) {
    const br = bio.read(data);
    this.hash = br.readHash('hex');
    this.height = br.readU32();
    this.time = br.readU32();
    return this;
  }

  /**
   * Instantiate block meta from chain entry.
   * @param {ChainEntry} entry
   * @returns {BlockMeta}
   */

  static fromEntry(entry) {
    return new this().fromEntry(entry);
  }

  /**
   * Instantiate block meta from json object.
   * @param {Object} json
   * @returns {BlockMeta}
   */

  static fromJSON(json) {
    return new this().fromJSON(json);
  }

  /**
   * Instantiate block meta from serialized data.
   * @param {Hash} hash
   * @param {Buffer} data
   * @returns {BlockMeta}
   */

  static fromRaw(data) {
    return new this().fromRaw(data);
  }

  /**
   * Serialize the block meta.
   * @returns {Buffer}
   */

  toRaw() {
    const bw = bio.write(42);
    bw.writeHash(this.hash);
    bw.writeU32(this.height);
    bw.writeU32(this.time);
    return bw.render();
  }

  /**
   * Convert the block meta to a more json-friendly object.
   * @returns {Object}
   */

  toJSON() {
    return {
      hash: util.revHex(this.hash),
      height: this.height,
      time: this.time
    };
  }
}

/**
 * TX Record
 */

class TXRecord {
  /**
   * Create tx record.
   * @constructor
   * @param {TX} tx
   * @param {BlockMeta?} block
   */

  constructor(tx, block) {
    this.tx = null;
    this.hash = null;
    this.mtime = util.now();
    this.height = -1;
    this.block = null;
    this.index = -1;
    this.time = 0;

    if (tx)
      this.fromTX(tx, block);
  }

  /**
   * Inject properties from tx and block.
   * @private
   * @param {TX} tx
   * @param {Block?} block
   * @returns {TXRecord}
   */

  fromTX(tx, block) {
    this.tx = tx;
    this.hash = tx.hash('hex');

    if (block)
      this.setBlock(block);

    return this;
  }

  /**
   * Instantiate tx record from tx and block.
   * @param {TX} tx
   * @param {Block?} block
   * @returns {TXRecord}
   */

  static fromTX(tx, block) {
    return new this().fromTX(tx, block);
  }

  /**
   * Set block data (confirm).
   * @param {BlockMeta} block
   */

  setBlock(block) {
    this.height = block.height;
    this.block = block.hash;
    this.time = block.time;
  }

  /**
   * Unset block (unconfirm).
   */

  unsetBlock() {
    this.height = -1;
    this.block = null;
    this.time = 0;
  }

  /**
   * Convert tx record to a block meta.
   * @returns {BlockMeta}
   */

  getBlock() {
    if (this.height === -1)
      return null;

    return new BlockMeta(this.block, this.height, this.time);
  }

  /**
   * Calculate current number of transaction confirmations.
   * @param {Number} height - Current chain height.
   * @returns {Number} confirmations
   */

  getDepth(height) {
    assert(typeof height === 'number', 'Must pass in height.');

    if (this.height === -1)
      return 0;

    if (height < this.height)
      return 0;

    return height - this.height + 1;
  }

  /**
   * Get serialization size.
   * @returns {Number}
   */

  getSize() {
    let size = 0;

    size += this.tx.getSize();
    size += 4;

    if (this.block) {
      size += 1;
      size += 32;
      size += 4 * 3;
    } else {
      size += 1;
    }

    return size;
  }

  /**
   * Serialize a transaction to "extended format".
   * @returns {Buffer}
   */

  toRaw() {
    const size = this.getSize();
    const bw = bio.write(size);

    let index = this.index;

    this.tx.toWriter(bw);

    bw.writeU32(this.mtime);

    if (this.block) {
      if (index === -1)
        index = 0x7fffffff;

      bw.writeU8(1);
      bw.writeHash(this.block);
      bw.writeU32(this.height);
      bw.writeU32(this.time);
      bw.writeU32(index);
    } else {
      bw.writeU8(0);
    }

    return bw.render();
  }

  /**
   * Inject properties from "extended" format.
   * @private
   * @param {Buffer} data
   */

  fromRaw(data) {
    const br = bio.read(data);

    this.tx = new TX();
    this.tx.fromReader(br);

    this.hash = this.tx.hash('hex');
    this.mtime = br.readU32();

    if (br.readU8() === 1) {
      this.block = br.readHash('hex');
      this.height = br.readU32();
      this.time = br.readU32();
      this.index = br.readU32();
      if (this.index === 0x7fffffff)
        this.index = -1;
    }

    return this;
  }

  /**
   * Instantiate a transaction from a buffer
   * in "extended" serialization format.
   * @param {Buffer} data
   * @returns {TX}
   */

  static fromRaw(data) {
    return new this().fromRaw(data);
  }
}

/**
 * Map Record
 */

class MapRecord {
  /**
   * Create map record.
   * @constructor
   */

  constructor() {
    this.wids = new Set();
  }

  add(wid) {
    if (this.wids.has(wid))
      return false;

    this.wids.add(wid);

    return true;
  }

  remove(wid) {
    return this.wids.delete(wid);
  }

  toWriter(bw) {
    bw.writeU32(this.wids.size);

    for (const wid of this.wids)
      bw.writeU32(wid);

    return bw;
  }

  getSize() {
    return 4 + this.wids.size * 4;
  }

  toRaw() {
    const size = this.getSize();
    return this.toWriter(bio.write(size)).render();
  }

  fromReader(br) {
    const count = br.readU32();

    for (let i = 0; i < count; i++)
      this.wids.add(br.readU32());

    return this;
  }

  fromRaw(data) {
    return this.fromReader(bio.read(data));
  }

  static fromReader(br) {
    return new this().fromReader(br);
  }

  static fromRaw(data) {
    return new this().fromRaw(data);
  }
}

/*
 * Expose
 */

exports.ChainState = ChainState;
exports.BlockMeta = BlockMeta;
exports.TXRecord = TXRecord;
exports.MapRecord = MapRecord;

module.exports = exports;
