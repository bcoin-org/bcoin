/*!
 * records.js - walletdb records
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/**
 * @module wallet/records
 */

const assert = require('bsert');
const bio = require('bufio');
const util = require('../utils/util');
const TX = require('../primitives/tx');
const consensus = require('../protocol/consensus');

/**
 * Chain State
 */

class ChainState extends bio.Struct {
  /**
   * Create a chain state.
   * @constructor
   */

  constructor() {
    super();

    this.startHeight = 0;
    this.startHash = consensus.ZERO_HASH;
    this.height = 0;
    this.marked = false;
  }

  /**
   * Inject state from another state object.
   * @param {ChainState} state
   * @returns {ChainState}
   */

  inject(state) {
    this.startHeight = state.startHeight;
    this.startHash = state.startHash;
    this.height = state.height;
    this.marked = state.marked;
    return this;
  }

  /**
   * Calculate serialized size.
   * @returns {Number}
   */

  getSize() {
    return 41;
  }

  /**
   * Deserialize the chain state.
   * @private
   * @param {BufferReader} br
   * @returns {ChainState}
   */

  read(br) {
    this.startHeight = br.readU32();
    this.startHash = br.readHash();
    this.height = br.readU32();
    this.marked = br.readU8() === 1;
    return this;
  }

  /**
   * Serialize the chain state.
   * @param {BufferWriter}
   * @returns {BufferWriter}
   */

  write(bw) {
    bw.writeU32(this.startHeight);
    bw.writeHash(this.startHash);
    bw.writeU32(this.height);
    bw.writeU8(this.marked ? 1 : 0);
    return bw;
  }
}

/**
 * Block Meta
 */

class BlockMeta extends bio.Struct {
  /**
   * Create block meta.
   * @constructor
   * @param {Hash} hash
   * @param {Number} height
   * @param {Number} time
   */

  constructor(hash, height, time) {
    super();
    this.hash = hash || consensus.ZERO_HASH;
    this.height = height != null ? height : -1;
    this.time = time || 0;
  }

  /**
   * Inject properties from BlockMeta.
   * @param {BlockMeta} meta
   * @returns {BlockMeta}
   */

  inject(meta) {
    this.hash = meta.hash;
    this.height = meta.height;
    this.time = meta.time;
    return this;
  }

  /**
   * Get block meta hash as a buffer.
   * @returns {Buffer}
   */

  toHash() {
    return this.hash;
  }

  /**
   * Instantiate block meta from chain entry.
   * @private
   * @param {ChainEntry} entry
   * @returns {BlockMeta}
   */

  fromEntry(entry) {
    this.hash = entry.hash;
    this.height = entry.height;
    this.time = entry.time;
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
   * Convert the block meta to a more json-friendly object.
   * @returns {Object}
   */

  getJSON() {
    return {
      hash: util.revHex(this.hash),
      height: this.height,
      time: this.time
    };
  }

  /**
   * Instantiate block meta from json object.
   * @private
   * @param {Object} json
   * @returns {BlockMeta}
   */

  fromJSON(json) {
    this.hash = util.revHex(json.hash);
    this.height = json.height;
    this.time = json.time;
    return this;
  }

  /**
   * Calculate size.
   * @returns {Number}
   */

  getSize() {
    return 40;
  }

  /**
   * Serialize the block meta.
   * @private
   * @param {BufferWriter} bw
   * @returns {BufferWriter}
   */

  write(bw) {
    bw.writeHash(this.hash);
    bw.writeU32(this.height);
    bw.writeU32(this.time);
    return bw;
  }

  /**
   * Instantiate block meta from serialized tip data.
   * @private
   * @param {BufferReader} br
   * @returns {BlockMeta}
   */

  read(br) {
    this.hash = br.readHash();
    this.height = br.readU32();
    this.time = br.readU32();
    return br;
  }
}

/**
 * TX Record
 */

class TXRecord extends bio.Struct {
  /**
   * Create tx record.
   * @constructor
   * @param {TX} tx
   * @param {BlockMeta?} block
   */

  constructor(tx, block) {
    super();

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
    this.hash = tx.hash();

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
   * @param {BufferWriter} bw
   * @returns {BufferWriter}
   */

  write(bw) {
    let index = this.index;

    this.tx.write(bw);

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

    return bw;
  }

  /**
   * Inject properties from "extended" format.
   * @private
   * @param {BufferReader} br
   * @returns {TXRecord}
   */

  read(br) {
    this.tx = new TX();
    this.tx.read(br);

    this.hash = this.tx.hash();
    this.mtime = br.readU32();

    if (br.readU8() === 1) {
      this.block = br.readHash();
      this.height = br.readU32();
      this.time = br.readU32();
      this.index = br.readU32();
      if (this.index === 0x7fffffff)
        this.index = -1;
    }

    return this;
  }
}

/**
 * Map Record
 * @property {Set<Number>} wids
 */

class MapRecord extends bio.Struct {
  /**
   * Create map record.
   * @constructor
   */

  constructor() {
    super();

    this.wids = new Set();
  }

  /**
   * Add wallet id to the set.
   * @param {Number} wid
   * @returns {Boolean} - true if there was no wid, false otherwise.
   */

  add(wid) {
    if (this.wids.has(wid))
      return false;

    this.wids.add(wid);

    return true;
  }

  /**
   * Remove wallet id from the set
   * @param {Number} wid
   */

  remove(wid) {
    return this.wids.delete(wid);
  }

  /**
   * Get serialized size.
   * @returns {Number}
   */

  getSize() {
    return 4 + this.wids.size * 4;
  }

  /**
   * Serialize the MapRecord.
   * @private
   * @param {BufferWriter} bw
   * @returns {BufferWriter}
   */

  write(bw) {
    bw.writeU32(this.wids.size);

    for (const wid of this.wids)
      bw.writeU32(wid);

    return bw;
  }

  /**
   * Deserialize the MapRecord.
   * @private
   * @param {BufferReader} br
   * @returns {MapRecord}
   */

  read(br) {
    const count = br.readU32();

    for (let i = 0; i < count; i++)
      this.wids.add(br.readU32());

    return this;
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
