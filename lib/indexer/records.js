/*!
 * records.js - indexer records
 * Copyright (c) 2018, the bcoin developers (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/**
 * @module lib/records
 */

const bio = require('bufio');
const util = require('../utils/util');
const consensus = require('../protocol/consensus');

/**
 * Chain State
 * @alias module:indexer.ChainState
 */

class ChainState {
  /**
   * Create a chain state.
   * @constructor
   */

  constructor() {
    this.startHeight = 0;
    this.height = 0;
  }

  /**
   * Clone the state.
   * @returns {ChainState}
   */

  clone() {
    const state = new ChainState();
    state.startHeight = this.startHeight;
    state.height = this.height;
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
    this.height = br.readU32();

    return this;
  }

  /**
   * Instantiate chain state from serialized data.
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
    const bw = bio.write(8);

    bw.writeU32(this.startHeight);
    bw.writeU32(this.height);

    return bw.render();
  }
}

/**
 * Block Meta
 * @alias module:indexer.BlockMeta
 */

class BlockMeta {
  /**
   * Create block meta.
   * @constructor
   * @param {Hash} hash
   * @param {Number} height
   */

  constructor(hash, height) {
    this.hash = hash || consensus.NULL_HASH;
    this.height = height != null ? height : -1;
  }

  /**
   * Clone the block.
   * @returns {BlockMeta}
   */

  clone() {
    return new this.constructor(this.hash, this.height);
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
   * @param {IndexEntry} entry
   */

  fromEntry(entry) {
    this.hash = entry.hash;
    this.height = entry.height;
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
    this.height = br.readI32();
    return this;
  }

  /**
   * Instantiate block meta from chain entry.
   * @param {IndexEntry} entry
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
    const bw = bio.write(36);
    bw.writeHash(this.hash);
    bw.writeI32(this.height);
    return bw.render();
  }

  /**
   * Convert the block meta to a more json-friendly object.
   * @returns {Object}
   */

  toJSON() {
    return {
      hash: util.revHex(this.hash),
      height: this.height
    };
  }
}

/*
 * Expose
 */

exports.ChainState = ChainState;
exports.BlockMeta = BlockMeta;

module.exports = exports;
