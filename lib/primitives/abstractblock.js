/*!
 * abstractblock.js - abstract block object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const hash256 = require('bcrypto/lib/hash256');
const bio = require('bufio');
const util = require('../utils/util');
const InvItem = require('./invitem');
const consensus = require('../protocol/consensus');

/**
 * Abstract Block
 * The class which all block-like objects inherit from.
 * @alias module:primitives.AbstractBlock
 * @abstract
 * @property {Number} version
 * @property {Hash} prevBlock
 * @property {Hash} merkleRoot
 * @property {Number} time
 * @property {Number} bits
 * @property {Number} nonce
 */

class AbstractBlock {
  /**
   * Create an abstract block.
   * @constructor
   */

  constructor() {
    this.version = 1;
    this.prevBlock = consensus.NULL_HASH;
    this.merkleRoot = consensus.NULL_HASH;
    this.time = 0;
    this.bits = 0;
    this.nonce = 0;

    this.mutable = false;

    this._hash = null;
    this._hhash = null;
  }

  /**
   * Inject properties from options object.
   * @private
   * @param {Object} options
   */

  parseOptions(options) {
    assert(options, 'Block data is required.');
    assert((options.version >>> 0) === options.version);
    assert(typeof options.prevBlock === 'string');
    assert(typeof options.merkleRoot === 'string');
    assert((options.time >>> 0) === options.time);
    assert((options.bits >>> 0) === options.bits);
    assert((options.nonce >>> 0) === options.nonce);

    this.version = options.version;
    this.prevBlock = options.prevBlock;
    this.merkleRoot = options.merkleRoot;
    this.time = options.time;
    this.bits = options.bits;
    this.nonce = options.nonce;

    if (options.mutable != null) {
      assert(typeof options.mutable === 'boolean');
      this.mutable = options.mutable;
    }

    return this;
  }

  /**
   * Inject properties from json object.
   * @private
   * @param {Object} json
   */

  parseJSON(json) {
    assert(json, 'Block data is required.');
    assert((json.version >>> 0) === json.version);
    assert(typeof json.prevBlock === 'string');
    assert(typeof json.merkleRoot === 'string');
    assert((json.time >>> 0) === json.time);
    assert((json.bits >>> 0) === json.bits);
    assert((json.nonce >>> 0) === json.nonce);

    this.version = json.version;
    this.prevBlock = util.revHex(json.prevBlock);
    this.merkleRoot = util.revHex(json.merkleRoot);
    this.time = json.time;
    this.bits = json.bits;
    this.nonce = json.nonce;

    return this;
  }

  /**
   * Test whether the block is a memblock.
   * @returns {Boolean}
   */

  isMemory() {
    return false;
  }

  /**
   * Clear any cached values (abstract).
   */

  _refresh() {
    this._hash = null;
    this._hhash = null;
  }

  /**
   * Clear any cached values.
   */

  refresh() {
    return this._refresh();
  }

  /**
   * Hash the block headers.
   * @param {String?} enc - Can be `'hex'` or `null`.
   * @returns {Hash|Buffer} hash
   */

  hash(enc) {
    let h = this._hash;

    if (!h) {
      h = hash256.digest(this.toHead());
      if (!this.mutable)
        this._hash = h;
    }

    if (enc === 'hex') {
      let hex = this._hhash;
      if (!hex) {
        hex = h.toString('hex');
        if (!this.mutable)
          this._hhash = hex;
      }
      h = hex;
    }

    return h;
  }

  /**
   * Serialize the block headers.
   * @returns {Buffer}
   */

  toHead() {
    return this.writeHead(bio.write(80)).render();
  }

  /**
   * Inject properties from serialized data.
   * @private
   * @param {Buffer} data
   */

  fromHead(data) {
    return this.readHead(bio.read(data));
  }

  /**
   * Serialize the block headers.
   * @param {BufferWriter} bw
   */

  writeHead(bw) {
    bw.writeU32(this.version);
    bw.writeHash(this.prevBlock);
    bw.writeHash(this.merkleRoot);
    bw.writeU32(this.time);
    bw.writeU32(this.bits);
    bw.writeU32(this.nonce);
    return bw;
  }

  /**
   * Parse the block headers.
   * @param {BufferReader} br
   */

  readHead(br) {
    this.version = br.readU32();
    this.prevBlock = br.readHash('hex');
    this.merkleRoot = br.readHash('hex');
    this.time = br.readU32();
    this.bits = br.readU32();
    this.nonce = br.readU32();
    return this;
  }

  /**
   * Verify the block.
   * @returns {Boolean}
   */

  verify() {
    if (!this.verifyPOW())
      return false;

    if (!this.verifyBody())
      return false;

    return true;
  }

  /**
   * Verify proof-of-work.
   * @returns {Boolean}
   */

  verifyPOW() {
    return consensus.verifyPOW(this.hash(), this.bits);
  }

  /**
   * Verify the block.
   * @returns {Boolean}
   */

  verifyBody() {
    throw new Error('Abstract method.');
  }

  /**
   * Get little-endian block hash.
   * @returns {Hash}
   */

  rhash() {
    return util.revHex(this.hash('hex'));
  }

  /**
   * Convert the block to an inv item.
   * @returns {InvItem}
   */

  toInv() {
    return new InvItem(InvItem.types.BLOCK, this.hash('hex'));
  }
}

/*
 * Expose
 */

module.exports = AbstractBlock;
