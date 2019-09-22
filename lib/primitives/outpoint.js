/*!
 * outpoint.js - outpoint object for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');
const bio = require('bufio');
const util = require('../utils/util');
const consensus = require('../protocol/consensus');

/**
 * Outpoint
 * Represents a COutPoint.
 * @alias module:primitives.Outpoint
 * @property {Hash} hash
 * @property {Number} index
 */

class Outpoint extends bio.Struct {
  /**
   * Create an outpoint.
   * @constructor
   * @param {Hash?} hash
   * @param {Number?} index
   */

  constructor(hash, index) {
    super();

    this.hash = consensus.ZERO_HASH;
    this.index = 0xffffffff;

    if (hash != null) {
      assert(Buffer.isBuffer(hash));
      assert((index >>> 0) === index, 'Index must be a uint32.');
      this.hash = hash;
      this.index = index;
    }
  }

  /**
   * Inject properties from options object.
   * @private
   * @param {Object} options
   */

  fromOptions(options) {
    assert(options, 'Outpoint data is required.');
    assert(Buffer.isBuffer(options.hash));
    assert((options.index >>> 0) === options.index, 'Index must be a uint32.');
    this.hash = options.hash;
    this.index = options.index;
    return this;
  }

  /**
   * Inject properties from another outpoint.
   * @param {Outpoint} prevout
   * @returns {Outpoint}
   */

  inject(prevout) {
    assert(prevout instanceof this.constructor);
    this.hash = prevout.hash;
    this.index = prevout.index;
    return this;
  }

  /**
   * Test equality against another outpoint.
   * @param {Outpoint} prevout
   * @returns {Boolean}
   */

  equals(prevout) {
    assert(Outpoint.isOutpoint(prevout));
    return this.hash.equals(prevout.hash)
      && this.index === prevout.index;
  }

  /**
   * Compare against another outpoint (BIP69).
   * @param {Outpoint} prevout
   * @returns {Number}
   */

  compare(prevout) {
    assert(Outpoint.isOutpoint(prevout));

    const cmp = strcmp(this.txid(), prevout.txid());

    if (cmp !== 0)
      return cmp;

    return this.index - prevout.index;
  }

  /**
   * Test whether the outpoint is null (hash of zeroes
   * with max-u32 index). Used to detect coinbases.
   * @returns {Boolean}
   */

  isNull() {
    return this.index === 0xffffffff && this.hash.equals(consensus.ZERO_HASH);
  }

  /**
   * Get little-endian hash.
   * @returns {Hash}
   */

  rhash() {
    return util.revHex(this.hash);
  }

  /**
   * Get little-endian hash.
   * @returns {Hash}
   */

  txid() {
    return this.rhash();
  }

  /**
   * Serialize outpoint to a key
   * suitable for a hash table.
   * @returns {String}
   */

  toKey() {
    return this.encode();
  }

  /**
   * Inject properties from hash table key.
   * @private
   * @param {String} key
   * @returns {Outpoint}
   */

  fromKey(key) {
    assert(Buffer.isBuffer(key) && key.length === 36);
    this.hash = key.slice(0, 32);
    this.index = bio.readU32(key, 32);
    return this;
  }

  /**
   * Instantiate outpoint from hash table key.
   * @param {String} key
   * @returns {Outpoint}
   */

  static fromKey(key) {
    return new this().fromKey(key);
  }

  /**
   * Calculate size of outpoint.
   * @returns {Number}
   */

  getSize() {
    return 36;
  }

  /**
   * Write outpoint to a buffer writer.
   * @private
   * @param {BufferWriter} bw
   * @returns {BufferWriter}
   */

  write(bw) {
    bw.writeHash(this.hash);
    bw.writeU32(this.index);
    return bw;
  }

  /**
   * Inject properties from buffer reader.
   * @private
   * @param {BufferReader} br
   * @returns {Outpoint}
   */

  read(br) {
    this.hash = br.readHash();
    this.index = br.readU32();
    return this;
  }

  /**
   * Inject properties from json object.
   * @private
   * @param {Object} json
   */

  fromJSON(json) {
    assert(json, 'Outpoint data is required.');
    assert(typeof json.hash === 'string', 'Hash must be a string.');
    assert((json.index >>> 0) === json.index, 'Index must be a uint32.');
    this.hash = util.fromRev(json.hash);
    this.index = json.index;
    return this;
  }

  /**
   * Convert the outpoint to an object suitable
   * for JSON serialization. Note that the hash
   * will be reversed to abide by bitcoind's legacy
   * of little-endian uint256s.
   * @returns {Object}
   */

  getJSON() {
    return {
      hash: util.revHex(this.hash),
      index: this.index
    };
  }

  /**
   * Inject properties from tx.
   * @private
   * @param {TX} tx
   * @param {Number} index
   */

  fromTX(tx, index) {
    assert(tx);
    assert(typeof index === 'number');
    assert(index >= 0);
    this.hash = tx.hash();
    this.index = index;
    return this;
  }

  /**
   * Instantiate outpoint from tx.
   * @param {TX} tx
   * @param {Number} index
   * @returns {Outpoint}
   */

  static fromTX(tx, index) {
    return new this().fromTX(tx, index);
  }

  /**
   * Serialize outpoint to a key
   * suitable for a hash table.
   * @param {Hash} hash
   * @param {Number} index
   * @returns {String}
   */

  static toKey(hash, index) {
    return new Outpoint(hash, index).toKey();
  }

  /**
   * Convert the outpoint to a user-friendly string.
   * @returns {String}
   */

  format() {
    return `<Outpoint: ${this.rhash()}/${this.index}>`;
  }

  /**
   * Test an object to see if it is an outpoint.
   * @param {Object} obj
   * @returns {Boolean}
   */

  static isOutpoint(obj) {
    return obj instanceof Outpoint;
  }
}

/*
 * Helpers
 */

function strcmp(a, b) {
  const len = Math.min(a.length, b.length);

  for (let i = 0; i < len; i++) {
    if (a[i] < b[i])
      return -1;
    if (a[i] > b[i])
      return 1;
  }

  if (a.length < b.length)
    return -1;

  if (a.length > b.length)
    return 1;

  return 0;
}

/*
 * Expose
 */

module.exports = Outpoint;
