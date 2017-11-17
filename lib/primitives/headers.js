/*!
 * headers.js - headers object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const bio = require('bufio');
const util = require('../utils/util');
const AbstractBlock = require('./abstractblock');

/**
 * Headers
 * Represents block headers obtained
 * from the network via `headers`.
 * @alias module:primitives.Headers
 * @extends AbstractBlock
 */

class Headers extends AbstractBlock {
  /**
   * Create headers.
   * @constructor
   * @param {Object} options
   */

  constructor(options) {
    super();

    if (options)
      this.parseOptions(options);
  }

  /**
   * Perform non-contextual
   * verification on the headers.
   * @returns {Boolean}
   */

  verifyBody() {
    return true;
  }

  /**
   * Get size of the headers.
   * @returns {Number}
   */

  getSize() {
    return 81;
  }

  /**
   * Serialize the headers to a buffer writer.
   * @param {BufferWriter} bw
   */

  toWriter(bw) {
    this.writeHead(bw);
    bw.writeVarint(0);
    return bw;
  }

  /**
   * Serialize the headers.
   * @returns {Buffer|String}
   */

  toRaw() {
    const size = this.getSize();
    return this.toWriter(bio.write(size)).render();
  }

  /**
   * Inject properties from buffer reader.
   * @private
   * @param {Buffer} data
   */

  fromReader(br) {
    this.readHead(br);
    br.readVarint();
    return this;
  }

  /**
   * Inject properties from serialized data.
   * @private
   * @param {Buffer} data
   */

  fromRaw(data) {
    return this.fromReader(bio.read(data));
  }

  /**
   * Instantiate headers from buffer reader.
   * @param {BufferReader} br
   * @returns {Headers}
   */

  static fromReader(br) {
    return new this().fromReader(br);
  }

  /**
   * Instantiate headers from serialized data.
   * @param {Buffer} data
   * @param {String?} enc - Encoding, can be `'hex'` or null.
   * @returns {Headers}
   */

  static fromRaw(data, enc) {
    if (typeof data === 'string')
      data = Buffer.from(data, enc);
    return new this().fromRaw(data);
  }

  /**
   * Instantiate headers from serialized data.
   * @param {Buffer} data
   * @param {String?} enc - Encoding, can be `'hex'` or null.
   * @returns {Headers}
   */

  static fromHead(data, enc) {
    if (typeof data === 'string')
      data = Buffer.from(data, enc);
    return new this().fromHead(data);
  }

  /**
   * Instantiate headers from a chain entry.
   * @param {ChainEntry} entry
   * @returns {Headers}
   */

  static fromEntry(entry) {
    const headers = new this();
    headers.version = entry.version;
    headers.prevBlock = entry.prevBlock;
    headers.merkleRoot = entry.merkleRoot;
    headers.time = entry.time;
    headers.bits = entry.bits;
    headers.nonce = entry.nonce;
    headers._hash = Buffer.from(entry.hash, 'hex');
    headers._hhash = entry.hash;
    return headers;
  }

  /**
   * Convert the block to a headers object.
   * @returns {Headers}
   */

  toHeaders() {
    return this;
  }

  /**
   * Convert the block to a headers object.
   * @param {Block|MerkleBlock} block
   * @returns {Headers}
   */

  static fromBlock(block) {
    const headers = new this(block);
    headers._hash = block._hash;
    headers._hhash = block._hhash;
    return headers;
  }

  /**
   * Convert the block to an object suitable
   * for JSON serialization.
   * @returns {Object}
   */

  toJSON() {
    return this.getJSON();
  }

  /**
   * Convert the block to an object suitable
   * for JSON serialization. Note that the hashes
   * will be reversed to abide by bitcoind's legacy
   * of little-endian uint256s.
   * @param {Network} network
   * @param {CoinView} view
   * @param {Number} height
   * @returns {Object}
   */

  getJSON(network, view, height) {
    return {
      hash: this.rhash(),
      height: height,
      version: this.version,
      prevBlock: util.revHex(this.prevBlock),
      merkleRoot: util.revHex(this.merkleRoot),
      time: this.time,
      bits: this.bits,
      nonce: this.nonce
    };
  }

  /**
   * Inject properties from json object.
   * @private
   * @param {Object} json
   */

  fromJSON(json) {
    this.parseJSON(json);
    return this;
  }

  /**
   * Instantiate a merkle block from a jsonified block object.
   * @param {Object} json - The jsonified block object.
   * @returns {Headers}
   */

  static fromJSON(json) {
    return new this().fromJSON(json);
  }

  /**
   * Inspect the headers and return a more
   * user-friendly representation of the data.
   * @returns {Object}
   */

  inspect() {
    return this.format();
  }

  /**
   * Inspect the headers and return a more
   * user-friendly representation of the data.
   * @param {CoinView} view
   * @param {Number} height
   * @returns {Object}
   */

  format(view, height) {
    return {
      hash: this.rhash(),
      height: height != null ? height : -1,
      date: util.date(this.time),
      version: this.version.toString(16),
      prevBlock: util.revHex(this.prevBlock),
      merkleRoot: util.revHex(this.merkleRoot),
      time: this.time,
      bits: this.bits,
      nonce: this.nonce
    };
  }

  /**
   * Test an object to see if it is a Headers object.
   * @param {Object} obj
   * @returns {Boolean}
   */

  static isHeaders(obj) {
    return obj instanceof Headers;
  }
}

/*
 * Expose
 */

module.exports = Headers;
