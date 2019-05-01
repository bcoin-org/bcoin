/*!
 * filters.js - filter object for bcoin
 * Copyright (c) 2019, the bcoin developers (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');
const bio = require('bufio');
const util = require('../utils/util');
const consensus = require('../protocol/consensus');
const {inspectSymbol} = require('../utils');

/*
 * Constants
 */

const EMPTY_BUFFER = Buffer.alloc(0);

/**
 * Filter
 * Represents a GCSFilter.
 * @alias module:primitives.Filter
 * @property {Hash} hash
 * @property {Number} index
 */

class Filter {
  /**
   * Create an filter.
   * @constructor
   * @param {Object?} options
   */

  constructor(options) {
    this.header = consensus.ZERO_HASH;
    this.filter = EMPTY_BUFFER;

    if (options)
      this.fromOptions(options);
  }

  /**
   * Inject properties from options object.
   * @private
   * @param {Object} options
   */

  fromOptions(options) {
    assert(options, 'Filter data is required.');
    assert(Buffer.isBuffer(options.header));
    assert(Buffer.isBuffer(options.filter));
    this.header = options.header;
    this.filter = options.filter;
    return this;
  }

  /**
   * Instantate outpoint from options object.
   * @param {Object} options
   * @returns {Filter}
   */

  static fromOptions(options) {
    return new this().fromOptions(options);
  }

  /**
   * Write filter to a buffer writer.
   * @param {BufferWriter} bw
   */

  toWriter(bw) {
    bw.writeHash(this.header);
    bw.writeBytes(this.filter);
    return bw;
  }

  /**
   * Calculate size of filter.
   * @returns {Number}
   */

  getSize() {
    let size = 0;
    size += 32;
    size += this.filter.length;
    return size;
  }

  /**
   * Serialize filter.
   * @returns {Buffer}
   */

  toRaw() {
    const size = this.getSize();
    return this.toWriter(bio.write(size)).render();
  }

  /**
   * Inject properties from buffer reader.
   * @private
   * @param {BufferReader} br
   */

  fromReader(br) {
    this.header = br.readHash();
    this.filter = br.readBytes(br.getSize() - br.offset);
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
   * Instantiate filter from a buffer reader.
   * @param {BufferReader} br
   * @returns {Filter}
   */

  static fromReader(br) {
    return new this().fromReader(br);
  }

  /**
   * Instantiate filter from serialized data.
   * @param {Buffer} data
   * @returns {Filter}
   */

  static fromRaw(data) {
    return new this().fromRaw(data);
  }

  /**
   * Inject properties from json object.
   * @private
   * @params {Object} json
   */

  fromJSON(json) {
    assert(json, 'Filter data is required.');
    assert(typeof json.filter === 'string', 'Filter must be a string.');
    assert(typeof json.header === 'string', 'Header must be a string.');
    this.filter = Buffer.from(json.filter);
    this.header = Buffer.from(json.header);
    return this;
  }

  /**
   * Convert the filter to an object suitable
   * for JSON serialization.
   * @returns {Object}
   */

  toJSON() {
    return {
      filter: this.filter.toString('hex'),
      header: util.revHex(this.header)
    };
  }

  /**
   * Instantiate filter from json object.
   * @param {Object} json
   * @returns {Filter}
   */

  static fromJSON(json) {
    return new this().fromJSON(json);
  }

  /**
   * Convert the filter to a user-friendly string.
   * @returns {String}
   */

  [inspectSymbol]() {
    return `<Filter: ${this.filter.toString('hex')}>`;
  }

  /**
   * Test an object to see if it is an filter.
   * @param {Object} obj
   * @returns {Boolean}
   */

  static isFilter(obj) {
    return obj instanceof Filter;
  }
}

/*
 * Expose
 */

module.exports = Filter;
