/*!
 * keyorigin.js - hd key path object for bcoin
 * Copyright (c) 2023, the bcoin developers (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const common = require('./common');
const bio = require('bufio');
const {inspectSymbol} = require('../utils');

/**
 * KeyOriginInfo
 * Represents hd key path.
 * @property {Number} fingerPrint - master key fingerprint (uint32)
 * @property {Number[]} path - bip32 derivation path in uint32 array
 */

class KeyOriginInfo {
  /**
   * Create key origin info.
   * @constructor
   * @param {Object} options
   */

  constructor(options) {
    this.fingerPrint = 0;
    this.path = [];

    if (options) {
      this.fromOptions(options);
    }
  }

  /**
   * Inject properties from options object.
   * @param {Object} options
   * @returns {KeyOriginInfo}
   */

  fromOptions(options) {
    assert(options, 'requires options');

    if (options.fingerPrint != null) {
      assert(
        options.fingerPrint >>> 0 === options.fingerPrint,
        'Fingerprint must be uint32'
      );
      this.fingerPrint = options.fingerPrint;
    }

    if (options.path != null) {
      if (Array.isArray(options.path)) {
        assert(
          options.path.every(p => p >>> 0 === p),
          'All path indices must be uint32'
        );
        this.path = options.path;
      }
    }

    return this;
  }

  /**
   * Instantiate KeyOriginInfo from options.
   * @param {Object} options
   * @returns {KeyOriginInfo}
   */

  static fromOptions(options) {
    return new this().fromOptions(options);
  }

  /**
   * Inject properties from string.
   * @param {String} str
   * @returns {KeyOriginInfo}
   */

  fromString(str) {
    assert(typeof str === 'string');

    const slashSplit = str.split('/');

    assert(
      slashSplit[0].length === 8,
      `Expected 8 characters fingerprint, found ${slashSplit[0].length} instead`
    );

    this.fingerPrint = validateFingerPrint(slashSplit[0]);

    const pathArray = slashSplit.slice(1);
    this.path = common.parsePathFromArray(pathArray, true);

    return this;
  }

  /**
   * Instantiate KeyOriginInfo from string.
   * @param {String} str
   * @returns {KeyOriginInfo}
   */

  static fromString(str) {
    return new this().fromString(str);
  }

  /**
   * Test whether two KeyOriginInfo objects are equal.
   * @param {KeyOriginInfo} keyInfo
   * @returns {Boolean}
   */

  equals(keyInfo) {
    if (
      !KeyOriginInfo.isKeyOriginInfo(keyInfo)  ||
      this.fingerPrint !== keyInfo.fingerPrint ||
      this.path.length !== keyInfo.path.length
    ) {
      return false;
    }

    return (
      this.path.every((p, i) => p === keyInfo.path[i])
    );
  }

  /**
   * Convert KeyOriginInfo to a more user-friendly object.
   * @returns {Object}
   */

  inspect() {
    return this.format();
  }

  /**
   * Convert KeyOriginInfo to a more user-friendly object.
   * (uses 'h' as the default hardened marker for path)
   * @returns {Object}
   */

  format() {
    return {
      fingerPrint: this.fingerPrint.toString(16).padStart(8, '0'),
      path: 'm' + common.format(this.path, 'h')
    };
  }

   /**
   * Inject properties from serialized data.
   * @private
   * @param {Buffer} data
   * @returns {KeyOriginInfo}
   */

   fromRaw(data) {
    return this.fromReader(bio.read(data));
  }

  /**
   * Instantiate KeyOriginInfo from serialized data.
   * @param {Buffer} data
   * @returns {KeyOriginInfo}
   */

  static fromRaw(data) {
    return new this().fromRaw(data);
  }

  /**
   * Inject properties from buffer reader.
   * @private
   * @param {BufferReader} br
   */

  fromReader(br) {
    this.fingerPrint = br.readU32BE();
    while (br.left()) {
      this.path.push(br.readU32BE());
    }
    return this;
  }

  /**
   * Instantiate KeyOriginInfo from buffer reader.
   * @param {BufferReader} br
   * @returns {KeyOriginInfo}
   */

  static fromReader(br) {
    return new this().fromReader(br);
  }

  /**
   * Serialize the KeyOriginInfo.
   * @returns {Buffer}
   */

  toRaw() {
    return this.toWriter(bio.write(this.getSize())).render();
  }

  /**
   * Write the KeyOriginInfo to a buffer writer.
   * @param {BufferWriter} bw
   */

  toWriter(bw) {
    bw.writeU32BE(this.fingerPrint);

    for (const p of this.path) {
      bw.writeU32BE(p);
    }

    return bw;
  }

  /**
   * Inspect the KeyOriginInfo.
   * @returns {Object}
   */

  [inspectSymbol]() {
    return this.toJSON();
  }

  /**
   * Convert KeyOriginInfo to a more json-friendly object.
   * @returns {Object}
   */

  toJSON() {
    return this.format();
  }

  /**
   * Convert KeyOriginInfo to string.
   * @param {String} [hardenedMarker = 'h']
   * Whether to use apostrophe as the hardened marker for path.
   * Defaults to 'h' (uses 'h' as the hardened marker).
   * @returns {String}
   */

  toString(hardenedMarker = 'h') {
    const fingerPrint = this.format().fingerPrint;
    const path = common.format(this.path, hardenedMarker);
    return `${fingerPrint}${path}`;
  }

  /**
   * Instantiate KeyOriginInfo from json object.
   * @param {Object} json
   * @returns {KeyOriginInfo}
   */

  static fromJSON(json) {
    return new this().fromJSON(json);
  }

   /**
   * Inject properties from json object.
   * @private
   * @param {Object} json
   * @returns {KeyOriginInfo}
   */

  fromJSON(json) {
    if (json.fingerPrint) {
      if (typeof json.fingerPrint === 'string') {
        json.fingerPrint = validateFingerPrint(json.fingerPrint);
      } else {
        assert(
          json.fingerPrint >>> 0 === json.fingerPrint,
          'Fingerprint must be uint32'
        );
      }

      this.fingerPrint = json.fingerPrint;
    }

    if (json.path) {
      if (Array.isArray(json.path)) {
        assert(
          json.path.every(p => p >>> 0 === p),
          'All path indices must be uint32'
        );
        this.path = json.path;
      } else {
        this.path = common.parsePath(json.path, true);
      }
    }

    return this;
  }

  /**
   * Test whether an object is a KeyOriginInfo.
   * @param {Object} obj
   * @returns {Boolean}
   */

  static isKeyOriginInfo(obj) {
    return obj instanceof KeyOriginInfo;
  }

  /**
   * Clone the KeyOriginInfo.
   * @returns {KeyOriginInfo}
   */

  clone() {
    const path = this.path.slice();
    return new KeyOriginInfo({fingerPrint: this.fingerPrint, path});
  }

  /**
   * Clear the KeyOriginInfo.
   */

  clear() {
    this.fingerPrint = 0;
    this.path = [];
  }

  /**
   * Calculate serialization size.
   * @returns {Number}
   */

  getSize() {
    return 4 + this.path.length * 4;
  }
}

/**
 * Helpers
 */

/**
 * Test whether a string is a valid fingerprint.
 * @param {String} str
 * @returns {Number}
 */

function validateFingerPrint(str) {
  assert(
    str.length === 8,
    `Expected 8 characters fingerprint, found ${str.length} instead`
  );

  const fingerPrint = parseInt(str, 16);

  assert(
    !isNaN(fingerPrint),
    `Fingerprint ${str} is not hex`
  );

  assert(
    fingerPrint >>> 0 === fingerPrint,
    'Fingerprint must be uint32'
  );

  return fingerPrint;
}

module.exports = KeyOriginInfo;
