/*!
 * path.js - path object for wallets
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const bio = require('bufio');
const Address = require('../primitives/address');
const {encoding} = bio;

/**
 * Path
 * @alias module:wallet.Path
 * @property {String} name - Account name.
 * @property {Number} account - Account index.
 * @property {Number} branch - Branch index.
 * @property {Number} index - Address index.
 */

class Path {
  /**
   * Create a path.
   * @constructor
   * @param {Object?} options
   */

  constructor(options) {
    this.keyType = Path.types.HD;

    this.name = null; // Passed in by caller.
    this.account = 0;

    this.type = Address.types.PUBKEYHASH;
    this.version = -1;

    this.branch = -1;
    this.index = -1;

    this.encrypted = false;
    this.data = null;

    this.hash = null; // Passed in by caller.

    if (options)
      this.fromOptions(options);
  }

  /**
   * Instantiate path from options object.
   * @private
   * @param {Object} options
   * @returns {Path}
   */

  fromOptions(options) {
    this.keyType = options.keyType;

    this.name = options.name;
    this.account = options.account;
    this.branch = options.branch;
    this.index = options.index;

    this.encrypted = options.encrypted;
    this.data = options.data;

    this.type = options.type;
    this.version = options.version;
    this.hash = options.hash;

    return this;
  }

  /**
   * Instantiate path from options object.
   * @param {Object} options
   * @returns {Path}
   */

  static fromOptions(options) {
    return new this().fromOptions(options);
  }

  /**
   * Clone the path object.
   * @returns {Path}
   */

  clone() {
    const path = new this.constructor();

    path.keyType = this.keyType;

    path.name = this.name;
    path.account = this.account;
    path.branch = this.branch;
    path.index = this.index;

    path.encrypted = this.encrypted;
    path.data = this.data;

    path.type = this.type;
    path.version = this.version;
    path.hash = this.hash;

    return path;
  }

  /**
   * Inject properties from serialized data.
   * @private
   * @param {Buffer} data
   */

  fromRaw(data) {
    const br = bio.read(data);

    this.account = br.readU32();
    this.keyType = br.readU8();

    const flags = br.readU8();

    this.type = flags & 7;
    this.version = flags >>> 3;

    if (this.version === 0x1f)
      this.version = -1;

    switch (this.keyType) {
      case Path.types.HD:
        this.branch = br.readU32();
        this.index = br.readU32();
        break;
      case Path.types.KEY:
        this.encrypted = br.readU8() === 1;
        this.data = br.readVarBytes();
        break;
      case Path.types.ADDRESS:
        // Hash will be passed in by caller.
        break;
      default:
        assert(false);
        break;
    }

    return this;
  }

  /**
   * Instantiate path from serialized data.
   * @param {Buffer} data
   * @returns {Path}
   */

  static fromRaw(data) {
    return new this().fromRaw(data);
  }

  /**
   * Calculate serialization size.
   * @returns {Number}
   */

  getSize() {
    let size = 0;

    size += 6;

    switch (this.keyType) {
      case Path.types.HD:
        size += 8;
        break;
      case Path.types.KEY:
        size += 1;
        size += encoding.sizeVarBytes(this.data);
        break;
    }

    return size;
  }

  /**
   * Serialize path.
   * @returns {Buffer}
   */

  toRaw() {
    const size = this.getSize();
    const bw = bio.write(size);

    bw.writeU32(this.account);
    bw.writeU8(this.keyType);

    let version = this.version;

    if (version === -1)
      version = 0x1f;

    const flags = (version << 3) | this.type;

    bw.writeU8(flags);

    switch (this.keyType) {
      case Path.types.HD:
        assert(!this.data);
        assert(this.index !== -1);
        bw.writeU32(this.branch);
        bw.writeU32(this.index);
        break;
      case Path.types.KEY:
        assert(this.data);
        assert(this.index === -1);
        bw.writeU8(this.encrypted ? 1 : 0);
        bw.writeVarBytes(this.data);
        break;
      case Path.types.ADDRESS:
        assert(!this.data);
        assert(this.index === -1);
        break;
      default:
        assert(false);
        break;
    }

    return bw.render();
  }

  /**
   * Inject properties from address.
   * @private
   * @param {Account} account
   * @param {Address} address
   */

  fromAddress(account, address) {
    this.keyType = Path.types.ADDRESS;
    this.name = account.name;
    this.account = account.accountIndex;
    this.version = address.version;
    this.type = address.type;
    this.hash = address.getHash('hex');
    return this;
  }

  /**
   * Instantiate path from address.
   * @param {Account} account
   * @param {Address} address
   * @returns {Path}
   */

  static fromAddress(account, address) {
    return new this().fromAddress(account, address);
  }

  /**
   * Convert path object to string derivation path.
   * @returns {String}
   */

  toPath() {
    if (this.keyType !== Path.types.HD)
      return null;

    return `m/${this.account}'/${this.branch}/${this.index}`;
  }

  /**
   * Convert path object to an address (currently unused).
   * @returns {Address}
   */

  toAddress() {
    return Address.fromHash(this.hash, this.type, this.version);
  }

  /**
   * Convert path to a json-friendly object.
   * @returns {Object}
   */

  toJSON() {
    return {
      name: this.name,
      account: this.account,
      change: this.branch === 1,
      derivation: this.toPath()
    };
  }

  /**
   * Inspect the path.
   * @returns {String}
   */

  inspect() {
    return `<Path: ${this.name}:${this.toPath()}>`;
  }
}

/**
 * Path types.
 * @enum {Number}
 * @default
 */

Path.types = {
  HD: 0,
  KEY: 1,
  ADDRESS: 2
};

/**
 * Path types.
 * @enum {Number}
 * @default
 */

Path.typesByVal = [
  'HD',
  'KEY',
  'ADDRESS'
];

/**
 * Expose
 */

module.exports = Path;
