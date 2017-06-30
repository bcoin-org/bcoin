/*!
 * txmeta.js - extended transaction object for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const util = require('../utils/util');
const TX = require('./tx');
const StaticWriter = require('../utils/staticwriter');
const BufferReader = require('../utils/reader');

/**
 * An extended transaction object.
 * @alias module:primitives.TXMeta
 * @constructor
 * @param {Object} options
 */

function TXMeta(options) {
  if (!(this instanceof TXMeta))
    return new TXMeta(options);

  this.tx = new TX();
  this.ps = util.now();
  this.height = -1;
  this.block = null;
  this.ts = 0;
  this.index = 0;

  if (options)
    this.fromOptions(options);
}

/**
 * Inject properties from options object.
 * @private
 * @param {Object} options
 */

TXMeta.prototype.fromOptions = function fromOptions(options) {
  if (options.tx) {
    assert(options.tx instanceof TX);
    this.tx = options.tx;
  }

  if (options.ps != null) {
    assert(util.isNumber(options.ps));
    this.ps = options.ps;
  }

  if (options.height != null) {
    assert(util.isNumber(options.height));
    this.height = options.height;
  }

  if (options.block !== undefined) {
    assert(options.block === null || typeof options.block === 'string');
    this.block = options.block;
  }

  if (options.ts != null) {
    assert(util.isNumber(options.ts));
    this.ts = options.ts;
  }

  if (options.index != null) {
    assert(util.isNumber(options.index));
    this.index = options.index;
  }

  return this;
};

/**
 * Instantiate TXMeta from options.
 * @param {Object} options
 * @returns {TXMeta}
 */

TXMeta.fromOptions = function fromOptions(options) {
  return new TXMeta().fromOptions(options);
};

/**
 * Inject properties from options object.
 * @private
 * @param {Object} options
 */

TXMeta.prototype.fromTX = function fromTX(tx, entry, index) {
  this.tx = tx;
  if (entry) {
    this.height = entry.height;
    this.block = entry.hash;
    this.ts = entry.ts;
    this.index = index;
  }
  return this;
};

/**
 * Instantiate TXMeta from options.
 * @param {Object} options
 * @returns {TXMeta}
 */

TXMeta.fromTX = function fromTX(tx, entry, index) {
  return new TXMeta().fromTX(tx, entry, index);
};

/**
 * Inspect the transaction.
 * @returns {Object}
 */

TXMeta.prototype.inspect = function inspect() {
  return this.format();
};

/**
 * Inspect the transaction.
 * @returns {Object}
 */

TXMeta.prototype.format = function format(view) {
  let data = this.tx.format(view, null, this.index);
  data.ps = this.ps;
  data.height = this.height;
  data.block = this.block ? util.revHex(this.block) : null;
  data.ts = this.ts;
  return data;
};

/**
 * Convert transaction to JSON.
 * @returns {Object}
 */

TXMeta.prototype.toJSON = function toJSON() {
  return this.getJSON();
};

/**
 * Convert the transaction to an object suitable
 * for JSON serialization.
 * @param {Network} network
 * @param {CoinView} view
 * @returns {Object}
 */

TXMeta.prototype.getJSON = function getJSON(network, view) {
  let json = this.tx.getJSON(network, view, null, this.index);
  json.ps = this.ps;
  json.height = this.height;
  json.block = this.block ? util.revHex(this.block) : null;
  json.ts = this.ts;
  return json;
};

/**
 * Inject properties from a json object.
 * @private
 * @param {Object} json
 */

TXMeta.prototype.fromJSON = function fromJSON(json) {
  this.tx.fromJSON(json);

  assert(util.isNumber(json.ps));
  assert(util.isNumber(json.height));
  assert(!json.block || typeof json.block === 'string');
  assert(util.isNumber(json.ts));
  assert(util.isNumber(json.index));

  this.ps = json.ps;
  this.height = json.height;
  this.block = util.revHex(json.block);
  this.index = json.index;

  return this;
};

/**
 * Instantiate a transaction from a
 * jsonified transaction object.
 * @param {Object} json - The jsonified transaction object.
 * @returns {TX}
 */

TXMeta.fromJSON = function fromJSON(json) {
  return new TXMeta().fromJSON(JSON);
};

/**
 * Calculate serialization size.
 * @returns {Number}
 */

TXMeta.prototype.getSize = function getSize() {
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
};

/**
 * Serialize a transaction to "extended format".
 * This is the serialization format bcoin uses internally
 * to store transactions in the database. The extended
 * serialization includes the height, block hash, index,
 * timestamp, and pending-since time.
 * @returns {Buffer}
 */

TXMeta.prototype.toRaw = function toRaw() {
  let size = this.getSize();
  let bw = new StaticWriter(size);

  this.tx.toWriter(bw);

  bw.writeU32(this.ps);

  if (this.block) {
    bw.writeU8(1);
    bw.writeHash(this.block);
    bw.writeU32(this.height);
    bw.writeU32(this.ts);
    bw.writeU32(this.index);
  } else {
    bw.writeU8(0);
  }

  return bw.render();
};

/**
 * Inject properties from "extended" serialization format.
 * @private
 * @param {Buffer} data
 */

TXMeta.prototype.fromRaw = function fromRaw(data) {
  let br = new BufferReader(data);

  this.tx.fromReader(br);

  this.ps = br.readU32();

  if (br.readU8() === 1) {
    this.block = br.readHash('hex');
    this.height = br.readU32();
    this.ts = br.readU32();
    this.index = br.readU32();
    if (this.index === 0x7fffffff)
      this.index = -1;
  }

  return this;
};

/**
 * Instantiate a transaction from a Buffer
 * in "extended" serialization format.
 * @param {Buffer} data
 * @param {String?} enc - One of `"hex"` or `null`.
 * @returns {TX}
 */

TXMeta.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = Buffer.from(data, enc);
  return new TXMeta().fromRaw(data);
};

/**
 * Test whether an object is an TXMeta.
 * @param {Object} obj
 * @returns {Boolean}
 */

TXMeta.isTXMeta = function isTXMeta(obj) {
  return obj
    && Array.isArray(obj.inputs)
    && typeof obj.locktime === 'number'
    && typeof obj.ps === 'number';
};

/*
 * Expose
 */

module.exports = TXMeta;
