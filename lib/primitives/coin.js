/*!
 * coin.js - coin object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var util = require('../utils/util');
var constants = require('../protocol/constants');
var Network = require('../protocol/network');
var Amount = require('../btc/amount');
var Output = require('./output');
var Script = require('../script/script');
var Network = require('../protocol/network');
var BufferWriter = require('../utils/writer');
var BufferReader = require('../utils/reader');
var compressor = require('../blockchain/compress');
var compress = compressor.compress;
var decompress = compressor.decompress;

/**
 * Represents an unspent output.
 * @exports Coin
 * @constructor
 * @extends Output
 * @param {NakedCoin|Coin} options
 * @property {Number} version - Transaction version.
 * @property {Number} height - Transaction height (-1 if unconfirmed).
 * @property {Amount} value - Output value in satoshis.
 * @property {Script} script - Output script.
 * @property {Boolean} coinbase - Whether the containing
 * transaction is a coinbase.
 * @property {Hash} hash - Transaction hash.
 * @property {Number} index - Output index.
 */

function Coin(options) {
  if (!(this instanceof Coin))
    return new Coin(options);

  this.version = 1;
  this.height = -1;
  this.value = 0;
  this.script = new Script();
  this.coinbase = true;
  this.hash = constants.NULL_HASH;
  this.index = 0;

  if (options)
    this.fromOptions(options);
}

util.inherits(Coin, Output);

/**
 * Inject options into coin.
 * @private
 * @param {Object} options
 */

Coin.prototype.fromOptions = function fromOptions(options) {
  assert(options, 'Coin data is required.');
  assert(util.isNumber(options.version));
  assert(util.isNumber(options.height));
  assert(util.isNumber(options.value));
  assert(typeof options.coinbase === 'boolean');
  assert(options.hash == null || typeof options.hash === 'string');
  assert(options.index == null || util.isNumber(options.index));

  this.version = options.version;
  this.height = options.height;
  this.value = options.value;

  if (options.script)
    this.script.fromOptions(options.script);

  this.coinbase = options.coinbase;
  this.hash = options.hash;
  this.index = options.index;

  return this;
};

/**
 * Instantiate Coin from options object.
 * @private
 * @param {Object} options
 */

Coin.fromOptions = function fromOptions(options) {
  return new Coin().fromOptions(options);
};

/**
 * Calculate number of confirmations since coin was created.
 * @param {Number?} height - Current chain height. Network
 * height is used if not passed in.
 * @return {Number}
 */

Coin.prototype.getConfirmations = function getConfirmations(height) {
  assert(typeof height === 'number', 'Must pass a height.');

  if (this.height === -1)
    return 0;

  if (height < this.height)
    return 0;

  return height - this.height + 1;
};

/**
 * Convert the coin to a more user-friendly object.
 * @returns {Object}
 */

Coin.prototype.inspect = function inspect() {
  return {
    type: this.getType(),
    version: this.version,
    height: this.height,
    value: Amount.btc(this.value),
    script: this.script,
    coinbase: this.coinbase,
    hash: this.hash ? util.revHex(this.hash) : null,
    index: this.index,
    address: this.getAddress()
  };
};

/**
 * Convert the coin to an object suitable
 * for JSON serialization. Note that the hash
 * will be reversed to abide by bitcoind's legacy
 * of little-endian uint256s.
 * @returns {Object}
 */

Coin.prototype.toJSON = function toJSON(network) {
  var address = this.getAddress();

  network = Network.get(network);

  if (address)
    address = address.toBase58(network);

  return {
    version: this.version,
    height: this.height,
    value: Amount.btc(this.value),
    script: this.script.toJSON(),
    address: address,
    coinbase: this.coinbase,
    hash: this.hash ? util.revHex(this.hash) : null,
    index: this.index
  };
};

/**
 * Instantiate an Coin from a jsonified coin object.
 * @param {Object} json - The jsonified coin object.
 * @returns {Coin}
 */

Coin.fromJSON = function fromJSON(json) {
  return new Coin().fromJSON(json);
};

/**
 * Inject JSON properties into coin.
 * @private
 * @param {Object} json
 */

Coin.prototype.fromJSON = function fromJSON(json) {
  assert(json, 'Coin data required.');
  assert(util.isNumber(json.version));
  assert(util.isNumber(json.height));
  assert(typeof json.value === 'string');
  assert(typeof json.coinbase === 'boolean');
  assert(!json.hash || typeof json.hash === 'string');
  assert(!json.index || util.isNumber(json.index));

  this.version = json.version;
  this.height = json.height;
  this.value = Amount.value(json.value);
  this.script.fromJSON(json.script);
  this.coinbase = json.coinbase;
  this.hash = json.hash ? util.revHex(json.hash) : null;
  this.index = json.index;

  return this;
};

/**
 * Serialize the coin.
 * @param {String?} enc - Encoding, can be `'hex'` or null.
 * @returns {Buffer|String}
 */

Coin.prototype.toRaw = function toRaw(writer) {
  var bw = BufferWriter(writer);
  var height = this.height;

  if (height === -1)
    height = 0x7fffffff;

  bw.writeU32(this.version);
  bw.writeU32(height);
  bw.write64(this.value);
  bw.writeVarBytes(this.script.toRaw());
  bw.writeU8(this.coinbase ? 1 : 0);

  if (!writer)
    bw = bw.render();

  return bw;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

Coin.prototype.fromRaw = function fromRaw(data) {
  var br = BufferReader(data);

  this.version = br.readU32();
  this.height = br.readU32();
  this.value = br.read64N();
  this.script.fromRaw(br.readVarBytes());
  this.coinbase = br.readU8() === 1;

  if (this.height === 0x7fffffff)
    this.height = -1;

  return this;
};

/**
 * Instantiate an coin from a serialized Buffer.
 * @param {Buffer} data
 * @param {String?} enc - Encoding, can be `'hex'` or null.
 * @returns {Coin}
 */

Coin.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = new Buffer(data, enc);
  return new Coin().fromRaw(data);
};

/**
 * Serialize the coin to its compressed form.
 * @param {String?} enc - Encoding, can be `'hex'` or null.
 * @returns {Buffer|String}
 */

Coin.prototype.toCompressed = function toCompressed(writer) {
  var bw = BufferWriter(writer);
  var height = this.height;
  var bits;

  if (height === -1)
    height = 0x7fffffff;

  bits = height << 1;

  if (this.coinbase)
    bits |= 1;

  if (bits < 0)
    bits += 0x100000000;

  bw.writeVarint(this.version);
  bw.writeU32(bits);
  bw.writeVarint(this.value);
  compress.script(this.script, bw);

  if (!writer)
    bw = bw.render();

  return bw;
};

/**
 * Inject properties from compressed serialized data.
 * @private
 * @param {Buffer} data
 */

Coin.prototype.fromCompressed = function fromCompressed(data) {
  var br = BufferReader(data);
  var bits;

  this.version = br.readVarint();
  bits = br.readU32();
  this.height = bits >>> 1;
  this.coinbase = (bits & 1) !== 0;
  this.value = br.readVarint();
  decompress.script(this.script, br);

  if (this.height === 0x7fffffff)
    this.height = -1;

  return this;
};

/**
 * Instantiate an coin from a serialized Buffer.
 * @param {Buffer} data
 * @param {String?} enc - Encoding, can be `'hex'` or null.
 * @returns {Coin}
 */

Coin.fromCompressed = function fromCompressed(data, enc) {
  if (typeof data === 'string')
    data = new Buffer(data, enc);
  return new Coin().fromCompressed(data);
};

/**
 * Inject properties from TX.
 * @param {TX} tx
 * @param {Number} index
 */

Coin.prototype.fromTX = function fromTX(tx, index) {
  assert(util.isNumber(index));
  this.version = tx.version;
  this.height = tx.height;
  this.value = tx.outputs[index].value;
  this.script = tx.outputs[index].script;
  this.coinbase = tx.isCoinbase();
  this.hash = tx.hash('hex');
  this.index = index;
  return this;
};

/**
 * Instantiate a coin from a TX
 * @param {TX} tx
 * @param {Number} index - Output index.
 * @returns {Coin}
 */

Coin.fromTX = function fromTX(tx, index) {
  return new Coin().fromTX(tx, index);
};

/**
 * Test an object to see if it is a Coin.
 * @param {Object} obj
 * @returns {Boolean}
 */

Coin.isCoin = function isCoin(obj) {
  return obj
    && obj.version !== undefined
    && obj.script !== undefined
    && typeof obj.getConfirmations === 'function';
};

/*
 * Expose
 */

module.exports = Coin;
