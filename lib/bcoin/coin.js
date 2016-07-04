/*!
 * coin.js - coin object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var bcoin = require('./env');
var utils = require('./utils');
var constants = bcoin.protocol.constants;
var assert = utils.assert;
var Output = bcoin.output;

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
  this.script = new bcoin.script();
  this.coinbase = true;
  this.hash = constants.NULL_HASH;
  this.index = 0;

  if (options)
    this.fromOptions(options);
}

utils.inherits(Coin, Output);

/**
 * Inject options into coin.
 * @private
 * @param {Object} options
 */

Coin.prototype.fromOptions = function fromOptions(options) {
  assert(options, 'Coin data is required.');
  assert(utils.isNumber(options.version));
  assert(utils.isNumber(options.height));
  assert(utils.isNumber(options.value));
  assert(typeof options.coinbase === 'boolean');
  assert(options.hash == null || typeof options.hash === 'string');
  assert(options.index == null || utils.isNumber(options.index));

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
  if (height == null)
    height = bcoin.network.get().height;

  if (this.height === -1)
    return 0;

  if (height < this.height)
    return 1;

  return height - this.height + 1;
};

/**
 * Calculate coin age. This is slightly different from
 * confirmations. If the confirmations are incalculable,
 * age is zero. If the age is non-zero, 1 is added to the age.
 * @param {Number?} height - Current chain height. Network
 * height is used if not passed in.
 * @returns {Number} age
 */

Coin.prototype.getAge = function getAge(height) {
  var age = this.getConfirmations(height);

  if (age === -1)
    age = 0;

  if (age !== 0)
    age += 1;

  return age;
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
    value: utils.btc(this.value),
    script: this.script,
    coinbase: this.coinbase,
    hash: this.hash ? utils.revHex(this.hash) : null,
    index: this.index,
    age: this.getAge(),
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

Coin.prototype.toJSON = function toJSON() {
  return {
    version: this.version,
    height: this.height,
    value: utils.btc(this.value),
    script: this.script.toJSON(),
    coinbase: this.coinbase,
    hash: this.hash ? utils.revHex(this.hash) : null,
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
  assert(utils.isNumber(json.version));
  assert(utils.isNumber(json.height));
  assert(typeof json.value === 'string');
  assert(typeof json.coinbase === 'boolean');
  assert(!json.hash || typeof json.hash === 'string');
  assert(!json.index || utils.isNumber(json.index));

  this.version = json.version;
  this.height = json.height;
  this.value = utils.satoshi(json.value);
  this.script.fromJSON(json.script);
  this.coinbase = json.coinbase;
  this.hash = json.hash ? utils.revHex(json.hash) : null;
  this.index = json.index;

  return this;
};

/**
 * Serialize the coin.
 * @param {String?} enc - Encoding, can be `'hex'` or null.
 * @returns {Buffer|String}
 */

Coin.prototype.toRaw = function toRaw(writer) {
  var p = bcoin.writer(writer);
  var height = this.height;

  if (height === -1)
    height = 0x7fffffff;

  p.writeU32(this.version);
  p.writeU32(height);
  p.write64(this.value);
  p.writeVarBytes(this.script.toRaw());
  p.writeU8(this.coinbase ? 1 : 0);

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

Coin.prototype.fromRaw = function fromRaw(data) {
  var p = bcoin.reader(data);

  this.version = p.readU32();
  this.height = p.readU32();
  this.value = p.read64N();
  this.script.fromRaw(p.readVarBytes());
  this.coinbase = p.readU8() === 1;

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
 * Serialize the coin to an "extended" format,
 * including both the hash and the index.
 * @param {String?} enc - Encoding, can be `'hex'` or null.
 * @returns {Buffer|String}
 */

Coin.prototype.toExtended = function toExtended(writer) {
  var p = bcoin.writer(writer);

  this.toRaw(p);
  p.writeHash(this.hash);
  p.writeU32(this.index);

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Inject properties from extended serialized data.
 * @private
 * @param {Buffer} data
 */

Coin.prototype.fromExtended = function fromExtended(data) {
  var p = bcoin.reader(data);
  this.fromRaw(p);
  this.hash = p.readHash('hex');
  this.index = p.readU32();
  return this;
};

/**
 * Instantiate a coin from a Buffer
 * in "extended" serialization format.
 * @param {Buffer} data
 * @param {String?} enc - Encoding, can be `'hex'` or null.
 * @returns {Coin}
 */

Coin.fromExtended = function fromExtended(data, enc) {
  if (typeof data === 'string')
    data = new Buffer(data, enc);
  return new Coin().fromExtended(data);
};

/**
 * Inject properties from TX.
 * @param {TX} tx
 * @param {Number} index
 */

Coin.prototype.fromTX = function fromTX(tx, index) {
  assert(utils.isNumber(index));
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
