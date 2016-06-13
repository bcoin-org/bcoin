/*!
 * coin.js - coin object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

var bcoin = require('./env');
var utils = require('./utils');
var assert = utils.assert;

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
  if (options instanceof Coin)
    return options;

  if (!(this instanceof Coin))
    return new Coin(options);

  assert(options, 'Coin data is required.');

  this.version = options.version;
  this.height = options.height;
  this.value = options.value;
  this.script = bcoin.script(options.script, false);
  this.coinbase = options.coinbase;
  this.hash = options.hash;
  this.index = options.index;

  assert(typeof this.version === 'number');
  assert(utils.isNumber(this.height));
  assert(typeof this.value === 'number');
  assert(this.script instanceof bcoin.script);
  assert(typeof this.coinbase === 'boolean');
  assert(!this.hash || typeof this.hash === 'string');
  assert(!this.index || typeof this.index === 'number');
}

utils.inherits(Coin, bcoin.output);

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
    script: this.script.toRaw('hex'),
    coinbase: this.coinbase,
    hash: this.hash ? utils.revHex(this.hash) : null,
    index: this.index
  };
};

/**
 * Handle a deserialized JSON coin object.
 * @returns {NakedCoin} A "naked" coin (a
 * plain javascript object which is suitable
 * for passing to the Coin constructor).
 */

Coin.parseJSON = function parseJSON(json) {
  return {
    version: json.version,
    height: json.height,
    value: utils.satoshi(json.value),
    script: bcoin.script.parseRaw(json.script, 'hex'),
    coinbase: json.coinbase,
    hash: json.hash ? utils.revHex(json.hash) : null,
    index: json.index
  };
};

/**
 * Instantiate an Coin from a jsonified coin object.
 * @param {Object} json - The jsonified coin object.
 * @returns {Coin}
 */

Coin.fromJSON = function fromJSON(json) {
  return new Coin(Coin.parseJSON(json));
};

/**
 * Serialize the coin.
 * @param {String?} enc - Encoding, can be `'hex'` or null.
 * @returns {Buffer|String}
 */

Coin.prototype.toRaw = function toRaw(enc) {
  var data = bcoin.protocol.framer.coin(this, false);

  if (enc === 'hex')
    data = data.toString('hex');

  return data;
};

/**
 * Parse a serialized coin.
 * @param {Buffer} data
 * @param {String?} enc - Encoding, can be `'hex'` or null.
 * @returns {NakedCoin} A "naked" coin object.
 */

Coin.parseRaw = function parseRaw(data, enc) {
  if (enc === 'hex')
    data = new Buffer(data, 'hex');

  return bcoin.protocol.parser.parseCoin(data, false);
};

/**
 * Instantiate an coin from a serialized Buffer.
 * @param {Buffer} data
 * @param {String?} enc - Encoding, can be `'hex'` or null.
 * @returns {Coin}
 */

Coin.fromRaw = function fromRaw(data, enc) {
  return new Coin(Coin.parseRaw(data, enc));
};

/**
 * Serialize the coin to an "extended" format,
 * including both the hash and the index.
 * @param {String?} enc - Encoding, can be `'hex'` or null.
 * @returns {Buffer|String}
 */

Coin.prototype.toExtended = function toExtended(enc) {
  var data = bcoin.protocol.framer.coin(this, true);

  if (enc === 'hex')
    data = data.toString('hex');

  return data;
};

/**
 * Parse an coin in "extended" serialization format.
 * @param {Buffer} data
 * @param {String?} enc - Encoding, can be `'hex'` or null.
 * @returns {NakedCoin} - A "naked" coin object.
 */

Coin.parseExtended = function parseExtended(data, enc) {
  if (enc === 'hex')
    data = new Buffer(data, 'hex');

  return bcoin.protocol.parser.parseCoin(data, true);
};

/**
 * Instantiate a coin from a Buffer
 * in "extended" serialization format.
 * @param {Buffer} data
 * @param {String?} enc - Encoding, can be `'hex'` or null.
 * @returns {Coin}
 */

Coin.fromExtended = function fromExtended(data, enc) {
  return new Coin(Coin.parseExtended(data, enc));
};

/**
 * Instantiate a coin from a TX
 * @param {TX} tx
 * @param {Number} index - Output index.
 * @returns {Coin}
 */

Coin.fromTX = function fromTX(tx, index) {
  return new Coin({
    version: tx.version,
    height: tx.height,
    value: tx.outputs[index].value,
    script: tx.outputs[index].script,
    coinbase: tx.isCoinbase(),
    hash: tx.hash('hex'),
    index: index
  });
};

/**
 * Test an object to see if it is a Coin.
 * @param {Object} obj
 * @returns {Boolean}
 */

Coin.isCoin = function isCoin(obj) {
  return obj
    && typeof obj.version === 'number'
    && typeof obj.script === 'object'
    && typeof obj.getConfirmations === 'function';
};

/*
 * Expose
 */

module.exports = Coin;
