/*!
 * output.js - output object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var bcoin = require('./env');
var utils = require('./utils');
var constants = bcoin.protocol.constants;
var assert = utils.assert;

/**
 * Represents a transaction output.
 * @exports Output
 * @constructor
 * @param {NakedOutput} options
 * @param {Boolean?} mutable
 * @property {Amount} value - Value in satoshis.
 * @property {Script} script
 * @property {String} type - Script type.
 * @property {String?} address - Input address.
 * @property {Boolean} mutable
 */

function Output(options, mutable) {
  if (!(this instanceof Output))
    return new Output(options, mutable);

  this.mutable = false;
  this.value = null;
  this.script = null;

  if (options)
    this.fromOptions(options, mutable);
}

/**
 * Inject properties from options object.
 * @private
 * @param {NakedOutput} options
 * @param {Boolean} mutable
 */

Output.prototype.fromOptions = function fromOptions(options, mutable) {
  assert(options, 'Output data is required.');
  assert(!options.value || utils.isNumber(options.value));
  assert(!mutable || options.value >= 0);

  this.mutable = !!mutable;
  this.value = options.value || 0;
  this.script = bcoin.script(options.script);

  return this;
};

/**
 * Instantiate output from options object.
 * @param {NakedOutput} options
 * @param {Boolean} mutable
 * @returns {Output}
 */

Output.fromOptions = function fromOptions(options, mutable) {
  return new Output().fromOptions(options, mutable);
};

/**
 * Get the script type.
 * @returns {String} type
 */

Output.prototype.getType = function getType() {
  var type;

  if (this._type)
    return this._type;

  type = this.script.getType();

  if (!this.mutable)
    this._type = type;

  return type;
};

/**
 * Get the address.
 * @returns {Address} address
 */

Output.prototype.getAddress = function getAddress() {
  var address;

  if (this._address)
    return this._address;

  address = this.script.getAddress();

  if (!this.mutable)
    this._address = address;

  return address;
};

/**
 * Get the address hash.
 * @param {String?} enc
 * @returns {Hash} hash
 */

Output.prototype.getHash = function getHash(enc) {
  var address = this.getAddress();
  if (!address)
    return;
  return address.getHash(enc);
};

/**
 * Test the output against an address, an
 * array of addresses, or a map of addresses.
 * @param {Hash|Hash[]|AddressHashMap} addressMap
 * @returns {Boolean} Whether the output matched.
 */

Output.prototype.test = function test(addressMap) {
  var hash = this.getHash('hex');

  if (!hash)
    return false;

  if (typeof addressMap === 'string')
    return hash === addressMap;

  if (Array.isArray(addressMap))
    return addressMap.indexOf(hash) !== -1;

  if (addressMap[hash] != null)
    return true;

  return false;
};

/**
 * Convert the input to a more user-friendly object.
 * @returns {Object}
 */

Output.prototype.inspect = function inspect() {
  return {
    type: this.getType(),
    value: utils.btc(this.value),
    script: this.script,
    address: this.getAddress()
  };
};

/**
 * Convert the output to an object suitable
 * for JSON serialization.
 * @returns {Object}
 */

Output.prototype.toJSON = function toJSON() {
  return {
    value: utils.btc(this.value),
    script: this.script.toJSON()
  };
};

/**
 * Calculate the dust threshold for this
 * output, based on serialize size and rate.
 * @param {Rate?} rate
 * @returns {Amount}
 */

Output.prototype.getDustThreshold = function getDustThreshold(rate) {
  var size;

  if (rate == null)
    rate = constants.tx.MIN_RELAY;

  if (this.script.isUnspendable())
    return 0;

  size = this.getSize() + 148;

  return 3 * bcoin.tx.getMinFee(size, rate);
};

/**
 * Calculate size of serialized output.
 * @returns {Number}
 */

Output.prototype.getSize = function getSize() {
  return this.toRaw(bcoin.writer()).written;
};

/**
 * Test whether the output should be considered dust.
 * @param {Rate?} rate
 * @returns {Boolean}
 */

Output.prototype.isDust = function isDust(rate) {
  return this.value < this.getDustThreshold(rate);
};

/**
 * Inject properties from a JSON object.
 * @private
 * @param {Object} json
 */

Output.prototype.fromJSON = function fromJSON(json) {
  this.value = utils.satoshi(json.value);
  this.script = bcoin.script.fromJSON(json.script);
  return this;
};

/**
 * Instantiate an Output from a jsonified output object.
 * @param {Object} json - The jsonified output object.
 * @returns {Output}
 */

Output.fromJSON = function fromJSON(json) {
  return new Output().fromJSON(json);
};

/**
 * Serialize the output.
 * @param {String?} enc - Encoding, can be `'hex'` or null.
 * @returns {Buffer|String}
 */

Output.prototype.toRaw = function toRaw(writer) {
  var p = bcoin.writer(writer);

  p.write64(this.value);
  p.writeVarBytes(this.script.toRaw());

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

Output.prototype.fromRaw = function fromRaw(data) {
  var p = bcoin.reader(data);

  this.value = p.read64N();
  this.script = bcoin.script.fromRaw(p.readVarBytes());

  return this;
};

/**
 * Instantiate an output from a serialized Buffer.
 * @param {Buffer} data
 * @param {String?} enc - Encoding, can be `'hex'` or null.
 * @returns {Output}
 */

Output.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = new Buffer(data, enc);

  return new Output().fromRaw(data);
};

/**
 * Test an object to see if it is an Output.
 * @param {Object} obj
 * @returns {Boolean}
 */

Output.isOutput = function isOutput(obj) {
  return obj
    && obj.value !== undefined
    && obj.script !== undefined
    && typeof obj.getAddress === 'function';
};

/*
 * Expose
 */

module.exports = Output;
