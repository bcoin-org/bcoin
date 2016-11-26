/*!
 * output.js - output object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var util = require('../utils/util');
var constants = require('../protocol/constants');
var btcutils = require('../btc/utils');
var Amount = require('../btc/amount');
var Network = require('../protocol/network');
var Script = require('../script/script');
var BufferWriter = require('../utils/writer');
var BufferReader = require('../utils/reader');
var assert = require('assert');

/**
 * Represents a transaction output.
 * @exports Output
 * @constructor
 * @param {NakedOutput} options
 * @property {Amount} value - Value in satoshis.
 * @property {Script} script
 */

function Output(options) {
  if (!(this instanceof Output))
    return new Output(options);

  this.value = 0;
  this.script = new Script();
  this.mutable = false;
  this._address = null;

  if (options)
    this.fromOptions(options);
}

/**
 * Inject properties from options object.
 * @private
 * @param {NakedOutput} options
 */

Output.prototype.fromOptions = function fromOptions(options) {
  assert(options, 'Output data is required.');

  if (options.value) {
    assert(util.isNumber(options.value));
    this.value = options.value;
  }

  if (options.script)
    this.script.fromOptions(options.script);

  if (options.address)
    this.script.fromAddress(options.address);

  return this;
};

/**
 * Instantiate output from options object.
 * @param {NakedOutput} options
 * @returns {Output}
 */

Output.fromOptions = function fromOptions(options) {
  return new Output().fromOptions(options);
};

/**
 * Get the script type as a string.
 * @returns {ScriptType} type
 */

Output.prototype.getType = function getType() {
  return constants.scriptTypesByVal[this.script.getType()].toLowerCase();
};

/**
 * Get the address.
 * @returns {Address} address
 */

Output.prototype.getAddress = function getAddress() {
  var address = this._address;

  if (!address) {
    address = this.script.getAddress();
    if (!this.mutable)
      this._address = address;
  }

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
 * Convert the input to a more user-friendly object.
 * @returns {Object}
 */

Output.prototype.inspect = function inspect() {
  return {
    type: this.getType(),
    value: Amount.btc(this.value),
    script: this.script,
    address: this.getAddress()
  };
};

/**
 * Convert the output to an object suitable
 * for JSON serialization.
 * @returns {Object}
 */

Output.prototype.toJSON = function toJSON(network) {
  var address = this.getAddress();

  network = Network.get(network);

  if (address)
    address = address.toBase58(network);

  return {
    value: Amount.btc(this.value),
    script: this.script.toJSON(),
    address: address
  };
};

/**
 * Calculate the dust threshold for this
 * output, based on serialize size and rate.
 * @param {Rate?} rate
 * @returns {Amount}
 */

Output.prototype.getDustThreshold = function getDustThreshold(rate) {
  var scale = constants.WITNESS_SCALE_FACTOR;
  var size;

  if (rate == null)
    rate = constants.tx.MIN_RELAY;

  if (this.script.isUnspendable())
    return 0;

  size = this.getSize();

  if (this.script.isProgram()) {
    // 75% segwit discount applied to script size.
    size += 32 + 4 + 1 + (107 / scale | 0) + 4;
  } else {
    size += 32 + 4 + 1 + 107 + 4;
  }

  return 3 * btcutils.getMinFee(size, rate);
};

/**
 * Calculate size of serialized output.
 * @returns {Number}
 */

Output.prototype.getSize = function getSize() {
  return this.toRaw(BufferWriter()).written;
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
  assert(typeof json.value === 'string');
  this.value = Amount.value(json.value);
  this.script.fromJSON(json.script);
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
  var bw = BufferWriter(writer);

  bw.write64(this.value);
  bw.writeVarBytes(this.script.toRaw());

  if (!writer)
    bw = bw.render();

  return bw;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

Output.prototype.fromRaw = function fromRaw(data) {
  var br = BufferReader(data);

  this.value = br.read64N();
  this.script.fromRaw(br.readVarBytes());

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
