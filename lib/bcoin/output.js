/*!
 * output.js - output object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

module.exports = function(bcoin) {

var bn = require('bn.js');
var utils = require('./utils');
var assert = utils.assert;

/**
 * Represents a transaction output.
 * @exports Output
 * @constructor
 * @param {NakedOutput} options
 * @param {Boolean?} mutable
 * @property {BN} value - Value in satoshis.
 * @property {Script} script
 * @property {String} type - Script type.
 * @property {String?} address - Input address.
 * @property {Boolean} mutable
 */

function Output(options, mutable) {
  var value;

  if (!(this instanceof Output))
    return new Output(options);

  assert(options, 'Output data is required.');

  value = options.value;

  if (typeof value === 'number') {
    assert(value % 1 === 0, 'Output value cannot be a float.');
    value = new bn(value);
  }

  this.mutable = !!mutable;
  this.value = utils.satoshi(value || new bn(0));
  this.script = bcoin.script(options.script, false);

  assert(typeof value !== 'number');
  assert(!this.mutable || !this.value.isNeg());
}

Output.prototype.__defineGetter__('type', function() {
  return this.getType();
});

Output.prototype.__defineGetter__('address', function() {
  return this.getAddress();
});

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
 * @returns {String?} address
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
 * Test the output against an address, an
 * array of addresses, or a map of addresses.
 * @param {String|String[]|Object} addressMap
 * @returns {Boolean} Whether the output matched.
 */

Output.prototype.test = function test(addressMap) {
  var address = this.getAddress();

  if (!address)
    return false;

  if (typeof addressMap === 'string')
    return address === addressMap;

  if (Array.isArray(addressMap))
    return addressMap.indexOf(address) !== -1;

  if (addressMap[address] != null)
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
    script: this.script.toRaw('hex')
  };
};

/**
 * Handle a deserialized JSON output object.
 * @returns {NakedOutput} A "naked" output (a
 * plain javascript object which is suitable
 * for passing to the Output constructor).
 */

Output.parseJSON = function parseJSON(json) {
  return {
    value: utils.satoshi(json.value),
    script: bcoin.script.parseRaw(json.script, 'hex')
  };
};

/**
 * Instantiate an Output from a jsonified output object.
 * @param {Object} json - The jsonified output object.
 * @returns {Output}
 */

Output.fromJSON = function fromJSON(json) {
  return new Output(Output.parseJSON(json));
};

/**
 * Serialize the output.
 * @param {String?} enc - Encoding, can be `'hex'` or null.
 * @returns {Buffer|String}
 */

Output.prototype.toRaw = function toRaw(enc) {
  var data = bcoin.protocol.framer.output(this);

  if (enc === 'hex')
    data = data.toString('hex');

  return data;
};

/**
 * Parse a serialized output.
 * @param {Buffer} data
 * @param {String?} enc - Encoding, can be `'hex'` or null.
 * @returns {NakedOutput} A "naked" output object.
 */

Output.parseRaw = function parseRaw(data, enc) {
  if (enc === 'hex')
    data = new Buffer(data, 'hex');

  data = bcoin.protocol.parser.parseOutput(data);

  return data;
};

/**
 * Instantiate an output from a serialized Buffer.
 * @param {Buffer} data
 * @param {String?} enc - Encoding, can be `'hex'` or null.
 * @returns {Output}
 */

Output.fromRaw = function fromRaw(data, enc) {
  return new Output(Output.parseRaw(data, enc));
};

/**
 * Test an object to see if it is an Output.
 * @param {Object} obj
 * @returns {Boolean}
 */

Output.isOutput = function isOutput(obj) {
  return obj
    && obj.value
    && obj.script
    && typeof obj.getAddress === 'function';
};

return Output;
};
