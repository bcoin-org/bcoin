/**
 * output.js - output object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bn = require('bn.js');
var bcoin = require('../bcoin');
var utils = require('./utils');
var assert = utils.assert;

/**
 * Output
 */

function Output(options, tx) {
  var value;

  if (!(this instanceof Output))
    return new Output(options);

  assert(typeof options.script !== 'string');

  value = options.value;

  if (typeof value === 'number') {
    assert(value % 1 === 0);
    value = new bn(value);
  }

  this.value = utils.satoshi(value || new bn(0));
  this.script = options.script || new bcoin.script([]);
  this._size = options._size || 0;
  this._offset = options._offset || 0;
  this._mutable = !tx || (tx instanceof bcoin.mtx);

  // For safety: do not allow usage of
  // Numbers, do not allow negative values.
  assert(typeof value !== 'number');
  assert(!this.value.isNeg());
  assert(this.value.bitLength() <= 63);
  assert(!(this.value.toArray('be', 8)[0] & 0x80));
}

Output.prototype.__defineGetter__('type', function() {
  return this.getType();
});

Output.prototype.__defineGetter__('address', function() {
  return this.getAddress();
});

Output.prototype.getType = function getType() {
  var type;

  if (this._type)
    return this._type;

  type = this.script.getType();

  if (!this._mutable)
    this._type = type;

  return type;
};

Output.prototype.getAddress = function getAddress() {
  var address;

  if (this._address)
    return this._address;

  address = this.script.getAddress();

  if (!this._mutable)
    this._address = address;

  return address;
};

Output.prototype.test = function test(addressTable) {
  var address = this.getAddress();

  if (!address)
    return false;

  if (typeof addressTable === 'string')
    addressTable = [addressTable];

  if (Array.isArray(addressTable)) {
    addressTable = addressTable.reduce(function(out, address) {
      out[address] = true;
      return out;
    }, {});
  }

  if (addressTable[address] != null)
    return true;

  return false;
};

Output.prototype.getID = function getID() {
  var data = this.script.encode();
  var hash = utils.toHex(utils.ripesha(data));
  return '[' + this.type + ':' + hash.slice(0, 7) + ']';
};

Output.prototype.inspect = function inspect() {
  return {
    type: this.getType(),
    value: utils.btc(this.value),
    script: bcoin.script.format(this.script),
    address: this.getAddress()
  };
};

Output.prototype.toJSON = function toJSON() {
  return {
    value: utils.btc(this.value),
    script: utils.toHex(this.script.encode())
  };
};

Output._fromJSON = function _fromJSON(json) {
  return {
    value: utils.satoshi(json.value),
    script: new bcoin.script(new Buffer(json.script, 'hex'))
  };
};

Output.fromJSON = function fromJSON(json) {
  return new Output(Output._fromJSON(json));
};

Output.prototype.toRaw = function toRaw(enc) {
  var data = bcoin.protocol.framer.output(this);

  if (enc === 'hex')
    data = utils.toHex(data);

  return data;
};

Output._fromRaw = function _fromRaw(data, enc) {
  if (enc === 'hex')
    data = new Buffer(data, 'hex');

  data = bcoin.protocol.parser.parseOutput(data);

  return data;
};

Output.fromRaw = function fromRaw(data, enc) {
  return new Output(Output._fromRaw(data, enc));
};

/**
 * Expose
 */

module.exports = Output;
