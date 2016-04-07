/**
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
 * Output
 */

function Output(options, tx) {
  var value;

  if (!(this instanceof Output))
    return new Output(options);

  value = options.value;

  if (typeof value === 'number') {
    assert(value % 1 === 0);
    value = new bn(value);
  }

  this.value = utils.satoshi(value || new bn(0));
  this.script = bcoin.script(options.script);
  this._mutable = !tx || (tx instanceof bcoin.mtx);

  assert(typeof value !== 'number');
  assert(!this._mutable || !this.value.isNeg());
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

Output.prototype.inspect = function inspect() {
  return {
    type: this.getType(),
    value: utils.btc(this.value),
    script: this.script,
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
    script: bcoin.script.parseScript(new Buffer(json.script, 'hex'))
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

Output.isOutput = function isOutput(obj) {
  return obj
    && obj.value
    && obj.script
    && typeof obj.getAddress === 'function';
};

/**
 * Expose
 */

return Output;
};
