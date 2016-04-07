/**
 * input.js - input object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

module.exports = function(bcoin) {

var utils = require('./utils');
var assert = utils.assert;
var constants = bcoin.protocol.constants;
var BufferReader = require('./reader');
var BufferWriter = require('./writer');

/**
 * Input
 */

function Input(options, tx) {
  if (!(this instanceof Input))
    return new Input(options);

  this.prevout = options.prevout;
  this.script = bcoin.script(options.script);
  this.sequence = options.sequence == null ? 0xffffffff : options.sequence;
  this.witness = bcoin.script.witness(options.witness);
  this._mutable = !tx || (tx instanceof bcoin.mtx);

  if (options.coin)
    this.coin = bcoin.coin(options.coin);

  if (Buffer.isBuffer(this.prevout.hash))
    this.prevout.hash = utils.toHex(this.prevout.hash);

  assert(typeof this.prevout.hash === 'string');
  assert(typeof this.prevout.index === 'number');
}

Input.prototype.__defineGetter__('type', function() {
  return this.getType();
});

Input.prototype.__defineGetter__('address', function() {
  return this.getAddress();
});

Input.prototype.getType = function getType() {
  var type;

  if (this.isCoinbase())
    return 'coinbase';

  if (this.coin)
    return this.coin.getType();

  if (this._type)
    return this._type;

  if (this.witness.items.length > 0)
    type = this.witness.getInputType();

  if (!type || type === 'unknown')
    type = this.script.getInputType();

  if (!this._mutable)
    this._type = type;

  return type;
};

Input.prototype.getRedeem = function getRedeem() {
  var redeem = this.script;
  var type;

  if (this.isCoinbase())
    return;

  type = this.getType();

  if (type === 'scripthash') {
    redeem = redeem.getRedeem();
    if (!redeem)
      return;
  }

  if (redeem.isWitnessScripthash())
    redeem = this.witness.getRedeem();

  return redeem;
};

Input.prototype.getSubtype = function getSubtype() {
  var redeem;

  if (this.isCoinbase())
    return;

  redeem = this.getRedeem();

  if (!redeem)
    return;

  return redeem.getType();
};

Input.prototype.getAddress = function getAddress() {
  var address;

  if (this.isCoinbase())
    return;

  if (this.coin)
    return this.coin.getAddress();

  if (this._address)
    return this._address;

  if (this.witness.items.length > 0)
    address = this.witness.getInputAdddress();

  if (!address)
    address = this.script.getInputAddress();

  if (!this._mutable)
    this._address = address;

  return address;
};

Input.prototype.isFinal = function isFinal() {
  return this.sequence === 0xffffffff;
};

Input.prototype.isCoinbase = function isCoinbase() {
  return this.prevout.hash === constants.nullHash;
};

Input.prototype.test = function test(addressMap) {
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

Input.prototype.inspect = function inspect() {
  var coin;

  if (this.coin) {
    coin = this.coin;
  } else {
    coin = {
      type: 'unknown',
      version: 1,
      height: -1,
      value: '0.0',
      script: '',
      coinbase: false,
      hash: this.prevout.hash,
      index: this.prevout.index,
      age: 0,
      address: null
    };
  }

  return {
    type: this.getType(),
    subtype: this.getSubtype(),
    address: this.getAddress(),
    value: utils.btc(coin.value),
    script: this.script,
    witness: this.witness,
    redeem: this.getRedeem(),
    sequence: this.sequence,
    coin: coin
  };
};

Input.prototype.toJSON = function toJSON() {
  return {
    prevout: {
      hash: utils.revHex(this.prevout.hash),
      index: this.prevout.index
    },
    coin: this.coin ? this.coin.toJSON() : null,
    script: utils.toHex(this.script.encode()),
    witness: utils.toHex(bcoin.protocol.framer.witness(this.witness)),
    sequence: this.sequence
  };
};

Input._fromJSON = function _fromJSON(json) {
  return {
    prevout: {
      hash: utils.revHex(json.prevout.hash),
      index: json.prevout.index
    },
    coin: json.coin ? bcoin.coin._fromJSON(json.coin) : null,
    script: bcoin.script.parseScript(new Buffer(json.script, 'hex')),
    witness: bcoin.protocol.parser.parseWitness(new Buffer(json.witness, 'hex')),
    sequence: json.sequence
  };
};

Input.fromJSON = function fromJSON(json) {
  return new Input(Input._fromJSON(json));
};

Input.prototype.toRaw = function toRaw(enc) {
  var data = bcoin.protocol.framer.input(this);

  if (enc === 'hex')
    data = utils.toHex(data);

  return data;
};

Input._fromRaw = function _fromRaw(data, enc) {
  if (enc === 'hex')
    data = new Buffer(data, 'hex');

  data = bcoin.protocol.parser.parseInput(data);

  return data;
};

Input.fromRaw = function fromRaw(data, enc) {
  return new Input(Input._fromRaw(data, enc));
};

Input.prototype.toExtended = function toExtended(enc) {
  var p = new BufferWriter();
  var data;

  bcoin.protocol.framer.input(this, p);
  bcoin.protocol.framer.witness(this.witness, p);

  data = p.render();

  if (enc === 'hex')
    data = utils.toHex(data);

  return data;
};

Input._fromExtended = function _fromExtended(data, enc) {
  var input, p;

  if (enc === 'hex')
    data = new Buffer(data, 'hex');

  p = new BufferReader(data);
  p.start();
  input = bcoin.protocol.parser.parseInput(p);
  input.witness = bcoin.protocol.parser.parseWitness(p);
  p.end();

  return input;
};

Input.fromExtended = function fromExtended(data, enc) {
  return new Input(Input._fromExtended(data, enc));
};

Input.isInput = function isInput(obj) {
  return obj
    && obj.prevout
    && obj.script
    && obj.witness
    && typeof obj.getAddress === 'function';
};

/**
 * Expose
 */

return Input;
};
