/**
 * input.js - input object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bcoin = require('../bcoin');
var utils = bcoin.utils;
var assert = utils.assert;
var constants = bcoin.protocol.constants;

/**
 * Input
 */

function Input(options, tx) {
  if (!(this instanceof Input))
    return new Input(options);

  assert(typeof options.script !== 'string');

  this.prevout = options.prevout;
  this.script = options.script || new bcoin.script([]);
  this.sequence = options.sequence == null ? 0xffffffff : options.sequence;
  this.witness = options.witness || new bcoin.script.witness([]);
  this._size = options._size || 0;
  this._offset = options._offset || 0;
  this._witnessSize = options._witnessSize || 0;
  this._witnessOffset = options._witnessOffset || 0;
  this._mutable = !tx || (tx instanceof bcoin.mtx);

  if (options.output)
    this.output = bcoin.coin(options.output);

  if (Buffer.isBuffer(this.prevout.hash))
    this.prevout.hash = utils.toHex(this.prevout.hash);
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

  if (this.output)
    return this.output.getType();

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
  var type, redeem;

  if (this.isCoinbase())
    return;

  type = this.getType();

  if (type === 'witnessscripthash')
    return this.witness.getRedeem();

  if (type === 'scripthash') {
    redeem = this.script.getRedeem();
    if (!redeem)
      return;
    if (redeem.isWitnessScripthash())
      return this.witness.getRedeem();
    return redeem;
  }
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

  if (this.output)
    return this.output.getAddress();

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

Input.prototype.isRBF = function isRBF() {
  return this.sequence === 0xffffffff - 1;
};

Input.prototype.isFinal = function isFinal() {
  return this.sequence === 0xffffffff;
};

Input.prototype.getLocktime = function getLocktime() {
  var output, redeem;

  assert(this.output);

  output = this.output;
  redeem = output.script;

  if (redeem.isScripthash())
    redeem = this.script.getRedeem();

  if (redeem[1] !== 'checklocktimeverify')
    return;

  return redeem.getLocktime();
};

Input.prototype.isCoinbase = function isCoinbase() {
  return +this.prevout.hash === 0;
};

Input.prototype.test = function test(addressTable) {
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

Input.prototype.getID = function getID() {
  var data = this.script.encode();
  var hash = utils.toHex(utils.ripesha(data));
  return '[' + this.type + ':' + hash.slice(0, 7) + ']';
};

Input.prototype.inspect = function inspect() {
  var redeem = this.getRedeem();
  var output;

  if (this.output) {
    output = this.output.inspect();
  } else {
    output = {
      type: 'unknown',
      version: 1,
      height: -1,
      value: '0.0',
      script: '',
      hash: this.prevout.hash,
      index: this.prevout.index,
      spent: false,
      address: null
    };
  }

  return {
    type: this.getType(),
    subtype: this.getSubtype(),
    address: this.getAddress(),
    value: utils.btc(output.value),
    script: bcoin.script.format(this.script),
    witness: bcoin.script.format(this.witness),
    redeem: redeem ? bcoin.script.format(redeem) : null,
    sequence: this.sequence,
    output: output
  };
};

Input.prototype.toJSON = function toJSON() {
  return {
    prevout: {
      hash: utils.revHex(this.prevout.hash),
      index: this.prevout.index
    },
    output: this.output ? this.output.toJSON() : null,
    script: utils.toHex(this.script.encode()),
    witness: utils.toHex(this.witness.encode()),
    sequence: this.sequence
  };
};

Input._fromJSON = function _fromJSON(json) {
  return {
    prevout: {
      hash: utils.revHex(json.prevout.hash),
      index: json.prevout.index
    },
    output: json.output ? bcoin.coin._fromJSON(json.output) : null,
    script: new bcoin.script(new Buffer(json.script, 'hex')),
    witness: new bcoin.script.witness(new Buffer(json.witness, 'hex')),
    sequence: json.sequence
  };
};

Input.fromJSON = function fromJSON(json) {
  return new Input(Input._fromJSON(json));
};

// NOTE: We cannot encode the witness here.
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
  var input = bcoin.protocol.framer.input(this);
  var witness = this.witness.encode();
  var data = new Buffer(data.length + witness.length);
  var off = 0;

  off += utils.copy(input, data, off);
  off += utils.copy(witness, data, off);

  if (enc === 'hex')
    data = utils.toHex(data);

  return data;
};

Input._fromExtended = function _fromExtended(data, enc) {
  var input;

  if (enc === 'hex')
    data = new Buffer(data, 'hex');

  input = bcoin.protocol.parser.parseInput(data);
  input.witness = bcoin.protocol.parser.parseWitness(data.slice(input._size));

  return input;
};

Input.fromExtended = function fromExtended(data, enc) {
  return new Input(Input._fromExtended(data, enc));
};

/**
 * Expose
 */

module.exports = Input;
