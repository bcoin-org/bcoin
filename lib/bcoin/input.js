/**
 * input.js - input object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bn = require('bn.js');
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
  this.script = options.script || [];
  this.sequence = options.sequence == null ? 0xffffffff : options.sequence;
  this.witness = options.witness || [];
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

  if (this.witness.length > 0)
    type = bcoin.script.getInputType(this.witness, null, true);

  if (!type || type === 'unknown')
    type = bcoin.script.getInputType(this.script);

  if (!this._mutable)
    this._type = type;

  return type;
};

Input.prototype.getRedeem = function getRedeem() {
  var type;

  if (this.isCoinbase())
    return;

  type = this.getType();

  if (type === 'witnessscripthash')
    return bcoin.script.getRedeem(this.witness);

  if (type === 'scripthash') {
    redeem = bcoin.script.getRedeem(this.script);
    if (bcoin.script.isWitnessScripthash(redeem))
      return bcoin.script.getRedeem(this.witness);
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

  return bcoin.script.getOutputType(redeem);
};

Input.prototype.getAddress = function getAddress() {
  var address;

  if (this.isCoinbase())
    return;

  if (this.output)
    return this.output.getAddress();

  if (this._address)
    return this._address;

  if (this.witness.length > 0)
    address = bcoin.script.getInputAddress(this.witness, null, true);

  if (!address)
    address = bcoin.script.getInputAddress(this.script);

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
  var output, redeem, lock, type;

  assert(this.output);

  output = this.output;
  redeem = output.script;

  if (bcoin.script.isScripthash(redeem))
    redeem = bcoin.script.getRedeem(this.script);

  if (redeem[1] !== 'checklocktimeverify')
    return;

  return bcoin.script.getLocktime(redeem);
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

Input.prototype.getSigops = function getSigops(scriptHash, accurate) {
  var n = bcoin.script.getSigops(this.script, accurate);
  if (scriptHash && !this.isCoinbase())
    n += bcoin.script.getScripthashSigops(this.script);
  return n;
};

Input.prototype.getID = function getID() {
  var data = bcoin.script.encode(this.script);
  var hash = utils.toHex(utils.ripesha(data));
  return '[' + this.type + ':' + hash.slice(0, 7) + ']';
};

Input.prototype.getData = function getData() {
  var def, data;

  assert(this instanceof Input);

  def = {
    side: 'input',
    value: new bn(0),
    script: this.script,
    sequence: this.sequence
  };

  def.prev = this.prevout.hash;
  def.index = this.prevout.index;

  if (this.isCoinbase()) {
    data = bcoin.script.getCoinbaseData(this.script);
    return utils.merge(def, data, {
      type: 'coinbase',
      none: true
    });
  }

  if (this.output) {
    data = bcoin.script.getInputData(this.script, this.output.script);
    data.value = this.output.value;
    return utils.merge(def, data);
  }

  return utils.merge(def, bcoin.script.getInputData(this.script));
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
    script: utils.toHex(bcoin.script.encode(this.script)),
    witness: this.witness.map(function(chunk) {
      return utils.toHex(chunk);
    }),
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
    script: bcoin.script.decode(new Buffer(json.script, 'hex')),
    witness: json.witness.map(function(chunk) {
      return new Buffer(chunk, 'hex');
    }),
    sequence: json.sequence
  };
};

Input.fromJSON = function fromJSON(json) {
  return new Input(Input._fromJSON(json));
};

Input.prototype.toCompact = function toCompact() {
  return {
    type: 'input',
    input: this.toRaw('hex'),
    witness: this.witness.map(function(chunk) {
      return utils.toHex(chunk);
    }),
  };
};

Input._fromCompact = function _fromCompact(json) {
  json = Input._fromRaw(json.input, 'hex');
  json.witness = json.witness.map(function(chunk) {
    return new Buffer(chunk, 'hex');
  });
  return json;
};

Input.fromCompact = function fromCompact(json) {
  return new Input(Input._fromCompact(json));
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

/**
 * Expose
 */

module.exports = Input;
