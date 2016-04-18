/*!
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
 * Represents a transaction input.
 * @exports Input
 * @constructor
 * @param {NakedInput} options
 * @param {Boolean?} mutable
 * @property {Object} prevout - Outpoint.
 * @property {Hash} prevout.hash - Previous transaction hash.
 * @property {Number} prevout.index - Previous output index.
 * @property {Script} script - Input script / scriptSig.
 * @property {Number} sequence - nSequence.
 * @property {Witness} witness - Witness (empty if not present).
 * @property {Coin?} coin - Previous output.
 * @property {String} type - Script type.
 * @property {String?} address - Input address.
 * @property {Boolean} mutable
 */

function Input(options, mutable) {
  if (!(this instanceof Input))
    return new Input(options);

  this.mutable = !!mutable;
  this.prevout = options.prevout;
  this.script = bcoin.script(options.script, this.mutable);
  this.sequence = options.sequence == null ? 0xffffffff : options.sequence;
  this.witness = bcoin.script.witness(options.witness, this.mutable);

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

/**
 * Get the previous output script type. Will "guess"
 * based on the input script and/or witness if coin
 * is not available.
 * @returns {String} type
 */

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

  if (!this.mutable)
    this._type = type;

  return type;
};

/**
 * Get the redeem script. Will attempt to resolve nested
 * redeem scripts if witnesspubkeyhash is behind a scripthash.
 * @returns {Script?} Redeem script.
 */

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

/**
 * Get the redeem script type.
 * @returns {String} subtype
 */

Input.prototype.getSubtype = function getSubtype() {
  var redeem;

  if (this.isCoinbase())
    return;

  redeem = this.getRedeem();

  if (!redeem)
    return;

  return redeem.getType();
};

/**
 * Get the previous output script's address. Will "guess"
 * based on the input script and/or witness if coin
 * is not available.
 * @returns {String?} address
 */

Input.prototype.getAddress = function getAddress() {
  var address;

  if (this.isCoinbase())
    return;

  if (this.coin)
    return this.coin.getAddress();

  if (this._address)
    return this._address;

  if (this.witness.items.length > 0)
    address = this.witness.getInputAddress();

  if (!address)
    address = this.script.getInputAddress();

  if (!this.mutable)
    this._address = address;

  return address;
};

/**
 * Test to see if nSequence is equal to uint32max.
 * @returns {Boolean}
 */

Input.prototype.isFinal = function isFinal() {
  return this.sequence === 0xffffffff;
};

/**
 * Test to see if outpoint hash is null.
 * @returns {Boolean}
 */

Input.prototype.isCoinbase = function isCoinbase() {
  return this.prevout.hash === constants.NULL_HASH;
};

/**
 * Test the input against an address, an
 * array of addresses, or a map of addresses.
 * @param {String|String[]|Object} addressMap
 * @returns {Boolean} Whether the input matched.
 */

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

/**
 * Convert the input to a more user-friendly object.
 * @returns {Object}
 */

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

/**
 * Convert the input to an object suitable
 * for JSON serialization. Note that the hashes
 * will be reversed to abide by bitcoind's legacy
 * of little-endian uint256s.
 * @returns {Object}
 */

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

/**
 * Handle a deserialized JSON input object.
 * @returns {NakedInput} A "naked" input (a
 * plain javascript object which is suitable
 * for passing to the Input constructor).
 */

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

/**
 * Instantiate an Input from a jsonified input object.
 * @param {Object} json - The jsonified input object.
 * @returns {Input}
 */

Input.fromJSON = function fromJSON(json) {
  return new Input(Input._fromJSON(json));
};

/**
 * Serialize the input.
 * @param {String?} enc - Encoding, can be `'hex'` or null.
 * @returns {Buffer|String}
 */

Input.prototype.toRaw = function toRaw(enc) {
  var data = bcoin.protocol.framer.input(this);

  if (enc === 'hex')
    data = utils.toHex(data);

  return data;
};

/**
 * Parse a serialized input.
 * @param {Buffer} data
 * @param {String?} enc - Encoding, can be `'hex'` or null.
 * @returns {NakedInput} A "naked" input object.
 */

Input._fromRaw = function _fromRaw(data, enc) {
  if (enc === 'hex')
    data = new Buffer(data, 'hex');

  data = bcoin.protocol.parser.parseInput(data);

  return data;
};

/**
 * Instantiate an input from a serialized Buffer.
 * @param {Buffer} data
 * @param {String?} enc - Encoding, can be `'hex'` or null.
 * @returns {Input}
 */

Input.fromRaw = function fromRaw(data, enc) {
  return new Input(Input._fromRaw(data, enc));
};

/**
 * Serialize the input to an "extended" format,
 * including both the input and the witness.
 * @param {String?} enc - Encoding, can be `'hex'` or null.
 * @returns {Buffer|String}
 */

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

/**
 * Parse an input in "extended" serialization format.
 * @param {Buffer} data
 * @param {String?} enc - Encoding, can be `'hex'` or null.
 * @returns {NakedInput} - A "naked" input object.
 */

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

/**
 * Instantiate an input from a Buffer
 * in "extended" serialization format.
 * @param {Buffer} data
 * @param {String?} enc - Encoding, can be `'hex'` or null.
 * @returns {TX}
 */

Input.fromExtended = function fromExtended(data, enc) {
  return new Input(Input._fromExtended(data, enc));
};

/**
 * Test an object to see if it is an Input.
 * @param {Object} obj
 * @returns {Boolean}
 */

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
