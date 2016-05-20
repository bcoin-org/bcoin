/*!
 * input.js - input object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

var bcoin = require('./env');
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

  assert(options, 'Input data is required.');

  this.mutable = !!mutable;
  this.prevout = options.prevout;
  this.script = bcoin.script(options.script, this.mutable);
  this.sequence = options.sequence == null ? 0xffffffff : options.sequence;
  this.witness = bcoin.witness(options.witness, this.mutable);

  if (options.coin)
    this.coin = bcoin.coin(options.coin);

  assert(typeof this.prevout === 'object');
  assert(typeof this.prevout.hash === 'string');
  assert(typeof this.prevout.index === 'number');
  assert(typeof this.sequence === 'number');
}

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
 * redeem scripts if witnessscripthash is behind a scripthash.
 * @returns {Script?} Redeem script.
 */

Input.prototype.getRedeem = function getRedeem() {
  var redeem, prev;

  if (this.isCoinbase())
    return;

  if (!this.coin) {
    if (this.script.isScripthashInput()) {
      redeem = this.script.getRedeem();

      if (redeem && redeem.isWitnessScripthash())
        redeem = this.witness.getRedeem();

      return redeem;
    }

    if (this.witness.isScripthashInput())
      return this.witness.getRedeem();

    return;
  }

  prev = this.coin.script;

  if (prev.isScripthash()) {
    prev = this.script.getRedeem();
    redeem = prev;
  }

  if (prev && prev.isWitnessScripthash()) {
    prev = this.witness.getRedeem();
    redeem = prev;
  }

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
 * @returns {Address?} address
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
 * Get the address hash.
 * @returns {Hash} hash
 */

Input.prototype.getHash = function getHash(enc) {
  var address = this.getAddress();
  if (!address)
    return;
  return address.getHash('hex');
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
 * array of addresses, or a map of hashes.
 * @param {Hash|Hash[]|AddressHashMap} addressMap
 * @returns {Boolean} Whether the input matched.
 */

Input.prototype.test = function test(addressMap) {
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
    script: this.script.toRaw('hex'),
    witness: this.witness.toRaw('hex'),
    sequence: this.sequence
  };
};

/**
 * Handle a deserialized JSON input object.
 * @returns {NakedInput} A "naked" input (a
 * plain javascript object which is suitable
 * for passing to the Input constructor).
 */

Input.parseJSON = function parseJSON(json) {
  return {
    prevout: {
      hash: utils.revHex(json.prevout.hash),
      index: json.prevout.index
    },
    coin: json.coin ? bcoin.coin.parseJSON(json.coin) : null,
    script: bcoin.script.parseRaw(json.script, 'hex'),
    witness: bcoin.witness.parseRaw(json.witness, 'hex'),
    sequence: json.sequence
  };
};

/**
 * Instantiate an Input from a jsonified input object.
 * @param {Object} json - The jsonified input object.
 * @returns {Input}
 */

Input.fromJSON = function fromJSON(json) {
  return new Input(Input.parseJSON(json));
};

/**
 * Serialize the input.
 * @param {String?} enc - Encoding, can be `'hex'` or null.
 * @returns {Buffer|String}
 */

Input.prototype.toRaw = function toRaw(enc) {
  var data = bcoin.protocol.framer.input(this);

  if (enc === 'hex')
    data = data.toString('hex');

  return data;
};

/**
 * Parse a serialized input.
 * @param {Buffer} data
 * @param {String?} enc - Encoding, can be `'hex'` or null.
 * @returns {NakedInput} A "naked" input object.
 */

Input.parseRaw = function parseRaw(data, enc) {
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
  return new Input(Input.parseRaw(data, enc));
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
    data = data.toString('hex');

  return data;
};

/**
 * Parse an input in "extended" serialization format.
 * @param {Buffer} data
 * @param {String?} enc - Encoding, can be `'hex'` or null.
 * @returns {NakedInput} - A "naked" input object.
 */

Input.parseExtended = function parseExtended(data, enc) {
  var input, p;

  if (enc === 'hex')
    data = new Buffer(data, 'hex');

  p = new BufferReader(data);
  input = bcoin.protocol.parser.parseInput(p);
  input.witness = bcoin.protocol.parser.parseWitness(p);

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
  return new Input(Input.parseExtended(data, enc));
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

/*
 * Expose
 */

module.exports = Input;
