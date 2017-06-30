/*!
 * input.js - input object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const util = require('../utils/util');
const Network = require('../protocol/network');
const Script = require('../script/script');
const Witness = require('../script/witness');
const Outpoint = require('./outpoint');
const StaticWriter = require('../utils/staticwriter');
const BufferReader = require('../utils/reader');

/**
 * Represents a transaction input.
 * @alias module:primitives.Input
 * @constructor
 * @param {NakedInput} options
 * @property {Outpoint} prevout - Outpoint.
 * @property {Script} script - Input script / scriptSig.
 * @property {Number} sequence - nSequence.
 * @property {Witness} witness - Witness (empty if not present).
 */

function Input(options) {
  if (!(this instanceof Input))
    return new Input(options);

  this.prevout = new Outpoint();
  this.script = new Script();
  this.sequence = 0xffffffff;
  this.witness = new Witness();

  if (options)
    this.fromOptions(options);
}

/**
 * Inject properties from options object.
 * @private
 * @param {Object} options
 */

Input.prototype.fromOptions = function fromOptions(options) {
  assert(options, 'Input data is required.');

  this.prevout.fromOptions(options.prevout);

  if (options.script)
    this.script.fromOptions(options.script);

  if (options.sequence != null) {
    assert(util.isUInt32(options.sequence), 'Sequence must be a uint32.');
    this.sequence = options.sequence;
  }

  if (options.witness)
    this.witness.fromOptions(options.witness);

  return this;
};

/**
 * Instantiate an Input from options object.
 * @param {NakedInput} options
 * @returns {Input}
 */

Input.fromOptions = function fromOptions(options) {
  return new Input().fromOptions(options);
};

/**
 * Clone the input.
 * @returns {Input}
 */

Input.prototype.clone = function clone() {
  let input = new Input();
  input.prevout = this.prevout;
  input.script.inject(this.script);
  input.sequence = this.sequence;
  input.witness.inject(this.witness);
  return input;
};

/**
 * Get the previous output script type as a string.
 * Will "guess" based on the input script and/or
 * witness if coin is not available.
 * @param {Coin?} coin
 * @returns {ScriptType} type
 */

Input.prototype.getType = function getType(coin) {
  let type;

  if (this.isCoinbase())
    return 'coinbase';

  if (coin)
    return coin.getType();

  if (this.witness.items.length > 0)
    type = this.witness.getInputType();
  else
    type = this.script.getInputType();

  return Script.typesByVal[type].toLowerCase();
};

/**
 * Get the redeem script. Will attempt to resolve nested
 * redeem scripts if witnessscripthash is behind a scripthash.
 * @param {Coin?} coin
 * @returns {Script?} Redeem script.
 */

Input.prototype.getRedeem = function getRedeem(coin) {
  let redeem, prev;

  if (this.isCoinbase())
    return;

  if (!coin) {
    if (this.witness.isScripthashInput())
      return this.witness.getRedeem();

    if (this.script.isScripthashInput())
      return this.script.getRedeem();

    return;
  }

  prev = coin.script;

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
 * @param {Coin?} coin
 * @returns {String} subtype
 */

Input.prototype.getSubtype = function getSubtype(coin) {
  let redeem, type;

  if (this.isCoinbase())
    return;

  redeem = this.getRedeem(coin);

  if (!redeem)
    return;

  type = redeem.getType();

  return Script.typesByVal[type].toLowerCase();
};

/**
 * Get the previous output script's address. Will "guess"
 * based on the input script and/or witness if coin
 * is not available.
 * @param {Coin?} coin
 * @returns {Address?} addr
 */

Input.prototype.getAddress = function getAddress(coin) {
  if (this.isCoinbase())
    return;

  if (coin)
    return coin.getAddress();

  if (this.witness.items.length > 0)
    return this.witness.getInputAddress();

  return this.script.getInputAddress();
};

/**
 * Get the address hash.
 * @param {String?} enc
 * @returns {Hash} hash
 */

Input.prototype.getHash = function getHash(enc) {
  let addr = this.getAddress();
  if (!addr)
    return;
  return addr.getHash(enc);
};

/**
 * Test to see if nSequence is equal to uint32max.
 * @returns {Boolean}
 */

Input.prototype.isFinal = function isFinal() {
  return this.sequence === 0xffffffff;
};

/**
 * Test to see if nSequence is less than 0xfffffffe.
 * @returns {Boolean}
 */

Input.prototype.isRBF = function isRBF() {
  return this.sequence < 0xfffffffe;
};

/**
 * Test to see if outpoint is null.
 * @returns {Boolean}
 */

Input.prototype.isCoinbase = function isCoinbase() {
  return this.prevout.isNull();
};

/**
 * Convert the input to a more user-friendly object.
 * @returns {Object}
 */

Input.prototype.inspect = function inspect() {
  return this.format();
};

/**
 * Convert the input to a more user-friendly object.
 * @param {Coin?} coin
 * @returns {Object}
 */

Input.prototype.format = function format(coin) {
  return {
    type: this.getType(coin),
    subtype: this.getSubtype(coin),
    address: this.getAddress(coin),
    script: this.script,
    witness: this.witness,
    redeem: this.getRedeem(coin),
    sequence: this.sequence,
    prevout: this.prevout,
    coin: coin || null
  };
};

/**
 * Convert the input to an object suitable
 * for JSON serialization.
 * @returns {Object}
 */

Input.prototype.toJSON = function toJSON(network, coin) {
  return this.getJSON();
};

/**
 * Convert the input to an object suitable
 * for JSON serialization. Note that the hashes
 * will be reversed to abide by bitcoind's legacy
 * of little-endian uint256s.
 * @param {Network} network
 * @param {Coin} coin
 * @returns {Object}
 */

Input.prototype.getJSON = function getJSON(network, coin) {
  let addr;

  network = Network.get(network);

  if (!coin) {
    addr = this.getAddress();
    if (addr)
      addr = addr.toString(network);
  }

  return {
    prevout: this.prevout.toJSON(),
    script: this.script.toJSON(),
    witness: this.witness.toJSON(),
    sequence: this.sequence,
    address: addr,
    coin: coin ? coin.getJSON(network, true) : undefined
  };
};

/**
 * Inject properties from a JSON object.
 * @private
 * @param {Object} json
 */

Input.prototype.fromJSON = function fromJSON(json) {
  assert(json, 'Input data is required.');
  assert(util.isUInt32(json.sequence), 'Sequence must be a uint32.');
  this.prevout.fromJSON(json.prevout);
  this.script.fromJSON(json.script);
  this.witness.fromJSON(json.witness);
  this.sequence = json.sequence;
  return this;
};

/**
 * Instantiate an Input from a jsonified input object.
 * @param {Object} json - The jsonified input object.
 * @returns {Input}
 */

Input.fromJSON = function fromJSON(json) {
  return new Input().fromJSON(json);
};

/**
 * Calculate size of serialized input.
 * @returns {Number}
 */

Input.prototype.getSize = function getSize() {
  return 40 + this.script.getVarSize();
};

/**
 * Serialize the input.
 * @param {String?} enc - Encoding, can be `'hex'` or null.
 * @returns {Buffer|String}
 */

Input.prototype.toRaw = function toRaw() {
  let size = this.getSize();
  return this.toWriter(new StaticWriter(size)).render();
};

/**
 * Write the input to a buffer writer.
 * @param {BufferWriter} bw
 */

Input.prototype.toWriter = function toWriter(bw) {
  this.prevout.toWriter(bw);
  bw.writeVarBytes(this.script.toRaw());
  bw.writeU32(this.sequence);
  return bw;
};

/**
 * Inject properties from buffer reader.
 * @private
 * @param {BufferReader} br
 */

Input.prototype.fromReader = function fromReader(br) {
  this.prevout.fromReader(br);
  this.script.fromRaw(br.readVarBytes());
  this.sequence = br.readU32();
  return this;
};

/**
 * Inject properties from serialized data.
 * @param {Buffer} data
 */

Input.prototype.fromRaw = function fromRaw(data) {
  return this.fromReader(new BufferReader(data));
};

/**
 * Instantiate an input from a buffer reader.
 * @param {BufferReader} br
 * @returns {Input}
 */

Input.fromReader = function fromReader(br) {
  return new Input().fromReader(br);
};

/**
 * Instantiate an input from a serialized Buffer.
 * @param {Buffer} data
 * @param {String?} enc - Encoding, can be `'hex'` or null.
 * @returns {Input}
 */

Input.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = Buffer.from(data, enc);
  return new Input().fromRaw(data);
};

/**
 * Inject properties from outpoint.
 * @private
 * @param {Outpoint} outpoint
 */

Input.prototype.fromOutpoint = function fromOutpoint(outpoint) {
  assert(typeof outpoint.hash === 'string');
  assert(typeof outpoint.index === 'number');
  this.prevout.hash = outpoint.hash;
  this.prevout.index = outpoint.index;
  return this;
};

/**
 * Instantiate input from outpoint.
 * @param {Outpoint}
 * @returns {Input}
 */

Input.fromOutpoint = function fromOutpoint(outpoint) {
  return new Input().fromOutpoint(outpoint);
};

/**
 * Inject properties from coin.
 * @private
 * @param {Coin} coin
 */

Input.prototype.fromCoin = function fromCoin(coin) {
  assert(typeof coin.hash === 'string');
  assert(typeof coin.index === 'number');
  this.prevout.hash = coin.hash;
  this.prevout.index = coin.index;
  return this;
};

/**
 * Instantiate input from coin.
 * @param {Coin}
 * @returns {Input}
 */

Input.fromCoin = function fromCoin(coin) {
  return new Input().fromCoin(coin);
};

/**
 * Inject properties from transaction.
 * @private
 * @param {TX} tx
 * @param {Number} index
 */

Input.prototype.fromTX = function fromTX(tx, index) {
  assert(tx);
  assert(typeof index === 'number');
  assert(index >= 0 && index < tx.outputs.length);
  this.prevout.hash = tx.hash('hex');
  this.prevout.index = index;
  return this;
};

/**
 * Instantiate input from tx.
 * @param {TX} tx
 * @param {Number} index
 * @returns {Input}
 */

Input.fromTX = function fromTX(tx, index) {
  return new Input().fromTX(tx, index);
};

/**
 * Test an object to see if it is an Input.
 * @param {Object} obj
 * @returns {Boolean}
 */

Input.isInput = function isInput(obj) {
  return obj
    && typeof obj.prevout === 'object'
    && typeof obj.script === 'object'
    && typeof obj.witness === 'object'
    && typeof obj.getAddress === 'function';
};

/*
 * Expose
 */

module.exports = Input;
