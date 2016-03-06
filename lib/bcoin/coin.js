/**
 * coin.js - coin object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bn = require('bn.js');
var bcoin = require('../bcoin');
var utils = bcoin.utils;
var assert = utils.assert;
var constants = bcoin.protocol.constants;

/**
 * Coin
 */

// This is basically a UTXO/Coin object. It is immutable once instantiated. It
// needs to store 5 properties: the tx hash, output index, output value, output
// script, and the block height the transaction was mined (to later calculate
// age).

function Coin(tx, index) {
  var options;

  if (!(this instanceof Coin))
    return new Coin(tx, index);

  if (tx instanceof Coin)
    return tx;

  if (tx instanceof bcoin.tx) {
    this.version = tx.version;
    this.height = tx.height;
    this.value = tx.outputs[index].value;
    this.script = tx.outputs[index].script;
    this._offset = tx.outputs[index]._offset;
    this._size = tx.outputs[index]._size;
    this.hash = tx.hash('hex');
    this.index = index;
    this.spent = false;
  } else {
    options = tx;
    assert(typeof options.script !== 'string');
    this.version = options.version;
    this.height = options.height;
    this.value = options.value;
    this.script = options.script;
    this.hash = options.hash;
    this.index = options.index;
    this.spent = options.spent;
    this._size = options._size || 0;
    this._offset = options._offset || 0;
  }

  if (Buffer.isBuffer(this.hash))
    this.hash = utils.toHex(this.hash);

  // Object.freeze(this);

  assert(typeof this.version === 'number');
  assert(utils.isFinite(this.height));
  assert(this.value instanceof bn);
  assert(Array.isArray(this.script));
  assert(typeof this.hash === 'string');
  assert(utils.isFinite(this.index));
  assert(typeof this.spent === 'boolean');
}

utils.inherits(Coin, bcoin.output);

Coin.prototype.__defineGetter__('chain', function() {
  return this._chain || bcoin.chain.global;
});

Coin.prototype.getSize = function getSize() {
  return 4 + 4 + 8 + bcoin.script.getSize(this.script) + 32 + 4 + 1;
};

Coin.prototype.getConfirmations = function getConfirmations(height) {
  var top;

  if (height == null) {
    if (!this.chain)
      return 0;

    top = this.chain.height;
  } else {
    top = height;
  }

  if (this.height === -1)
    return 0;

  if (top < this.height)
    return 1;

  return top - this.height + 1;
};

Coin.prototype.__defineGetter__('confirmations', function() {
  return this.getConfirmations();
});

Coin.prototype.getAge = function getAge(height) {
  var age = this.getConfirmations(height);

  if (age === -1)
    age = 0;

  if (age !== 0)
    age += 1;

  return age;
};

Coin.prototype.__defineGetter__('age', function() {
  return this.getAge();
});

Coin.prototype.inspect = function inspect() {
  return {
    type: this.getType(),
    version: this.version,
    height: this.height,
    value: utils.btc(this.value),
    script: bcoin.script.format(this.script),
    hash: utils.revHex(this.hash),
    index: this.index,
    address: this.getAddress(),
    spent: this.spent
  };
};

Coin.prototype.toJSON = function toJSON() {
  return {
    version: this.version,
    height: this.height,
    value: utils.btc(this.value),
    script: utils.toHex(bcoin.script.encode(this.script)),
    hash: utils.revHex(this.hash),
    index: this.index,
    spent: this.spent
  };
};

Coin._fromJSON = function _fromJSON(json) {
  return {
    version: json.version,
    height: json.height,
    value: utils.satoshi(json.value),
    script: bcoin.script.decode(new Buffer(json.script, 'hex')),
    hash: utils.revHex(json.hash),
    index: json.index,
    spent: json.spent
  };
};

Coin.fromJSON = function fromJSON(json) {
  return new Coin(Coin._fromJSON(json));
};

Coin.prototype.toRaw = function toRaw(enc) {
  var data = bcoin.protocol.framer.coin(this, false);

  if (enc === 'hex')
    data = utils.toHex(data);

  return data;
};

Coin._fromRaw = function _fromRaw(data, enc) {
  if (enc === 'hex')
    data = new Buffer(data, 'hex');

  data = bcoin.protocol.parser.parseCoin(data, false);

  return data;
};

Coin.fromRaw = function fromRaw(data, enc) {
  return new Coin(Coin._fromRaw(data, enc));
};

Coin.prototype.toExtended = function toExtended(enc) {
  var data = bcoin.protocol.framer.coin(this, true);

  if (enc === 'hex')
    data = utils.toHex(data);

  return data;
};

Coin._fromExtended = function _fromExtended(data, enc) {
  if (enc === 'hex')
    data = new Buffer(data, 'hex');

  data = bcoin.protocol.parser.parseCoin(data, true);

  return data;
};

Coin.fromExtended = function fromExtended(data, enc) {
  return new Coin(Coin._fromExtended(data, enc));
};

/**
 * Expose
 */

module.exports = Coin;
