/**
 * coin.js - coin object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bn = require('bn.js');
var bcoin = require('../bcoin');
var inherits = require('inherits');
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
    this.hash = tx.hash('hex');
    this.index = index;
    this.value = tx.outputs[index].value;
    this.script = tx.outputs[index].script;
    this.height = tx.height;
  } else {
    options = tx;
    this.hash = options.hash;
    this.index = options.index;
    this.value = options.value;
    this.script = options.script;
    this.height = options.height;
  }

  if (utils.isBuffer(this.hash))
    this.hash = utils.toHex(this.hash);

  this.rhash = utils.revHex(this.hash);

  assert(typeof this.hash === 'string');
  assert(utils.isFinite(this.index));
  assert(this.value instanceof bn);
  assert(Array.isArray(this.script));
  assert(utils.isFinite(this.height));

  // Object.freeze(this);
}

inherits(Coin, bcoin.output);

Coin.prototype.__defineGetter__('chain', function() {
  return this._chain || bcoin.chain.global;
});

Coin.prototype.getConfirmations = function getConfirmations(height) {
  var top;

  if (height == null) {
    if (!this.chain)
      return 0;

    top = this.chain.height();
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

Coin.prototype.toJSON = function toJSON() {
  return {
    hash: this.hash,
    index: this.index,
    value: utils.btc(this.value),
    script: utils.toHex(bcoin.script.encode(this.script)),
    height: this.height,
    address: this.getAddress()
  };
};

Coin.fromJSON = function fromJSON(json) {
  return new Coin({
    hash: json.hash,
    index: json.index,
    value: utils.satoshi(json.value),
    script: bcoin.script.decode(utils.toArray(json.script, 'hex')),
    height: json.height,
    address: json.address
  });
};

// Not totally necessary, but this is 3 times
// faster than JSON serialization if high performance
// is a goal.
Coin.prototype.toRaw = function toRaw(enc) {
  var script = bcoin.script.encode(this.script);
  var height = this.height;
  var data = new Buffer(48 + script.length);

  if (height === -1)
    height = 0xffffffff;

  utils.copy(utils.toArray(this.hash, 'hex'), data, 0);
  utils.writeU32BE(data, this.index, 32);
  utils.writeU32BE(data, height, 36);
  utils.write64BE(data, this.value, 40);
  utils.copy(script, data, 48);

  if (enc === 'hex')
    data = utils.toHex(data);

  return data;
};

Coin.fromRaw = function fromRaw(data, enc) {
  var height;

  if (enc === 'hex')
    data = utils.toArray(data, 'hex');

  height = utils.readU32BE(data, 36);

  if (height === 0xffffffff)
    height = -1;

  return new Coin({
    hash: utils.toHex(data.slice(0, 32)),
    index: utils.readU32BE(data, 32),
    height: height,
    value: utils.read64BE(data, 40),
    script: bcoin.script.decode(utils.toArray(data.slice(48)))
  });
};

/**
 * Expose
 */

module.exports = Coin;
