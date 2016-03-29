/**
 * coin.js - coin object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bn = require('bn.js');
var bcoin = require('../bcoin');
var utils = require('./utils');
var assert = utils.assert;
var network = bcoin.protocol.network;

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
    this.coinbase = tx.isCoinbase();
    this.hash = tx.hash('hex');
    this.index = index;
  } else {
    options = tx;
    assert(typeof options.script !== 'string');
    this.version = options.version;
    this.height = options.height;
    this.value = options.value;
    this.script = bcoin.script(options.script);
    this.coinbase = options.coinbase;
    this.hash = options.hash;
    this.index = options.index;
  }

  if (Buffer.isBuffer(this.hash))
    this.hash = utils.toHex(this.hash);

  // Object.freeze(this);

  assert(typeof this.version === 'number');
  assert(utils.isFinite(this.height));
  assert(bn.isBN(this.value));
  assert(this.script instanceof bcoin.script);
  assert(typeof this.coinbase === 'boolean');
  // assert(typeof this.hash === 'string');
  // assert(utils.isFinite(this.index));
}

utils.inherits(Coin, bcoin.output);

Coin.prototype.getConfirmations = function getConfirmations(height) {
  if (height == null)
    height = network.height;

  if (this.height === -1)
    return 0;

  if (height < this.height)
    return 1;

  return height - this.height + 1;
};

Coin.prototype.getAge = function getAge(height) {
  var age = this.getConfirmations(height);

  if (age === -1)
    age = 0;

  if (age !== 0)
    age += 1;

  return age;
};

Coin.prototype.__defineGetter__('confirmations', function() {
  return this.getConfirmations();
});

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
    coinbase: this.coinbase,
    hash: this.hash ? utils.revHex(this.hash) : null,
    index: this.index,
    age: this.age,
    address: this.getAddress()
  };
};

Coin.prototype.toJSON = function toJSON() {
  return {
    version: this.version,
    height: this.height,
    value: utils.btc(this.value),
    script: utils.toHex(bcoin.protocol.framer(this.script)),
    coinbase: this.coinbase,
    hash: this.hash ? utils.revHex(this.hash) : null,
    index: this.index
  };
};

Coin._fromJSON = function _fromJSON(json) {
  return {
    version: json.version,
    height: json.height,
    value: utils.satoshi(json.value),
    script: new bcoin.script(new Buffer(json.script, 'hex')),
    coinbase: json.coinbase,
    hash: json.hash ? utils.revHex(json.hash) : null,
    index: json.index
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

Coin.prototype.toUTXO = function toUTXO(enc) {
  var data = bcoin.protocol.framer.utxo(this);

  if (enc === 'hex')
    data = utils.toHex(data);

  return data;
};

Coin._fromUTXO = function _fromUTXO(data, enc) {
  if (enc === 'hex')
    data = new Buffer(data, 'hex');

  data = bcoin.protocol.parser.parseUTXO(data);

  return data;
};

Coin.fromUTXO = function fromUTXO(data, enc) {
  return new Coin(Coin._fromUTXO(data, enc));
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

Coin.isCoin = function isCoin(obj) {
  return obj
    && typeof obj.version === 'number'
    && typeof obj.script === 'object'
    && typeof obj.getConfirmations === 'function';
};

/**
 * Expose
 */

module.exports = Coin;
