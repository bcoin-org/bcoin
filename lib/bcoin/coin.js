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

  this.rhash = utils.revHex(this.hash);

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

Coin.prototype.toJSON = function toJSON() {
  return {
    version: this.version,
    height: this.height,
    value: utils.btc(this.value),
    script: utils.toHex(bcoin.script.encode(this.script)),
    hash: this.hash,
    index: this.index,
    spent: this.spent,
    address: this.getAddress()
  };
};

Coin.fromJSON = function fromJSON(json) {
  return new Coin({
    version: json.version,
    height: json.height,
    value: utils.satoshi(json.value),
    script: bcoin.script.decode(new Buffer(json.script, 'hex')),
    hash: json.hash,
    index: json.index,
    spent: json.spent,
    address: json.address
  });
};

Coin.prototype.toFullJSON = function toFullJSON() {
  return {
    version: this.version,
    height: this.height,
    value: utils.btc(this.value),
    script: utils.toHex(bcoin.script.encode(this.script)),
    hash: utils.revHex(this.hash),
    index: this.index,
    spent: this.spent,
    address: this.getAddress()
  };
};

Coin.fromFullJSON = function fromFullJSON(json) {
  return new Coin({
    version: json.version,
    height: json.height,
    value: utils.satoshi(json.value),
    script: bcoin.script.decode(new Buffer(json.script, 'hex')),
    hash: utils.revHex(json.hash),
    index: json.index,
    spent: json.spent,
    address: json.address
  });
};

// This is basically BIP64 with some
// extra fields tacked on the end.
Coin.prototype.toRaw = function toRaw(enc, strict) {
  var script = bcoin.script.encode(this.script);
  var intSize = utils.sizeIntv(script.length);
  var height = this.height;
  var data = new Buffer(16 + intSize + script.length + (!strict ? 37 : 0));
  var off = 0;

  if (height === -1)
    height = 0x7fffffff;

  off += utils.writeU32(data, this.version, off);
  off += utils.writeU32(data, height, off);
  off += utils.write64(data, this.value, off);
  assert(this.value.byteLength() <= 8);
  off += utils.writeIntv(data, script.length, off);
  off += utils.copy(script, data, off);

  if (!strict) {
    off += utils.copy(new Buffer(this.hash, 'hex'), data, off);
    off += utils.writeU32(data, this.index, off);
    off += utils.writeU8(data, this.spent ? 1 : 0, off);
  }

  if (enc === 'hex')
    data = utils.toHex(data);

  return data;
};

Coin.fromRaw = function fromRaw(data, enc, strict) {
  var off = 0;
  var version, height, value, script, hash, index, spent, scriptLen;

  if (enc === 'hex')
    data = new Buffer(data, 'hex');

  if (data.length < 17 + (!strict ? 37 : 0))
    throw new Error('Invalid utxo size');

  version = utils.readU32(data, off);
  off += 4;

  height = utils.readU32(data, off);
  if (height === 0x7fffffff)
    height = -1;
  off += 4;

  value = utils.read64(data, off);
  off += 8;

  scriptLen = utils.readIntv(data, off);
  off = scriptLen.off;
  scriptLen = scriptLen.r;

  if (off + scriptLen > data.length - (!strict ? 37 : 0))
    throw new Error('Invalid utxo script length');

  script = bcoin.script.decode(data.slice(off, off + scriptLen));
  off += scriptLen;

  if (!strict) {
    hash = utils.toHex(data.slice(off, off + 32));
    off += 32;

    index = utils.readU32(data, off);
    off += 4;

    spent = utils.readU8(data, off) === 1;
    off += 1;
  } else {
    hash = constants.zeroHash.slice();
    index = 0xffffffff;
    spent = false;
  }

  return new Coin({
    version: version,
    height: height,
    value: value,
    script: script,
    hash: hash,
    index: index,
    spent: spent
  });
};

/**
 * Expose
 */

module.exports = Coin;
