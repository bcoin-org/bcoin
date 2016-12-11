/*!
 * undocoins.js - undocoins object for bcoin
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var BufferReader = require('../utils/reader');
var BufferWriter = require('../utils/writer');
var Output = require('../primitives/output');
var Coins = require('./coins');
var compressor = require('./compress');
var compress = compressor.compress;
var decompress = compressor.decompress;

/**
 * UndoCoins
 * Coins need to be resurrected from somewhere
 * during a reorg. The undo coins store all
 * spent coins in a single record per block
 * (in a compressed format).
 * @constructor
 * @property {UndoCoin[]} items
 */

function UndoCoins() {
  if (!(this instanceof UndoCoins))
    return new UndoCoins();

  this.items = [];
}

/**
 * Push coin entry onto undo coin array.
 * @param {CoinEntry}
 */

UndoCoins.prototype.push = function push(entry) {
  var undo = new UndoCoin();
  undo.entry = entry;
  this.items.push(undo);
};

/**
 * Serialize all undo coins.
 * @returns {Buffer}
 */

UndoCoins.prototype.toRaw = function toRaw() {
  var bw = new BufferWriter();
  var i, coin;

  bw.writeU32(this.items.length);

  for (i = 0; i < this.items.length; i++) {
    coin = this.items[i];
    coin.toWriter(bw);
  }

  return bw.render();
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 * @returns {UndoCoins}
 */

UndoCoins.prototype.fromRaw = function fromRaw(data) {
  var br = new BufferReader(data);
  var count = br.readU32();
  var i;

  for (i = 0; i < count; i++)
    this.items.push(UndoCoin.fromReader(br));

  return this;
};

/**
 * Instantiate undo coins from serialized data.
 * @param {Buffer} data
 * @returns {UndoCoins}
 */

UndoCoins.fromRaw = function fromRaw(data) {
  return new UndoCoins().fromRaw(data);
};

/**
 * Test whether the undo coins have any members.
 * @returns {Boolean}
 */

UndoCoins.prototype.isEmpty = function isEmpty() {
  return this.items.length === 0;
};

/**
 * Render the undo coins.
 * @returns {Buffer}
 */

UndoCoins.prototype.commit = function commit() {
  var raw = this.toRaw();
  this.items.length = 0;
  return raw;
};

/**
 * Retrieve the last undo coin.
 * @returns {UndoCoin}
 */

UndoCoins.prototype.top = function top() {
  return this.items[this.items.length - 1];
};

/**
 * Re-apply undo coins to a view, effectively unspending them.
 * @param {CoinView} view
 * @param {Outpoint} outpoint
 */

UndoCoins.prototype.apply = function apply(view, outpoint) {
  var undo = this.items.pop();
  var hash = outpoint.hash;
  var index = outpoint.index;
  var coins;

  assert(undo);

  if (undo.height !== -1) {
    coins = new Coins();

    assert(!view.map[hash]);
    view.map[hash] = coins;

    coins.hash = hash;
    coins.coinbase = undo.coinbase;
    coins.height = undo.height;
    coins.version = undo.version;
  } else {
    coins = view.map[hash];
    assert(coins);
  }

  coins.addOutput(index, undo.toOutput());

  assert(coins.has(index));
};

/**
 * UndoCoin
 * @constructor
 * @property {CoinEntry|null} entry
 * @property {Output|null} output
 * @property {Number} version
 * @property {Number} height
 * @property {Boolean} coinbase
 */

function UndoCoin() {
  this.entry = null;
  this.output = null;
  this.version = -1;
  this.height = -1;
  this.coinbase = false;
}

/**
 * Convert undo coin to an output.
 * @returns {Output}
 */

UndoCoin.prototype.toOutput = function toOutput() {
  if (!this.output) {
    assert(this.entry);
    return this.entry.toOutput();
  }
  return this.output;
};

/**
 * Write the undo coin to a buffer writer.
 * @param {BufferWriter} bw
 */

UndoCoin.prototype.toWriter = function toWriter(bw) {
  var height = this.height;

  assert(height !== 0);

  if (height === -1)
    height = 0;

  bw.writeVarint(height * 2 + (this.coinbase ? 1 : 0));

  if (this.height !== -1) {
    assert(this.version !== -1);
    bw.writeVarint(this.version);
  }

  if (this.entry) {
    // Cached from spend.
    this.entry.toWriter(bw);
  } else {
    compress.output(this.output, bw);
  }

  return bw;
};

/**
 * Serialize the undo coin.
 * @returns {Buffer}
 */

UndoCoin.prototype.toRaw = function toRaw() {
  return this.toWriter(new BufferWriter()).render();
};

/**
 * Inject properties from buffer reader.
 * @private
 * @param {BufferReader} br
 * @returns {UndoCoin}
 */

UndoCoin.prototype.fromReader = function fromReader(br) {
  var code = br.readVarint();

  this.output = new Output();

  this.height = code / 2 | 0;

  if (this.height === 0)
    this.height = -1;

  this.coinbase = (code & 1) !== 0;

  if (this.height !== -1)
    this.version = br.readVarint();

  decompress.output(this.output, br);

  return this;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 * @returns {UndoCoin}
 */

UndoCoin.prototype.fromRaw = function fromRaw(data) {
  return this.fromReader(new BufferReader(data));
};

/**
 * Instantiate undo coin from serialized data.
 * @param {Buffer} data
 * @returns {UndoCoin}
 */

UndoCoin.fromReader = function fromReader(br) {
  return new UndoCoin().fromReader(br);
};

/**
 * Instantiate undo coin from serialized data.
 * @param {Buffer} data
 * @returns {UndoCoin}
 */

UndoCoin.fromRaw = function fromRaw(data) {
  return new UndoCoin().fromRaw(data);
};

/*
 * Expose
 */

exports = UndoCoins;
exports.UndoCoins = UndoCoins;
exports.UndoCoin = UndoCoin;

module.exports = exports;
