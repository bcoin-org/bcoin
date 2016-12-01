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
    coin.toRaw(bw);
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
    this.items.push(UndoCoin.fromRaw(br));

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
 * @returns {Coin}
 */

UndoCoins.prototype.apply = function apply(view, outpoint) {
  var undo = this.items.pop();
  var hash = outpoint.hash;
  var index = outpoint.index;
  var coins;

  assert(undo);

  if (undo.height !== -1) {
    coins = new Coins();

    assert(!view.unspent[hash]);
    view.unspent[hash] = coins;

    coins.coinbase = undo.coinbase;
    coins.height = undo.height;
    coins.version = undo.version;
  } else {
    coins = view.unspent[hash];
    assert(coins);
  }

  coins.add(index, undo.toOutput());

  assert(coins.has(index));

  return coins.getCoin(index);
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
 * Serialize the undo coin.
 * @returns {Buffer}
 */

UndoCoin.prototype.toRaw = function toRaw(writer) {
  var bw = new BufferWriter(writer);
  var height = this.height;

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

  if (!writer)
    bw = bw.render();

  return bw;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 * @returns {UndoCoin}
 */

UndoCoin.prototype.fromRaw = function fromRaw(data) {
  var br = new BufferReader(data);
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

module.exports = UndoCoins;
