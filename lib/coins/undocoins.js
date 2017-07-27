/*!
 * undocoins.js - undocoins object for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const BufferReader = require('../utils/reader');
const StaticWriter = require('../utils/staticwriter');
const CoinEntry = require('../coins/coinentry');

/**
 * UndoCoins
 * Coins need to be resurrected from somewhere
 * during a reorg. The undo coins store all
 * spent coins in a single record per block
 * (in a compressed format).
 * @alias module:coins.UndoCoins
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
 * @returns {Number}
 */

UndoCoins.prototype.push = function push(coin) {
  return this.items.push(coin);
};

/**
 * Calculate undo coins size.
 * @returns {Number}
 */

UndoCoins.prototype.getSize = function getSize() {
  let size = 0;

  size += 4;

  for (const coin of this.items)
    size += coin.getSize();

  return size;
};

/**
 * Serialize all undo coins.
 * @returns {Buffer}
 */

UndoCoins.prototype.toRaw = function toRaw() {
  const size = this.getSize();
  const bw = new StaticWriter(size);

  bw.writeU32(this.items.length);

  for (const coin of this.items)
    coin.toWriter(bw);

  return bw.render();
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 * @returns {UndoCoins}
 */

UndoCoins.prototype.fromRaw = function fromRaw(data) {
  const br = new BufferReader(data);
  const count = br.readU32();

  for (let i = 0; i < count; i++)
    this.items.push(CoinEntry.fromReader(br));

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
  const raw = this.toRaw();
  this.items.length = 0;
  return raw;
};

/**
 * Re-apply undo coins to a view, effectively unspending them.
 * @param {CoinView} view
 * @param {Outpoint} prevout
 */

UndoCoins.prototype.apply = function apply(view, prevout) {
  const undo = this.items.pop();

  assert(undo);

  view.addEntry(prevout, undo);
};

/*
 * Expose
 */

module.exports = UndoCoins;
