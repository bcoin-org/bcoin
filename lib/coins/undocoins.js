/*!
 * undocoins.js - undocoins object for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');
const bio = require('bufio');
const CoinEntry = require('../coins/coinentry');

/**
 * Undo Coins
 * Coins need to be resurrected from somewhere
 * during a reorg. The undo coins store all
 * spent coins in a single record per block
 * (in a compressed format).
 * @alias module:coins.UndoCoins
 * @property {UndoCoin[]} items
 */

class UndoCoins extends bio.Struct {
  /**
   * Create undo coins.
   * @constructor
   */

  constructor() {
    super();
    this.items = [];
  }

  /**
   * Push coin entry onto undo coin array.
   * @param {CoinEntry}
   * @returns {Number}
   */

  push(coin) {
    return this.items.push(coin);
  }

  /**
   * Calculate undo coins size.
   * @returns {Number}
   */

  getSize() {
    let size = 0;

    size += 4;

    for (const coin of this.items)
      size += coin.getSize();

    return size;
  }

  /**
   * Serialize all undo coins.
   * @param {BufferWriter} bw
   * @returns {BufferWriter}
   */

  write(bw) {
    bw.writeU32(this.items.length);

    for (const coin of this.items)
      coin.write(bw);

    return bw;
  }

  /**
   * Inject properties from serialized data.
   * @private
   * @param {BufferReader} br
   * @returns {UndoCoins}
   */

  read(br) {
    const count = br.readU32();

    for (let i = 0; i < count; i++)
      this.items.push(CoinEntry.read(br));

    return this;
  }

  /**
   * Test whether the undo coins have any members.
   * @returns {Boolean}
   */

  isEmpty() {
    return this.items.length === 0;
  }

  /**
   * Render the undo coins.
   * @returns {Buffer}
   */

  commit() {
    const raw = this.encode();
    this.items.length = 0;
    return raw;
  }

  /**
   * Re-apply undo coins to a view, effectively unspending them.
   * @param {CoinView} view
   * @param {Outpoint} prevout
   */

  apply(view, prevout) {
    const undo = this.items.pop();

    assert(undo);

    view.addEntry(prevout, undo);
  }
}

/*
 * Expose
 */

module.exports = UndoCoins;
