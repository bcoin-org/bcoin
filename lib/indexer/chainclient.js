/*!
 * chainclient.js - chain client for bcoin
 * Copyright (c) 2018, the bcoin developers (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const AsyncEmitter = require('bevent');
const Chain = require('../blockchain/chain');

/**
 * Chain Client
 * @extends AsyncEmitter
 * @alias module:indexer.ChainClient
 */

class ChainClient extends AsyncEmitter {
  /**
   * Create a chain client.
   * @constructor
   * @param {Chain} chain
   */

  constructor(chain) {
    super();

    assert(chain instanceof Chain);

    this.chain = chain;
    this.network = chain.network;
    this.opened = false;

    this.init();
  }

  /**
   * Initialize the client.
   */

  init() {
    this.chain.on('connect', async (entry, block, view) => {
      if (!this.opened)
        return;

      await this.emitAsync('block connect', entry, block, view);
    });

    this.chain.on('disconnect', async (entry, block, view) => {
      if (!this.opened)
        return;

      await this.emitAsync('block disconnect', entry, block, view);
    });

    this.chain.on('reset', async (tip) => {
      if (!this.opened)
        return;

      await this.emitAsync('chain reset', tip);
    });
  }

  /**
   * Open the client.
   * @returns {Promise}
   */

  async open(options) {
    assert(!this.opened, 'ChainClient is already open.');
    this.opened = true;
    setImmediate(() => this.emit('connect'));
  }

  /**
   * Close the client.
   * @returns {Promise}
   */

  async close() {
    assert(this.opened, 'ChainClient is not open.');
    this.opened = false;
    setImmediate(() => this.emit('disconnect'));
  }

  /**
   * Get chain tip.
   * @returns {Promise}
   */

  async getTip() {
    return this.chain.tip;
  }

  /**
   * Get chain entry.
   * @param {Hash} hash
   * @returns {Promise} - Returns {@link ChainEntry}.
   */

  async getEntry(hash) {
    const entry = await this.chain.getEntry(hash);

    if (!entry)
      return null;

    if (!await this.chain.isMainChain(entry))
      return null;

    return entry;
  }

  /**
   * Get a coin (unspents only).
   * @param {Hash} hash
   * @param {Number} index
   * @returns {Promise} - Returns {@link Coin}.
   */

  async getCoin(hash, index) {
    return this.chain.getCoin(hash, index);
  }

  /**
   * Get hash range.
   * @param {Number} start
   * @param {Number} end
   * @returns {Promise}
   */

  async getHashes(start = -1, end = -1) {
    return this.chain.getHashes(start, end);
  }

  /**
   * Get block
   * @param {Hash} hash
   * @returns {Promise} - Returns {@link Block}
   */

  async getBlock(hash) {
    const block = await this.chain.getBlock(hash);

    if (!block)
      return null;

    return block;
  }

  /**
   * Get a historical block coin viewpoint.
   * @param {Block} hash
   * @returns {Promise} - Returns {@link CoinView}.
   */

  async getBlockView(block) {
    return this.chain.getBlockView(block);
  }

  /**
   * Get coin viewpoint.
   * @param {TX} tx
   * @returns {Promise} - Returns {@link CoinView}.
   */

  async getCoinView(tx) {
    return this.chain.getCoinView(tx);
  }

  /**
   * Rescan for any missed blocks.
   * @param {Number} start - Start block.
   * @returns {Promise}
   */

  async rescan(start) {
    for (let i = start; ; i++) {
      const entry = await this.getEntry(i);
      if (!entry) {
        await this.emitAsync('chain tip');
        break;
      };

      const block = await this.getBlock(entry.hash);
      assert(block);

      const view = await this.getBlockView(block);
      assert(view);

      await this.emitAsync('block rescan', entry, block, view);
    }
  };
}

/*
 * Expose
 */

module.exports = ChainClient;
