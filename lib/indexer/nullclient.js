/*!
 * nullclient.js - chain client for bcoin
 * Copyright (c) 2018, the bcoin developers (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const EventEmitter = require('events');

/**
 * Null Client
 * Sort of a fake local client for separation of concerns.
 * @alias module:indexer.NullClient
 */

class NullClient extends EventEmitter {
  /**
   * Create a client.
   * @constructor
   * @param {Chain} chain
   */

  constructor(chain) {
    super();

    this.chain = chain;
    this.network = chain.network;
    this.opened = false;
  }

  /**
   * Open the client.
   * @returns {Promise}
   */

  async open(options) {
    assert(!this.opened, 'NullClient is already open.');
    this.opened = true;
    setImmediate(() => this.emit('connect'));
  }

  /**
   * Close the client.
   * @returns {Promise}
   */

  async close() {
    assert(this.opened, 'NullClient is not open.');
    this.opened = false;
    setImmediate(() => this.emit('disconnect'));
  }

  /**
   * Get chain tip.
   * @returns {Promise}
   */

  async getTip() {
    const {hash, height, time} = this.network.genesis;
    return { hash, height, time };
  }

  /**
   * Get chain entry.
   * @param {Hash} hash
   * @returns {Promise} - Returns {@link ChainEntry}.
   */

  async getEntry(hash) {
    return { hash, height: 0, time: 0 };
  }

  /**
   * Get a coin (unspents only).
   * @param {Hash} hash
   * @param {Number} index
   * @returns {Promise} - Returns {@link Coin}.
   */

  async getCoin(hash, index) {
    return null;
  }

  /**
   * Get hash range.
   * @param {Number} start
   * @param {Number} end
   * @returns {Promise}
   */

  async getHashes(start = -1, end = -1) {
    return [this.network.genesis.hash];
  }

  /**
   * Get block
   * @param {Hash} hash
   * @returns {Promise}
   */

  async getBlock(hash) {
    return null;
  }

  /**
   * Get a historical block coin viewpoint.
   * @param {Block} hash
   * @returns {Promise} - Returns {@link CoinView}.
   */

  async getBlockView(block) {
    return null;
  }

  /**
   * Get coin viewpoint.
   * @param {TX} tx
   * @returns {Promise} - Returns {@link CoinView}.
   */

  async getCoinView(tx) {
    return null;
  }

  /**
   * Rescan for any missed blocks.
   * @param {Number} start - Start block.
   * @returns {Promise}
   */

  async rescan(start) {
    ;
  }
}

/*
 * Expose
 */

module.exports = NullClient;
