/*!
 * nodeclient.js - node client for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const AsyncEmitter = require('bevent');

/**
 * Node Client
 * @alias module:node.NodeClient
 */

class NodeClient extends AsyncEmitter {
  /**
   * Create a node client.
   * @constructor
   */

  constructor(node) {
    super();

    this.node = node;
    this.network = node.network;
    this.filter = null;
    this.opened = false;

    this.init();
  }

  /**
   * Initialize the client.
   */

  init() {
    this.node.chain.on('connect', (entry, block, view) => {
      if (!this.opened)
        return;

      this.emit('block connect', entry, block, view);
    });

    this.node.chain.on('disconnect', (entry, block, view) => {
      if (!this.opened)
        return;

      this.emit('block disconnect', entry, block, view);
    });

    this.node.on('tx', (tx) => {
      if (!this.opened)
        return;

      this.emit('tx', tx);
    });

    this.node.on('reset', (tip) => {
      if (!this.opened)
        return;

      this.emit('chain reset', tip);
    });
  }

  /**
   * Open the client.
   * @returns {Promise}
   */

  async open(options) {
    assert(!this.opened, 'NodeClient is already open.');
    this.opened = true;
    setImmediate(() => this.emit('connect'));
  }

  /**
   * Close the client.
   * @returns {Promise}
   */

  async close() {
    assert(this.opened, 'NodeClient is not open.');
    this.opened = false;
    setImmediate(() => this.emit('disconnect'));
  }

  /**
   * Add a listener.
   * @param {String} type
   * @param {Function} handler
   */

  bind(type, handler) {
    return this.on(type, handler);
  }

  /**
   * Add a listener.
   * @param {String} type
   * @param {Function} handler
   */

  hook(type, handler) {
    return this.on(type, handler);
  }

  /**
   * Get chain tip.
   * @returns {Promise}
   */

  async getTip() {
    return this.node.chain.tip;
  }

  /**
   * Get chain entry.
   * @param {Hash} hash
   * @returns {Promise}
   */

  async getEntry(hash) {
    const entry = await this.node.chain.getEntry(hash);

    if (!entry)
      return null;

    if (!await this.node.chain.isMainChain(entry))
      return null;

    return entry;
  }

  /**
   * Send a transaction. Do not wait for promise.
   * @param {TX} tx
   * @returns {Promise}
   */

  async send(tx) {
    this.node.relay(tx);
  }

  /**
   * Set bloom filter.
   * @param {Bloom} filter
   * @returns {Promise}
   */

  async setFilter(filter) {
    this.filter = filter;
    this.node.pool.setFilter(filter);
  }

  /**
   * Add data to filter.
   * @param {Buffer} data
   * @returns {Promise}
   */

  async addFilter(data) {
    this.node.pool.queueFilterLoad();
  }

  /**
   * Reset filter.
   * @returns {Promise}
   */

  async resetFilter() {
    this.node.pool.queueFilterLoad();
  }

  /**
   * Esimate smart fee.
   * @param {Number?} blocks
   * @returns {Promise}
   */

  async estimateFee(blocks) {
    if (!this.node.fees)
      return this.network.feeRate;

    return this.node.fees.estimateFee(blocks);
  }

  /**
   * Get hash range.
   * @param {Number} start
   * @param {Number} end
   * @returns {Promise}
   */

  async getHashes(start = -1, end = -1) {
    return this.node.chain.getHashes(start, end);
  }

  /**
   * Get block
   * @param {Hash} hash
   * @returns {Promise}
   */

  async getBlock(hash) {
    const block = await this.node.chain.getBlock(hash);

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
    const view  = this.node.chain.getBlockView(block);
    return view;
  }

  /**
   * Rescan for any missed blocks.
   * @param {Number} start - Start block.
   * @returns {Promise}
   */

  async rescan(start) {
    for (let i = start; ; i++) {
      const entry = await this.getEntry(i);
      if (!entry)
        break;

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

module.exports = NodeClient;
