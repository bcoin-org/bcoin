/*!
 * node.js - http node client for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');
const {Client} = require('bcurl');

/**
 * Node Client
 * @alias module:client.NodeClient
 * @extends {bcurl.Client}
 */

class NodeClient extends Client {
  /**
   * Creat a node client.
   * @param {Object?} options
   */

  constructor(options) {
    super(options);
  }

  /**
   * Auth with server.
   * @returns {Promise}
   */

  async auth() {
    await this.call('auth', this.password);
    await this.watchChain();
    await this.watchMempool();
  }

  /**
   * Make an RPC call.
   * @returns {Promise}
   */

  execute(name, params) {
    return super.execute('/', name, params);
  }

  /**
   * Get a mempool snapshot.
   * @returns {Promise}
   */

  getMempool() {
    return this.get('/mempool');
  }

  /**
   * Get some info about the server (network and version).
   * @returns {Promise}
   */

  getInfo() {
    return this.get('/');
  }

  /**
   * Get coins that pertain to an address from the mempool or chain database.
   * Takes into account spent coins in the mempool.
   * @param {String} address
   * @returns {Promise}
   */

  getCoinsByAddress(address) {
    assert(typeof address === 'string');
    return this.get(`/coin/address/${address}`);
  }

  /**
   * Get coins that pertain to addresses from the mempool or chain database.
   * Takes into account spent coins in the mempool.
   * @param {String[]} addresses
   * @returns {Promise}
   */

  getCoinsByAddresses(addresses) {
    assert(Array.isArray(addresses));
    return this.post('/coin/address', { addresses });
  }

  /**
   * Retrieve a coin from the mempool or chain database.
   * Takes into account spent coins in the mempool.
   * @param {Hash} hash
   * @param {Number} index
   * @returns {Promise}
   */

  getCoin(hash, index) {
    assert(typeof hash === 'string');
    assert((index >>> 0) === index);
    return this.get(`/coin/${hash}/${index}`);
  }

  /**
   * Retrieve transactions pertaining to an
   * address from the mempool or chain database.
   * @param {String} address
   * @returns {Promise}
   */

  getTXByAddress(address) {
    assert(typeof address === 'string');
    return this.get(`/tx/address/${address}`);
  }

  /**
   * Retrieve transactions pertaining to
   * addresses from the mempool or chain database.
   * @param {String[]} addresses
   * @returns {Promise}
   */

  getTXByAddresses(addresses) {
    assert(Array.isArray(addresses));
    return this.post('/tx/address', { addresses });
  }

  /**
   * Retrieve a transaction from the mempool or chain database.
   * @param {Hash} hash
   * @returns {Promise}
   */

  getTX(hash) {
    assert(typeof hash === 'string');
    return this.get(`/tx/${hash}`);
  }

  /**
   * Retrieve a block from the chain database.
   * @param {Hash|Number} block
   * @returns {Promise}
   */

  getBlock(block) {
    assert(typeof block === 'string' || typeof block === 'number');
    return this.get(`/block/${block}`);
  }

  /**
   * Retrieve a block header.
   * @param {Hash|Number} block
   * @returns {Promise}
   */

  getBlockHeader(block) {
    assert(typeof block === 'string' || typeof block === 'number');
    return this.get(`/header/${block}`);
  }

  /**
   * Retreive a filter from the filter indexer.
   * @param {Hash|Number} filter
   * @returns {Promise}
   */

  getFilter(filter) {
    assert(typeof filter === 'string' || typeof filter === 'number');
    return this.get(`/filter/${filter}`);
  }

  /**
   * Add a transaction to the mempool and broadcast it.
   * @param {TX} tx
   * @returns {Promise}
   */

  broadcast(tx) {
    assert(typeof tx === 'string');
    return this.post('/broadcast', { tx });
  }

  /**
   * Reset the chain.
   * @param {Number} height
   * @returns {Promise}
   */

  reset(height) {
    return this.post('/reset', { height });
  }

  /**
   * Watch the blockchain.
   * @private
   * @returns {Promise}
   */

  watchChain() {
    return this.call('watch chain');
  }

  /**
   * Watch the blockchain.
   * @private
   * @returns {Promise}
   */

  watchMempool() {
    return this.call('watch mempool');
  }

  /**
   * Get chain tip.
   * @returns {Promise}
   */

  getTip() {
    return this.call('get tip');
  }

  /**
   * Get chain entry.
   * @param {Hash} block
   * @returns {Promise}
   */

  getEntry(block) {
    return this.call('get entry', block);
  }

  /**
   * Get hashes.
   * @param {Number} [start=-1]
   * @param {Number} [end=-1]
   * @returns {Promise}
   */

  getHashes(start, end) {
    return this.call('get hashes', start, end);
  }

  /**
   * Send a transaction. Do not wait for promise.
   * @param {TX} tx
   * @returns {Promise}
   */

  send(tx) {
    assert(Buffer.isBuffer(tx));
    return this.call('send', tx);
  }

  /**
   * Set bloom filter.
   * @param {BloomFilter} filter
   * @returns {Promise}
   */

  setFilter(filter) {
    assert(Buffer.isBuffer(filter));
    return this.call('set filter', filter);
  }

  /**
   * Add data to filter.
   * @param {Buffer|Buffer[]} chunks
   * @returns {Promise}
   */

  addFilter(chunks) {
    if (!Array.isArray(chunks))
      chunks = [chunks];

    return this.call('add filter', chunks);
  }

  /**
   * Reset filter.
   * @returns {Promise}
   */

  resetFilter() {
    return this.call('reset filter');
  }

  /**
   * Estimate smart fee.
   * @param {Number?} blocks
   * @returns {Promise}
   */

  estimateFee(blocks) {
    assert(blocks == null || typeof blocks === 'number');
    let query = '/fee';
    if (blocks != null)
      query += `?blocks=${blocks}`;
    return this.get(query);
  }

  /**
   * Rescan for any missed transactions.
   * @param {Number|Hash} start - Start block.
   * @returns {Promise}
   */

  rescan(start) {
    if (start == null)
      start = 0;

    assert(typeof start === 'number' || typeof start === 'string');

    return this.call('rescan', start);
  }

  /**
   * Abort scanning blockchain
   * @returns {Promise}
   */

  abortRescan() {
    return this.call('abortrescan');
  }
}

/*
 * Expose
 */

module.exports = NodeClient;
