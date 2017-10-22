/*!
 * client.js - http client for wallets
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const {Client} = require('bcurl');

class HTTPClient extends Client {
  /**
   * Bcoin HTTP client.
   * @alias module:http.Client
   * @constructor
   * @param {String} uri
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
    return this.call('auth', this.password);
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
   * @returns {Promise} - Returns {@link Hash}[].
   */

  getMempool() {
    return this.get('/mempool');
  }

  /**
   * Get some info about the server (network and version).
   * @returns {Promise} - Returns Object.
   */

  getInfo() {
    return this.get('/');
  }

  /**
   * Get coins that pertain to an address from the mempool or chain database.
   * Takes into account spent coins in the mempool.
   * @param {String} address
   * @returns {Promise} - Returns {@link Coin}[].
   */

  getCoinsByAddress(address) {
    assert(typeof address === 'string');
    return this.get(`/coin/address/${address}`);
  }

  /**
   * Get coins that pertain to addresses from the mempool or chain database.
   * Takes into account spent coins in the mempool.
   * @param {String[]} addresses
   * @returns {Promise} - Returns {@link Coin}[].
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
   * @returns {Promise} - Returns {@link Coin}.
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
   * @returns {Promise} - Returns {@link TX}[].
   */

  getTXByAddress(address) {
    assert(typeof address === 'string');
    return this.get(`/tx/address/${address}`);
  }

  /**
   * Retrieve transactions pertaining to
   * addresses from the mempool or chain database.
   * @param {String[]} addresses
   * @returns {Promise} - Returns {@link TX}[].
   */

  getTXByAddresses(addresses) {
    assert(Array.isArray(addresses));
    return this.post('/tx/address', { addresses });
  }

  /**
   * Retrieve a transaction from the mempool or chain database.
   * @param {Hash} hash
   * @returns {Promise} - Returns {@link TX}.
   */

  getTX(hash) {
    assert(typeof hash === 'string');
    return this.get(`/tx/${hash}`);
  }

  /**
   * Retrieve a block from the chain database.
   * @param {Hash|Number} block
   * @returns {Promise} - Returns {@link Block}.
   */

  getBlock(block) {
    assert(typeof block === 'string' || typeof block === 'number');
    return this.get(`/block/${block}`);
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
   * @param {Hash} hash
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
   * @param {Bloom} filter
   * @returns {Promise}
   */

  setFilter(filter) {
    assert(Buffer.isBuffer(filter));
    return this.call('set filter', filter);
  }

  /**
   * Add data to filter.
   * @param {Buffer} data
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
   * Esimate smart fee.
   * @param {Number?} blocks
   * @returns {Promise}
   */

  estimateFee(blocks) {
    assert(blocks == null || typeof blocks === 'number');
    return this.call('estimate fee', blocks);
  }

  /**
   * Rescan for any missed transactions.
   * @param {Number|Hash} start - Start block.
   * @param {Bloom} filter
   * @param {Function} iter - Iterator.
   * @returns {Promise}
   */

  rescan(start) {
    if (start == null)
      start = 0;

    assert(typeof start === 'number' || typeof start === 'string');

    return this.call('rescan', start);
  }
}

/*
 * Expose
 */

module.exports = HTTPClient;
