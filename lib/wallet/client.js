/*!
 * client.js - http client for wallets
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const {Client} = require('bcurl');
const TX = require('../primitives/tx');
const Headers = require('../primitives/headers');
const util = require('../utils/util');
const BufferReader = require('../utils/reader');

class WalletClient extends Client {
  /**
   * Bcoin HTTP client.
   * @alias module:wallet.WalletClient
   * @constructor
   * @param {Object|String} options
   */

  constructor(options) {
    super(options);
  }

  /**
   * Open the client, wait for socket to connect.
   * @returns {Promise}
   */

  async open() {
    await super.open();

    this.on('error', (err) => {
      this.emit('error', err);
    });

    this.listen('block connect', (entry, txs) => {
      this.emit('block connect', ...parseBlock(entry, txs));
    });

    this.listen('block disconnect', (entry) => {
      this.emit('block disconnect', parseEntry(entry));
    });

    this.listen('block rescan', (entry, txs) => {
      this.emit('block rescan', ...parseBlock(entry, txs));
    });

    this.listen('chain reset', (tip) => {
      this.emit('chain reset', parseEntry(tip));
    });

    this.listen('tx', (tx) => {
      this.emit('tx', TX.fromRaw(tx));
    });

    await this.watchChain();
    await this.watchMempool();
  }

  /**
   * Auth with server.
   * @private
   * @returns {Promise}
   */

  auth() {
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

  async getTip() {
    const raw = await this.call('get tip');
    return parseEntry(raw);
  }

  /**
   * Get chain entry.
   * @param {Hash} hash
   * @returns {Promise}
   */

  async getEntry(block) {
    if (typeof block === 'string')
      block = util.revHex(block);

    const raw = await this.call('get entry', block);
    return parseEntry(raw);
  }

  /**
   * Get hashes.
   * @param {Number} [start=-1]
   * @param {Number} [end=-1]
   * @returns {Promise}
   */

  getHashes(start = -1, end = -1) {
    return this.call('get hashes', start, end);
  }

  /**
   * Send a transaction. Do not wait for promise.
   * @param {TX} tx
   * @returns {Promise}
   */

  send(tx) {
    return this.call('send', tx.toRaw());
  }

  /**
   * Set bloom filter.
   * @param {Bloom} filter
   * @returns {Promise}
   */

  setFilter(filter) {
    return this.call('set filter', filter.toRaw());
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
    if (typeof start === 'string')
      start = util.revHex(start);

    return this.call('rescan', start);
  }
}

/*
 * Helpers
 */

function parseEntry(data) {
  const block = Headers.fromHead(data);

  const br = new BufferReader(data);
  br.seek(80);

  const height = br.readU32();
  const hash = block.hash('hex');

  return { hash, height, time: block.time };
}

function parseBlock(entry, txs) {
  const block = parseEntry(entry);
  const out = [];

  for (const raw of txs) {
    const tx = TX.fromRaw(raw);
    out.push(tx);
  }

  return [block, out];
}

/*
 * Expose
 */

module.exports = WalletClient;
