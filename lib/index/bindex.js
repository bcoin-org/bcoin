/*!
 * index.js - index for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const EventEmitter = require('events');
const IndexDB = require('./indexdb');

/**
 * Index
 */

class Index extends EventEmitter {
  /**
   * Create a plugin.
   * @constructor
   * @param {Options} options
   */

  constructor(options) {
    super();

    this.db = new IndexDB(options);
    this.options = this.db.options;
    this.init();
  }

  init() {
    this.db.on('error', err => this.emit('error', err));
  }

  /**
   * Open the index
   * @returns {Promise}
   */

  async open() {
    await this.db.open();
  }

  /**
   * Close the index
   * @returns {Promise}
   */

  async close() {
    await this.db.close();
  }

  /**
   * Get tip.
   * @param {Hash} hash
   * @returns {Promise}
   */

  getTip() {
    return this.db.getTip();
  }

  /**
   * Get a transaction with metadata.
   * @param {Hash} hash
   * @returns {Promise} - Returns {@link TXMeta}.
   */

  getMeta(hash) {
    return this.db.getMeta(hash);
  }

  /**
   * Retrieve a transaction.
   * @param {Hash} hash
   * @returns {Promise} - Returns {@link TX}.
   */

  getTX(hash) {
    return this.db.getTX(hash);
  }

  /**
   * @param {Hash} hash
   * @returns {Promise} - Returns Boolean.
   */

  hasTX(hash) {
    return this.db.hasTX(hash);
  }

  /**
   * Get all coins pertinent to an address.
   * @param {Address[]} addrs
   * @returns {Promise} - Returns {@link Coin}[].
   */

  getCoinsByAddress(addrs) {
    return this.db.getCoinsByAddress(addrs);
  }

  /**
   * Get all transaction hashes to an address.
   * @param {Address[]} addrs
   * @returns {Promise} - Returns {@link Hash}[].
   */

  getHashesByAddress(addrs) {
    return this.db.getHashesByAddress(addrs);
  }

  /**
   * Get all transactions pertinent to an address.
   * @param {Address[]} addrs
   * @returns {Promise} - Returns {@link TX}[].
   */

  getTXByAddress(addrs) {
    return this.db.getTXByAddress(addrs);
  }

  /**
   * Get all transactions pertinent to an address.
   * @param {Address[]} addrs
   * @returns {Promise} - Returns {@link TXMeta}[].
   */

  getMetaByAddress(addrs) {
    return this.db.getMetaByAddress(addrs);
  }

  /**
   * Retrieve compact filter by hash and type..
   * @param {Hash} hash
   * @param {Number} type
   * @returns {Promise} - Returns {@link Buffer}.
   */

   getCFilter(hash, type) {
     return this.db.getCFilter(hash, type);
  }

  /**
   * Retrieve compact filter header by hash and type..
   * @param {Hash} hash
   * @param {Number} type
   * @returns {Promise} - Returns {@link Hash}.
   */

   getCFHeader(hash, type) {
     return this.db.getCFHeader(hash, type);
  }
}

/*
 * Expose
 */

module.exports = Index;
