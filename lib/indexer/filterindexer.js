/*!
 * filterindexer.js - filter indexer
 * Copyright (c) 2018, the bcoin developers (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const bdb = require('bdb');
const assert = require('bsert');
const Indexer = require('./indexer');
const consensus = require('../protocol/consensus');
const Filter = require('../primitives/filter');

/**
 * FilterIndexer
 * @alias module:indexer.FilterIndexer
 * @extends Indexer
 */

class FilterIndexer extends Indexer {
  /**
   * Create a indexer
   * @constructor
   * @param {Object} options
   */

  constructor(options) {
    super('filter', options);

    this.db = bdb.create(this.options);
  }

  /**
   * Store genesis previous filter header.
   * @private
   * @returns {Promise}
   */

  async saveGenesis() {
    const prevHash = this.network.genesis.prevBlock;

    // Genesis prev filter headers are defined to be zero hashes
    const filter = new Filter();
    filter.header = consensus.ZERO_HASH;
    await this.blocks.writeFilter(prevHash, filter.toRaw());

    await super.saveGenesis();
  }

  /**
   * Index compact filters.
   * @private
   * @param {BlockMeta} meta
   * @param {Block} block
   * @param {CoinView} view
   */

  async indexBlock(meta, block, view) {
    const hash = block.hash();
    const prev = await this.getFilterHeader(block.prevBlock);
    const basic = block.toFilter(view);

    const filter = new Filter();
    filter.header = basic.header(prev);
    filter.filter = basic.toRaw();
    await this.blocks.writeFilter(hash, filter.toRaw());
  }

  /**
   * Prune compact filters.
   * @private
   * @param {BlockMeta} meta
   */

  async pruneBlock(meta) {
    await this.blocks.pruneFilter(meta.hash);
  }

  /**
   * Retrieve compact filter by hash.
   * @param {Hash} hash
   * @param {Number} type
   * @returns {Promise} - Returns {@link Filter}.
   */

  async getFilter(hash) {
    assert(hash);

    const filter = await this.blocks.readFilter(hash);
    if (!filter)
      return null;

    return Filter.fromRaw(filter);
  }

  /**
   * Retrieve compact filter header by hash.
   * @param {Hash} hash
   * @returns {Promise} - Returns {@link Hash}.
   */

  async getFilterHeader(hash) {
    assert(hash);

    return this.blocks.readFilterHeader(hash);
  }
}

module.exports = FilterIndexer;
