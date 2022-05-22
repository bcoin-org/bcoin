/*!
 * filterindexer.js - filter indexer
 * Copyright (c) 2018, the bcoin developers (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const bdb = require('bdb');
const assert = require('bsert');
const Indexer = require('./indexer');
const layout = require('./layout');
const consensus = require('../protocol/consensus');
const Filter = require('../primitives/filter');
const path = require('path');
const {filters} = require('../blockstore/common');

/*
 * FilterIndexer Database Layout:
 *  f[hash] -> filter hash
 *
 *  The filter index db maps a filter hash to a block.
 *  The filters and the filter headers are themselves stored
 *  in the blockstore instead.
 */
Object.assign(layout, {
  f: bdb.key('f', ['hash256'])
});
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
    super(path.join('filter', options.filterType), options);

    this.db = bdb.create(this.options);
    this.filterType = filters[options.filterType];
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
    await this.blocks.writeFilter(prevHash, filter.toRaw(), this.filterType);

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
    const gcsFilter = block.toFilter(view, this.filterType);

    const filter = new Filter();
    filter.header = gcsFilter.header(prev);
    filter.filter = gcsFilter.toRaw();

    await this.blocks.writeFilter(hash, filter.toRaw(), this.filterType);

    this.put(layout.f.encode(hash), gcsFilter.hash());
  }

  /**
   * Prune compact filters.
   * @private
   * @param {BlockMeta} meta
   */

  async pruneBlock(meta) {
    this.del(layout.f.encode(meta.hash));
    await this.blocks.pruneFilter(meta.hash, this.filterType);
  }

  /**
   * Retrieve compact filter by hash.
   * @param {Hash} hash
   * @returns {Promise} - Returns {@link Filter}.
   */

  async getFilter(hash) {
    assert(hash);

    const filter = await this.blocks.readFilter(hash, this.filterType);
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

    return this.blocks.readFilterHeader(hash, this.filterType);
  }

  /**
   * Retrieve compact filter hash by block hash.
   * @param {Hash} hash
   * @returns {Promise} - Returns {@link Hash}.
   */

  async getFilterHash(hash) {
    assert(hash);

    return this.db.get(layout.f.encode(hash));
  }
}

module.exports = FilterIndexer;
