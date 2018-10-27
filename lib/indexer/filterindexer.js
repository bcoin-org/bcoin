/*!
 * filterindexer.js - filter indexer
 * Copyright (c) 2018, the bcoin developers (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');
const bdb = require('bdb');
const layout = require('./layout');
const Indexer = require('./indexer');
const common = require('../net/common');
const consensus = require('../protocol/consensus');
const Block = require('../primitives/block');
const GCSFilter = require('golomb');

/*
 * FilterIndexer Database Layout:
 *  g[hash] -> basic filter
 *  G[hash] -> basic filter header
 *  H[hash] -> basic filter hash
*/

Object.assign(layout, {
  g: bdb.key('g', ['hash256']),
  G: bdb.key('G', ['hash256']),
  H: bdb.key('H', ['hash256'])
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
    super('filter', options);

    this.db = bdb.create(this.options);
  }

  async syncState() {
    await super.syncState();

    const b = this.db.batch();

    const genesis = this.network.genesisBlock;
    const block = Block.fromRaw(genesis, 'hex');
    const prevHash = Buffer.from(block.prevBlock);

    // Genesis prev filter headers are defined to be zero hashes
    b.put(layout.G.encode(prevHash), consensus.ZERO_HASH);

    await b.write();
  }

  /**
   * Index transactions by filterid.
   * @private
   * @param {ChainEntry} entry
   * @param {Block} block
   * @param {CoinView} view
   */

  async indexBlock(entry, block, view) {
    const b = this.db.batch();

    const hash = block.hash();

    const prevHeader = await this.getCFHeader(
      Buffer.from(block.prevBlock),
      common.FILTERS.REGULAR
    );

    const basic = GCSFilter.fromBlock(block, view);
    b.put(layout.g.encode(hash), basic.toRaw());
    b.put(layout.G.encode(hash), basic.header(prevHeader));
    b.put(layout.H.encode(hash), basic.hash());

    return b.write();
  }

  /**
   * Remove transactions from index.
   * @private
   * @param {ChainEntry} entry
   * @param {Block} block
   * @param {CoinView} view
   */

  async unindexBlock(entry, block, view) {
    const b = this.db.batch();

    const hash = block.hash();
    b.del(layout.g(hash));
    b.del(layout.G(hash));
    b.del(layout.H(hash));

    return b.write();
  }

  /**
   * Retrieve compact filter by hash and type..
   * @param {Hash} hash
   * @param {Number} type
   * @returns {Promise} - Returns {@link Buffer}.
   */

  async getCFilter(hash, type) {
    assert(hash);
    assert(typeof type === 'number');

    let pair;
    switch (type) {
      case common.FILTERS.REGULAR:
        pair = layout.g;
        break;
      default:
        assert(false, 'Bad filter type.');
        break;
    }
    const cfilter = await this.db.get(pair.encode(hash));
    assert(cfilter, `Missing cfilter ${hash.toString('hex')} ${type}.`);

    return cfilter;
  }

  /**
   * Retrieve compact filter header by hash and type..
   * @param {Hash} hash
   * @param {Number} type
   * @returns {Promise} - Returns {@link Hash}.
   */

  async getCFHeader(hash, type) {
    assert(hash);
    assert(typeof type === 'number');

    let pair;
    switch (type) {
      case common.FILTERS.REGULAR:
        pair = layout.G;
        break;
      default:
        assert(false, 'Bad filter type.');
        break;
    }
    const cfheader = await this.db.get(pair.encode(hash));
    assert(cfheader, `Missing cfheader ${hash.toString('hex')} ${type}.`);

    return cfheader;
  }

  /**
   * Retrieve compact filters by block hashes
   * @param {Number} type
   * @param {[]Hash} hashes
   * @returns {Promise} - Returns {@link []Hash}.
   */

  async getCFiltersByBlockHashes(type, hashes) {
    assert(typeof type === 'number');
    assert(Array.isArray(hashes));

    let pair;
    switch (type) {
      case common.FILTERS.REGULAR:
        pair = layout.g;
        break;
      default:
        assert(false, 'Bad filter type.');
        break;
    }

    const cfilters = [];
    for (const hash of hashes) {
      const cfilter = await this.db.get(pair.encode(hash));
      assert(cfilter, `Missing cfilter ${hash.toString('hex')} ${type}.`);
      cfilters.push(cfilter);
    }

    return cfilters;
  }

  /**
   * Retrieve compact filter headers by block hashes
   * @param {Number} type
   * @param {[]Hash} hashes
   * @returns {Promise} - Returns {@link []Hash}.
   */

  async getCFHeadersByBlockHashes(type, hashes) {
    assert(typeof type === 'number');
    assert(Array.isArray(hashes));

    let pair;
    switch (type) {
      case common.FILTERS.REGULAR:
        pair = layout.G;
        break;
      default:
        assert(false, 'Bad filter type.');
        break;
    }

    const cfheaders = [];
    for (const hash of hashes) {
      const cfheader = await this.db.get(pair.encode(hash));
      assert(cfheader, `Missing cfheader ${hash.toString('hex')} ${type}.`);
      cfheaders.push(cfheader);
    }

    return cfheaders;
  }

  /**
   * Retrieve compact filter hashes by block hashes
   * @param {Number} type
   * @param {[]Hash} hashes
   * @returns {Promise} - Returns {@link []Hash}.
   */

  async getCFilterHashesByBlockHashes(type, hashes) {
    assert(typeof type === 'number');
    assert(Array.isArray(hashes));

    let pair;
    switch (type) {
      case common.FILTERS.REGULAR:
        pair = layout.H;
        break;
      default:
        assert(false, 'Bad filter type.');
        break;
    }

    const filterHashes = [];
    for (const hash of hashes) {
      const filterHash = await this.db.get(pair.encode(hash));
      assert(filterHash, `Missing filterhash ${hash.toString('hex')} ${type}.`);
      filterHashes.push(filterHash);
    }

    return filterHashes;
  }
}

module.exports = FilterIndexer;
