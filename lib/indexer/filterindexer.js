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
const GCSFilter = require('golomb');

/*
 * FilterIndexer Database Layout:
 *  t[hash] -> extended filter
*/

Object.assign(layout, {
  g: bdb.key('g', ['hash256']),
  G: bdb.key('G', ['hash256']),
  x: bdb.key('x', ['hash256']),
  X: bdb.key('X', ['hash256'])
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

    const prevBasic = await this.getCFHeader(
      Buffer.from(block.prevBlock, 'hex'),
      common.FILTERS.REGULAR
    );
    const prevExt = await this.getCFHeader(
      Buffer.from(block.prevBlock, 'hex'),
      common.FILTERS.EXTENDED
    );

    let basicRaw;
    const basic = GCSFilter.fromBlock(block);
    if (basic.data.length > 0)
      basicRaw = basic.toRaw();
    b.put(layout.g.encode(hash), basicRaw);
    b.put(layout.G.encode(hash), basic.header(prevBasic));

    let extRaw;
    const ext = GCSFilter.fromExtended(block);
    if (ext.data.length > 0)
      extRaw = ext.toRaw();
    b.put(layout.x.encode(hash), extRaw);
    b.put(layout.X.encode(hash), ext.header(prevExt));

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
    b.del(layout.x(hash));
    b.del(layout.G(hash));
    b.del(layout.X(hash));

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
      case common.FILTERS.EXTENDED:
        pair = layout.x;
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
      case common.FILTERS.EXTENDED:
        pair = layout.X;
        break;
      default:
        assert(false, 'Bad filter type.');
        break;
    }
    const cfheader = await this.db.get(pair.encode(hash));
    assert(cfheader, `Missing cfheader ${hash.toString('hex')} ${type}.`);

    return cfheader;
  }
}

module.exports = FilterIndexer;
