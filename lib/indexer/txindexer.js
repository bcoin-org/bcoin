/*!
 * txindexer.js - tx indexer
 * Copyright (c) 2018, the bcoin developers (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const bdb = require('bdb');
const layout = require('./layout');
const TXMeta = require('../primitives/txmeta');
const Indexer = require('./indexer');

/*
 * TXIndexer Database Layout:
 *  t[hash] -> extended tx
*/

Object.assign(layout, {
  t: bdb.key('t', ['hash256'])
});

/**
 * TXIndexer
 * @alias module:indexer.TXIndexer
 * @extends Indexer
 */

class TXIndexer extends Indexer {
  /**
   * Create a indexer
   * @constructor
   * @param {Object} options
   */

  constructor(options) {
    super('tx', options);

    this.db = bdb.create(this.options);
  }

  /**
   * Index transactions by txid.
   * @private
   * @param {ChainEntry} entry
   * @param {Block} block
   * @param {CoinView} view
   */

  async indexBlock(entry, block, view) {
    const b = this.db.batch();

    for (let i = 0; i < block.txs.length; i++) {
      const tx = block.txs[i];
      const hash = tx.hash();
      const meta = TXMeta.fromTX(tx, entry, i);
      b.put(layout.t.encode(hash), meta.toRaw());
    }

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

    for (let i = 0; i < block.txs.length; i++) {
      const tx = block.txs[i];
      const hash = tx.hash();
      b.del(layout.t.encode(hash));
    }

    return b.write();
  }

  /**
   * Get a transaction with metadata.
   * @param {Hash} hash
   * @returns {Promise} - Returns {@link TXMeta}.
   */

  async getMeta(hash) {
    const data = await this.db.get(layout.t.encode(hash));

    if (!data)
      return null;

    return TXMeta.fromRaw(data);
  }

  /**
   * Retrieve a transaction.
   * @param {Hash} hash
   * @returns {Promise} - Returns {@link TX}.
   */

  async getTX(hash) {
    const meta = await this.getMeta(hash);

    if (!meta)
      return null;

    return meta.tx;
  }

  /**
   * @param {Hash} hash
   * @returns {Promise} - Returns Boolean.
   */

  async hasTX(hash) {
    return this.db.has(layout.t.encode(hash));
  }

  /**
   * Get coin viewpoint (historical).
   * @param {TX} tx
   * @returns {Promise} - Returns {@link CoinView}.
   */

  async getSpentView(tx) {
    const view = await this.client.getCoinView(tx);

    for (const {prevout} of tx.inputs) {
      if (view.hasEntry(prevout))
        continue;

      const {hash, index} = prevout;
      const meta = await this.getMeta(hash);

      if (!meta)
        continue;

      const {tx, height} = meta;

      if (index < tx.outputs.length)
        view.addIndex(tx, index, height);
    }

    return view;
  }
}

module.exports = TXIndexer;
