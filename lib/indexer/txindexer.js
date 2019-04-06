/*!
 * txindexer.js - tx indexer
 * Copyright (c) 2018, the bcoin developers (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');
const bdb = require('bdb');
const bio = require('bufio');
const layout = require('./layout');
const consensus = require('../protocol/consensus');
const TX = require('../primitives/tx');
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
 * Transaction Record
 */

class TxRecord {
  /**
   * Create a block record.
   * @constructor
   */

  constructor(options = {}) {
    this.block = options.block || consensus.ZERO_HASH;
    this.height = options.height || 0;
    this.time = options.time || 0;
    this.index = options.index || 0;
    this.offset = options.offset || 0;
    this.length = options.length || 0;

    assert((this.height >>> 0) === this.height);
    assert((this.time >>> 0) === this.time);
    assert((this.index >>> 0) === this.index);
    assert((this.offset >>> 0) === this.offset);
    assert((this.length >>> 0) === this.length);
  }

  /**
   * Inject properties from serialized data.
   * @private
   * @param {Buffer} data
   */

  fromRaw(data) {
    const br = bio.read(data);

    this.block = br.readHash();
    this.height = br.readU32();
    this.time = br.readU32();
    this.index = br.readU32();
    if (this.index === 0x7fffffff)
      this.index = -1;

    this.offset = br.readU32();
    this.length = br.readU32();

    return this;
  }

  /**
   * Instantiate block record from serialized data.
   * @param {Hash} hash
   * @param {Buffer} data
   * @returns {BlockRecord}
   */

  static fromRaw(data) {
    return new this().fromRaw(data);
  }

  /**
   * Serialize the block record.
   * @returns {Buffer}
   */

  toRaw() {
    const bw = bio.write(52);

    bw.writeHash(this.block);
    bw.writeU32(this.height);
    bw.writeU32(this.time);
    bw.writeU32(this.index);
    bw.writeU32(this.offset);
    bw.writeU32(this.length);

    return bw.render();
  }
}

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
    for (let i = 0; i < block.txs.length; i++) {
      const tx = block.txs[i];

      const hash = tx.hash();
      const {offset, size} = tx.getPosition();

      const txrecord = new TxRecord({
        block: entry.hash,
        height: entry.height,
        time: entry.time,
        index: i,
        offset: offset,
        length: size
      });

      this.put(layout.t.encode(hash), txrecord.toRaw());
    }
  }

  /**
   * Remove transactions from index.
   * @private
   * @param {ChainEntry} entry
   * @param {Block} block
   * @param {CoinView} view
   */

  async unindexBlock(entry, block, view) {
    for (let i = 0; i < block.txs.length; i++) {
      const tx = block.txs[i];
      const hash = tx.hash();
      this.del(layout.t.encode(hash));
    }
  }

  /**
   * Get a transaction with metadata.
   * @param {Hash} hash
   * @returns {Promise} - Returns {@link TXMeta}.
   */

  async getMeta(hash) {
    const raw = await this.db.get(layout.t.encode(hash));
    if (!raw)
      return null;

    const record = TxRecord.fromRaw(raw);
    const {block, offset, length} = record;

    const data = await this.blocks.read(block, offset, length);

    const tx = TX.fromRaw(data);

    const meta = TXMeta.fromTX(tx);
    meta.height = record.height;
    meta.block = record.block;
    meta.time = record.time;
    meta.index = record.index;

    return meta;
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
    const view = await this.chain.getCoinView(tx);

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
