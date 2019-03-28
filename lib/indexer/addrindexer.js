/*!
 * addrindexer.js - addr indexer
 * Copyright (c) 2018, the bcoin developers (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const bdb = require('bdb');
const bio = require('bufio');
const {BufferSet} = require('buffer-map');
const layout = require('./layout');
const Address = require('../primitives/address');
const Indexer = require('./indexer');

/*
 * AddrIndexer Database Layout:
 *  A[addr-prefix][addr-hash][height][index][hash] ->
 *      dummy (tx by address, height and index)
 *  a[addr-prefix][addr-hash][hash] ->
 *      (tx height and index by address and tx hash)
 *
 * The database layout is organized so that transactions are sorted in
 * the same order as the blocks (e.g. chronological order) using the block
 * height and transaction index. This provides the ability to query for
 * sets of transactions within that order. For a wallet that would like to
 * synchronize or rescan, this could be a query for all of the latest
 * transactions, but not for earlier transactions that are already known.
 * Furthermore, to be able to query for all transactions in multiple sets
 * without reference to height and index, there is a mapping from address
 * and tx hash to the height and index as an entry point to the
 * ordered transactions.
 */

Object.assign(layout, {
  A: bdb.key('A', ['uint8', 'hash', 'uint32', 'uint32', 'hash256']),
  a: bdb.key('a', ['uint8', 'hash', 'hash256'])
});

/**
 * Count
 */

class Count {
  /**
   * Create count record.
   * @constructor
   * @param {Number} height
   * @param {Number} index
   */

  constructor(height, index, coin) {
    this.height = height || 0;
    this.index = index || 0;

    assert((this.height >>> 0) === this.height);
    assert((this.index >>> 0) === this.index);
  }

  /**
   * Serialize.
   * @returns {Buffer}
   */

  toRaw() {
    const bw = bio.write(8);

    bw.writeU32(this.height);
    bw.writeU32(this.index);

    return bw.render();
  }

  /**
   * Deserialize.
   * @private
   * @param {Buffer} data
   */

  fromRaw(data) {
    const br = bio.read(data);

    this.height = br.readU32();
    this.index = br.readU32();

    return this;
  }

  /**
   * Instantiate a count from a buffer.
   * @param {Buffer} data
   * @returns {Count}
   */

  static fromRaw(data) {
    return new this().fromRaw(data);
  }
}

/**
 * AddrIndexer
 * @alias module:indexer.AddrIndexer
 * @extends Indexer
 */

class AddrIndexer extends Indexer {
  /**
   * Create a indexer
   * @constructor
   * @param {Object} options
   */

  constructor(options) {
    super('addr', options);

    this.db = bdb.create(this.options);
    this.maxTxs = options.maxTxs || 100;
  }

  /**
   * Index transactions by address.
   * @private
   * @param {ChainEntry} entry
   * @param {Block} block
   * @param {CoinView} view
   */

  async indexBlock(entry, block, view) {
    const b = this.db.batch();
    const height = entry.height;

    for (let i = 0; i < block.txs.length; i++) {
      const tx = block.txs[i];
      const hash = tx.hash();

      for (const addr of tx.getAddresses(view)) {
        const prefix = addr.getPrefix();
        const addrHash = addr.getHash();
        const count = new Count(height, i);

        b.put(layout.A.encode(prefix, addrHash, height, i, hash), null);
        b.put(layout.a.encode(prefix, addrHash, hash), count.toRaw());
      }
    }

    return b.write();
  }

  /**
   * Remove addresses from index.
   * @private
   * @param {ChainEntry} entry
   * @param {Block} block
   * @param {CoinView} view
   */

  async unindexBlock(entry, block, view) {
    const b = this.db.batch();
    const height = entry.height;

    for (let i = 0; i < block.txs.length; i++) {
      const tx = block.txs[i];
      const hash = tx.hash();

      for (const addr of tx.getAddresses(view)) {
        const prefix = addr.getPrefix();
        const addrHash = addr.getHash();
        b.del(layout.A.encode(prefix, addrHash, height, i, hash));
        b.del(layout.a.encode(prefix, addrHash, hash));
      }
    }

    return b.write();
  }

  /**
   * Get all transaction hashes to an address.
   * @param {Address} addr
   * @param {Object} options
   * @param {Boolean} options.limit
   * @param {Boolean} options.reverse
   * @returns {Promise} - Returns {@link Hash}[].
   */

  async getHashesByAddress(addr, options = {}) {
    const set = new BufferSet();

    const {reverse} = options;
    let {limit} = options;

    if (!limit)
      limit = this.maxTxs;

    if (limit > this.maxTxs)
      throw new Error('Limit above max of ${this.maxTxs}.');

    const hash = Address.getHash(addr);
    const prefix = addr.getPrefix();

    await this.db.keys({
      gte: layout.A.min(prefix, hash),
      lte: layout.A.max(prefix, hash),
      limit,
      reverse,
      parse: (key) => {
        const [,,,, txid] = layout.A.decode(key);
        set.add(txid);
      }
    });

    return set.toArray();
  }

  /**
   * Get all transaction hashes to an address after
   * a specific txid.
   * @param {Address} addr
   * @param {Object} options
   * @param {Buffer} options.txid
   * @param {Boolean} options.limit
   * @param {Boolean} options.reverse
   * @returns {Promise} - Returns {@link Hash}[].
   */

  async getHashesByAddressAfter(addr, options = {}) {
    const set = new BufferSet();

    const hash = Address.getHash(addr);
    const prefix = addr.getPrefix();

    const {txid, reverse} = options;
    let {limit} = options;

    if (!limit)
      limit = this.maxTxs;

    if (limit > this.maxTxs)
      throw new Error('Limit above max of ${this.maxTxs}.');

    const raw = await this.db.get(layout.a.encode(prefix, hash, txid));

    if (!raw)
      return [];

    const count = Count.fromRaw(raw);
    const {height, index} = count;

    const opts = {
      limit,
      reverse,
      parse: (key) => {
        const [,,,, txid] = layout.A.decode(key);
        set.add(txid);
      }
    };

    if (!reverse) {
      opts.gt = layout.A.min(prefix, hash, height, index, txid);
      opts.lte = layout.A.max(prefix, hash);
    } else {
      opts.gte = layout.A.min(prefix, hash);
      opts.lt = layout.A.max(prefix, hash, height, index, txid);
    }

    await this.db.keys(opts);

    return set.toArray();
  }
}

module.exports = AddrIndexer;
