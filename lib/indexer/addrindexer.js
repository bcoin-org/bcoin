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
 *  T[addr-hash][height][tx-index][hash] -> dummy (tx by address)
 *  C[addr-hash][height][tx-index][hash][coin-index] -> dummy (coin by address)
 *  x[addr-hash][hash] -> height and tx-index for tx
 *  y[addr-hash][hash][index] -> height, tx-index and coin-index for coin
*/

Object.assign(layout, {
  T: bdb.key('T', ['hash', 'uint32', 'uint32', 'hash256']),
  C: bdb.key('C', ['hash', 'uint32', 'uint32', 'hash256', 'uint32']),
  x: bdb.key('x', ['hash', 'hash256']),
  y: bdb.key('y', ['hash', 'hash256', 'uint32'])
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
    this.height = height >= 0 ? height : 0;
    this.index = index >= 0 ? index : 0;
    this.coin = coin >= 0 ? coin : -1;

    assert((this.height >>> 0) === this.height);
    assert((this.index >>> 0) === this.index);

    if (coin)
      assert((this.coin >>> 0) === this.coin);
  }

  /**
   * Serialize.
   * @returns {Buffer}
   */

  toRaw() {
    let len = 8;
    if (this.coin >= 0)
      len += 4;

    const bw = bio.write(len);

    bw.writeU32(this.height);
    bw.writeU32(this.index);

    if (this.coin >= 0)
      bw.writeU32(this.coin);

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

    if (br.left() >= 4)
      this.coin = br.readU32();

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
    this.maxCoins = options.maxCoins || 500;
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

      for (const addr of tx.getHashes(view)) {
        const count = new Count(height, i);

        b.put(layout.T.encode(addr, height, i, hash), null);
        b.put(layout.x.encode(addr, hash), count.toRaw());
      }

      if (!tx.isCoinbase()) {
        for (const {prevout} of tx.inputs) {
          const {hash, index} = prevout;
          const coin = view.getOutput(prevout);
          assert(coin);

          const addr = coin.getHash();

          if (!addr)
            continue;

          b.del(layout.C.encode(addr, height, i, hash, index));
          b.del(layout.y.encode(addr, hash, index));
        }
      }

      for (let j = 0; j < tx.outputs.length; j++) {
        const output = tx.outputs[j];
        const addr = output.getHash();

        if (!addr)
          continue;

        const count = new Count(height, i, j);

        b.put(layout.C.encode(addr, height, i, hash, j), null);
        b.put(layout.y.encode(addr, hash, j), count.toRaw());
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

      for (const addr of tx.getHashes(view)) {
        b.del(layout.T.encode(addr, height, i, hash));
        b.del(layout.x.encode(addr, hash));
      }

      if (!tx.isCoinbase()) {
        for (const {prevout} of tx.inputs) {
          const {hash, index} = prevout;
          const coin = view.getOutput(prevout);
          assert(coin);

          const addr = coin.getHash();

          if (!addr)
            continue;

          const count = new Count(height, i);

          b.put(layout.C.encode(addr, height, i, hash, index), null);
          b.put(layout.y.encode(addr, hash, index), count.toRaw());
        }
      }

      for (let j = 0; j < tx.outputs.length; j++) {
        const output = tx.outputs[j];
        const addr = output.getHash();

        if (!addr)
          continue;

        b.del(layout.C.encode(addr, height, i, hash, j));
        b.del(layout.y.encode(addr, hash, j));
      }
    }

    return b.write();
  }

  /**
   * Get all coins pertinent to an address.
   * @param {Address} addr
   * @param {Object} options
   * @param {Boolean} options.reverse
   * @param {Boolean} options.limit
   * @returns {Promise} - Returns {@link Coin}[].
   */

  async getCoinsByAddress(addr, options = {}) {
    const coins = [];

    const {reverse} = options;
    let {limit} = options;

    if (!limit)
      limit = this.maxCoins;

    if (limit > this.maxCoins)
      throw new Error('Limit above max of ${this.maxCoins}.');

    const hash = Address.getHash(addr);

    const keys = await this.db.keys({
      gte: layout.C.min(hash),
      lte: layout.C.max(hash),
      limit,
      reverse,
      parse: (key) => {
        const [,,, txid, index] = layout.C.decode(key);
        return [txid, index];
      }
    });

    for (const [hash, index] of keys) {
      const coin = await this.chain.getCoin(hash, index);
      assert(coin);
      coins.push(coin);
    }

    return coins;
  }

  /**
   * Get all coins pertinent to an address after a
   * specific txid and output/coin index.
   * @param {Address} addr
   * @param {Object} options
   * @param {Buffer} options.txid
   * @param {Number} options.index
   * @param {Boolean} options.limit
   * @param {Boolean} options.reverse
   * @returns {Promise} - Returns {@link Coin}[].
   */

  async getCoinsByAddressAfter(addr, options = {}) {
    const coins = [];

    const {txid, index, reverse} = options;
    let {limit} = options;

    if (!limit)
      limit = this.maxCoins;

    if (limit > this.maxCoins)
      throw new Error('Limit above max of ${this.maxCoins}.');

    const hash = Address.getHash(addr);

    const raw = await this.db.get(layout.y.encode(hash, txid, index));

    if (!raw)
      return coins;

    const count = Count.fromRaw(raw);

    const opts = {
      limit,
      reverse,
      parse: (key) => {
        const [,,, txid, index] = layout.C.decode(key);
        return [txid, index];
      }
    };

    if (!reverse) {
      opts.gt = layout.C.min(hash, count.height, count.index, txid, count.coin);
      opts.lte = layout.C.max(hash);
    } else {
      opts.gte = layout.C.min(hash);
      opts.lt = layout.C.max(hash, count.height, count.index, txid, count.coin);
    }

    const keys = await this.db.keys(opts);

    for (const [hash, index] of keys) {
      const coin = await this.chain.getCoin(hash, index);
      assert(coin);
      coins.push(coin);
    }

    return coins;
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

    await this.db.keys({
      gte: layout.T.min(hash),
      lte: layout.T.max(hash),
      limit,
      reverse,
      parse: (key) => {
        const [,,, txid] = layout.T.decode(key);
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

    const {txid, reverse} = options;
    let {limit} = options;

    if (!limit)
      limit = this.maxTxs;

    if (limit > this.maxTxs)
      throw new Error('Limit above max of ${this.maxTxs}.');

    const raw = await this.db.get(layout.x.encode(hash, txid));

    if (!raw)
      return [];

    const count = Count.fromRaw(raw);
    const {height, index} = count;

    const opts = {
      limit,
      reverse,
      parse: (key) => {
        const [,,, txid] = layout.T.decode(key);
        set.add(txid);
      }
    };

    if (!reverse) {
      opts.gt = layout.T.min(hash, height, index, txid);
      opts.lte = layout.T.max(hash);
    } else {
      opts.gte = layout.T.min(hash);
      opts.lt = layout.T.max(hash, height, index, txid);
    }

    await this.db.keys(opts);

    return set.toArray();
  }
}

module.exports = AddrIndexer;
