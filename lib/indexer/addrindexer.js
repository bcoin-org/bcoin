/*!
 * addrindexer.js - addr indexer
 * Copyright (c) 2018, the bcoin developers (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const bdb = require('bdb');
const {BufferSet} = require('buffer-map');
const layout = require('./layout');
const Address = require('../primitives/address');
const Indexer = require('./indexer');

/*
 * AddrIndexer Database Layout:
 *  T[addr-hash][hash] -> dummy (tx by address)
 *  C[addr-hash][hash][index] -> dummy (coin by address)
*/

Object.assign(layout, {
  T: bdb.key('T', ['hash', 'hash256']),
  C: bdb.key('C', ['hash', 'hash256', 'uint32'])
});

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

    for (let i = 0; i < block.txs.length; i++) {
      const tx = block.txs[i];
      const hash = tx.hash();
      for (const addr of tx.getHashes(view))
        b.put(layout.T.encode(addr, hash), null);

      if (!tx.isCoinbase()) {
        for (const {prevout} of tx.inputs) {
          const {hash, index} = prevout;
          const coin = view.getOutput(prevout);
          assert(coin);

          const addr = coin.getHash();

          if (!addr)
            continue;

          b.del(layout.C.encode(addr, hash, index));
        }
      }

      for (let i = 0; i < tx.outputs.length; i++) {
        const output = tx.outputs[i];
        const addr = output.getHash();

        if (!addr)
          continue;

        b.put(layout.C.encode(addr, hash, i), null);
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
    for (let i = 0; i < block.txs.length; i++) {
      const tx = block.txs[i];
      const hash = tx.hash();
      for (const addr of tx.getHashes(view))
        b.del(layout.T.encode(addr, hash));

      if (!tx.isCoinbase()) {
        for (const {prevout} of tx.inputs) {
          const {hash, index} = prevout;
          const coin = view.getOutput(prevout);
          assert(coin);

          const addr = coin.getHash();

          if (!addr)
            continue;

          b.put(layout.C.encode(addr, hash, index), null);
        }
      }

      for (let i = 0; i < tx.outputs.length; i++) {
        const output = tx.outputs[i];
        const addr = output.getHash();

        if (!addr)
          continue;

        b.del(layout.C.encode(addr, hash, i));
      }
    }

    return b.write();
  }

  /**
   * Get all coins pertinent to an address.
   * @param {Address[]} addrs
   * @returns {Promise} - Returns {@link Coin}[].
   */

  async getCoinsByAddress(addrs) {
    if (!Array.isArray(addrs))
      addrs = [addrs];

    const coins = [];

    for (const addr of addrs) {
      const hash = Address.getHash(addr);

      const keys = await this.db.keys({
        gte: layout.C.min(hash),
        lte: layout.C.max(hash),
        parse: (key) => {
          const [, txid, index] = layout.C.decode(key);
          return [txid, index];
        }
      });

      for (const [hash, index] of keys) {
        const coin = await this.client.getCoin(hash, index);
        assert(coin);
        coins.push(coin);
      }
    }

    return coins;
  }

  /**
   * Get all transaction hashes to an address.
   * @param {Address[]} addrs
   * @returns {Promise} - Returns {@link Hash}[].
   */

  async getHashesByAddress(addrs) {
    const set = new BufferSet();

    for (const addr of addrs) {
      const hash = Address.getHash(addr);

      await this.db.keys({
        gte: layout.T.min(hash),
        lte: layout.T.max(hash),
        parse: (key) => {
          const [, txid] = layout.T.decode(key);
          set.add(txid);
        }
      });
    }

    return set.toArray();
  }
}

module.exports = AddrIndexer;
