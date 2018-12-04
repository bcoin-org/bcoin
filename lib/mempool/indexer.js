/*!
 * mempool/index.js - mempool for bcoin
 * Copyright (c) 2018, the bcoin developers (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');
const {BufferMap} = require('buffer-map');
const Address = require('../primitives/address');
const Outpoint = require('../primitives/outpoint');
const TXMeta = require('../primitives/txmeta');
const Coin = require('../primitives/coin');

/**
 * Mempool indexer
 * Handles TXIndex and CoinIndex for looking up by address.
 *
 * Coin index in mempool keeps track of the coins available for an address
 * in the mempool, those that have not been indexed by chain indexer yet.
 *
 * There are several reasons transaction can be added or removed from the
 * mempool, as well as coins associated with addresses with it.
 *  - Transaction was received from the network or orphan got resolved:
 *    - events: add entry and tx
 *    - We want to remove coins that are in tx inputs.
 *      If there are any - Meaning they are spending transaction in mempool
 *    - We want to add outputs as coins in the mempool.
 *    - If outputs are resolving orphans those orphans will be added via same
 *      events (tx and add entry)
 *  - Transaction was included in block
 *    - events: `remove entry` and `confirmed` OR `double spend`
 *      (Can potentially resolve orphans)
 *    - if tx was confirmed we wont have tx.hash() in the mempool,
 *      so we can leave things to removeEntry.
 *    - On double spend transaction that was spent in mempool
 *      will get unindexed(remove entry), which will recover
 *      all coins that are in the mempool. (inputs that were
 *      double spent wont be in the mempool (getTX will fail).
 *  - Transaction was removed because of memory constraints
 *    - events: `remove entry`
 *    - In this case we want to recover inputs as coins
 *  - on reorganization we need to also clean up coins
 *    - events: `unconfirmed` and `add entry` + `tx`
 *    - add tx creates new coins
 *    - on unconfirmed we need to recover outputs as coins
 *      (Unless they are not spent in mempool)
 *
 * We don't need to take care of conflict as
 * that event prevents tx from entering the mempool.
 *
 * and orphan related events as they are not part of
 * the coin or tx indexers as orphans.
 *
 *
 * @alias module:mempool.MempoolIndexer
 */

class MempoolIndexer {
  /**
   * Create a mempool indexer.
   * @param {Mempool} mempool
   */

  constructor(options) {
    this.options = new MempoolIndexerOptions(options);
    this.mempool = this.options.mempool;

    this.coinIndex = new CoinIndex();
    this.txIndex = new TXIndex();

    this.init();
  }

  /**
   * Start listening for the mempool events
   */

  init() {
    this.mempool.on('unconfirmed', (tx, block) => this.unconfirmed(tx, block));
    this.mempool.on('add entry', (entry, view) => this.addEntry(entry, view));
    this.mempool.on('remove entry', entry => this.removeEntry(entry));
  }

  /**
   * We have new entry in the mempool.
   * `add entry` is emitted after `tx`.
   * We can index coins.
   * - We received it from the network.
   * - Block was disconnected.
   * - Orphan got resolved
   * @param {MempoolEntry} entry
   * @param {CoinView} view
   */

  addEntry(entry, view) {
    const tx = entry.tx;

    this.txIndex.insert(entry, view);

    for (const {prevout} of tx.inputs) {
      const {hash, index} = prevout;

      this.coinIndex.remove(hash, index);
    }

    for (let i = 0; i < tx.outputs.length; i++)
      this.coinIndex.insert(tx, i);
  }

  /**
   * Transaction was removed from mempool.
   * This might happen for several reasons:
   *  - Mempool size limit got rid of it.
   *  - Transaction was included in block.
   *  - Double spend in a block
   *  - After reorg tx is no longer final
   * We concentrate on recovering inputs as coins.
   * @param {MempoolEntry} entry
   */

  removeEntry(entry) {
    const tx = entry.tx;
    const hash = tx.hash();

    this.txIndex.remove(hash);

    for (const {prevout} of tx.inputs) {
      const {hash, index} = prevout;
      const prev = this.mempool.getTX(hash);

      if (!prev)
        continue;

      this.coinIndex.insert(prev, index);
    }

    for (let i = 0; i < tx.outputs.length; i++)
      this.coinIndex.remove(hash, i);
  }

  /**
   * Block disconnected and we recover coins if they are available.
   * This event comes after `tx` and `add entry`, we might want to
   * check if outputs indexed by those are already spent in the mempool.
   * @param {TX} tx
   * @param {Block} block
   */

  unconfirmed(tx, block) {
    const hash = tx.hash();

    for (let i = 0; i < tx.outputs.length; i++) {
      if (this.mempool.isSpent(hash, i))
        this.coinIndex.remove(hash, i);
    }
  }

  /**
   * Reset indexes
   * @private
   */

  reset() {
    this.txIndex.reset();
    this.coinIndex.reset();
  }

  /**
   * Find all transactions pertaining to a certain address.
   * Note: this does not accept multiple addresses.
   * @param {Address} addrs
   * @returns {TX[]}
   */

  getTXByAddress(addrs) {
    if (!Array.isArray(addrs))
      addrs = [addrs];

    const out = [];

    for (const addr of addrs) {
      const hash = Address.getHash(addr, this.network);
      const txs = this.txIndex.get(hash);

      for (const tx of txs)
        out.push(tx);
    }

    return out;
  }

  /**
   * Find all transactions pertaining to a certain address.
   * @param {Address} addrs
   * @param {TXMeta[]]}
   */

  getMetaByAddress(addrs) {
    if (!Array.isArray(addrs))
      addrs = [addrs];

    const out = [];

    for (const addr of addrs) {
      const hash = Address.getHash(addr);
      const txs = this.txIndex.getMeta(hash);

      for (const tx of txs)
        out.push(tx);
    }

    return out;
  }

  /**
   * Find all coins pertaining to a certain address.
   * @param {Address} addr
   * @return {Coin[]}
   */

  getCoinsByAddress(addrs) {
    if (!Array.isArray(addrs))
      addrs = [addrs];

    const out = [];

    for (const addr of addrs) {
      const hash = Address.getHash(addr);
      const coins = this.coinIndex.get(hash);

      for (const coin of coins)
        out.push(coin);
    }

    return out;
  }
}

/**
 * Mempool Indexer Options
 * @alias module:mempool.MempoolIndexerOptions
 */

class MempoolIndexerOptions {
  /**
   * Create indexer options.
   * @param {Object}
   */

  constructor(options) {
    this.mempool = null;

    this.fromOptions(options);
  }

  /**
   * Inject properties from object.
   * @private
   * @param {Object} options
   * returns {MempoolIndexerOptions}
   */

  fromOptions(options) {
    assert(options, 'Mempool indexer requires options.');
    assert(options.mempool && typeof options.mempool === 'object',
      'Mempool indexer requires a mempool.'
    );

    this.mempool = options.mempool;

    return this;
  }
}

/**
 * TX Address Index
 * @ignore
 */

class TXIndex {
  /**
   * Create TX address index.
   * @constructor
   */

  constructor() {
    // Map of addr->entries.
    this.index = new BufferMap();

    // Map of txid->addrs.
    this.map = new BufferMap();
  }

  reset() {
    this.index.clear();
    this.map.clear();
  }

  get(addr) {
    const items = this.index.get(addr);

    if (!items)
      return [];

    const out = [];

    for (const entry of items.values())
      out.push(entry.tx);

    return out;
  }

  getMeta(addr) {
    const items = this.index.get(addr);

    if (!items)
      return [];

    const out = [];

    for (const entry of items.values()) {
      const meta = TXMeta.fromTX(entry.tx);
      meta.mtime = entry.time;
      out.push(meta);
    }

    return out;
  }

  insert(entry, view) {
    const tx = entry.tx;
    const hash = tx.hash();
    const addrs = tx.getHashes(view);

    if (addrs.length === 0)
      return;

    for (const addr of addrs) {
      let items = this.index.get(addr);

      if (!items) {
        items = new BufferMap();
        this.index.set(addr, items);
      }

      assert(!items.has(hash));
      items.set(hash, entry);
    }

    this.map.set(hash, addrs);
  }

  remove(hash) {
    const addrs = this.map.get(hash);

    if (!addrs)
      return;

    for (const addr of addrs) {
      const items = this.index.get(addr);

      assert(items);
      assert(items.has(hash));

      items.delete(hash);

      if (items.size === 0)
        this.index.delete(addr);
    }

    this.map.delete(hash);
  }
}

/**
 * Coin Address Index
 * @ignore
 */

class CoinIndex {
  /**
   * Create coin address index.
   * @constructor
   */

  constructor() {
    // Map of addr->coins.
    this.index = new BufferMap();

    // Map of outpoint->addr.
    this.map = new BufferMap();
  }

  reset() {
    this.index.clear();
    this.map.clear();
  }

  get(addr) {
    const items = this.index.get(addr);

    if (!items)
      return [];

    const out = [];

    for (const coin of items.values())
      out.push(coin.toCoin());

    return out;
  }

  insert(tx, index) {
    const output = tx.outputs[index];
    const hash = tx.hash();
    const addr = output.getHash();

    if (!addr)
      return;

    let items = this.index.get(addr);

    if (!items) {
      items = new BufferMap();
      this.index.set(addr, items);
    }

    const key = Outpoint.toKey(hash, index);

    assert(!items.has(key));
    items.set(key, new IndexedCoin(tx, index));

    this.map.set(key, addr);
  }

  remove(hash, index) {
    const key = Outpoint.toKey(hash, index);
    const addr = this.map.get(key);

    if (!addr)
      return;

    const items = this.index.get(addr);

    assert(items);
    assert(items.has(key));
    items.delete(key);

    if (items.size === 0)
      this.index.delete(addr);

    this.map.delete(key);
  }
}

/**
 * Indexed Coin
 * @ignore
 */

class IndexedCoin {
  /**
   * Create an indexed coin.
   * @constructor
   * @param {TX} tx
   * @param {Number} index
   */

  constructor(tx, index) {
    this.tx = tx;
    this.index = index;
  }

  toCoin() {
    return Coin.fromTX(this.tx, this.index, -1);
  }

  inspect() {
    return `<IndexedCoin tx=${this.tx.hash().toString('hex')}`
    + ` index=${this.index}>`;
  }
}

module.exports = MempoolIndexer;
