/*!
 * mempool/index.js - mempool for bcoin
 * Copyright (c) 2018, the bcoin developers (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');
const {BufferMap} = require('buffer-map');
const Address = require('../primitives/address');
const Network = require('../protocol/network');
const Outpoint = require('../primitives/outpoint');
const TXMeta = require('../primitives/txmeta');
const Coin = require('../primitives/coin');

/**
 * Mempool indexer
 * Handles TXIndex and CoinIndex for looking up by address.
 *
 * Coin index in mempool keeps track of the coins available for an address
 * in the mempool, those that have not been indexed by indexer yet.
 *
 * There are several reasons transaction can be added or removed from the
 * mempool, as well as coins assosiated with addresses with it.
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
 *    - We don't want to recover inputs as they are spent in chain.
 *    - We don't need outputs as well, because they are now part of the
 *      chain indexer.
 *    - On double spend we might need to partially recover
 *      double spent transaction's inputs as coins if they are in mempool
 *      (partial double spent test case)
 *  - Transaction was removed because of memory constraints
 *    - events: `remove entry`
 *    - In this case we want to recover inputs as coins
 *  - on reorganization we need to also clean up coins
 *    - events: `unconfirmed` and `add entry` + `tx`
 *    - add tx creates new coins
 *    - on unocnfirmed we need to recover outputs as coins
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
    this.mempool.on('confirmed', (tx, block) => this.confirmed(tx, block));
    this.mempool.on('unconfirmed', (tx, block) => this.unconfirmed(tx, block));
    this.mempool.on('add entry', (entry, view) => this.addEntry(entry, view));
    this.mempool.on('remove entry', entry => this.removeEntry(entry));
    this.mempool.on('double spend', entry => this.doubleSpend(entry));
  }
  /**
   * We have new tx in the mempool.
   * We can index to TXIndex here.
   * - We received it from the network.
   * - Block was disconnected.
   * - Orphan got resolved
   * @param {TX} tx
   * @param {CoinView} view
   */

  addTX(tx, view) {
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
   * Transaction was included in the block.
   * We want to get rid of the input coins as well as output coins.
   * (if there are any)
   * This event comes after remove entry, which recovers inputs
   * as coins, we want to get rid of those coins as well.
   * @param {TX} tx
   * @param {Block} block
   */

  confirmed(tx, block) {
  }

  /**
   * Block disconnected and we recover coins if they are available.
   * This event comes after `tx` and `add entry`, we might want to
   * check if outputs indexed by those are already spent in the mempool.
   * @param {TX} tx
   * @param {Block} block
   */

  unconfirmed(tx, block) {
  }

  /**
   * Transaction was double spent in the mempool.
   * We want to recover coisn that are not spent in the mempool.
   * @param {MempoolEntry} entry
   */

  doubleSpend(entry) {
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
   * Find all transactions partaining to a certain address.
   * Note: this does not accept multiple addresses.
   * @param {Address} addr
   * @returns {TX[]}
   */

  getTXByAddress(addr) {
    const hash = Address.getHash(addr);

    return this.txIndex.get(hash);
  }

  /**
   * Find all transactions pertaining to a certain address.
   * @param {Address} addr
   * @param {TXMeta[]]}
   */

  getMetaByAddress(addr) {
    const hash = Address.getHash(addr);

    return this.txIndex.getMeta(hash);
  }

  /**
   * Find all coins pertaining to a certain address.
   * @param {Address} addr
   * @return {Coin[]}
   */

  getCoinsByAddress(addr) {
    const hash = Address.getHash(addr);

    return this.coinIndex.get(hash);
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
