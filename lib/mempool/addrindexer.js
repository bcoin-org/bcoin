/*!
 * mempool.js - mempool for bcoin
 * Copyright (c) 2018-2019, the bcoin developers (MIT License).
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');
const {BufferMap} = require('buffer-map');
const TXMeta = require('../primitives/txmeta');

/**
 * Address Indexer
 * @ignore
 */

class AddrIndexer {
  /**
   * Create TX address index.
   * @constructor
   * @param {Network} network
   */

  constructor(network) {
    this.network = network;

    // Map of addr->entries.
    this.index = new BufferMap();

    // Map of txid->addrs.
    this.map = new BufferMap();
  }

  reset() {
    this.index.clear();
    this.map.clear();
  }

  getKey(addr) {
    const prefix = addr.getPrefix(this.network);

    if (prefix < 0)
      return null;

    const hash = addr.getHash();
    const size = hash.length + 1;
    const raw = Buffer.allocUnsafe(size);

    let written = raw.writeUInt8(prefix);
    written += hash.copy(raw, 1);
    assert(written === size);

    return raw;
  }

  /**
   * Get transactions by address.
   * @param {Address} addr
   * @param {Object} options
   * @param {Number} options.limit
   * @param {Number} options.reverse
   * @param {Buffer} options.after
   */

  get(addr, options = {}) {
    const values = this.getEntries(addr, options);

    const out = [];

    for (const entry of values)
      out.push(entry.tx);

    return out;
  }

  /**
   * Get transaction meta by address.
   * @param {Address} addr
   * @param {Object} options
   * @param {Number} options.limit
   * @param {Number} options.reverse
   * @param {Buffer} options.after
   */

  getMeta(addr, options = {}) {
    const values = this.getEntries(addr, options);

    const out = [];

    for (const entry of values) {
      const meta = TXMeta.fromTX(entry.tx);
      meta.mtime = entry.time;
      out.push(meta);
    }

    return out;
  }

  /**
   * Get entries by address.
   * @param {Address} addr
   * @param {Object} options
   * @param {Number} options.limit
   * @param {Number} options.reverse
   * @param {Buffer} options.after
   */

  getEntries(addr, options = {}) {
    const {limit, reverse, after} = options;
    const key = this.getKey(addr);

    if (!key)
      return [];

    const items = this.index.get(key);

    if (!items)
      return [];

    let values = [];

    // Check to see if results should be skipped because
    // the after hash is expected to be within a following
    // confirmed query.
    const skip = (after && !items.has(after) && reverse);

    if (skip)
      return values;

    if (after && items.has(after)) {
      // Give results starting from after
      // the tx hash for the address.
      let index = 0;

      for (const k of items.keys()) {
        if (k.compare(after) === 0)
          break;
        index += 1;
      }

      values = Array.from(items.values());

      let start = index + 1;
      let end = values.length;

      if (end - start > limit)
        end = start + limit;

      if (reverse) {
        start = 0;
        end = index;

        if (end > limit)
          start = end - limit;
      }

      values = values.slice(start, end);
    } else {
      // Give earliest or latest results
      // for the address.
      values = Array.from(items.values());

      if (values.length > limit) {
        let start = 0;
        let end = limit;

        if (reverse) {
          start = values.length - limit;
          end = values.length;
        }

        values = values.slice(start, end);
      }
    }

    if (reverse)
      values.reverse();

    return values;
  }

  insert(entry, view) {
    const tx = entry.tx;
    const hash = tx.hash();
    const addrs = tx.getAddresses(view);

    if (addrs.length === 0)
      return;

    for (const addr of addrs) {
      const key = this.getKey(addr);

      if (!key)
        continue;

      let items = this.index.get(key);

      if (!items) {
        items = new BufferMap();
        this.index.set(key, items);
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
      const key = this.getKey(addr);

      if (!key)
        continue;

      const items = this.index.get(key);

      assert(items);
      assert(items.has(hash));

      items.delete(hash);

      if (items.size === 0)
        this.index.delete(key);
    }

    this.map.delete(hash);
  }
}

/*
 * Expose
 */

module.exports = AddrIndexer;
