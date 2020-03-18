/*!
 * cache.js - blockchain internal state cache
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');
const {BufferMap} = require('buffer-map');

/**
 * State Cache
 */

class StateCache {
  /**
   * Create state cache.
   * @alias module:blockchain.StateCache
   * @constructor
   */

  constructor(network) {
    this.network = network;
    this.bits = [];
    this.updates = [];
    this.init();
  }

  init() {
    for (let i = 0; i < 32; i++)
      this.bits.push(null);

    for (const {bit} of this.network.deploys) {
      assert(!this.bits[bit]);
      this.bits[bit] = new BufferMap();
    }
  }

  set(bit, entry, state) {
    const cache = this.bits[bit];

    assert(cache);

    if (cache.get(entry.hash) !== state) {
      cache.set(entry.hash, state);
      this.updates.push(new CacheUpdate(bit, entry.hash, state));
    }
  }

  get(bit, entry) {
    const cache = this.bits[bit];

    assert(cache);

    const state = cache.get(entry.hash);

    if (state == null)
      return -1;

    return state;
  }

  commit() {
    this.updates.length = 0;
  }

  drop() {
    for (const {bit, hash} of this.updates) {
      const cache = this.bits[bit];
      assert(cache);
      cache.delete(hash);
    }

    this.updates.length = 0;
  }

  insert(bit, hash, state) {
    const cache = this.bits[bit];
    assert(cache);
    cache.set(hash, state);
  }
}

/**
 * Cache Update
 */

class CacheUpdate {
  /**
   * Create cache update.
   * @constructor
   * @ignore
   */

  constructor(bit, hash, state) {
    this.bit = bit;
    this.hash = hash;
    this.state = state;
  }

  toRaw() {
    const data = Buffer.allocUnsafe(1);
    data[0] = this.state;
    return data;
  }
}

/*
 * Expose
 */

module.exports = {
  StateCache,
  CacheUpdate
};
