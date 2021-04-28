/*!
 * sigcache.js - signature cache for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');
const {BufferMap} = require('buffer-map');
const secp256k1 = require('bcrypto/lib/secp256k1');

/**
 * Signature cache.
 * @alias module:script.SigCache
 * @property {Number} size
 * @property {Hash[]} keys
 * @property {Object} valid
 */

class SigCache {
  /**
   * Create a signature cache.
   * @constructor
   * @param {Number} [size=10000]
   */

  constructor(size) {
    if (size == null)
      size = 10000;

    assert((size >>> 0) === size);

    this.size = size;
    this.keys = [];
    this.valid = new BufferMap();
  }

  /**
   * Resize the sigcache.
   * @param {Number} size
   */

  resize(size) {
    assert((size >>> 0) === size);

    this.size = size;
    this.keys.length = 0;
    this.valid.clear();
  }

  /**
   * Add item to the sigcache.
   * Potentially evict a random member.
   * @param {Hash} msg - Sig hash.
   * @param {Buffer} sig
   * @param {Buffer} key
   */

  add(msg, sig, key) {
    if (this.size === 0)
      return;

    this.valid.set(msg, new SigCacheEntry(sig, key));

    if (this.keys.length >= this.size) {
      const i = Math.floor(Math.random() * this.keys.length);
      const k = this.keys[i];
      this.valid.delete(k);
      this.keys[i] = msg;
    } else {
      this.keys.push(msg);
    }
  }

  /**
   * Test whether the sig exists.
   * @param {Hash} msg - Sig hash.
   * @param {Buffer} sig
   * @param {Buffer} key
   * @returns {Boolean}
   */

  has(msg, sig, key) {
    const entry = this.valid.get(msg);

    if (!entry)
      return false;

    return entry.equals(sig, key);
  }

  /**
   * Verify a signature, testing
   * it against the cache first.
   * @param {Buffer} msg
   * @param {Buffer} sig
   * @param {Buffer} key
   * @returns {Boolean}
   */

  verify(msg, sig, key) {
    if (this.size === 0)
      return secp256k1.verifyDER(msg, sig, key);

    if (this.has(msg, sig, key))
      return true;

    const result = secp256k1.verifyDER(msg, sig, key);

    if (!result)
      return false;

    this.add(msg, sig, key);

    return true;
  }
}

/**
 * Signature Cache Entry
 * @ignore
 * @property {Buffer} sig
 * @property {Buffer} key
 */

class SigCacheEntry {
  /**
   * Create a cache entry.
   * @constructor
   * @param {Buffer} sig
   * @param {Buffer} key
   */

  constructor(sig, key) {
    this.sig = Buffer.from(sig);
    this.key = Buffer.from(key);
  }

  /**
   * Compare an entry to a sig and key.
   * @param {Buffer} sig
   * @param {Buffer} key
   * @returns {Boolean}
   */

  equals(sig, key) {
    return this.sig.equals(sig) && this.key.equals(key);
  }
}

/*
 * Expose
 */

module.exports = SigCache;
