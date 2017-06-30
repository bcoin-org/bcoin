/*!
 * sigcache.js - signature cache for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const util = require('../utils/util');
const secp256k1 = require('../crypto/secp256k1');

/**
 * Signature cache.
 * @alias module:script.SigCache
 * @constructor
 * @param {Number} [size=10000]
 * @property {Number} size
 * @property {Hash[]} keys
 * @property {Object} valid
 */

function SigCache(size) {
  if (!(this instanceof SigCache))
    return new SigCache(size);

  if (size == null)
    size = 10000;

  assert(util.isNumber(size));
  assert(size >= 0);

  this.size = size;
  this.keys = [];
  this.valid = new Map();
}

/**
 * Resize the sigcache.
 * @param {Number} size
 */

SigCache.prototype.resize = function resize(size) {
  assert(util.isNumber(size));
  assert(size >= 0);

  this.size = size;
  this.keys.length = 0;
  this.valid.clear();
};

/**
 * Add item to the sigcache.
 * Potentially evict a random member.
 * @param {Hash} hash - Sig hash.
 * @param {Buffer} sig
 * @param {Buffer} key
 */

SigCache.prototype.add = function add(hash, sig, key) {
  if (this.size === 0)
    return;

  this.valid.set(hash, new SigCacheEntry(sig, key));

  if (this.keys.length >= this.size) {
    let i = Math.floor(Math.random() * this.keys.length);
    let k = this.keys[i];
    this.valid.delete(k);
    this.keys[i] = hash;
  } else {
    this.keys.push(hash);
  }
};

/**
 * Test whether the sig exists.
 * @param {Hash} hash - Sig hash.
 * @param {Buffer} sig
 * @param {Buffer} key
 * @returns {Boolean}
 */

SigCache.prototype.has = function has(hash, sig, key) {
  let entry = this.valid.get(hash);

  if (!entry)
    return false;

  return entry.equal(sig, key);
};

/**
 * Verify a signature, testing
 * it against the cache first.
 * @param {Buffer} msg
 * @param {Buffer} sig
 * @param {Buffer} key
 * @returns {Boolean}
 */

SigCache.prototype.verify = function verify(msg, sig, key) {
  let hash, result;

  if (this.size === 0)
    return secp256k1.verify(msg, sig, key);

  hash = msg.toString('hex');

  if (this.has(hash, sig, key))
    return true;

  result = secp256k1.verify(msg, sig, key);

  if (!result)
    return false;

  this.add(hash, sig, key);

  return true;
};

/**
 * Signature cache entry.
 * @constructor
 * @ignore
 * @param {Buffer} sig
 * @param {Buffer} key
 * @property {Buffer} sig
 * @property {Buffer} key
 */

function SigCacheEntry(sig, key) {
  this.sig = util.copy(sig);
  this.key = util.copy(key);
}

/**
 * Compare an entry to a sig and key.
 * @param {Buffer} sig
 * @param {Buffer} key
 * @returns {Boolean}
 */

SigCacheEntry.prototype.equal = function equal(sig, key) {
  return this.sig.equals(sig) && this.key.equals(key);
};

/*
 * Expose
 */

module.exports = SigCache;
