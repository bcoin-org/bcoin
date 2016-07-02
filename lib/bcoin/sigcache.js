/*!
 * sigcache.js - signature cache for bcoin
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var bcoin = require('./env');
var utils = bcoin.utils;
var assert = utils.assert;

/**
 * Signature cache.
 * @constructor
 * @param {Number} [size=50000]
 * @property {Number} size
 * @property {Hash[]} keys
 * @property {Object} valid
 */

function SigCache(size) {
  if (!(this instanceof SigCache))
    return new SigCache(size);

  if (size == null)
    size = 10000;

  assert(utils.isNumber(size));
  assert(size >= 0);

  this.size = size;
  this.keys = [];
  this.valid = {};
}

/**
 * Add item to the sigcache.
 * Potentially evict a random member.
 * @param {Hash} hash - Sig hash.
 * @param {Buffer} sig
 * @param {Buffer} key
 */

SigCache.prototype.add = function add(hash, sig, key) {
  var index, key;

  if (this.size === 0)
    return;

  this.valid[hash] = new SigCacheEntry(sig, key);

  if (this.keys.length === this.size) {
    index = Math.floor(Math.random() * this.keys.length);
    key = this.keys[index];
    delete this.valid[key];
    this.keys[index] = hash;
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
  var entry = this.valid[hash];

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
 * @param {Boolean?} historical
 * @param {Boolean?} high
 * @returns {Boolean}
 */

SigCache.prototype.verify = function verify(msg, sig, key, historical, high) {
  var hash, result;

  if (historical || this.size === 0)
    return bcoin.ec.verify(msg, sig, key, historical, high);

  hash = msg.toString('hex');

  if (this.has(hash, sig, key))
    return true;

  result = bcoin.ec.verify(msg, sig, key, historical, high);

  if (!result)
    return false;

  this.add(hash, sig, key);

  return true;
};

/**
 * Signature cache entry.
 * @constructor
 * @param {Buffer} sig
 * @param {Buffer} key
 * @property {Buffer} sig
 * @property {Buffer} key
 */

function SigCacheEntry(sig, key) {
  this.sig = sig;
  this.key = key;
}

/**
 * Compare an entry to a sig and key.
 * @param {Buffer} sig
 * @param {Buffer} key
 * @returns {Boolean}
 */

SigCacheEntry.prototype.equal = function equal(sig, key) {
  return utils.equal(this.sig, sig) && utils.equal(this.key, key);
};

/*
 * Expose
 */

module.exports = SigCache;
