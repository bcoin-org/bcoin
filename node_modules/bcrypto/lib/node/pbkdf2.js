/*!
 * pbkdf2.js - pbkdf2 for bcrypto
 * Copyright (c) 2014-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const crypto = require('crypto');

/*
 * Constants
 */

const ossl = {
  BLAKE2B160: 'blake2b160',
  BLAKE2B256: 'blake2b256',
  BLAKE2B384: 'blake2b384',
  BLAKE2B512: 'blake2b512',
  BLAKE2S128: 'blake2s128',
  BLAKE2S160: 'blake2s160',
  BLAKE2S224: 'blake2s224',
  BLAKE2S256: 'blake2s256',
  MD2: 'md2',
  MD4: 'md4',
  MD5: 'md5',
  MD5SHA1: 'md5-sha1',
  RIPEMD160: 'ripemd160',
  SHA1: 'sha1',
  SHA224: 'sha224',
  SHA256: 'sha256',
  SHA384: 'sha384',
  SHA512: 'sha512',
  SHA3_224: 'sha3-224',
  SHA3_256: 'sha3-256',
  SHA3_384: 'sha3-384',
  SHA3_512: 'sha3-512',
  WHIRLPOOL: 'whirlpool'
};

/**
 * Whether the backend is a binding.
 * @const {Number}
 */

exports.native = 1;

/**
 * Perform key derivation using PBKDF2.
 * @param {Object} hash
 * @param {Buffer} key
 * @param {Buffer} salt
 * @param {Number} iter
 * @param {Number} len
 * @returns {Buffer}
 */

exports.derive = function derive(hash, key, salt, iter, len) {
  assert(hash && typeof hash.id === 'string');
  assert(Buffer.isBuffer(key));
  assert(Buffer.isBuffer(salt));
  assert((iter >>> 0) === iter);
  assert((len >>> 0) === len);

  if (!hasHash(hash.id))
    return fallback().derive(hash, key, salt, iter, len);

  return crypto.pbkdf2Sync(key, salt, iter, len, ossl[hash.id]);
};

/**
 * Execute pbkdf2 asynchronously.
 * @param {Object} hash
 * @param {Buffer} key
 * @param {Buffer} salt
 * @param {Number} iter
 * @param {Number} len
 * @returns {Promise}
 */

exports.deriveAsync = async function deriveAsync(hash, key, salt, iter, len) {
  assert(hash && typeof hash.id === 'string');
  assert(Buffer.isBuffer(key));
  assert(Buffer.isBuffer(salt));
  assert((iter >>> 0) === iter);
  assert((len >>> 0) === len);

  if (!hasHash(hash.id))
    return fallback().deriveAsync(hash, key, salt, iter, len);

  return new Promise((resolve, reject) => {
    const cb = (err, result) => {
      if (err) {
        reject(err);
        return;
      }
      resolve(result);
    };

    try {
      crypto.pbkdf2(key, salt, iter, len, ossl[hash.id], cb);
    } catch (e) {
      reject(e);
    }
  });
};

/*
 * Helpers
 */

let hashes = null;
let fb = null;

function hasHash(name) {
  if (!hashes) {
    hashes = new Set();

    for (const hash of crypto.getHashes())
      hashes.add(hash.toLowerCase());
  }

  if (!ossl.hasOwnProperty(name))
    return false;

  return hashes.has(ossl[name]);
}

function fallback() {
  if (!fb)
    fb = require('../js/pbkdf2');
  return fb;
}
