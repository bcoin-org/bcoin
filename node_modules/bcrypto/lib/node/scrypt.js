/*!
 * scrypt.js - scrypt for bcrypto
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const crypto = require('crypto');

/*
 * Feature Detection
 */

if (!crypto.scryptSync)
  throw new Error('Scrypt not available.');

try {
  crypto.scryptSync();
} catch (e) {
  if (e.code === 'ERR_CRYPTO_SCRYPT_NOT_SUPPORTED')
    throw new Error('Scrypt not available.');
}

/**
 * Perform scrypt key derivation.
 * @param {Buffer} passwd
 * @param {Buffer} salt
 * @param {Number} N
 * @param {Number} r
 * @param {Number} p
 * @param {Number} len
 * @returns {Buffer}
 */

function derive(passwd, salt, N, r, p, len) {
  assert(Buffer.isBuffer(passwd));
  assert(Buffer.isBuffer(salt));
  assert((N >>> 0) === N);
  assert((r >>> 0) === r);
  assert((p >>> 0) === p);
  assert((len >>> 0) === len);

  if (r * p >= (1 << 30))
    throw new Error('EFBIG');

  if ((N & (N - 1)) !== 0 || N === 0)
    throw new Error('EINVAL');

  if (N > 0xffffffff)
    throw new Error('EINVAL');

  const options = {
    N,
    r,
    p,
    maxmem: 2 ** 31 - 1
  };

  return crypto.scryptSync(passwd, salt, len, options);
}

/**
 * Perform scrypt key derivation (async).
 * @param {Buffer} passwd
 * @param {Buffer} salt
 * @param {Number} N
 * @param {Number} r
 * @param {Number} p
 * @param {Number} len
 * @returns {Promise}
 */

async function deriveAsync(passwd, salt, N, r, p, len) {
  assert(Buffer.isBuffer(passwd));
  assert(Buffer.isBuffer(salt));
  assert((N >>> 0) === N);
  assert((r >>> 0) === r);
  assert((p >>> 0) === p);
  assert((len >>> 0) === len);

  if (r * p >= (1 << 30))
    throw new Error('EFBIG');

  if ((N & (N - 1)) !== 0 || N === 0)
    throw new Error('EINVAL');

  if (N > 0xffffffff)
    throw new Error('EINVAL');

  const options = {
    N,
    r,
    p,
    maxmem: 2 ** 31 - 1
  };

  return new Promise((resolve, reject) => {
    const cb = (err, key) => {
      if (err) {
        reject(err);
        return;
      }

      resolve(key);
    };

    try {
      crypto.scrypt(passwd, salt, len, options, cb);
    } catch (e) {
      reject(e);
    }
  });
}

/*
 * Expose
 */

exports.native = 1;
exports.derive = derive;
exports.deriveAsync = deriveAsync;
