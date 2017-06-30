/*!
 * hkdf.js - hkdf for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/**
 * @module crypto/hkdf
 */

const digest = require('./digest');

/**
 * Perform hkdf extraction.
 * @param {Buffer} ikm
 * @param {Buffer} key
 * @param {String} alg
 * @returns {Buffer}
 */

exports.extract = function extract(ikm, key, alg) {
  return digest.hmac(alg, ikm, key);
};

/**
 * Perform hkdf expansion.
 * @param {Buffer} prk
 * @param {Buffer} info
 * @param {Number} len
 * @param {String} alg
 * @returns {Buffer}
 */

exports.expand = function expand(prk, info, len, alg) {
  let size = digest.hash(alg, Buffer.alloc(0)).length;
  let blocks = Math.ceil(len / size);
  let okm, buf, out;

  if (blocks > 255)
    throw new Error('Too many blocks.');

  okm = Buffer.allocUnsafe(len);

  if (blocks === 0)
    return okm;

  buf = Buffer.allocUnsafe(size + info.length + 1);

  // First round:
  info.copy(buf, size);
  buf[buf.length - 1] = 1;
  out = digest.hmac(alg, buf.slice(size), prk);
  out.copy(okm, 0);

  for (let i = 1; i < blocks; i++) {
    out.copy(buf, 0);
    buf[buf.length - 1]++;
    out = digest.hmac(alg, buf, prk);
    out.copy(okm, i * size);
  }

  return okm;
};
