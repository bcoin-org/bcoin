/*!
 * ccmp.js - constant-time compare for bcoin
 * Copyright (c) 2016-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/**
 * memcmp in constant time (can only return true or false).
 * This protects us against timing attacks when
 * comparing an input against a secret string.
 * @alias module:crypto.ccmp
 * @see https://cryptocoding.net/index.php/Coding_rules
 * @see `$ man 3 memcmp` (NetBSD's consttime_memequal)
 * @param {Buffer} a
 * @param {Buffer} b
 * @returns {Boolean}
 */

module.exports = function ccmp(a, b) {
  let res;

  if (!Buffer.isBuffer(a))
    return false;

  if (!Buffer.isBuffer(b))
    return false;

  if (b.length === 0)
    return a.length === 0;

  res = a.length ^ b.length;

  for (let i = 0; i < a.length; i++)
    res |= a[i] ^ b[i % b.length];

  return res === 0;
};
