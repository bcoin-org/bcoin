/*!
 * eb2k.js - EVP_BytesToKey for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on crypto-browserify/EVP_BytesToKey:
 *   Copyright (c) 2017, crypto-browserify contributors
 *   https://github.com/crypto-browserify/EVP_BytesToKey
 *
 * Resources:
 *   https://github.com/openssl/openssl/blob/2e9d61e/crypto/evp/evp_key.c
 *   https://github.com/crypto-browserify/EVP_BytesToKey/blob/master/index.js
 *   https://github.com/openssl/openssl/blob/master/crypto/evp/evp_key.c
 */

'use strict';

const assert = require('./internal/assert');
const MD5 = require('./md5');

/*
 * EB2K
 */

function derive(passwd, salt, keyLen, ivLen) {
  if (typeof passwd === 'string')
    passwd = Buffer.from(passwd, 'utf8');

  if (typeof salt === 'string')
    salt = Buffer.from(salt, 'utf8');

  if (salt == null)
    salt = Buffer.alloc(0);

  if (ivLen == null)
    ivLen = 0;

  assert(Buffer.isBuffer(passwd));
  assert(Buffer.isBuffer(salt));
  assert((keyLen >>> 0) === keyLen);
  assert((ivLen >>> 0) === ivLen);

  if (salt.length > 8)
    salt = salt.slice(0, 8);

  if (salt.length !== 0 && salt.length !== 8)
    throw new RangeError('Salt must be at least 8 bytes.');

  const key = Buffer.alloc(keyLen);
  const iv = Buffer.alloc(ivLen);

  let prev = Buffer.alloc(0);

  while (keyLen > 0 || ivLen > 0) {
    let used = 0;

    prev = MD5.multi(prev, passwd, salt);

    if (keyLen > 0) {
      const keyStart = key.length - keyLen;
      used = Math.min(keyLen, prev.length);
      prev.copy(key, keyStart, 0, used);
      keyLen -= used;
    }

    if (used < prev.length && ivLen > 0) {
      const ivStart = iv.length - ivLen;
      const length = Math.min(ivLen, prev.length - used);
      prev.copy(iv, ivStart, used, used + length);
      ivLen -= length;
    }
  }

  prev.fill(0x00);

  return [key, iv];
}

/*
 * Expose
 */

exports.native = 0;
exports.derive = derive;
