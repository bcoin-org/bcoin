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

const assert = require('../internal/assert');

/*
 * EB2K
 */

function derive(hash, pass, salt, keyLen, ivLen) {
  if (typeof pass === 'string')
    pass = Buffer.from(pass, 'utf8');

  if (typeof salt === 'string')
    salt = Buffer.from(salt, 'utf8');

  if (salt == null)
    salt = Buffer.alloc(0);

  if (ivLen == null)
    ivLen = 0;

  assert(hash && typeof hash.id === 'string');
  assert(Buffer.isBuffer(pass));
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
  let keyPos = 0;
  let ivPos = 0;

  while (keyPos < keyLen || ivPos < ivLen) {
    let prevPos = 0;

    prev = hash.multi(prev, pass, salt);

    if (keyPos < keyLen) {
      const need = Math.min(keyLen - keyPos, prev.length - prevPos);

      prev.copy(key, keyPos, prevPos, prevPos + need);

      keyPos += need;
      prevPos += need;
    }

    if (ivPos < ivLen) {
      const need = Math.min(ivLen - ivPos, prev.length - prevPos);

      prev.copy(iv, ivPos, prevPos, prevPos + need);

      ivPos += need;
      prevPos += need;
    }
  }

  return [key, iv];
}

/*
 * Expose
 */

exports.native = 0;
exports.derive = derive;
