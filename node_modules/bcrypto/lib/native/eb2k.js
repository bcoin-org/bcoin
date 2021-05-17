/*!
 * eb2k.js - EVP_BytesToKey for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('../internal/assert');
const binding = require('./binding');

/*
 * EB2K
 */

function derive(hash, pass, salt, keyLen, ivLen) {
  if (typeof pass === 'string')
    pass = Buffer.from(pass, 'utf8');

  if (typeof salt === 'string')
    salt = Buffer.from(salt, 'utf8');

  if (salt == null)
    salt = binding.NULL;

  if (ivLen == null)
    ivLen = 0;

  assert(Buffer.isBuffer(pass));
  assert(Buffer.isBuffer(salt));
  assert((keyLen >>> 0) === keyLen);
  assert((ivLen >>> 0) === ivLen);

  return binding.eb2k_derive(binding.hash(hash), pass, salt, keyLen, ivLen);
}

/*
 * Expose
 */

exports.native = 2;
exports.derive = derive;
