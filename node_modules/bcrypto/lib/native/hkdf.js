/*!
 * hkdf.js - hkdf for bcrypto
 * Copyright (c) 2014-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('../internal/assert');
const binding = require('./binding');

/**
 * HKDF
 */

function extract(hash, ikm, salt) {
  assert(hash && typeof hash.id === 'string');

  if (ikm == null)
    ikm = binding.NULL;

  if (salt == null)
    salt = Buffer.alloc(hash.size, 0x00);

  assert(Buffer.isBuffer(ikm));
  assert(Buffer.isBuffer(salt));

  return binding.hkdf_extract(binding.hash(hash), ikm, salt);
}

function expand(hash, prk, info, len) {
  if (info == null)
    info = binding.NULL;

  assert(Buffer.isBuffer(prk));
  assert(Buffer.isBuffer(info));
  assert((len >>> 0) === len);

  return binding.hkdf_expand(binding.hash(hash), prk, info, len);
}

function derive(hash, ikm, salt, info, len) {
  const prk = extract(hash, ikm, salt);
  return expand(hash, prk, info, len);
}

/*
 * Expose
 */

exports.native = 2;
exports.extract = extract;
exports.expand = expand;
exports.derive = derive;
