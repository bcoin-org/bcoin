/*!
 * pgpdf.js - PGP derivation functions for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('../internal/assert');
const binding = require('./binding');

/*
 * PGPDF
 */

function deriveSimple(hash, input, size) {
  assert(Buffer.isBuffer(input));
  assert((size >>> 0) === size);

  return binding.pgpdf_derive_simple(binding.hash(hash), input, size);
}

function deriveSalted(hash, input, salt, size) {
  assert(Buffer.isBuffer(input));
  assert(Buffer.isBuffer(salt));
  assert((size >>> 0) === size);

  return binding.pgpdf_derive_salted(binding.hash(hash), input, salt, size);
}

function deriveIterated(hash, input, salt, count, size) {
  assert(hash && typeof hash.id === 'string');
  assert(Buffer.isBuffer(input));
  assert(Buffer.isBuffer(salt));
  assert((count >>> 0) === count);
  assert((size >>> 0) === size);

  return binding.pgpdf_derive_iterated(binding.hash(hash),
                                       input, salt, count, size);
}

/*
 * Expose
 */

exports.native = 2;
exports.deriveSimple = deriveSimple;
exports.deriveSalted = deriveSalted;
exports.deriveIterated = deriveIterated;
