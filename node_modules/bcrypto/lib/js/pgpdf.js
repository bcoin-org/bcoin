/*!
 * pgpdf.js - PGP derivation functions for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on golang/crypto:
 *   Copyright (c) 2009 The Go Authors. All rights reserved.
 *   https://github.com/golang/crypto
 *
 * Resources:
 *   https://github.com/golang/crypto/tree/master/openpgp
 */

'use strict';

const assert = require('../internal/assert');

/*
 * Constants
 */

const EMPTY = Buffer.alloc(0);
const ZERO = Buffer.alloc(1, 0x00);

/*
 * PGPDF
 */

function deriveSimple(hash, input, size) {
  return deriveSalted(hash, input, EMPTY, size);
}

function deriveSalted(hash, input, salt, size) {
  assert(hash && typeof hash.id === 'string');
  assert(Buffer.isBuffer(input));
  assert(Buffer.isBuffer(salt));
  assert((size >>> 0) === size);

  // eslint-disable-next-line
  const ctx = new hash();
  const out = Buffer.alloc(size);

  let i = 0;
  let pos = 0;

  while (pos < size) {
    ctx.init();

    for (let j = 0; j < i; j++)
      ctx.update(ZERO);

    ctx.update(salt);
    ctx.update(input);

    pos += ctx.final().copy(out, pos);
    i += 1;
  }

  return out;
}

function deriveIterated(hash, input, salt, count, size) {
  assert(hash && typeof hash.id === 'string');
  assert(Buffer.isBuffer(input));
  assert(Buffer.isBuffer(salt));
  assert((count >>> 0) === count);
  assert((size >>> 0) === size);

  // eslint-disable-next-line
  const ctx = new hash();
  const out = Buffer.alloc(size);
  const combined = salt.length + input.length;

  if (count < combined)
    count = combined;

  let i = 0;
  let pos = 0;

  while (pos < size) {
    ctx.init();

    for (let j = 0; j < i; j++)
      ctx.update(ZERO);

    let w = 0;

    while (w < count) {
      if (w + combined > count) {
        const todo = count - w;

        if (todo < salt.length) {
          ctx.update(salt.slice(0, todo));
        } else {
          ctx.update(salt);
          ctx.update(input.slice(0, todo - salt.length));
        }

        break;
      }

      ctx.update(salt);
      ctx.update(input);

      w += combined;
    }

    pos += ctx.final().copy(out, pos);
    i += 1;
  }

  return out;
}

/*
 * Expose
 */

exports.native = 0;
exports.deriveSimple = deriveSimple;
exports.deriveSalted = deriveSalted;
exports.deriveIterated = deriveIterated;
