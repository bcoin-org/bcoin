/*!
 * secretbox.js - nacl secretbox for bcrypto
 * Copyright (c) 2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on golang/go:
 *   Copyright (c) 2009 The Go Authors. All rights reserved.
 *   https://github.com/golang/go
 *
 * Resources:
 *   https://nacl.cr.yp.to/secretbox.html
 *   https://github.com/golang/crypto/tree/master/nacl
 *   https://github.com/golang/crypto/blob/master/nacl/secretbox/secretbox.go
 *   https://github.com/golang/crypto/blob/master/nacl/secretbox/secretbox_test.go
 *   https://github.com/golang/crypto/blob/master/nacl/secretbox/example_test.go
 *   https://github.com/golang/crypto/blob/master/nacl/box/box.go
 *   https://github.com/golang/crypto/blob/master/nacl/box/box_test.go
 *   https://github.com/golang/crypto/blob/master/nacl/box/example_test.go
 */

'use strict';

const assert = require('../internal/assert');
const Salsa20 = require('../salsa20');
const Poly1305 = require('../poly1305');

/*
 * Constants
 */

const ZERO16 = Buffer.alloc(16, 0x00);

/*
 * Secret Box
 */

function seal(msg, key, nonce) {
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(key));
  assert(Buffer.isBuffer(nonce));
  assert(key.length === 32);
  assert(nonce.length === 24);

  const polyKey = Buffer.alloc(32, 0x00);
  const box = Buffer.alloc(16 + msg.length);
  const ciphertext = box.slice(16);
  const salsa = new Salsa20();
  const poly = new Poly1305();

  msg.copy(box, 16);

  salsa.init(key, nonce);
  salsa.encrypt(polyKey);
  salsa.encrypt(ciphertext);

  poly.init(polyKey);
  poly.update(ciphertext);
  poly.final().copy(box, 0);

  return box;
}

function open(sealed, key, nonce) {
  assert(Buffer.isBuffer(sealed));
  assert(Buffer.isBuffer(key));
  assert(Buffer.isBuffer(nonce));
  assert(key.length === 32);
  assert(nonce.length === 24);

  if (sealed.length < 16)
    throw new Error('Invalid secret box size.');

  const polyKey = Buffer.alloc(32, 0x00);
  const input = Buffer.from(sealed);
  const tag = input.slice(0, 16);
  const msg = input.slice(16);
  const salsa = new Salsa20();
  const poly = new Poly1305();

  salsa.init(key, nonce);
  salsa.encrypt(polyKey);

  poly.init(polyKey);
  poly.update(msg);

  if (!poly.verify(tag))
    throw new Error('Invalid secret box tag.');

  salsa.encrypt(msg);

  return msg;
}

function derive(secret, kdf) {
  const key = deriveSecret(secret, kdf);
  return Salsa20.derive(key, ZERO16);
}

/*
 * Helpers
 */

function deriveSecret(secret, kdf) {
  assert(Buffer.isBuffer(secret));

  if (kdf == null) {
    if (secret.length !== 32)
      throw new RangeError('Invalid secret size for secret box.');

    return secret;
  }

  let key;

  if (typeof kdf.digest === 'function')
    key = kdf.digest(secret);
  else if (typeof kdf === 'function')
    key = kdf(secret);
  else
    throw new Error('Invalid key derivation function.');

  assert(Buffer.isBuffer(key));

  if (key.length < 32)
    throw new RangeError('Key is too small for secret box.');

  return key.slice(0, 32);
}

/*
 * Expose
 */

exports.native = 0;
exports.seal = seal;
exports.open = open;
exports.derive = derive;
