/*!
 * box.js - nacl secretbox for bcrypto (crypto_secretbox_xsalsa20poly1305)
 * Copyright (c) 2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on golang/go:
 *   Copyright (c) 2009 The Go Authors. All rights reserved.
 *   https://github.com/golang/go
 *
 * Resources:
 *   https://nacl.cr.yp.to/secretbox.html
 *   https://github.com/golang/crypto/blob/master/nacl/box/box.go
 *   https://github.com/golang/crypto/blob/master/nacl/box/box_test.go
 *   https://github.com/golang/crypto/blob/master/nacl/box/example_test.go
 */

'use strict';

const assert = require('assert');
const box = require('./secretbox');
const random = require('./random');
const x25519 = require('./x25519');

/*
 * Box
 */

// In the future, could be implemented as:
//
// function seal(msg, pub, priv = null) {
//   return ecies.encrypt(x25519, null, msg, pub, priv);
// }
//
// function open(msg, priv) {
//   return ecies.decrypt(x25519, null, msg, priv);
// }

function seal(msg, pub, priv = null) {
  if (priv == null)
    priv = x25519.privateKeyGenerate();

  const ourPub = x25519.publicKeyCreate(priv);
  const secret = x25519.derive(pub, priv);
  const key = box.derive(secret);
  const nonce = random.randomBytes(24);
  const sealed = box.seal(msg, key, nonce);

  return Buffer.concat([ourPub, nonce, sealed]);
}

function open(msg, priv) {
  assert(Buffer.isBuffer(msg));

  if (msg.length < 32 + 24)
    throw new Error('Invalid secret box size.');

  const theirPub = msg.slice(0, 32);
  const nonce = msg.slice(32, 32 + 24);
  const sealed = msg.slice(32 + 24);
  const secret = x25519.derive(theirPub, priv);
  const key = box.derive(secret);

  return box.open(sealed, key, nonce);
}

/*
 * Expose
 */

exports.native = box.native;
exports.seal = seal;
exports.open = open;
