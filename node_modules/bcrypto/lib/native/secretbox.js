/*!
 * secretbox.js - nacl secretbox for bcrypto
 * Copyright (c) 2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('../internal/assert');
const binding = require('./binding');

/*
 * Secret Box
 */

function seal(msg, key, nonce) {
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(key));
  assert(Buffer.isBuffer(nonce));

  return binding.secretbox_seal(msg, key, nonce);
}

function open(sealed, key, nonce) {
  assert(Buffer.isBuffer(sealed));
  assert(Buffer.isBuffer(key));
  assert(Buffer.isBuffer(nonce));

  return binding.secretbox_open(sealed, key, nonce);
}

function derive(secret, kdf) {
  const key = deriveSecret(secret, kdf);
  return binding.secretbox_derive(key);
}

/*
 * Helpers
 */

function deriveSecret(secret, kdf) {
  assert(Buffer.isBuffer(secret));

  if (kdf == null)
    return secret;

  let key;

  if (typeof kdf.digest === 'function')
    key = kdf.digest(secret);
  else if (typeof kdf === 'function')
    key = kdf(secret);
  else
    assert(false);

  assert(Buffer.isBuffer(key));

  return key.slice(0, 32);
}

/*
 * Expose
 */

exports.native = 2;
exports.seal = seal;
exports.open = open;
exports.derive = derive;
