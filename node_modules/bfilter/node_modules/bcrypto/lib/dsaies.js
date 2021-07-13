/*!
 * dsaies.js - dsaies for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme
 *   https://nacl.cr.yp.to/secretbox.html
 */

'use strict';

const assert = require('./internal/assert');
const dsa = require('./dsa');
const random = require('./random');
const box = require('./secretbox');
const {padLeft} = require('./encoding/util');

/*
 * DSAIES
 */

function encrypt(kdf, msg, pub, priv = null) {
  assert(kdf != null);
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(pub));
  assert(priv == null || Buffer.isBuffer(priv));

  if (priv == null) {
    const params = dsa.paramsCreate(pub);

    priv = dsa.privateKeyCreate(params);
  }

  const klen = (dsa.publicKeyBits(pub) + 7) >>> 3;
  const {y} = dsa.privateKeyExport(priv);
  const secret = dsa.derive(pub, priv);
  const key = box.derive(secret, kdf);
  const nonce = random.randomBytes(24);
  const ourY = padLeft(y, klen);
  const sealed = box.seal(msg, key, nonce);

  return Buffer.concat([ourY, nonce, sealed]);
}

function decrypt(kdf, msg, priv) {
  assert(kdf != null);
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(priv));

  const klen = (dsa.privateKeyBits(priv) + 7) >>> 3;

  if (msg.length < klen + 24)
    throw new Error('Invalid ciphertext.');

  const {p, q, g} = dsa.privateKeyExport(priv);
  const y = msg.slice(0, klen);
  const theirPub = dsa.publicKeyImport({ p, q, g, y });
  const nonce = msg.slice(klen, klen + 24);
  const sealed = msg.slice(klen + 24);
  const secret = dsa.derive(theirPub, priv);
  const key = box.derive(secret, kdf);

  return box.open(sealed, key, nonce);
}

/*
 * Expose
 */

exports.encrypt = encrypt;
exports.decrypt = decrypt;
