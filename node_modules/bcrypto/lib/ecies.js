/*!
 * ecies.js - ecies for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const AEAD = require('./aead');
const random = require('./random');

/*
 * ECIES
 */

const ECIES = {
  encrypt(curve, kdf, msg, pub, priv = null) {
    assert(curve && typeof curve.id === 'string');
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(pub));
    assert(priv == null || Buffer.isBuffer(priv));

    if (priv == null)
      priv = curve.privateKeyGenerate();

    const derive = toKDF(kdf);
    const ourPriv = priv;
    const ourPub = curve.publicKeyCreate(ourPriv);
    const secret = curve.derive(pub, ourPriv);
    const key = derive(secret);
    const iv = random.randomBytes(16);
    const ct = Buffer.from(msg);
    const tag = AEAD.encrypt(key, iv, ct, ourPub);

    return Buffer.concat([ourPub, iv, tag, ct]);
  },

  decrypt(curve, kdf, msg, priv) {
    assert(curve && typeof curve.id === 'string');
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(priv));

    const derive = toKDF(kdf);

    const klen = curve.type === 'short'
      ? 1 + curve.size
      : curve.size;

    if (msg.length < klen + 16 + 16)
      throw new Error('Invalid ciphertext.');

    const theirPub = msg.slice(0, klen);
    const iv = msg.slice(klen, klen + 16);
    const tag = msg.slice(klen + 16, klen + 16 + 16);
    const pt = Buffer.from(msg.slice(klen + 16 + 16));
    const secret = curve.derive(theirPub, priv);
    const key = derive(secret);
    const result = AEAD.decrypt(key, iv, pt, tag, theirPub);

    if (!result)
      throw new Error('Invalid ciphertext.');

    return pt;
  }
};

/*
 * Helpers
 */

function toKDF(kdf) {
  assert(kdf != null);

  if (typeof kdf.digest === 'function') {
    assert(kdf.size >= 32);

    return secret =>
      kdf.digest(secret).slice(0, 32);
  }

  assert(typeof kdf === 'function');

  return (secret) => {
    const key = kdf(secret);

    assert(Buffer.isBuffer(key));
    assert(key.length >= 32);

    return key.slice(0, 32);
  };
}

/*
 * Expose
 */

module.exports = ECIES;
