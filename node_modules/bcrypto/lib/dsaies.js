/*!
 * dsaies.js - dsaies for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const AEAD = require('./aead');
const dsa = require('./dsa');
const random = require('./random');
const {leftPad} = require('./internal/util');

/*
 * DSAIES
 */

const DSAIES = {
  encrypt(kdf, msg, pub, priv = null) {
    assert(Buffer.isBuffer(msg));
    assert(pub instanceof dsa.DSAKey);
    assert(priv == null || (priv instanceof dsa.DSAPrivateKey));

    if (priv == null)
      priv = dsa.privateKeyCreate(pub);

    const derive = toKDF(kdf);
    const klen = (pub.bits() + 7) >>> 3;
    const ourPriv = priv;
    const ourPub = dsa.publicKeyCreate(ourPriv);
    const secret = dsa.derive(pub, ourPriv);
    const key = derive(secret);
    const iv = random.randomBytes(16);
    const ct = Buffer.from(msg);
    const ourY = leftPad(ourPub.y, klen);
    const tag = AEAD.encrypt(key, iv, ct, ourY);

    return Buffer.concat([ourY, iv, tag, ct]);
  },

  decrypt(kdf, msg, priv) {
    assert(Buffer.isBuffer(msg));
    assert(priv instanceof dsa.DSAPrivateKey);

    const derive = toKDF(kdf);
    const klen = (priv.bits() + 7) >>> 3;

    if (msg.length < klen + 16 + 16)
      throw new Error('Invalid ciphertext.');

    const theirY = msg.slice(0, klen);

    const theirPub = new dsa.DSAPublicKey(
      priv.p,
      priv.q,
      priv.g,
      theirY
    );

    const iv = msg.slice(klen, klen + 16);
    const tag = msg.slice(klen + 16, klen + 16 + 16);
    const pt = Buffer.from(msg.slice(klen + 16 + 16));
    const secret = dsa.derive(theirPub, priv);
    const key = derive(secret);
    const result = AEAD.decrypt(key, iv, pt, tag, theirY);

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

module.exports = DSAIES;
