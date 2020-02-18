/*!
 * rsaies.js - rsaies for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const AEAD = require('./aead');
const rsa = require('./rsa');
const random = require('./random');
const {trimZeroes} = require('./internal/util');

/*
 * RSAIES
 */

const RSAIES = {
  encrypt(hash, msg, pub, size = null, label = null) {
    assert(hash && typeof hash.id === 'string');
    assert(Buffer.isBuffer(msg));

    const key = random.randomBytes(32);

    let ct0 = rsa.encryptOAEP(hash, key, pub, label);

    if (size != null)
      ct0 = rsa.veil(ct0, size, pub);

    const iv = random.randomBytes(16);
    const ct = Buffer.from(msg);
    const tag = AEAD.encrypt(key, iv, ct, trimZeroes(pub.n));

    return Buffer.concat([ct0, iv, tag, ct]);
  },

  decrypt(hash, msg, priv, size = null, label = null) {
    assert(hash && typeof hash.id === 'string');
    assert(Buffer.isBuffer(msg));
    assert(priv instanceof rsa.RSAPrivateKey);

    if (size == null)
      size = priv.bits();

    assert((size >>> 0) === size);

    const bytes = (size + 7) >>> 3;

    if (msg.length < bytes + 16 + 16)
      throw new Error('Invalid ciphertext.');

    const ct0 = rsa.unveil(msg.slice(0, bytes), size, priv);
    const key = rsa.decryptOAEP(hash, ct0, priv, label);
    const iv = msg.slice(bytes, bytes + 16);
    const tag = msg.slice(bytes + 16, bytes + 16 + 16);
    const pt = Buffer.from(msg.slice(bytes + 16 + 16));
    const result = AEAD.decrypt(key, iv, pt, tag, trimZeroes(priv.n));

    if (!result)
      throw new Error('Invalid ciphertext.');

    return pt;
  }
};

/*
 * Expose
 */

module.exports = RSAIES;
