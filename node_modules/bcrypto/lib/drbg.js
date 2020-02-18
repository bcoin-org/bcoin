/*!
 * drbg.js - hmac-drbg implementation for bcrypto
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on indutny/hmac-drbg:
 *   Copyright Fedor Indutny, 2017.
 *   https://github.com/indutny/hmac-drbg
 *
 * Resources:
 *   https://tools.ietf.org/html/rfc6979
 *   https://csrc.nist.gov/publications/detail/sp/800-90a/archive/2012-01-23
 *   https://github.com/indutny/hmac-drbg/blob/master/lib/hmac-drbg.js
 */

'use strict';

const assert = require('bsert');

/*
 * Constants
 */

const RESEED_INTERVAL = 0x1000000000000;
const ZERO = Buffer.from([0x00]);
const ONE = Buffer.from([0x01]);

/**
 * DRBG
 */

class DRBG {
  /**
   * Create a DRBG context.
   * @constructor
   */

  constructor(alg, entropy, nonce, pers) {
    assert(alg && typeof alg.id === 'string');

    this.alg = alg;
    this.minEntropy = alg.id === 'SHA1' ? 10 : 24;

    this.K = Buffer.allocUnsafe(alg.size);
    this.V = Buffer.allocUnsafe(alg.size);
    this.rounds = 0;

    if (entropy)
      this.init(entropy, nonce, pers);
  }

  mac(data) {
    return this.alg.mac(data, this.K);
  }

  hmac() {
    return this.alg.hmac().init(this.K);
  }

  init(entropy, nonce = null, pers = null) {
    assert(Buffer.isBuffer(entropy));
    assert(!nonce || Buffer.isBuffer(nonce));
    assert(!pers || Buffer.isBuffer(pers));

    for (let i = 0; i < this.V.length; i++) {
      this.K[i] = 0x00;
      this.V[i] = 0x01;
    }

    const seed = concat(entropy, nonce, pers);

    if (seed.length < this.minEntropy)
      throw new Error('Not enough entropy.');

    this.update(seed);
    this.rounds = 1;

    return this;
  }

  update(seed = null) {
    assert(!seed || Buffer.isBuffer(seed));

    const kmac = this.hmac();

    kmac.update(this.V);
    kmac.update(ZERO);

    if (seed)
      kmac.update(seed);

    this.K = kmac.final();
    this.V = this.mac(this.V);

    if (seed) {
      const kmac = this.hmac();

      kmac.update(this.V);
      kmac.update(ONE);
      kmac.update(seed);

      this.K = kmac.final();
      this.V = this.mac(this.V);
    }

    return this;
  }

  reseed(entropy, add = null) {
    assert(Buffer.isBuffer(entropy));
    assert(!add || Buffer.isBuffer(add));

    if (entropy.length < this.minEntropy)
     throw new Error('Not enough entropy.');

    if (add)
      entropy = concat(entropy, add);

    this.update(entropy);
    this.rounds = 1;

    return this;
  }

  generate(len, add = null) {
    assert((len >>> 0) === len);
    assert(!add || Buffer.isBuffer(add));

    if (this.rounds === 0)
      throw new Error('DRBG not initialized.');

    if (this.rounds > RESEED_INTERVAL)
      throw new Error('Reseed is required.');

    if (add)
      this.update(add);

    const data = Buffer.allocUnsafe(len);

    let pos = 0;

    while (pos < len) {
      this.V = this.mac(this.V);
      this.V.copy(data, pos);
      pos += this.alg.size;
    }

    this.update(add);
    this.rounds += 1;

    return data;
  }

  randomBytes(size) {
    return this.generate(size);
  }

  randomFill(buf, off, size) {
    assert(Buffer.isBuffer(buf));

    if (off == null)
      off = 0;

    assert((off >>> 0) === off);

    if (size == null)
      size = buf.length - off;

    assert((size >>> 0) === size);
    assert(off + size <= buf.length);

    this.generate(size).copy(buf, off);

    return buf;
  }
}

DRBG.native = 0;

/*
 * Helpers
 */

function concat(a, b = null, c = null) {
  if (!b && !c)
    return a;

  let s = a.length;
  let p = 0;

  if (b)
    s += b.length;

  if (c)
    s += c.length;

  const d = Buffer.allocUnsafe(s);

  p += a.copy(d, p);

  if (b)
    p += b.copy(d, p);

  if (c)
    c.copy(d, p);

  return d;
}

/*
 * Expose
 */

module.exports = DRBG;
