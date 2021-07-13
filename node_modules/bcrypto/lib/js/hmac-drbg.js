/*!
 * hmac-drbg.js - hmac-drbg implementation for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
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

const assert = require('../internal/assert');

/*
 * Constants
 */

const RESEED_INTERVAL = 0x1000000000000;
const ZERO = Buffer.from([0x00]);
const ONE = Buffer.from([0x01]);

/**
 * HmacDRBG
 */

class HmacDRBG {
  constructor(hash, entropy, nonce, pers) {
    assert(hash && typeof hash.id === 'string');

    this.hash = hash;
    this.minEntropy = hash.id === 'SHA1' ? 10 : 24;

    this.K = Buffer.alloc(hash.size);
    this.V = Buffer.alloc(hash.size);
    this.rounds = 0;

    if (entropy)
      this.init(entropy, nonce, pers);
  }

  init(entropy, nonce, pers) {
    if (nonce == null)
      nonce = Buffer.alloc(0);

    if (pers == null)
      pers = Buffer.alloc(0);

    assert(Buffer.isBuffer(entropy));
    assert(Buffer.isBuffer(nonce));
    assert(Buffer.isBuffer(pers));

    for (let i = 0; i < this.V.length; i++) {
      this.K[i] = 0x00;
      this.V[i] = 0x01;
    }

    const seed = Buffer.concat([entropy, nonce, pers]);

    if (seed.length < this.minEntropy)
      throw new Error('Not enough entropy.');

    this.update(seed);
    this.rounds = 1;

    return this;
  }

  reseed(entropy, add) {
    if (add == null)
      add = Buffer.alloc(0);

    assert(Buffer.isBuffer(entropy));
    assert(Buffer.isBuffer(add));

    if (this.rounds === 0)
      throw new Error('DRBG not initialized.');

    const seed = Buffer.concat([entropy, add]);

    if (seed.length < this.minEntropy)
     throw new Error('Not enough entropy.');

    this.update(seed);
    this.rounds = 1;

    return this;
  }

  generate(len, add) {
    assert((len >>> 0) === len);
    assert(add == null || Buffer.isBuffer(add));

    if (this.rounds === 0)
      throw new Error('DRBG not initialized.');

    if (this.rounds > RESEED_INTERVAL)
      throw new Error('Reseed is required.');

    if (add && add.length > 0)
      this.update(add);

    const blocks = Math.ceil(len / this.hash.size);
    const out = Buffer.alloc(blocks * this.hash.size);

    for (let i = 0; i < blocks; i++) {
      this.V = this.mac(this.V);
      this.V.copy(out, i * this.hash.size);
    }

    this.update(add);
    this.rounds += 1;

    return out.slice(0, len);
  }

  randomBytes(size) {
    return this.generate(size);
  }

  /*
   * Helpers
   */

  mac(data) {
    return this.hash.mac(data, this.K);
  }

  hmac() {
    return this.hash.hmac().init(this.K);
  }

  update(seed) {
    assert(seed == null || Buffer.isBuffer(seed));

    const kmac = this.hmac();

    kmac.update(this.V);
    kmac.update(ZERO);

    if (seed)
      kmac.update(seed);

    this.K = kmac.final();
    this.V = this.mac(this.V);

    if (seed && seed.length > 0) {
      const kmac = this.hmac();

      kmac.update(this.V);
      kmac.update(ONE);
      kmac.update(seed);

      this.K = kmac.final();
      this.V = this.mac(this.V);
    }

    return this;
  }
}

/*
 * Static
 */

HmacDRBG.native = 0;

/*
 * Expose
 */

module.exports = HmacDRBG;
