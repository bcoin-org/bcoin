/*!
 * hash-drbg.js - hash-drbg implementation for bcrypto
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on cryptocoinjs/drbg.js:
 *   Copyright (c) 2016 Kirill Fomichev
 *   https://github.com/cryptocoinjs/drbg.js
 *
 * Resources:
 *   https://csrc.nist.gov/publications/detail/sp/800-90a/archive/2012-01-23
 *   https://github.com/cryptocoinjs/drbg.js/blob/master/hash.js
 */

'use strict';

const assert = require('./internal/assert');

/*
 * Constants
 */

const RESEED_INTERVAL = 0x1000000000000;
const ONE = Buffer.from([0x01]);
const TWO = Buffer.from([0x02]);
const THREE = Buffer.from([0x03]);

/**
 * HashDRBG
 */

class HashDRBG {
  constructor(hash, entropy, nonce, pers) {
    assert(hash && typeof hash.id === 'string');

    this.hash = hash;
    this.minEntropy = hash.id === 'SHA1' ? 10 : 24;
    this.seedLen = hash.size <= 32 ? 55 : 111;

    this.V = Buffer.allocUnsafe(this.seedLen);
    this.C = Buffer.allocUnsafe(this.seedLen);
    this.len = Buffer.allocUnsafe(8);
    this.rounds = 0;

    if (entropy)
      this.init(entropy, nonce, pers);
  }

  init(entropy, nonce = null, pers = null) {
    assert(Buffer.isBuffer(entropy));
    assert(!nonce || Buffer.isBuffer(nonce));
    assert(!pers || Buffer.isBuffer(pers));

    const seed = concat(entropy, nonce, pers);

    if (seed.length < this.minEntropy)
      throw new Error('Not enough entropy.');

    this.V = this.derive(seed, this.seedLen, null);
    this.C = this.derive(this.V, this.seedLen, 0x00);
    this.rounds = 1;

    return this;
  }

  reseed(entropy, add = null) {
    assert(Buffer.isBuffer(entropy));
    assert(!add || Buffer.isBuffer(add));

    if (this.rounds === 0)
      throw new Error('DRBG not initialized.');

    const seed = concat(this.V, entropy, add);

    if (seed.length < this.minEntropy)
      throw new Error('Not enough entropy.');

    this.V = this.derive(seed, this.seedLen, 0x01);
    this.C = this.derive(this.V, this.seedLen, 0x00);
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

    if (add && add.length !== 0)
      this.sum(this.V, this.hash.multi(TWO, this.V, add));

    const data = Buffer.from(this.V);
    const blocks = Math.ceil(len / this.hash.size);
    const out = Buffer.allocUnsafe(blocks * this.hash.size);

    for (let i = 0; i < blocks; i++) {
      this.hash.digest(data).copy(out, i * this.hash.size);
      this.sum(data, ONE);
    }

    this.update();
    this.rounds += 1;

    return out.slice(0, len);
  }

  randomBytes(size) {
    return this.generate(size);
  }

  /*
   * Helpers
   */

  update() {
    const H = this.hash.multi(THREE, this.V);
    const hi = (this.rounds / 0x100000000) >>> 0;
    const lo = this.rounds >>> 0;

    this.len[0] = hi >>> 24;
    this.len[1] = hi >>> 16;
    this.len[2] = hi >>> 8;
    this.len[3] = hi;
    this.len[4] = lo >>> 24;
    this.len[5] = lo >>> 16;
    this.len[6] = lo >>> 8;
    this.len[7] = lo;

    this.sum(this.V, H, this.C, this.len);

    return this;
  }

  derive(input, len, prepend = null) {
    assert(Buffer.isBuffer(input));
    assert((len >>> 0) === len);

    const p = prepend != null ? 1 : 0;
    const data = Buffer.allocUnsafe(5 + p + input.length);

    data[0] = 0x01;
    data[1] = len >>> 21;
    data[2] = len >>> 13;
    data[3] = len >>> 5;
    data[4] = (len & 0x1f) << 3;

    if (p)
      data[5] = prepend;

    input.copy(data, 5 + p);

    const blocks = Math.ceil(len / this.hash.size);
    const out = Buffer.allocUnsafe(blocks * this.hash.size);

    for (let i = 0; i < blocks; i++) {
      this.hash.digest(data).copy(out, i * this.hash.size);
      data[0] += 1;
    }

    return out.slice(0, len);
  }

  sum(dst, ...args) {
    for (const buf of args) {
      let i = buf.length - 1;
      let j = dst.length - 1;
      let carry = 0;

      while (i >= 0) {
        carry += buf[i] + dst[j];
        dst[j] = carry & 0xff;
        carry >>>= 8;
        i -= 1;
        j -= 1;
      }

      while (carry > 0 && j >= 0) {
        carry += dst[j];
        dst[j] = carry & 0xff;
        carry >>>= 8;
        j -= 1;
      }
    }

    return dst;
  }
}

/*
 * Static
 */

HashDRBG.native = 0;

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

module.exports = HashDRBG;
