/*!
 * ctr-drbg.js - ctr-drbg implementation for bcrypto
 * Copyright (c) 2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on google/boringssl:
 *   https://github.com/google/boringssl
 *
 * Resources:
 *   https://csrc.nist.gov/publications/detail/sp/800-90a/archive/2012-01-23
 *   https://github.com/google/boringssl/blob/master/crypto/fipsmodule/rand/ctrdrbg.c
 *   https://github.com/google/boringssl/blob/master/crypto/fipsmodule/rand/internal.h
 *   https://github.com/openssl/openssl/blob/master/crypto/rand/drbg_lib.c
 *   https://github.com/cryptocoinjs/drbg.js/blob/master/ctr.js
 *   https://github.com/netroby/jdk9-dev/blob/master/jdk/src/java.base/share/classes/sun/security/provider/CtrDrbg.java
 */

'use strict';

const assert = require('../internal/assert');
const AES = require('./ciphers/aes');

/*
 * Constants
 */

const MAX_GENERATE_LENGTH = 65536;
const RESEED_INTERVAL = 0x1000000000000;

/**
 * CtrDRBG
 */

class CtrDRBG {
  constructor(bits, derivation, entropy, nonce, pers) {
    assert((bits >>> 0) === bits);
    assert(typeof derivation === 'boolean');

    this.bits = bits;
    this.ctr = new CTR(bits);
    this.keySize = bits >>> 3;
    this.blkSize = 16;
    this.entSize = this.keySize + this.blkSize;
    this.slab = Buffer.alloc(this.entSize);
    this.K = this.slab.slice(0, this.keySize);
    this.V = this.slab.slice(this.keySize);
    this.derivation = derivation;
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

    let seed;

    if (this.derivation) {
      seed = this.derive(entropy, nonce, pers);
    } else {
      if (entropy.length + nonce.length > this.entSize)
        throw new Error('Entropy is too long.');

      if (pers.length > this.entSize)
        throw new Error('Personalization string is too long.');

      seed = Buffer.alloc(this.entSize, 0x00);

      entropy.copy(seed, 0);
      nonce.copy(seed, entropy.length);

      for (let i = 0; i < pers.length; i++)
        seed[i] ^= pers[i];
    }

    this.slab.fill(0);
    this.ctr.init(this.K, this.V);
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

    let seed;

    if (this.derivation) {
      seed = this.derive(entropy, add);
    } else {
      if (add.length > this.entSize)
        throw new Error('Additional data is too long.');

      seed = Buffer.alloc(this.entSize, 0x00);

      entropy.copy(seed, 0);

      for (let i = 0; i < add.length; i++)
        seed[i] ^= add[i];
    }

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

    if (len > MAX_GENERATE_LENGTH)
      throw new Error('Requested length is too long.');

    if (add && add.length > 0) {
      if (this.derivation)
        add = this.derive(add);

      this.update(add);
    }

    const blocks = Math.ceil(len / this.blkSize);
    const out = Buffer.alloc(blocks * this.blkSize);

    for (let i = 0; i < blocks; i++)
      this.ctr.encrypt(out, i * this.blkSize);

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

  update(seed) {
    if (seed == null)
      seed = Buffer.alloc(0);

    assert(Buffer.isBuffer(seed));

    if (seed.length > this.entSize)
      throw new Error('Seed is too long.');

    this.slab.fill(0);

    for (let i = 0; i < this.entSize; i += this.blkSize)
      this.ctr.encrypt(this.slab, i);

    for (let i = 0; i < seed.length; i++)
      this.slab[i] ^= seed[i];

    this.ctr.init(this.K, this.V);

    return this;
  }

  serialize(...input) {
    const N = this.entSize;

    let L = 0;

    for (const item of input)
      L += item.length;

    let size = this.blkSize + 4 + 4 + L + 1;

    if (size % this.blkSize)
      size += this.blkSize - (size % this.blkSize);

    assert((size % this.blkSize) === 0);

    // S = IV || (L || N || input || 0x80 || 0x00...)
    const S = Buffer.alloc(size, 0x00);

    let pos = this.blkSize;

    pos = writeU32(S, L, pos);
    pos = writeU32(S, N, pos);

    for (const item of input)
      pos += item.copy(S, pos);

    S[pos++] = 0x80;

    assert(pos === this.blkSize + 4 + 4 + L + 1);

    return S;
  }

  derive(...input) {
    const S = this.serialize(...input);
    const N = S.length / this.blkSize;
    const K = Buffer.alloc(this.keySize);
    const blocks = Math.ceil(this.entSize / this.blkSize);
    const slab = Buffer.alloc(blocks * this.blkSize);
    const out = Buffer.alloc(blocks * this.blkSize);
    const chain = Buffer.alloc(this.blkSize);

    for (let i = 0; i < K.length; i++)
      K[i] = i;

    const ctx = new AES(this.bits).init(K);

    for (let i = 0; i < blocks; i++) {
      chain.fill(0);

      writeU32(S, i, 0);

      // chain = BCC(K, IV || S)
      for (let j = 0; j < N; j++) {
        for (let k = 0; k < chain.length; k++)
          chain[k] ^= S[j * this.blkSize + k];

        ctx.encrypt(chain, 0, chain, 0);
      }

      chain.copy(slab, i * this.blkSize);
    }

    const k = slab.slice(0, this.keySize);
    const x = slab.slice(this.keySize, this.entSize);

    ctx.init(k);

    for (let i = 0; i < blocks; i++) {
      ctx.encrypt(x, 0, x, 0);
      x.copy(out, i * this.blkSize);
    }

    return out.slice(0, this.entSize);
  }
}

/*
 * Static
 */

CtrDRBG.native = 0;

/*
 * CTR
 */

class CTR {
  constructor(bits) {
    this.ctx = new AES(bits);
    this.ctr = Buffer.alloc(16);
  }

  init(key, iv) {
    this.ctx.init(key);
    iv.copy(this.ctr, 0);
    return this;
  }

  increment() {
    for (let i = this.ctr.length - 1; i >= 0; i--) {
      this.ctr[i] += 1;

      if (this.ctr[i] !== 0x00)
        break;
    }
  }

  encrypt(output, opos) {
    this.increment();
    this.ctx.encrypt(output, opos, this.ctr, 0);
    return this;
  }
}

/*
 * Helpers
 */

function writeU32(dst, num, off) {
  dst[off++] = num >>> 24;
  dst[off++] = num >>> 16;
  dst[off++] = num >>> 8;
  dst[off++] = num;
  return off;
}

/*
 * Expose
 */

module.exports = CtrDRBG;
