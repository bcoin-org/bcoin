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

const assert = require('./internal/assert');
const cipher = require('./cipher');
const {Cipher} = cipher;

/*
 * Constants
 */

const MAX_GENERATE_LENGTH = 65536;
const RESEED_INTERVAL = 0x1000000000000;

/**
 * CtrDRBG
 */

class CtrDRBG {
  constructor(name, entropy, nonce, pers, derivation = true) {
    assert(derivation == null || typeof derivation === 'boolean');

    const [id, keySize, blkSize] = get(name);

    this.id = id;
    this.ctr = new CTR(id);
    this.keySize = keySize;
    this.blkSize = blkSize;
    this.entSize = keySize + blkSize;
    this.slab = Buffer.alloc(this.entSize);
    this.K = this.slab.slice(0, this.keySize);
    this.V = this.slab.slice(this.keySize);
    this.derivation = Boolean(derivation);
    this.rounds = 0;

    if (entropy)
      this.init(entropy, nonce, pers);
  }

  init(entropy, nonce = null, pers = null) {
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

    this.slab.fill(0x00);
    this.ctr.init(this.K, this.V);
    this.update(seed);
    this.rounds = 1;

    return this;
  }

  reseed(entropy, add = null) {
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

  generate(len, add = null) {
    assert((len >>> 0) === len);
    assert(!add || Buffer.isBuffer(add));

    if (this.rounds === 0)
      throw new Error('DRBG not initialized.');

    if (this.rounds > RESEED_INTERVAL)
      throw new Error('Reseed is required.');

    if (len > MAX_GENERATE_LENGTH)
      throw new Error('Requested length is too long.');

    if (add && add.length !== 0) {
      if (this.derivation)
        add = this.derive(add);

      this.update(add);
    }

    const blocks = Math.ceil(len / this.blkSize);
    const out = Buffer.allocUnsafe(blocks * this.blkSize);

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

  update(seed = null) {
    if (seed == null)
      seed = Buffer.alloc(0);

    assert(Buffer.isBuffer(seed));

    if (seed.length > this.entSize)
      throw new Error('Seed is too long.');

    this.slab.fill(0x00);

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

    S[pos++] = L >>> 24;
    S[pos++] = L >>> 16;
    S[pos++] = L >>> 8;
    S[pos++] = L;

    S[pos++] = N >>> 24;
    S[pos++] = N >>> 16;
    S[pos++] = N >>> 8;
    S[pos++] = N;

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

    for (let i = 0; i < K.length; i++)
      K[i] = i;

    const ctx = new Cipher(this.id).init(K);

    for (let i = 0; i < blocks; i++) {
      let chain = Buffer.alloc(this.blkSize, 0x00);

      S[0] = i >>> 24;
      S[1] = i >>> 16;
      S[2] = i >>> 8;
      S[3] = i;

      // chain = BCC(K, IV || S)
      for (let j = 0; j < N; j++) {
        for (let k = 0; k < chain.length; k++)
          chain[k] ^= S[j * this.blkSize + k];

        chain = ctx.update(chain);
      }

      chain.copy(slab, i * this.blkSize);
    }

    const k = slab.slice(0, this.keySize);

    ctx.init(k);

    let x = slab.slice(this.keySize, this.entSize);

    for (let i = 0; i < blocks; i++) {
      x = ctx.update(x);
      x.copy(slab, i * this.blkSize);
    }

    return slab.slice(0, this.entSize);
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
  constructor(name) {
    this.ctx = new Cipher(name);
    this.ctr = null;
  }

  init(key, iv) {
    this.ctx.init(key);
    this.ctr = Buffer.from(iv);
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
    this.ctx.update(this.ctr).copy(output, opos);
    return this;
  }
}

/*
 * Helpers
 */

function get(name) {
  assert(typeof name === 'string');

  switch (name) {
    case 'AES-128':
      return ['AES-128-ECB', 16, 16];
    case 'AES-192':
      return ['AES-192-ECB', 24, 16];
    case 'AES-256':
      return ['AES-256-ECB', 32, 16];
    default:
      throw new Error(`Unsupported cipher: ${name}.`);
  }
}

/*
 * Expose
 */

module.exports = CtrDRBG;
