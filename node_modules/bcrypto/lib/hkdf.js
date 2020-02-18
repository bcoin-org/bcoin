/*!
 * hkdf.js - hkdf for bcrypto
 * Copyright (c) 2014-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/HKDF
 *   https://tools.ietf.org/html/rfc5869
 */

'use strict';

const assert = require('./internal/assert');

/**
 * HKDF
 */

class HKDF {
  constructor(hash, ikm, salt, info) {
    assert(hash && typeof hash.id === 'string');

    this.hash = hash;
    this.size = hash.size;
    this.prk = null;
    this.state = null;
    this.slab = null;
    this.save = 0;

    if (ikm || salt || info)
      this.init(ikm, salt, info);
  }

  init(ikm, salt, info) {
    if (ikm == null)
      ikm = Buffer.alloc(0);

    if (salt == null)
      salt = Buffer.alloc(this.size, 0x00);

    this.prk = this.hash.mac(ikm, salt);
    this.reset(info);

    return this;
  }

  set(prk, info) {
    assert(Buffer.isBuffer(prk));
    assert(prk.length === this.size);

    this.prk = prk;
    this.reset(info);

    return this;
  }

  reset(info) {
    if (info == null)
      info = Buffer.alloc(0);

    assert(Buffer.isBuffer(info));

    // state = prev || info || counter
    const state = Buffer.alloc(this.size + info.length + 1);

    state.fill(0x00, 0, this.size);

    info.copy(state, this.size);

    state[state.length - 1] = 0;

    this.state = state;
    this.slab = Buffer.alloc(this.size);
    this.save = 0;

    return this;
  }

  generate(len) {
    assert((len >>> 0) === len);

    if (!this.prk || !this.state || !this.slab)
      throw new Error('HKDF is not initialized.');

    const left = (255 - this.state[this.state.length - 1]) * this.size;

    if (len > this.save + left)
      throw new Error('Too many bytes requested.');

    const blocks = Math.ceil(Math.max(0, len - this.save) / this.size);
    const okm = Buffer.alloc(this.save + blocks * this.size);

    this.slab.copy(okm, 0, 0, this.save);

    for (let i = 0; i < blocks; i++) {
      let state = this.state;

      if (state[state.length - 1] === 0)
        state = state.slice(this.size);

      assert(state[state.length - 1] !== 255);

      state[state.length - 1] += 1;

      const mac = this.hash.mac(state, this.prk);

      mac.copy(this.state, 0);
      mac.copy(okm, this.save + i * this.size);
    }

    this.save = okm.copy(this.slab, 0, len);

    return okm.slice(0, len);
  }

  randomBytes(size) {
    return this.generate(size);
  }

  static extract(hash, ikm, salt) {
    assert(hash && typeof hash.id === 'string');

    if (ikm == null)
      ikm = Buffer.alloc(0);

    if (salt == null)
      salt = Buffer.alloc(hash.size, 0x00);

    return hash.mac(ikm, salt);
  }

  static expand(hash, prk, info, len) {
    const hkdf = new HKDF(hash);
    return hkdf.set(prk, info)
               .generate(len);
  }

  static derive(hash, ikm, salt, info, len) {
    const hkdf = new HKDF(hash);
    return hkdf.init(ikm, salt, info)
               .generate(len);
  }
}

/*
 * Static
 */

HKDF.native = 0;

/*
 * Expose
 */

module.exports = HKDF;
