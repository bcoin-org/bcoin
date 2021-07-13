/*!
 * md2.js - MD2 implementation for bcrypto
 * Copyright (c) 2016-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on RustCrypto/hashes:
 *   Copyright (c) 2016-2018, The RustCrypto Authors (MIT License).
 *   https://github.com/RustCrypto/hashes
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/MD2_(hash_function)
 *   https://tools.ietf.org/html/rfc1319
 *   https://github.com/RustCrypto/hashes/blob/master/md2/src/lib.rs
 */

'use strict';

const assert = require('../internal/assert');
const HMAC = require('../internal/hmac');

/*
 * Constants
 */

const FINALIZED = -1;

const S = new Uint8Array([
  0x29, 0x2e, 0x43, 0xc9, 0xa2, 0xd8, 0x7c, 0x01,
  0x3d, 0x36, 0x54, 0xa1, 0xec, 0xf0, 0x06, 0x13,
  0x62, 0xa7, 0x05, 0xf3, 0xc0, 0xc7, 0x73, 0x8c,
  0x98, 0x93, 0x2b, 0xd9, 0xbc, 0x4c, 0x82, 0xca,
  0x1e, 0x9b, 0x57, 0x3c, 0xfd, 0xd4, 0xe0, 0x16,
  0x67, 0x42, 0x6f, 0x18, 0x8a, 0x17, 0xe5, 0x12,
  0xbe, 0x4e, 0xc4, 0xd6, 0xda, 0x9e, 0xde, 0x49,
  0xa0, 0xfb, 0xf5, 0x8e, 0xbb, 0x2f, 0xee, 0x7a,
  0xa9, 0x68, 0x79, 0x91, 0x15, 0xb2, 0x07, 0x3f,
  0x94, 0xc2, 0x10, 0x89, 0x0b, 0x22, 0x5f, 0x21,
  0x80, 0x7f, 0x5d, 0x9a, 0x5a, 0x90, 0x32, 0x27,
  0x35, 0x3e, 0xcc, 0xe7, 0xbf, 0xf7, 0x97, 0x03,
  0xff, 0x19, 0x30, 0xb3, 0x48, 0xa5, 0xb5, 0xd1,
  0xd7, 0x5e, 0x92, 0x2a, 0xac, 0x56, 0xaa, 0xc6,
  0x4f, 0xb8, 0x38, 0xd2, 0x96, 0xa4, 0x7d, 0xb6,
  0x76, 0xfc, 0x6b, 0xe2, 0x9c, 0x74, 0x04, 0xf1,
  0x45, 0x9d, 0x70, 0x59, 0x64, 0x71, 0x87, 0x20,
  0x86, 0x5b, 0xcf, 0x65, 0xe6, 0x2d, 0xa8, 0x02,
  0x1b, 0x60, 0x25, 0xad, 0xae, 0xb0, 0xb9, 0xf6,
  0x1c, 0x46, 0x61, 0x69, 0x34, 0x40, 0x7e, 0x0f,
  0x55, 0x47, 0xa3, 0x23, 0xdd, 0x51, 0xaf, 0x3a,
  0xc3, 0x5c, 0xf9, 0xce, 0xba, 0xc5, 0xea, 0x26,
  0x2c, 0x53, 0x0d, 0x6e, 0x85, 0x28, 0x84, 0x09,
  0xd3, 0xdf, 0xcd, 0xf4, 0x41, 0x81, 0x4d, 0x52,
  0x6a, 0xdc, 0x37, 0xc8, 0x6c, 0xc1, 0xab, 0xfa,
  0x24, 0xe1, 0x7b, 0x08, 0x0c, 0xbd, 0xb1, 0x4a,
  0x78, 0x88, 0x95, 0x8b, 0xe3, 0x63, 0xe8, 0x6d,
  0xe9, 0xcb, 0xd5, 0xfe, 0x3b, 0x00, 0x1d, 0x39,
  0xf2, 0xef, 0xb7, 0x0e, 0x66, 0x58, 0xd0, 0xe4,
  0xa6, 0x77, 0x72, 0xf8, 0xeb, 0x75, 0x4b, 0x0a,
  0x31, 0x44, 0x50, 0xb4, 0x8f, 0xed, 0x1f, 0x1a,
  0xdb, 0x99, 0x8d, 0x33, 0x9f, 0x11, 0x83, 0x14
]);

/**
 * MD2
 */

class MD2 {
  constructor() {
    this.state = Buffer.alloc(48);
    this.checksum = Buffer.alloc(16);
    this.block = Buffer.alloc(16);
    this.size = FINALIZED;
  }

  init() {
    this.state.fill(0);
    this.checksum.fill(0);
    this.size = 0;
    return this;
  }

  update(data) {
    assert(Buffer.isBuffer(data));
    this._update(data, data.length);
    return this;
  }

  final() {
    return this._final(Buffer.alloc(16));
  }

  _update(data, len) {
    assert(this.size !== FINALIZED, 'Context is not initialized.');

    let pos = this.size & 15;
    let off = 0;

    this.size += len;

    if (pos > 0) {
      let want = 16 - pos;

      if (want > len)
        want = len;

      data.copy(this.block, pos, off, off + want);

      pos += want;
      len -= want;
      off += want;

      if (pos < 16)
        return;

      this._transform(this.block, 0);
    }

    while (len >= 16) {
      this._transform(data, off);
      off += 16;
      len -= 16;
    }

    if (len > 0)
      data.copy(this.block, 0, off, off + len);
  }

  _final(out) {
    assert(this.size !== FINALIZED, 'Context is not initialized.');

    const pos = this.size & 15;
    const left = 16 - pos;
    const pad = Buffer.alloc(left);

    for (let i = 0; i < pad.length; i++)
      pad[i] = left;

    this._update(pad, left);
    this._update(this.checksum, 16);

    this.state.copy(out, 0, 0, 16);

    this.state.fill(0);
    this.checksum.fill(0);
    this.block.fill(0);

    this.size = FINALIZED;

    return out;
  }

  _transform(chunk, pos) {
    for (let j = 0; j < 16; j++) {
      this.state[16 + j] = chunk[pos + j];
      this.state[32 + j] = this.state[16 + j] ^ this.state[j];
    }

    let t = 0;

    for (let j = 0; j < 18; j++) {
      for (let k = 0; k < 48; k++) {
        this.state[k] ^= S[t];
        t = this.state[k];
      }
      t = (t + j) & 0xff;
    }

    let l = this.checksum[15];

    for (let j = 0; j < 16; j++) {
      this.checksum[j] ^= S[chunk[pos + j] ^ l];
      l = this.checksum[j];
    }
  }

  static hash() {
    return new MD2();
  }

  static hmac() {
    return new HMAC(MD2, 16);
  }

  static digest(data) {
    return MD2.ctx.init().update(data).final();
  }

  static root(left, right) {
    assert(Buffer.isBuffer(left) && left.length === 16);
    assert(Buffer.isBuffer(right) && right.length === 16);
    return MD2.ctx.init().update(left).update(right).final();
  }

  static multi(x, y, z) {
    const {ctx} = MD2;

    ctx.init();
    ctx.update(x);
    ctx.update(y);

    if (z)
      ctx.update(z);

    return ctx.final();
  }

  static mac(data, key) {
    return MD2.hmac().init(key).update(data).final();
  }
}

/*
 * Static
 */

MD2.native = 0;
MD2.id = 'MD2';
MD2.size = 16;
MD2.bits = 128;
MD2.blockSize = 16;
MD2.zero = Buffer.alloc(16, 0x00);
MD2.ctx = new MD2();

/*
 * Expose
 */

module.exports = MD2;
