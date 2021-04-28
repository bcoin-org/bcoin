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
  41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6, 19, 98, 167,
  5, 243, 192, 199, 115, 140, 152, 147, 43, 217, 188, 76, 130, 202, 30, 155,
  87, 60, 253, 212, 224, 22, 103, 66, 111, 24, 138, 23, 229, 18, 190, 78, 196,
  214, 218, 158, 222, 73, 160, 251, 245, 142, 187, 47, 238, 122, 169, 104, 121,
  145, 21, 178, 7, 63, 148, 194, 16, 137, 11, 34, 95, 33, 128, 127, 93, 154,
  90, 144, 50, 39, 53, 62, 204, 231, 191, 247, 151, 3, 255, 25, 48, 179, 72,
  165, 181, 209, 215, 94, 146, 42, 172, 86, 170, 198, 79, 184, 56, 210, 150,
  164, 125, 182, 118, 252, 107, 226, 156, 116, 4, 241, 69, 157, 112, 89, 100,
  113, 135, 32, 134, 91, 207, 101, 230, 45, 168, 2, 27, 96, 37, 173, 174, 176,
  185, 246, 28, 70, 97, 105, 52, 64, 126, 15, 85, 71, 163, 35, 221, 81, 175,
  58, 195, 92, 249, 206, 186, 197, 234, 38, 44, 83, 13, 110, 133, 40, 132, 9,
  211, 223, 205, 244, 65, 129, 77, 82, 106, 220, 55, 200, 108, 193, 171, 250,
  36, 225, 123, 8, 12, 189, 177, 74, 120, 136, 149, 139, 227, 99, 232, 109,
  233, 203, 213, 254, 59, 0, 29, 57, 242, 239, 183, 14, 102, 88, 208, 228, 166,
  119, 114, 248, 235, 117, 75, 10, 49, 68, 80, 180, 143, 237, 31, 26, 219, 153,
  141, 51, 159, 17, 131, 20
]);

/**
 * MD2
 */

class MD2 {
  constructor() {
    this.state = Buffer.allocUnsafe(48);
    this.checksum = Buffer.allocUnsafe(16);
    this.block = Buffer.allocUnsafe(16);
    this.size = FINALIZED;
  }

  init() {
    this.state.fill(0x00);
    this.checksum.fill(0x00);
    this.size = 0;
    return this;
  }

  update(data) {
    assert(Buffer.isBuffer(data));
    this._update(data, data.length);
    return this;
  }

  final() {
    return this._final(Buffer.allocUnsafe(16));
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
    const pad = Buffer.allocUnsafe(left);

    for (let i = 0; i < pad.length; i++)
      pad[i] = left;

    this._update(pad, left);
    this._update(this.checksum, 16);

    this.state.copy(out, 0, 0, 16);

    this.state.fill(0x00);
    this.checksum.fill(0x00);
    this.block.fill(0x00);

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
