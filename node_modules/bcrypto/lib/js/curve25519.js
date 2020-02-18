/*!
 * curve25519.js - curve25519 for bcrypto
 * Copyright (c) 2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on floodyberry/ed25519-donna:
 *   Public domain by Andrew M. <liquidsun@gmail.com>
 *   https://github.com/floodyberry/ed25519-donna
 */

/* eslint max-statements-per-line: "off" */

'use strict';

const assert = require('bsert');

/*
 * Constants
 */

const TWO_P0 = 0x07ffffda;
const TWO_P13579 = 0x03fffffe;
const TWO_P2468 = 0x07fffffe;
const FOUR_P0 = 0x0fffffb4;
const FOUR_P13579 = 0x07fffffc;
const FOUR_P2468 = 0x0ffffffc;

const M25 = (1 << 25) - 1;
const M26 = (1 << 26) - 1;

/**
 * Fe25519
 */

class Fe25519 {
  constructor(n = 0) {
    this.words = new Uint32Array(10);
    this.set(n);
  }

  set(n) {
    assert((n >>> 0) === n);

    this.words[0] = n;
    this.words[1] = 0;
    this.words[2] = 0;
    this.words[3] = 0;
    this.words[4] = 0;
    this.words[5] = 0;
    this.words[6] = 0;
    this.words[7] = 0;
    this.words[8] = 0;
    this.words[9] = 0;

    return this;
  }

  clone() {
    const f = new Fe25519();
    return f.copy(this);
  }

  copy(x) {
    assert(x instanceof Fe25519);

    const a = x.words;
    const o = this.words;

    o[0] = a[0];
    o[1] = a[1];
    o[2] = a[2];
    o[3] = a[3];
    o[4] = a[4];
    o[5] = a[5];
    o[6] = a[6];
    o[7] = a[7];
    o[8] = a[8];
    o[9] = a[9];

    return this;
  }

  isZero() {
    let n = 0;

    n |= this.words[0];
    n |= this.words[1];
    n |= this.words[2];
    n |= this.words[3];
    n |= this.words[4];
    n |= this.words[5];
    n |= this.words[6];
    n |= this.words[7];
    n |= this.words[8];
    n |= this.words[9];

    return n === 0;
  }

  add(x, y) {
    assert(x instanceof Fe25519);
    assert(y instanceof Fe25519);

    const a = x.words;
    const b = y.words;
    const o = this.words;

    o[0] = a[0] + b[0];
    o[1] = a[1] + b[1];
    o[2] = a[2] + b[2];
    o[3] = a[3] + b[3];
    o[4] = a[4] + b[4];
    o[5] = a[5] + b[5];
    o[6] = a[6] + b[6];
    o[7] = a[7] + b[7];
    o[8] = a[8] + b[8];
    o[9] = a[9] + b[9];

    return this;
  }

  addAfterBasic(x, y) {
    assert(x instanceof Fe25519);
    assert(y instanceof Fe25519);

    const a = x.words;
    const b = y.words;
    const o = this.words;

    let c;
    o[0] = a[0] + b[0]    ; c = (o[0] >>> 26); o[0] &= M26;
    o[1] = a[1] + b[1] + c; c = (o[1] >>> 25); o[1] &= M25;
    o[2] = a[2] + b[2] + c; c = (o[2] >>> 26); o[2] &= M26;
    o[3] = a[3] + b[3] + c; c = (o[3] >>> 25); o[3] &= M25;
    o[4] = a[4] + b[4] + c; c = (o[4] >>> 26); o[4] &= M26;
    o[5] = a[5] + b[5] + c; c = (o[5] >>> 25); o[5] &= M25;
    o[6] = a[6] + b[6] + c; c = (o[6] >>> 26); o[6] &= M26;
    o[7] = a[7] + b[7] + c; c = (o[7] >>> 25); o[7] &= M25;
    o[8] = a[8] + b[8] + c; c = (o[8] >>> 26); o[8] &= M26;
    o[9] = a[9] + b[9] + c; c = (o[9] >>> 25); o[9] &= M25;
    o[0] += 19 * c;

    return this;
  }

  addReduce(x, y) {
    assert(x instanceof Fe25519);
    assert(y instanceof Fe25519);

    const a = x.words;
    const b = y.words;
    const o = this.words;

    let c;
    o[0] = a[0] + b[0]    ; c = (o[0] >>> 26); o[0] &= M26;
    o[1] = a[1] + b[1] + c; c = (o[1] >>> 25); o[1] &= M25;
    o[2] = a[2] + b[2] + c; c = (o[2] >>> 26); o[2] &= M26;
    o[3] = a[3] + b[3] + c; c = (o[3] >>> 25); o[3] &= M25;
    o[4] = a[4] + b[4] + c; c = (o[4] >>> 26); o[4] &= M26;
    o[5] = a[5] + b[5] + c; c = (o[5] >>> 25); o[5] &= M25;
    o[6] = a[6] + b[6] + c; c = (o[6] >>> 26); o[6] &= M26;
    o[7] = a[7] + b[7] + c; c = (o[7] >>> 25); o[7] &= M25;
    o[8] = a[8] + b[8] + c; c = (o[8] >>> 26); o[8] &= M26;
    o[9] = a[9] + b[9] + c; c = (o[9] >>> 25); o[9] &= M25;
    o[0] += 19 * c;

    return this;
  }

  sub(x, y) {
    assert(x instanceof Fe25519);
    assert(y instanceof Fe25519);

    const a = x.words;
    const b = y.words;
    const o = this.words;

    let c;
    o[0] = TWO_P0     + a[0] - b[0]    ; c = (o[0] >>> 26); o[0] &= M26;
    o[1] = TWO_P13579 + a[1] - b[1] + c; c = (o[1] >>> 25); o[1] &= M25;
    o[2] = TWO_P2468  + a[2] - b[2] + c; c = (o[2] >>> 26); o[2] &= M26;
    o[3] = TWO_P13579 + a[3] - b[3] + c; c = (o[3] >>> 25); o[3] &= M25;
    o[4] = TWO_P2468  + a[4] - b[4] + c;
    o[5] = TWO_P13579 + a[5] - b[5]    ;
    o[6] = TWO_P2468  + a[6] - b[6]    ;
    o[7] = TWO_P13579 + a[7] - b[7]    ;
    o[8] = TWO_P2468  + a[8] - b[8]    ;
    o[9] = TWO_P13579 + a[9] - b[9]    ;

    return this;
  }

  subAfterBasic(x, y) {
    assert(x instanceof Fe25519);
    assert(y instanceof Fe25519);

    const a = x.words;
    const b = y.words;
    const o = this.words;

    let c;
    o[0] = FOUR_P0     + a[0] - b[0]    ; c = (o[0] >>> 26); o[0] &= M26;
    o[1] = FOUR_P13579 + a[1] - b[1] + c; c = (o[1] >>> 25); o[1] &= M25;
    o[2] = FOUR_P2468  + a[2] - b[2] + c; c = (o[2] >>> 26); o[2] &= M26;
    o[3] = FOUR_P13579 + a[3] - b[3] + c; c = (o[3] >>> 25); o[3] &= M25;
    o[4] = FOUR_P2468  + a[4] - b[4] + c; c = (o[4] >>> 26); o[4] &= M26;
    o[5] = FOUR_P13579 + a[5] - b[5] + c; c = (o[5] >>> 25); o[5] &= M25;
    o[6] = FOUR_P2468  + a[6] - b[6] + c; c = (o[6] >>> 26); o[6] &= M26;
    o[7] = FOUR_P13579 + a[7] - b[7] + c; c = (o[7] >>> 25); o[7] &= M25;
    o[8] = FOUR_P2468  + a[8] - b[8] + c; c = (o[8] >>> 26); o[8] &= M26;
    o[9] = FOUR_P13579 + a[9] - b[9] + c; c = (o[9] >>> 25); o[9] &= M25;
    o[0] += 19 * c;

    return this;
  }

  subReduce(x, y) {
    assert(x instanceof Fe25519);
    assert(y instanceof Fe25519);

    const a = x.words;
    const b = y.words;
    const o = this.words;

    let c;
    o[0] = FOUR_P0     + a[0] - b[0]    ; c = (o[0] >>> 26); o[0] &= M26;
    o[1] = FOUR_P13579 + a[1] - b[1] + c; c = (o[1] >>> 25); o[1] &= M25;
    o[2] = FOUR_P2468  + a[2] - b[2] + c; c = (o[2] >>> 26); o[2] &= M26;
    o[3] = FOUR_P13579 + a[3] - b[3] + c; c = (o[3] >>> 25); o[3] &= M25;
    o[4] = FOUR_P2468  + a[4] - b[4] + c; c = (o[4] >>> 26); o[4] &= M26;
    o[5] = FOUR_P13579 + a[5] - b[5] + c; c = (o[5] >>> 25); o[5] &= M25;
    o[6] = FOUR_P2468  + a[6] - b[6] + c; c = (o[6] >>> 26); o[6] &= M26;
    o[7] = FOUR_P13579 + a[7] - b[7] + c; c = (o[7] >>> 25); o[7] &= M25;
    o[8] = FOUR_P2468  + a[8] - b[8] + c; c = (o[8] >>> 26); o[8] &= M26;
    o[9] = FOUR_P13579 + a[9] - b[9] + c; c = (o[9] >>> 25); o[9] &= M25;
    o[0] += 19 * c;

    return this;
  }

  neg(x) {
    assert(x instanceof Fe25519);

    const a = x.words;
    const o = this.words;

    let c;
    o[0] = TWO_P0     - a[0]    ; c = (o[0] >>> 26); o[0] &= M26;
    o[1] = TWO_P13579 - a[1] + c; c = (o[1] >>> 25); o[1] &= M25;
    o[2] = TWO_P2468  - a[2] + c; c = (o[2] >>> 26); o[2] &= M26;
    o[3] = TWO_P13579 - a[3] + c; c = (o[3] >>> 25); o[3] &= M25;
    o[4] = TWO_P2468  - a[4] + c; c = (o[4] >>> 26); o[4] &= M26;
    o[5] = TWO_P13579 - a[5] + c; c = (o[5] >>> 25); o[5] &= M25;
    o[6] = TWO_P2468  - a[6] + c; c = (o[6] >>> 26); o[6] &= M26;
    o[7] = TWO_P13579 - a[7] + c; c = (o[7] >>> 25); o[7] &= M25;
    o[8] = TWO_P2468  - a[8] + c; c = (o[8] >>> 26); o[8] &= M26;
    o[9] = TWO_P13579 - a[9] + c; c = (o[9] >>> 25); o[9] &= M25;
    o[0] += 19 * c;

    return this;
  }

  swap(y, iswap) {
    assert(y instanceof Fe25519);
    assert((iswap >>> 0) === iswap);

    const a = this.words;
    const b = y.words;
    const swap = -iswap >>> 0;

    const x0 = swap & (a[0] ^ b[0]); a[0] ^= x0; b[0] ^= x0;
    const x1 = swap & (a[1] ^ b[1]); a[1] ^= x1; b[1] ^= x1;
    const x2 = swap & (a[2] ^ b[2]); a[2] ^= x2; b[2] ^= x2;
    const x3 = swap & (a[3] ^ b[3]); a[3] ^= x3; b[3] ^= x3;
    const x4 = swap & (a[4] ^ b[4]); a[4] ^= x4; b[4] ^= x4;
    const x5 = swap & (a[5] ^ b[5]); a[5] ^= x5; b[5] ^= x5;
    const x6 = swap & (a[6] ^ b[6]); a[6] ^= x6; b[6] ^= x6;
    const x7 = swap & (a[7] ^ b[7]); a[7] ^= x7; b[7] ^= x7;
    const x8 = swap & (a[8] ^ b[8]); a[8] ^= x8; b[8] ^= x8;
    const x9 = swap & (a[9] ^ b[9]); a[9] ^= x9; b[9] ^= x9;

    return this;
  }

  mul(x, y) {
    assert(x instanceof Fe25519);
    assert(y instanceof Fe25519);

    const a = x.words;
    const b = y.words;
    const o = this.words;

    const s0 = a[0];
    const s1 = a[1];
    const s2 = a[2];
    const s3 = a[3];
    const s4 = a[4];
    const s5 = a[5];
    const s6 = a[6];
    const s7 = a[7];
    const s8 = a[8];
    const s9 = a[9];

    let r0 = b[0];
    let r1 = b[1];
    let r2 = b[2];
    let r3 = b[3];
    let r4 = b[4];
    let r5 = b[5];
    let r6 = b[6];
    let r7 = b[7];
    let r8 = b[8];
    let r9 = b[9];

    let m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, c;
    let p;

    m1 = sum64(mul64(r0, s1), mul64(r1, s0));

    m3 = sum64(mul64(r0, s3), mul64(r1, s2), mul64(r2, s1),
               mul64(r3, s0));

    m5 = sum64(mul64(r0, s5), mul64(r1, s4), mul64(r2, s3),
               mul64(r3, s2), mul64(r4, s1), mul64(r5, s0));

    m7 = sum64(mul64(r0, s7), mul64(r1, s6), mul64(r2, s5),
               mul64(r3, s4), mul64(r4, s3), mul64(r5, s2),
               mul64(r6, s1), mul64(r7, s0));

    m9 = sum64(mul64(r0, s9), mul64(r1, s8), mul64(r2, s7),
               mul64(r3, s6), mul64(r4, s5), mul64(r5, s4),
               mul64(r6, s3), mul64(r7, s2), mul64(r8, s1),
               mul64(r9, s0));

    r1 *= 2;
    r3 *= 2;
    r5 *= 2;
    r7 *= 2;

    m0 = mul64(r0, s0);

    m2 = sum64(mul64(r0, s2), mul64(r1, s1), mul64(r2, s0));

    m4 = sum64(mul64(r0, s4), mul64(r1, s3), mul64(r2, s2),
               mul64(r3, s1), mul64(r4, s0));

    m6 = sum64(mul64(r0, s6), mul64(r1, s5), mul64(r2, s4),
               mul64(r3, s3), mul64(r4, s2), mul64(r5, s1),
               mul64(r6, s0));

    m8 = sum64(mul64(r0, s8), mul64(r1, s7), mul64(r2, s6),
               mul64(r3, s5), mul64(r4, s4), mul64(r5, s3),
               mul64(r6, s2), mul64(r7, s1), mul64(r8, s0));

    r1 *= 19;
    r2 *= 19;
    r3 = (r3 >>> 1) * 19;
    r4 *= 19;
    r5 = (r5 >>> 1) * 19;
    r6 *= 19;
    r7 = (r7 >>> 1) * 19;
    r8 *= 19;
    r9 *= 19;

    m1 = sum64(m1, mul64(r9, s2), mul64(r8, s3), mul64(r7, s4),
               mul64(r6, s5), mul64(r5, s6), mul64(r4, s7),
               mul64(r3, s8), mul64(r2, s9));

    m3 = sum64(m3, mul64(r9, s4), mul64(r8, s5), mul64(r7, s6),
               mul64(r6, s7), mul64(r5, s8), mul64(r4, s9));

    m5 = sum64(m5, mul64(r9, s6), mul64(r8, s7), mul64(r7, s8),
               mul64(r6, s9));

    m7 = sum64(m7, mul64(r9, s8), mul64(r8, s9));

    r3 *= 2;
    r5 *= 2;
    r7 *= 2;
    r9 *= 2;

    m0 = sum64(m0, mul64(r9, s1), mul64(r8, s2), mul64(r7, s3),
               mul64(r6, s4), mul64(r5, s5), mul64(r4, s6),
               mul64(r3, s7), mul64(r2, s8), mul64(r1, s9));

    m2 = sum64(m2, mul64(r9, s3), mul64(r8, s4), mul64(r7, s5),
               mul64(r6, s6), mul64(r5, s7), mul64(r4, s8),
               mul64(r3, s9));

    m4 = sum64(m4, mul64(r9, s5), mul64(r8, s6), mul64(r7, s7),
               mul64(r6, s8), mul64(r5, s9));

    m6 = sum64(m6, mul64(r9, s7), mul64(r8, s8), mul64(r7, s9));

    m8 = sum64(m8, mul64(r9, s9));

                                          r0 = m0[0] & M26; c = shift64(m0, 26);
    m1 = sum64(m1, c);                    r1 = m1[0] & M25; c = shift64(m1, 25);
    m2 = sum64(m2, c);                    r2 = m2[0] & M26; c = shift64(m2, 26);
    m3 = sum64(m3, c);                    r3 = m3[0] & M25; c = shift64(m3, 25);
    m4 = sum64(m4, c);                    r4 = m4[0] & M26; c = shift64(m4, 26);
    m5 = sum64(m5, c);                    r5 = m5[0] & M25; c = shift64(m5, 25);
    m6 = sum64(m6, c);                    r6 = m6[0] & M26; c = shift64(m6, 26);
    m7 = sum64(m7, c);                    r7 = m7[0] & M25; c = shift64(m7, 25);
    m8 = sum64(m8, c);                    r8 = m8[0] & M26; c = shift64(m8, 26);
    m9 = sum64(m9, c);                    r9 = m9[0] & M25; p = shift64(m9, 25);
    m0 = sum64([r0, 0], mul64(p[0], 19)); r0 = m0[0] & M26; p = shift64(m0, 26);
    r1 += p[0];

    o[0] = r0;
    o[1] = r1;
    o[2] = r2;
    o[3] = r3;
    o[4] = r4;
    o[5] = r5;
    o[6] = r6;
    o[7] = r7;
    o[8] = r8;
    o[9] = r9;

    return this;
  }

  sqr(x) {
    assert(x instanceof Fe25519);

    const a = x.words;
    const o = this.words;

    let r0 = a[0];
    let r1 = a[1];
    let r2 = a[2];
    let r3 = a[3];
    let r4 = a[4];
    let r5 = a[5];
    let r6 = a[6];
    let r7 = a[7];
    let r8 = a[8];
    let r9 = a[9];

    let m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, c;
    let p;

    m0 = mul64(r0, r0);

    r0 *= 2;

    m1 = mul64(r0, r1);
    m2 = sum64(mul64(r0, r2), mul64(r1, r1 * 2));

    r1 *= 2;

    m3 = sum64(mul64(r0, r3), mul64(r1, r2));
    m4 = sum64(mul64(r0, r4), mul64(r1, r3 * 2), mul64(r2, r2));

    r2 *= 2;

    m5 = sum64(mul64(r0, r5), mul64(r1, r4), mul64(r2, r3));

    m6 = sum64(mul64(r0, r6), mul64(r1, r5 * 2), mul64(r2, r4),
               mul64(r3, r3 * 2));

    r3 *= 2;

    m7 = sum64(mul64(r0, r7), mul64(r1, r6), mul64(r2, r5),
               mul64(r3, r4));

    m8 = sum64(mul64(r0, r8), mul64(r1, r7 * 2), mul64(r2, r6),
               mul64(r3, r5 * 2), mul64(r4, r4));

    m9 = sum64(mul64(r0, r9), mul64(r1, r8), mul64(r2, r7),
               mul64(r3, r6), mul64(r4, r5 * 2));

    const d6 = r6 * 19;
    const d7 = r7 * 2 * 19;
    const d8 = r8 * 19;
    const d9 = r9 * 2 * 19;

    m0 = sum64(m0, mul64(d9, r1), mul64(d8, r2), mul64(d7, r3),
               mul64(d6, r4 * 2), mul64(r5, r5 * 2 * 19));

    m1 = sum64(m1, mul64(d9, r2 >>> 1), mul64(d8, r3), mul64(d7, r4),
               mul64(d6, r5 * 2));

    m2 = sum64(m2, mul64(d9, r3), mul64(d8, r4 * 2), mul64(d7, r5 * 2),
               mul64(d6, r6));

    m3 = sum64(m3, mul64(d9, r4), mul64(d8, r5 * 2), mul64(d7, r6));
    m4 = sum64(m4, mul64(d9, r5 * 2), mul64(d8, r6 * 2), mul64(d7, r7));
    m5 = sum64(m5, mul64(d9, r6), mul64(d8, r7 * 2));
    m6 = sum64(m6, mul64(d9, r7 * 2), mul64(d8, r8));
    m7 = sum64(m7, mul64(d9, r8));
    m8 = sum64(m8, mul64(d9, r9));

                                          r0 = m0[0] & M26; c = shift64(m0, 26);
    m1 = sum64(m1, c);                    r1 = m1[0] & M25; c = shift64(m1, 25);
    m2 = sum64(m2, c);                    r2 = m2[0] & M26; c = shift64(m2, 26);
    m3 = sum64(m3, c);                    r3 = m3[0] & M25; c = shift64(m3, 25);
    m4 = sum64(m4, c);                    r4 = m4[0] & M26; c = shift64(m4, 26);
    m5 = sum64(m5, c);                    r5 = m5[0] & M25; c = shift64(m5, 25);
    m6 = sum64(m6, c);                    r6 = m6[0] & M26; c = shift64(m6, 26);
    m7 = sum64(m7, c);                    r7 = m7[0] & M25; c = shift64(m7, 25);
    m8 = sum64(m8, c);                    r8 = m8[0] & M26; c = shift64(m8, 26);
    m9 = sum64(m9, c);                    r9 = m9[0] & M25; p = shift64(m9, 25);
    m0 = sum64([r0, 0], mul64(p[0], 19)); r0 = m0[0] & M26; p = shift64(m0, 26);
    r1 += p[0];

    o[0] = r0;
    o[1] = r1;
    o[2] = r2;
    o[3] = r3;
    o[4] = r4;
    o[5] = r5;
    o[6] = r6;
    o[7] = r7;
    o[8] = r8;
    o[9] = r9;

    return this;
  }

  sqrn(x, times) {
    assert(x instanceof Fe25519);
    assert((times >>> 0) === times);

    this.copy(x);

    for (let i = 0; i < times; i++)
      this.sqr(this);

    return this;
  }

  powtwo5mtwo0two250mtwo0(z) {
    assert(z instanceof Fe25519);

    const b = this.copy(z);
    const t0 = new Fe25519();
    const c = new Fe25519();

    // In:  b =   2^5 - 2^0
    // Out: b = 2^250 - 2^0
    b; // 2^5  - 2^0
    t0.sqrn(b, 5); // 2^10 - 2^5
    b.mul(t0, b); // 2^10 - 2^0
    t0.sqrn(b, 10); // 2^20 - 2^10
    c.mul(t0, b); // 2^20 - 2^0
    t0.sqrn(c, 20); // 2^40 - 2^20
    t0.mul(t0, c); // 2^40 - 2^0
    t0.sqrn(t0, 10); // 2^50 - 2^10
    b.mul(t0, b); // 2^50 - 2^0
    t0.sqrn(b, 50); // 2^100 - 2^50
    c.mul(t0, b); // 2^100 - 2^0
    t0.sqrn(c, 100); // 2^200 - 2^100
    t0.mul(t0, c); // 2^200 - 2^0
    t0.sqrn(t0, 50); // 2^250 - 2^50
    b.mul(t0, b); // 2^250 - 2^0

    return this;
  }

  recip(z) {
    assert(z instanceof Fe25519);

    const out = this;
    const a = new Fe25519();
    const t0 = new Fe25519();
    const b = new Fe25519();

    // z^(p - 2) = z(2^255 - 21)
    a.sqrn(z, 1); // a = 2
    t0.sqrn(a, 2); // 8
    b.mul(t0, z); // b = 9
    a.mul(b, a); // a = 11
    t0.sqrn(a, 1); // 22
    b.mul(t0, b); // 2^5 - 2^0 = 31
    b.powtwo5mtwo0two250mtwo0(b); // 2^250 - 2^0
    b.sqrn(b, 5); // 2^255 - 2^5
    out.mul(b, a); // 2^255 - 21

    return this;
  }

  powtwo252m3(z) {
    assert(z instanceof Fe25519);

    const two252m3 = this;
    const b = new Fe25519();
    const c = new Fe25519();
    const t0 = new Fe25519();

    // z^((p-5)/8) = z^(2^252 - 3)
    c.sqrn(z, 1); // c = 2
    t0.sqrn(c, 2); // t0 = 8
    b.mul(t0, z); // b = 9
    c.mul(b, c); // c = 11
    t0.sqrn(c, 1); // 22
    b.mul(t0, b); // 2^5 - 2^0 = 31
    b.powtwo5mtwo0two250mtwo0(b); // 2^250 - 2^0
    b.sqrn(b, 2); // 2^252 - 2^2
    two252m3.mul(b, z); // 2^252 - 3

    return this;
  }

  encode() {
    const f = this.clone().words;

    passFull(f);
    passFull(f);

    // Now t is between 0 and 2^255-1, properly carried.
    // Case 1: between 0 and 2^255-20.
    // Case 2: between 2^255-19 and 2^255-1.
    f[0] += 19;
    passFull(f);

    // Now between 19 and 2^255-1 in both cases, and offset by 19.
    f[0] += (M26 + 1) - 19;
    f[1] += (M25 + 1) - 1;
    f[2] += (M26 + 1) - 1;
    f[3] += (M25 + 1) - 1;
    f[4] += (M26 + 1) - 1;
    f[5] += (M25 + 1) - 1;
    f[6] += (M26 + 1) - 1;
    f[7] += (M25 + 1) - 1;
    f[8] += (M26 + 1) - 1;
    f[9] += (M25 + 1) - 1;

    // Now between 2^255 and 2^256-20, and offset by 2^255.
    passFinal(f);

    f[1] <<= 2;
    f[2] <<= 3;
    f[3] <<= 5;
    f[4] <<= 6;
    f[6] <<= 1;
    f[7] <<= 3;
    f[8] <<= 4;
    f[9] <<= 6;

    const out = Buffer.allocUnsafe(32);

    out[0] = 0;
    out[16] = 0;

    write(out, f, 0, 0);
    write(out, f, 1, 3);
    write(out, f, 2, 6);
    write(out, f, 3, 9);
    write(out, f, 4, 12);
    write(out, f, 5, 16);
    write(out, f, 6, 19);
    write(out, f, 7, 22);
    write(out, f, 8, 25);
    write(out, f, 9, 28);

    return out;
  }

  static decode(data) {
    assert(Buffer.isBuffer(data));

    if (data.length !== 32)
      throw new Error('Invalid field element.');

    const f = new Fe25519();
    const x0 = data.readUInt32LE(0);
    const x1 = data.readUInt32LE(4);
    const x2 = data.readUInt32LE(8);
    const x3 = data.readUInt32LE(12);
    const x4 = data.readUInt32LE(16);
    const x5 = data.readUInt32LE(20);
    const x6 = data.readUInt32LE(24);
    const x7 = data.readUInt32LE(28);

    f.words[0] = (              x0        ) & 0x3ffffff;
    f.words[1] = ((x1 << 6)  | (x0 >>> 26)) & 0x1ffffff;
    f.words[2] = ((x2 << 13) | (x1 >>> 19)) & 0x3ffffff;
    f.words[3] = ((x3 << 19) | (x2 >>> 13)) & 0x1ffffff;
    f.words[4] = (              x3 >>>  6)  & 0x3ffffff;
    f.words[5] = (              x4        ) & 0x1ffffff;
    f.words[6] = ((x5 << 7)  | (x4 >>> 25)) & 0x3ffffff;
    f.words[7] = ((x6 << 13) | (x5 >>> 19)) & 0x1ffffff;
    f.words[8] = ((x7 << 20) | (x6 >>> 12)) & 0x3ffffff;
    f.words[9] = (              x7 >>>  6)  & 0x1ffffff;

    return f;
  }
}

/*
 * Helpers
 */

function add64(a, b) {
  const [alo, ahi] = a;
  const [blo, bhi] = b;

  // Credit to @indutny for this method.
  const lo = (alo + blo) | 0;

  const s = lo >> 31;
  const as = alo >> 31;
  const bs = blo >> 31;

  const c = ((as & bs) | (~s & (as ^ bs))) & 1;

  const hi = ((ahi + bhi) | 0) + c;

  return [lo, hi | 0];
}

function sum64(...items) {
  let ret = items[0];

  for (let i = 1; i < items.length; i++)
    ret = add64(ret, items[i]);

  return ret;
}

function shift64(num, bits) {
  let [lo, hi] = num;

  lo >>>= bits;
  lo |= hi << (32 - bits);
  hi >>>= bits;

  return [lo, hi | 0];
}

function mul64(a, b) {
  const a16 = a >>> 16;
  const a00 = a & 0xffff;

  const b16 = b >>> 16;
  const b00 = b & 0xffff;

  let c48 = 0;
  let c32 = 0;
  let c16 = 0;
  let c00 = 0;

  c00 += a00 * b00;
  c16 += c00 >>> 16;
  c00 &= 0xffff;
  c16 += a16 * b00;
  c32 += c16 >>> 16;
  c16 &= 0xffff;
  c16 += a00 * b16;
  c32 += c16 >>> 16;
  c16 &= 0xffff;
  c48 += c32 >>> 16;
  c32 &= 0xffff;
  c32 += a16 * b16;
  c48 += c32 >>> 16;
  c32 &= 0xffff;
  c48 += c32 >>> 16;
  c48 &= 0xffff;

  const hi = (c48 << 16) | c32;
  const lo = (c16 << 16) | c00;

  return [lo, hi];
}

function passInner(f) {
  f[1] += f[0] >>> 26; f[0] &= M26;
  f[2] += f[1] >>> 25; f[1] &= M25;
  f[3] += f[2] >>> 26; f[2] &= M26;
  f[4] += f[3] >>> 25; f[3] &= M25;
  f[5] += f[4] >>> 26; f[4] &= M26;
  f[6] += f[5] >>> 25; f[5] &= M25;
  f[7] += f[6] >>> 26; f[6] &= M26;
  f[8] += f[7] >>> 25; f[7] &= M25;
  f[9] += f[8] >>> 26; f[8] &= M26;
}

function passFull(f) {
  passInner(f);
  f[0] += 19 * (f[9] >>> 25); f[9] &= M25;
}

function passFinal(f) {
  passInner(f);
  f[9] &= M25;
}

function write(out, f, i, s) {
  out[s + 0] |= f[i];
  out[s + 1] = f[i] >>> 8;
  out[s + 2] = f[i] >>> 16;
  out[s + 3] = f[i] >>> 24;
}

/*
 * API
 */

function derive(point, scalar) {
  assert(Buffer.isBuffer(scalar));

  if (scalar.length !== 32)
    throw new Error('Invalid scalar.');

  const s = Buffer.allocUnsafe(32);

  for (let i = 0; i < 32; i++)
    s[i] = scalar[i];

  // Clamp.
  s[0] &= 248;
  s[31] &= 127;
  s[31] |= 64;

  const nd = new Fe25519(121666);
  const x1 = Fe25519.decode(point);
  const x2 = new Fe25519(1);
  const z2 = new Fe25519(0);
  const x3 = x1.clone();
  const z3 = new Fe25519(1);
  const t1 = new Fe25519();
  const t2 = new Fe25519();

  let swap = 0;

  for (let t = 255 - 1; t >= 0; t--) {
    const b = (s[t >>> 3] >>> (t & 7)) & 1;

    swap ^= b;

    x2.swap(x3, swap);
    z2.swap(z3, swap);

    swap = b;

    t1.sub(x3, z3);
    t2.sub(x2, z2);
    x2.add(x2, z2);
    z2.add(x3, z3);
    z3.mul(t1, x2);
    z2.mul(z2, t2);
    t1.sqr(t2);
    t2.sqr(x2);
    x3.add(z3, z2);
    z2.sub(z3, z2);
    x2.mul(t2, t1);
    t2.sub(t2, t1);
    z2.sqr(z2);
    z3.mul(t2, nd);
    x3.sqr(x3);
    t1.add(t1, z3);
    z3.mul(x1, z2);
    z2.mul(t2, t1);
  }

  // Finish.
  x2.swap(x3, swap);
  z2.swap(z3, swap);

  // Affinize.
  z2.recip(z2);
  x1.mul(x2, z2);

  if (x1.isZero())
    throw new Error('Invalid point.');

  return x1.encode();
}

function publicKeyCreate(priv) {
  const g = Buffer.alloc(32, 0x00);

  g[0] = 9;

  return derive(g, priv);
}

/*
 * Expose
 */

exports.Fe25519 = Fe25519;
exports.derive = derive;
exports.publicKeyCreate = publicKeyCreate;
