/*!
 * serpent.js - serpent128/192/256 for bcrypto
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on aead/serpent:
 *   Copyright (c) 2016, Andreas Auernhammer (MIT License).
 *   https://github.com/aead/serpent
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/Serpent_(cipher)
 *   https://www.cl.cam.ac.uk/~rja14/serpent.html
 *   https://github.com/aead/serpent
 */

'use strict';

const assert = require('../../internal/assert');

/*
 * Constants
 */

const PHI = 0x9e3779b9;

/**
 * Serpent
 */

class Serpent {
  constructor(bits) {
    assert((bits >>> 0) === bits);
    assert(bits === 128 || bits === 192 || bits === 256);

    this.bits = bits;
    this.subkeys = new Uint32Array(132);
    this.block = new Uint32Array(4);
  }

  get blockSize() {
    return 16;
  }

  init(key) {
    assert(Buffer.isBuffer(key));
    assert(key.length * 8 === this.bits);

    this.keySchedule(key);

    return this;
  }

  keySchedule(key) {
    const s = this.subkeys;
    const k = new Uint32Array(16);

    let j = 0;

    for (let i = 0; i < key.length; i += 4)
      k[j++] = readU32(key, i);

    if (j < 8)
      k[j++] = 1;

    while (j < 16)
      k[j++] = 0;

    for (let i = 8; i < 16; i++) {
      const x = k[i - 8] ^ k[i - 5] ^ k[i - 3] ^ k[i - 1] ^ PHI ^ (i - 8);
      k[i] = (x << 11) | (x >>> 21);
      s[i - 8] = k[i];
    }

    for (let i = 8; i < 132; i++) {
      const x = s[i - 8] ^ s[i - 5] ^ s[i - 3] ^ s[i - 1] ^ PHI ^ i;
      s[i] = (x << 11) | (x >>> 21);
    }

    sb3(s, 0, 1, 2, 3);
    sb2(s, 4, 5, 6, 7);
    sb1(s, 8, 9, 10, 11);
    sb0(s, 12, 13, 14, 15);
    sb7(s, 16, 17, 18, 19);
    sb6(s, 20, 21, 22, 23);
    sb5(s, 24, 25, 26, 27);
    sb4(s, 28, 29, 30, 31);

    sb3(s, 32, 33, 34, 35);
    sb2(s, 36, 37, 38, 39);
    sb1(s, 40, 41, 42, 43);
    sb0(s, 44, 45, 46, 47);
    sb7(s, 48, 49, 50, 51);
    sb6(s, 52, 53, 54, 55);
    sb5(s, 56, 57, 58, 59);
    sb4(s, 60, 61, 62, 63);

    sb3(s, 64, 65, 66, 67);
    sb2(s, 68, 69, 70, 71);
    sb1(s, 72, 73, 74, 75);
    sb0(s, 76, 77, 78, 79);
    sb7(s, 80, 81, 82, 83);
    sb6(s, 84, 85, 86, 87);
    sb5(s, 88, 89, 90, 91);
    sb4(s, 92, 93, 94, 95);

    sb3(s, 96, 97, 98, 99);
    sb2(s, 100, 101, 102, 103);
    sb1(s, 104, 105, 106, 107);
    sb0(s, 108, 109, 110, 111);
    sb7(s, 112, 113, 114, 115);
    sb6(s, 116, 117, 118, 119);
    sb5(s, 120, 121, 122, 123);
    sb4(s, 124, 125, 126, 127);

    sb3(s, 128, 129, 130, 131);

    return this;
  }

  encrypt(output, opos, input, ipos) {
    const sk = this.subkeys;
    const r = this.block;

    r[0] = readU32(input, ipos + 0);
    r[1] = readU32(input, ipos + 4);
    r[2] = readU32(input, ipos + 8);
    r[3] = readU32(input, ipos + 12);

    xor4(r, sk, 0, 1, 2, 3);
    sb0(r, 0, 1, 2, 3);
    linear(r, 0, 1, 2, 3);
    xor4(r, sk, 4, 5, 6, 7);
    sb1(r, 0, 1, 2, 3);
    linear(r, 0, 1, 2, 3);
    xor4(r, sk, 8, 9, 10, 11);
    sb2(r, 0, 1, 2, 3);
    linear(r, 0, 1, 2, 3);
    xor4(r, sk, 12, 13, 14, 15);
    sb3(r, 0, 1, 2, 3);
    linear(r, 0, 1, 2, 3);
    xor4(r, sk, 16, 17, 18, 19);
    sb4(r, 0, 1, 2, 3);
    linear(r, 0, 1, 2, 3);
    xor4(r, sk, 20, 21, 22, 23);
    sb5(r, 0, 1, 2, 3);
    linear(r, 0, 1, 2, 3);
    xor4(r, sk, 24, 25, 26, 27);
    sb6(r, 0, 1, 2, 3);
    linear(r, 0, 1, 2, 3);
    xor4(r, sk, 28, 29, 30, 31);
    sb7(r, 0, 1, 2, 3);
    linear(r, 0, 1, 2, 3);

    xor4(r, sk, 32, 33, 34, 35);
    sb0(r, 0, 1, 2, 3);
    linear(r, 0, 1, 2, 3);
    xor4(r, sk, 36, 37, 38, 39);
    sb1(r, 0, 1, 2, 3);
    linear(r, 0, 1, 2, 3);
    xor4(r, sk, 40, 41, 42, 43);
    sb2(r, 0, 1, 2, 3);
    linear(r, 0, 1, 2, 3);
    xor4(r, sk, 44, 45, 46, 47);
    sb3(r, 0, 1, 2, 3);
    linear(r, 0, 1, 2, 3);
    xor4(r, sk, 48, 49, 50, 51);
    sb4(r, 0, 1, 2, 3);
    linear(r, 0, 1, 2, 3);
    xor4(r, sk, 52, 53, 54, 55);
    sb5(r, 0, 1, 2, 3);
    linear(r, 0, 1, 2, 3);
    xor4(r, sk, 56, 57, 58, 59);
    sb6(r, 0, 1, 2, 3);
    linear(r, 0, 1, 2, 3);
    xor4(r, sk, 60, 61, 62, 63);
    sb7(r, 0, 1, 2, 3);
    linear(r, 0, 1, 2, 3);

    xor4(r, sk, 64, 65, 66, 67);
    sb0(r, 0, 1, 2, 3);
    linear(r, 0, 1, 2, 3);
    xor4(r, sk, 68, 69, 70, 71);
    sb1(r, 0, 1, 2, 3);
    linear(r, 0, 1, 2, 3);
    xor4(r, sk, 72, 73, 74, 75);
    sb2(r, 0, 1, 2, 3);
    linear(r, 0, 1, 2, 3);
    xor4(r, sk, 76, 77, 78, 79);
    sb3(r, 0, 1, 2, 3);
    linear(r, 0, 1, 2, 3);
    xor4(r, sk, 80, 81, 82, 83);
    sb4(r, 0, 1, 2, 3);
    linear(r, 0, 1, 2, 3);
    xor4(r, sk, 84, 85, 86, 87);
    sb5(r, 0, 1, 2, 3);
    linear(r, 0, 1, 2, 3);
    xor4(r, sk, 88, 89, 90, 91);
    sb6(r, 0, 1, 2, 3);
    linear(r, 0, 1, 2, 3);
    xor4(r, sk, 92, 93, 94, 95);
    sb7(r, 0, 1, 2, 3);
    linear(r, 0, 1, 2, 3);

    xor4(r, sk, 96, 97, 98, 99);
    sb0(r, 0, 1, 2, 3);
    linear(r, 0, 1, 2, 3);
    xor4(r, sk, 100, 101, 102, 103);
    sb1(r, 0, 1, 2, 3);
    linear(r, 0, 1, 2, 3);
    xor4(r, sk, 104, 105, 106, 107);
    sb2(r, 0, 1, 2, 3);
    linear(r, 0, 1, 2, 3);
    xor4(r, sk, 108, 109, 110, 111);
    sb3(r, 0, 1, 2, 3);
    linear(r, 0, 1, 2, 3);
    xor4(r, sk, 112, 113, 114, 115);
    sb4(r, 0, 1, 2, 3);
    linear(r, 0, 1, 2, 3);
    xor4(r, sk, 116, 117, 118, 119);
    sb5(r, 0, 1, 2, 3);
    linear(r, 0, 1, 2, 3);
    xor4(r, sk, 120, 121, 122, 123);
    sb6(r, 0, 1, 2, 3);
    linear(r, 0, 1, 2, 3);
    xor4(r, sk, 124, 125, 126, 127);
    sb7(r, 0, 1, 2, 3);

    r[0] ^= sk[128];
    r[1] ^= sk[129];
    r[2] ^= sk[130];
    r[3] ^= sk[131];

    writeU32(output, r[0], opos + 0);
    writeU32(output, r[1], opos + 4);
    writeU32(output, r[2], opos + 8);
    writeU32(output, r[3], opos + 12);

    return this;
  }

  decrypt(output, opos, input, ipos) {
    const sk = this.subkeys;
    const r = this.block;

    r[0] = readU32(input, ipos + 0);
    r[1] = readU32(input, ipos + 4);
    r[2] = readU32(input, ipos + 8);
    r[3] = readU32(input, ipos + 12);

    r[0] ^= sk[128];
    r[1] ^= sk[129];
    r[2] ^= sk[130];
    r[3] ^= sk[131];

    sb7inv(r, 0, 1, 2, 3);
    xor4(r, sk, 124, 125, 126, 127);
    linearinv(r, 0, 1, 2, 3);
    sb6inv(r, 0, 1, 2, 3);
    xor4(r, sk, 120, 121, 122, 123);
    linearinv(r, 0, 1, 2, 3);
    sb5inv(r, 0, 1, 2, 3);
    xor4(r, sk, 116, 117, 118, 119);
    linearinv(r, 0, 1, 2, 3);
    sb4inv(r, 0, 1, 2, 3);
    xor4(r, sk, 112, 113, 114, 115);
    linearinv(r, 0, 1, 2, 3);
    sb3inv(r, 0, 1, 2, 3);
    xor4(r, sk, 108, 109, 110, 111);
    linearinv(r, 0, 1, 2, 3);
    sb2inv(r, 0, 1, 2, 3);
    xor4(r, sk, 104, 105, 106, 107);
    linearinv(r, 0, 1, 2, 3);
    sb1inv(r, 0, 1, 2, 3);
    xor4(r, sk, 100, 101, 102, 103);
    linearinv(r, 0, 1, 2, 3);
    sb0inv(r, 0, 1, 2, 3);
    xor4(r, sk, 96, 97, 98, 99);
    linearinv(r, 0, 1, 2, 3);

    sb7inv(r, 0, 1, 2, 3);
    xor4(r, sk, 92, 93, 94, 95);
    linearinv(r, 0, 1, 2, 3);
    sb6inv(r, 0, 1, 2, 3);
    xor4(r, sk, 88, 89, 90, 91);
    linearinv(r, 0, 1, 2, 3);
    sb5inv(r, 0, 1, 2, 3);
    xor4(r, sk, 84, 85, 86, 87);
    linearinv(r, 0, 1, 2, 3);
    sb4inv(r, 0, 1, 2, 3);
    xor4(r, sk, 80, 81, 82, 83);
    linearinv(r, 0, 1, 2, 3);
    sb3inv(r, 0, 1, 2, 3);
    xor4(r, sk, 76, 77, 78, 79);
    linearinv(r, 0, 1, 2, 3);
    sb2inv(r, 0, 1, 2, 3);
    xor4(r, sk, 72, 73, 74, 75);
    linearinv(r, 0, 1, 2, 3);
    sb1inv(r, 0, 1, 2, 3);
    xor4(r, sk, 68, 69, 70, 71);
    linearinv(r, 0, 1, 2, 3);
    sb0inv(r, 0, 1, 2, 3);
    xor4(r, sk, 64, 65, 66, 67);
    linearinv(r, 0, 1, 2, 3);

    sb7inv(r, 0, 1, 2, 3);
    xor4(r, sk, 60, 61, 62, 63);
    linearinv(r, 0, 1, 2, 3);
    sb6inv(r, 0, 1, 2, 3);
    xor4(r, sk, 56, 57, 58, 59);
    linearinv(r, 0, 1, 2, 3);
    sb5inv(r, 0, 1, 2, 3);
    xor4(r, sk, 52, 53, 54, 55);
    linearinv(r, 0, 1, 2, 3);
    sb4inv(r, 0, 1, 2, 3);
    xor4(r, sk, 48, 49, 50, 51);
    linearinv(r, 0, 1, 2, 3);
    sb3inv(r, 0, 1, 2, 3);
    xor4(r, sk, 44, 45, 46, 47);
    linearinv(r, 0, 1, 2, 3);
    sb2inv(r, 0, 1, 2, 3);
    xor4(r, sk, 40, 41, 42, 43);
    linearinv(r, 0, 1, 2, 3);
    sb1inv(r, 0, 1, 2, 3);
    xor4(r, sk, 36, 37, 38, 39);
    linearinv(r, 0, 1, 2, 3);
    sb0inv(r, 0, 1, 2, 3);
    xor4(r, sk, 32, 33, 34, 35);
    linearinv(r, 0, 1, 2, 3);

    sb7inv(r, 0, 1, 2, 3);
    xor4(r, sk, 28, 29, 30, 31);
    linearinv(r, 0, 1, 2, 3);
    sb6inv(r, 0, 1, 2, 3);
    xor4(r, sk, 24, 25, 26, 27);
    linearinv(r, 0, 1, 2, 3);
    sb5inv(r, 0, 1, 2, 3);
    xor4(r, sk, 20, 21, 22, 23);
    linearinv(r, 0, 1, 2, 3);
    sb4inv(r, 0, 1, 2, 3);
    xor4(r, sk, 16, 17, 18, 19);
    linearinv(r, 0, 1, 2, 3);
    sb3inv(r, 0, 1, 2, 3);
    xor4(r, sk, 12, 13, 14, 15);
    linearinv(r, 0, 1, 2, 3);
    sb2inv(r, 0, 1, 2, 3);
    xor4(r, sk, 8, 9, 10, 11);
    linearinv(r, 0, 1, 2, 3);
    sb1inv(r, 0, 1, 2, 3);
    xor4(r, sk, 4, 5, 6, 7);
    linearinv(r, 0, 1, 2, 3);
    sb0inv(r, 0, 1, 2, 3);

    r[0] ^= sk[0];
    r[1] ^= sk[1];
    r[2] ^= sk[2];
    r[3] ^= sk[3];

    writeU32(output, r[0], opos + 0);
    writeU32(output, r[1], opos + 4);
    writeU32(output, r[2], opos + 8);
    writeU32(output, r[3], opos + 12);

    return this;
  }

  destroy() {
    for (let i = 0; i < 132; i++)
      this.subkeys[i] = 0;

    for (let i = 0; i < 4; i++)
      this.block[i] = 0;

    return this;
  }
}

/*
 * Helpers
 */

function xor4(r, s, s1, s2, s3, s4) {
  r[0] ^= s[s1];
  r[1] ^= s[s2];
  r[2] ^= s[s3];
  r[3] ^= s[s4];
}

function linear(v, v0, v1, v2, v3) {
  let t0 = ((v[v0] << 13) | (v[v0] >>> (32 - 13)));
  let t2 = ((v[v2] << 3) | (v[v2] >>> (32 - 3)));

  const t1 = v[v1] ^ t0 ^ t2;
  const t3 = v[v3] ^ t2 ^ (t0 << 3);

  v[v1] = (t1 << 1) | (t1 >>> (32 - 1));
  v[v3] = (t3 << 7) | (t3 >>> (32 - 7));

  t0 ^= v[v1] ^ v[v3];
  t2 ^= v[v3] ^ (v[v1] << 7);

  v[v0] = (t0 << 5) | (t0 >>> (32 - 5));
  v[v2] = (t2 << 22) | (t2 >>> (32 - 22));
}

function linearinv(v, v0, v1, v2, v3) {
  let t2 = (v[v2] >>> 22) | (v[v2] << (32 - 22));
  let t0 = (v[v0] >>> 5) | (v[v0] << (32 - 5));

  t2 ^= v[v3] ^ (v[v1] << 7);
  t0 ^= v[v1] ^ v[v3];

  const t3 = (v[v3] >>> 7) | (v[v3] << (32 - 7));
  const t1 = (v[v1] >>> 1) | (v[v1] << (32 - 1));

  v[v3] = t3 ^ t2 ^ (t0 << 3);
  v[v1] = t1 ^ t0 ^ t2;
  v[v2] = (t2 >>> 3) | (t2 << (32 - 3));
  v[v0] = (t0 >>> 13) | (t0 << (32 - 13));
}

function sb0(r, r0, r1, r2, r3) {
  const t0 = r[r0] ^ r[r3];
  const t1 = r[r2] ^ t0;
  const t2 = r[r1] ^ t1;

  r[r3] = (r[r0] & r[r3]) ^ t2;

  const t3 = r[r0] ^ (r[r1] & t0);

  r[r2] = t2 ^ (r[r2] | t3);

  const t4 = r[r3] & (t1 ^ t3);

  r[r1] = (~t1) ^ t4;
  r[r0] = t4 ^ (~t3);
}

function sb0inv(r, r0, r1, r2, r3) {
  const t0 = ~(r[r0]);
  const t1 = r[r0] ^ r[r1];
  const t2 = r[r3] ^ (t0 | t1);
  const t3 = r[r2] ^ t2;

  r[r2] = t1 ^ t3;

  const t4 = t0 ^ (r[r3] & t1);

  r[r1] = t2 ^ (r[r2] & t4);
  r[r3] = (r[r0] & t2) ^ (t3 | r[r1]);
  r[r0] = r[r3] ^ (t3 ^ t4);
}

function sb1(r, r0, r1, r2, r3) {
  const t0 = r[r1] ^ (~(r[r0]));
  const t1 = r[r2] ^ (r[r0] | t0);

  r[r2] = r[r3] ^ t1;

  const t2 = r[r1] ^ (r[r3] | t0);
  const t3 = t0 ^ r[r2];

  r[r3] = t3 ^ (t1 & t2);

  const t4 = t1 ^ t2;

  r[r1] = r[r3] ^ t4;
  r[r0] = t1 ^ (t3 & t4);
}

function sb1inv(r, r0, r1, r2, r3) {
  const t0 = r[r1] ^ r[r3];
  const t1 = r[r0] ^ (r[r1] & t0);
  const t2 = t0 ^ t1;

  r[r3] = r[r2] ^ t2;

  const t3 = r[r1] ^ (t0 & t1);
  const t4 = r[r3] | t3;

  r[r1] = t1 ^ t4;

  const t5 = ~(r[r1]);
  const t6 = r[r3] ^ t3;

  r[r0] = t5 ^ t6;
  r[r2] = t2 ^ (t5 | t6);
}

function sb2(r, r0, r1, r2, r3) {
  const v0 = r[r0];
  const v3 = r[r3];
  const t0 = ~v0;
  const t1 = r[r1] ^ v3;
  const t2 = r[r2] & t0;

  r[r0] = t1 ^ t2;

  const t3 = r[r2] ^ t0;
  const t4 = r[r2] ^ r[r0];
  const t5 = r[r1] & t4;

  r[r3] = t3 ^ t5;
  r[r2] = v0 ^ ((v3 | t5) & (r[r0] | t3));
  r[r1] = (t1 ^ r[r3]) ^ (r[r2] ^ (v3 | t0));
}

function sb2inv(r, r0, r1, r2, r3) {
  const v0 = r[r0];
  const v3 = r[r3];
  const t0 = r[r1] ^ v3;
  const t1 = ~t0;
  const t2 = v0 ^ r[r2];
  const t3 = r[r2] ^ t0;
  const t4 = r[r1] & t3;

  r[r0] = t2 ^ t4;

  const t5 = v0 | t1;
  const t6 = v3 ^ t5;
  const t7 = t2 | t6;

  r[r3] = t0 ^ t7;

  const t8 = ~t3;
  const t9 = r[r0] | r[r3];

  r[r1] = t8 ^ t9;
  r[r2] = (v3 & t8) ^ (t2 ^ t9);
}

function sb3(r, r0, r1, r2, r3) {
  const v1 = r[r1];
  const v3 = r[r3];
  const t0 = r[r0] ^ r[r1];
  const t1 = r[r0] & r[r2];
  const t2 = r[r0] | r[r3];
  const t3 = r[r2] ^ r[r3];
  const t4 = t0 & t2;
  const t5 = t1 | t4;

  r[r2] = t3 ^ t5;

  const t6 = r[r1] ^ t2;
  const t7 = t5 ^ t6;
  const t8 = t3 & t7;

  r[r0] = t0 ^ t8;

  const t9 = r[r2] & r[r0];

  r[r1] = t7 ^ t9;
  r[r3] = (v1 | v3) ^ (t3 ^ t9);
}

function sb3inv(r, r0, r1, r2, r3) {
  const t0 = r[r0] | r[r1];
  const t1 = r[r1] ^ r[r2];
  const t2 = r[r1] & t1;
  const t3 = r[r0] ^ t2;
  const t4 = r[r2] ^ t3;
  const t5 = r[r3] | t3;

  r[r0] = t1 ^ t5;

  const t6 = t1 | t5;
  const t7 = r[r3] ^ t6;

  r[r2] = t4 ^ t7;

  const t8 = t0 ^ t7;
  const t9 = r[r0] & t8;

  r[r3] = t3 ^ t9;
  r[r1] = r[r3] ^ (r[r0] ^ t8);
}

function sb4(r, r0, r1, r2, r3) {
  const v0 = r[r0];
  const t0 = v0 ^ r[r3];
  const t1 = r[r3] & t0;
  const t2 = r[r2] ^ t1;
  const t3 = r[r1] | t2;

  r[r3] = t0 ^ t3;

  const t4 = ~(r[r1]);
  const t5 = t0 | t4;

  r[r0] = t2 ^ t5;

  const t6 = v0 & r[r0];
  const t7 = t0 ^ t4;
  const t8 = t3 & t7;

  r[r2] = t6 ^ t8;
  r[r1] = (v0 ^ t2) ^ (t7 & r[r2]);
}

function sb4inv(r, r0, r1, r2, r3) {
  const v3 = r[r3];
  const t0 = r[r2] | v3;
  const t1 = r[r0] & t0;
  const t2 = r[r1] ^ t1;
  const t3 = r[r0] & t2;
  const t4 = r[r2] ^ t3;

  r[r1] = v3 ^ t4;

  const t5 = ~(r[r0]);
  const t6 = t4 & r[r1];

  r[r3] = t2 ^ t6;

  const t7 = r[r1] | t5;
  const t8 = v3 ^ t7;

  r[r0] = r[r3] ^ t8;
  r[r2] = (t2 & t8) ^ (r[r1] ^ t5);
}

function sb5(r, r0, r1, r2, r3) {
  const v1 = r[r1];
  const t0 = ~(r[r0]);
  const t1 = r[r0] ^ v1;
  const t2 = r[r0] ^ r[r3];
  const t3 = r[r2] ^ t0;
  const t4 = t1 | t2;

  r[r0] = t3 ^ t4;

  const t5 = r[r3] & r[r0];
  const t6 = t1 ^ r[r0];

  r[r1] = t5 ^ t6;

  const t7 = t0 | r[r0];
  const t8 = t1 | t5;
  const t9 = t2 ^ t7;

  r[r2] = t8 ^ t9;
  r[r3] = (v1 ^ t5) ^ (r[r1] & t9);
}

function sb5inv(r, r0, r1, r2, r3) {
  const v0 = r[r0];
  const v1 = r[r1];
  const v3 = r[r3];
  const t0 = ~(r[r2]);
  const t1 = v1 & t0;
  const t2 = v3 ^ t1;
  const t3 = v0 & t2;
  const t4 = v1 ^ t0;

  r[r3] = t3 ^ t4;

  const t5 = v1 | r[r3];
  const t6 = v0 & t5;

  r[r1] = t2 ^ t6;

  const t7 = v0 | v3;
  const t8 = t0 ^ t5;

  r[r0] = t7 ^ t8;
  r[r2] = (v1 & t7) ^ (t3 | (v0 ^ r[r2]));
}

function sb6(r, r0, r1, r2, r3) {
  const t0 = ~(r[r0]);
  const t1 = r[r0] ^ r[r3];
  const t2 = r[r1] ^ t1;
  const t3 = t0 | t1;
  const t4 = r[r2] ^ t3;

  r[r1] = r[r1] ^ t4;

  const t5 = t1 | r[r1];
  const t6 = r[r3] ^ t5;
  const t7 = t4 & t6;

  r[r2] = t2 ^ t7;

  const t8 = t4 ^ t6;

  r[r0] = r[r2] ^ t8;
  r[r3] = (~t4) ^ (t2 & t8);
}

function sb6inv(r, r0, r1, r2, r3) {
  const v1 = r[r1];
  const v3 = r[r3];
  const t0 = ~(r[r0]);
  const t1 = r[r0] ^ v1;
  const t2 = r[r2] ^ t1;
  const t3 = r[r2] | t0;
  const t4 = v3 ^ t3;

  r[r1] = t2 ^ t4;

  const t5 = t2 & t4;
  const t6 = t1 ^ t5;
  const t7 = v1 | t6;

  r[r3] = t4 ^ t7;

  const t8 = v1 | r[r3];

  r[r0] = t6 ^ t8;
  r[r2] = (v3 & t0) ^ (t2 ^ t8);
}

function sb7(r, r0, r1, r2, r3) {
  const t0 = r[r1] ^ r[r2];
  const t1 = r[r2] & t0;
  const t2 = r[r3] ^ t1;
  const t3 = r[r0] ^ t2;
  const t4 = r[r3] | t0;
  const t5 = t3 & t4;

  r[r1] = r[r1] ^ t5;

  const t6 = t2 | r[r1];
  const t7 = r[r0] & t3;

  r[r3] = t0 ^ t7;

  const t8 = t3 ^ t6;
  const t9 = r[r3] & t8;

  r[r2] = t2 ^ t9;
  r[r0] = (~t8) ^ (r[r3] & r[r2]);
}

function sb7inv(r, r0, r1, r2, r3) {
  const v0 = r[r0];
  const v3 = r[r3];
  const t0 = r[r2] | (v0 & r[r1]);
  const t1 = v3 & (v0 | r[r1]);

  r[r3] = t0 ^ t1;

  const t2 = ~v3;
  const t3 = r[r1] ^ t1;
  const t4 = t3 | (r[r3] ^ t2);

  r[r1] = v0 ^ t4;
  r[r0] = (r[r2] ^ t3) ^ (v3 | r[r1]);
  r[r2] = (t0 ^ r[r1]) ^ (r[r0] ^ (v0 & r[r3]));
}

function readU32(data, off) {
  return (data[off++]
        + data[off++] * 0x100
        + data[off++] * 0x10000
        + data[off++] * 0x1000000);
}

function writeU32(dst, num, off) {
  dst[off++] = num;
  num >>>= 8;
  dst[off++] = num;
  num >>>= 8;
  dst[off++] = num;
  num >>>= 8;
  dst[off++] = num;
  return off;
}

/*
 * Expose
 */

module.exports = Serpent;
