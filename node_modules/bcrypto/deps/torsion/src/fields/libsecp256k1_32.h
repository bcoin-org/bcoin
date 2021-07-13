/*!
 * libsecp256k1_32.h - optional libsecp256k1 backend
 *
 * From bitcoin-core/secp256k1:
 *   Copyright (c) 2013, Pieter Wuille
 *   https://github.com/bitcoin-core/secp256k1
 *
 * Modified to look like a fiat backend (note: this is NOT a fiat backend).
 */

#include <stdint.h>

typedef unsigned char fiat_secp256k1_uint1;

#if (-1 & 3) != 3
#error "This code only works on a two's complement system"
#endif

static void fiat_secp256k1_carry_mul(uint32_t r[10], const uint32_t a[10], const uint32_t b[10]) {
  uint64_t c, d;
  uint64_t u0, u1, u2, u3, u4, u5, u6, u7, u8;
  uint32_t t9, t1, t0, t2, t3, t4, t5, t6, t7;
  const uint32_t M = 0x3FFFFFFUL, R0 = 0x3D10UL, R1 = 0x400UL;

  d  = (uint64_t)a[0] * b[9]
     + (uint64_t)a[1] * b[8]
     + (uint64_t)a[2] * b[7]
     + (uint64_t)a[3] * b[6]
     + (uint64_t)a[4] * b[5]
     + (uint64_t)a[5] * b[4]
     + (uint64_t)a[6] * b[3]
     + (uint64_t)a[7] * b[2]
     + (uint64_t)a[8] * b[1]
     + (uint64_t)a[9] * b[0];
  t9 = d & M; d >>= 26;

  c  = (uint64_t)a[0] * b[0];
  d += (uint64_t)a[1] * b[9]
     + (uint64_t)a[2] * b[8]
     + (uint64_t)a[3] * b[7]
     + (uint64_t)a[4] * b[6]
     + (uint64_t)a[5] * b[5]
     + (uint64_t)a[6] * b[4]
     + (uint64_t)a[7] * b[3]
     + (uint64_t)a[8] * b[2]
     + (uint64_t)a[9] * b[1];
  u0 = d & M; d >>= 26; c += u0 * R0;
  t0 = c & M; c >>= 26; c += u0 * R1;

  c += (uint64_t)a[0] * b[1]
     + (uint64_t)a[1] * b[0];
  d += (uint64_t)a[2] * b[9]
     + (uint64_t)a[3] * b[8]
     + (uint64_t)a[4] * b[7]
     + (uint64_t)a[5] * b[6]
     + (uint64_t)a[6] * b[5]
     + (uint64_t)a[7] * b[4]
     + (uint64_t)a[8] * b[3]
     + (uint64_t)a[9] * b[2];
  u1 = d & M; d >>= 26; c += u1 * R0;
  t1 = c & M; c >>= 26; c += u1 * R1;

  c += (uint64_t)a[0] * b[2]
     + (uint64_t)a[1] * b[1]
     + (uint64_t)a[2] * b[0];
  d += (uint64_t)a[3] * b[9]
     + (uint64_t)a[4] * b[8]
     + (uint64_t)a[5] * b[7]
     + (uint64_t)a[6] * b[6]
     + (uint64_t)a[7] * b[5]
     + (uint64_t)a[8] * b[4]
     + (uint64_t)a[9] * b[3];
  u2 = d & M; d >>= 26; c += u2 * R0;
  t2 = c & M; c >>= 26; c += u2 * R1;

  c += (uint64_t)a[0] * b[3]
     + (uint64_t)a[1] * b[2]
     + (uint64_t)a[2] * b[1]
     + (uint64_t)a[3] * b[0];
  d += (uint64_t)a[4] * b[9]
     + (uint64_t)a[5] * b[8]
     + (uint64_t)a[6] * b[7]
     + (uint64_t)a[7] * b[6]
     + (uint64_t)a[8] * b[5]
     + (uint64_t)a[9] * b[4];
  u3 = d & M; d >>= 26; c += u3 * R0;
  t3 = c & M; c >>= 26; c += u3 * R1;

  c += (uint64_t)a[0] * b[4]
     + (uint64_t)a[1] * b[3]
     + (uint64_t)a[2] * b[2]
     + (uint64_t)a[3] * b[1]
     + (uint64_t)a[4] * b[0];
  d += (uint64_t)a[5] * b[9]
     + (uint64_t)a[6] * b[8]
     + (uint64_t)a[7] * b[7]
     + (uint64_t)a[8] * b[6]
     + (uint64_t)a[9] * b[5];
  u4 = d & M; d >>= 26; c += u4 * R0;
  t4 = c & M; c >>= 26; c += u4 * R1;

  c += (uint64_t)a[0] * b[5]
     + (uint64_t)a[1] * b[4]
     + (uint64_t)a[2] * b[3]
     + (uint64_t)a[3] * b[2]
     + (uint64_t)a[4] * b[1]
     + (uint64_t)a[5] * b[0];
  d += (uint64_t)a[6] * b[9]
     + (uint64_t)a[7] * b[8]
     + (uint64_t)a[8] * b[7]
     + (uint64_t)a[9] * b[6];
  u5 = d & M; d >>= 26; c += u5 * R0;
  t5 = c & M; c >>= 26; c += u5 * R1;

  c += (uint64_t)a[0] * b[6]
     + (uint64_t)a[1] * b[5]
     + (uint64_t)a[2] * b[4]
     + (uint64_t)a[3] * b[3]
     + (uint64_t)a[4] * b[2]
     + (uint64_t)a[5] * b[1]
     + (uint64_t)a[6] * b[0];
  d += (uint64_t)a[7] * b[9]
     + (uint64_t)a[8] * b[8]
     + (uint64_t)a[9] * b[7];
  u6 = d & M; d >>= 26; c += u6 * R0;
  t6 = c & M; c >>= 26; c += u6 * R1;

  c += (uint64_t)a[0] * b[7]
     + (uint64_t)a[1] * b[6]
     + (uint64_t)a[2] * b[5]
     + (uint64_t)a[3] * b[4]
     + (uint64_t)a[4] * b[3]
     + (uint64_t)a[5] * b[2]
     + (uint64_t)a[6] * b[1]
     + (uint64_t)a[7] * b[0];
  d += (uint64_t)a[8] * b[9]
     + (uint64_t)a[9] * b[8];
  u7 = d & M; d >>= 26; c += u7 * R0;
  t7 = c & M; c >>= 26; c += u7 * R1;

  c += (uint64_t)a[0] * b[8]
     + (uint64_t)a[1] * b[7]
     + (uint64_t)a[2] * b[6]
     + (uint64_t)a[3] * b[5]
     + (uint64_t)a[4] * b[4]
     + (uint64_t)a[5] * b[3]
     + (uint64_t)a[6] * b[2]
     + (uint64_t)a[7] * b[1]
     + (uint64_t)a[8] * b[0];
  d += (uint64_t)a[9] * b[9];
  u8 = d & M; d >>= 26; c += u8 * R0;

  r[3] = t3;
  r[4] = t4;
  r[5] = t5;
  r[6] = t6;
  r[7] = t7;

  r[8] = c & M; c >>= 26; c += u8 * R1;
  c   += d * R0 + t9;
  r[9] = c & (M >> 4); c >>= 22; c += d * (R1 << 4);

  d  = c * (R0 >> 4) + t0;
  r[0] = d & M; d >>= 26;
  d   += c * (R1 >> 4) + t1;
  r[1] = d & M; d >>= 26;
  d   += t2;
  r[2] = d;
}

static void fiat_secp256k1_carry_square(uint32_t r[10], const uint32_t a[10]) {
  uint64_t c, d;
  uint64_t u0, u1, u2, u3, u4, u5, u6, u7, u8;
  uint32_t t9, t0, t1, t2, t3, t4, t5, t6, t7;
  const uint32_t M = 0x3FFFFFFUL, R0 = 0x3D10UL, R1 = 0x400UL;

  d  = (uint64_t)(a[0]*2) * a[9]
     + (uint64_t)(a[1]*2) * a[8]
     + (uint64_t)(a[2]*2) * a[7]
     + (uint64_t)(a[3]*2) * a[6]
     + (uint64_t)(a[4]*2) * a[5];
  t9 = d & M; d >>= 26;

  c  = (uint64_t)a[0] * a[0];
  d += (uint64_t)(a[1]*2) * a[9]
     + (uint64_t)(a[2]*2) * a[8]
     + (uint64_t)(a[3]*2) * a[7]
     + (uint64_t)(a[4]*2) * a[6]
     + (uint64_t)a[5] * a[5];
  u0 = d & M; d >>= 26; c += u0 * R0;
  t0 = c & M; c >>= 26; c += u0 * R1;

  c += (uint64_t)(a[0]*2) * a[1];
  d += (uint64_t)(a[2]*2) * a[9]
     + (uint64_t)(a[3]*2) * a[8]
     + (uint64_t)(a[4]*2) * a[7]
     + (uint64_t)(a[5]*2) * a[6];
  u1 = d & M; d >>= 26; c += u1 * R0;
  t1 = c & M; c >>= 26; c += u1 * R1;

  c += (uint64_t)(a[0]*2) * a[2]
     + (uint64_t)a[1] * a[1];
  d += (uint64_t)(a[3]*2) * a[9]
     + (uint64_t)(a[4]*2) * a[8]
     + (uint64_t)(a[5]*2) * a[7]
     + (uint64_t)a[6] * a[6];
  u2 = d & M; d >>= 26; c += u2 * R0;
  t2 = c & M; c >>= 26; c += u2 * R1;

  c += (uint64_t)(a[0]*2) * a[3]
     + (uint64_t)(a[1]*2) * a[2];
  d += (uint64_t)(a[4]*2) * a[9]
     + (uint64_t)(a[5]*2) * a[8]
     + (uint64_t)(a[6]*2) * a[7];
  u3 = d & M; d >>= 26; c += u3 * R0;
  t3 = c & M; c >>= 26; c += u3 * R1;

  c += (uint64_t)(a[0]*2) * a[4]
     + (uint64_t)(a[1]*2) * a[3]
     + (uint64_t)a[2] * a[2];
  d += (uint64_t)(a[5]*2) * a[9]
     + (uint64_t)(a[6]*2) * a[8]
     + (uint64_t)a[7] * a[7];
  u4 = d & M; d >>= 26; c += u4 * R0;
  t4 = c & M; c >>= 26; c += u4 * R1;

  c += (uint64_t)(a[0]*2) * a[5]
     + (uint64_t)(a[1]*2) * a[4]
     + (uint64_t)(a[2]*2) * a[3];
  d += (uint64_t)(a[6]*2) * a[9]
     + (uint64_t)(a[7]*2) * a[8];
  u5 = d & M; d >>= 26; c += u5 * R0;
  t5 = c & M; c >>= 26; c += u5 * R1;

  c += (uint64_t)(a[0]*2) * a[6]
     + (uint64_t)(a[1]*2) * a[5]
     + (uint64_t)(a[2]*2) * a[4]
     + (uint64_t)a[3] * a[3];
  d += (uint64_t)(a[7]*2) * a[9]
     + (uint64_t)a[8] * a[8];
  u6 = d & M; d >>= 26; c += u6 * R0;
  t6 = c & M; c >>= 26; c += u6 * R1;

  c += (uint64_t)(a[0]*2) * a[7]
     + (uint64_t)(a[1]*2) * a[6]
     + (uint64_t)(a[2]*2) * a[5]
     + (uint64_t)(a[3]*2) * a[4];
  d += (uint64_t)(a[8]*2) * a[9];
  u7 = d & M; d >>= 26; c += u7 * R0;
  t7 = c & M; c >>= 26; c += u7 * R1;

  c += (uint64_t)(a[0]*2) * a[8]
     + (uint64_t)(a[1]*2) * a[7]
     + (uint64_t)(a[2]*2) * a[6]
     + (uint64_t)(a[3]*2) * a[5]
     + (uint64_t)a[4] * a[4];
  d += (uint64_t)a[9] * a[9];
  u8 = d & M; d >>= 26; c += u8 * R0;

  r[3] = t3;
  r[4] = t4;
  r[5] = t5;
  r[6] = t6;
  r[7] = t7;

  r[8] = c & M; c >>= 26; c += u8 * R1;
  c   += d * R0 + t9;
  r[9] = c & (M >> 4); c >>= 22; c += d * (R1 << 4);

  d  = c * (R0 >> 4) + t0;
  r[0] = d & M; d >>= 26;
  d   += c * (R1 >> 4) + t1;
  r[1] = d & M; d >>= 26;
  d   += t2;
  r[2] = d;
}

static void fiat_secp256k1_carry(uint32_t r[10], const uint32_t a[10]) {
  uint32_t t0 = a[0];
  uint32_t t1 = a[1];
  uint32_t t2 = a[2];
  uint32_t t3 = a[3];
  uint32_t t4 = a[4];
  uint32_t t5 = a[5];
  uint32_t t6 = a[6];
  uint32_t t7 = a[7];
  uint32_t t8 = a[8];
  uint32_t t9 = a[9];
  uint32_t m;
  uint32_t x = t9 >> 22; t9 &= 0x03FFFFFUL;

  t0 += x * 0x3D1UL; t1 += (x << 6);
  t1 += (t0 >> 26); t0 &= 0x3FFFFFFUL;
  t2 += (t1 >> 26); t1 &= 0x3FFFFFFUL;
  t3 += (t2 >> 26); t2 &= 0x3FFFFFFUL; m = t2;
  t4 += (t3 >> 26); t3 &= 0x3FFFFFFUL; m &= t3;
  t5 += (t4 >> 26); t4 &= 0x3FFFFFFUL; m &= t4;
  t6 += (t5 >> 26); t5 &= 0x3FFFFFFUL; m &= t5;
  t7 += (t6 >> 26); t6 &= 0x3FFFFFFUL; m &= t6;
  t8 += (t7 >> 26); t7 &= 0x3FFFFFFUL; m &= t7;
  t9 += (t8 >> 26); t8 &= 0x3FFFFFFUL; m &= t8;

  x = (t9 >> 22) | ((t9 == 0x03FFFFFUL) & (m == 0x3FFFFFFUL)
    & ((t1 + 0x40UL + ((t0 + 0x3D1UL) >> 26)) > 0x3FFFFFFUL));

  t0 += x * 0x3D1UL; t1 += (x << 6);
  t1 += (t0 >> 26); t0 &= 0x3FFFFFFUL;
  t2 += (t1 >> 26); t1 &= 0x3FFFFFFUL;
  t3 += (t2 >> 26); t2 &= 0x3FFFFFFUL;
  t4 += (t3 >> 26); t3 &= 0x3FFFFFFUL;
  t5 += (t4 >> 26); t4 &= 0x3FFFFFFUL;
  t6 += (t5 >> 26); t5 &= 0x3FFFFFFUL;
  t7 += (t6 >> 26); t6 &= 0x3FFFFFFUL;
  t8 += (t7 >> 26); t7 &= 0x3FFFFFFUL;
  t9 += (t8 >> 26); t8 &= 0x3FFFFFFUL;

  t9 &= 0x03FFFFFUL;

  r[0] = t0;
  r[1] = t1;
  r[2] = t2;
  r[3] = t3;
  r[4] = t4;
  r[5] = t5;
  r[6] = t6;
  r[7] = t7;
  r[8] = t8;
  r[9] = t9;
}

static void fiat_secp256k1_add(uint32_t r[10], const uint32_t a[10], const uint32_t b[10]) {
  r[0] = a[0] + b[0];
  r[1] = a[1] + b[1];
  r[2] = a[2] + b[2];
  r[3] = a[3] + b[3];
  r[4] = a[4] + b[4];
  r[5] = a[5] + b[5];
  r[6] = a[6] + b[6];
  r[7] = a[7] + b[7];
  r[8] = a[8] + b[8];
  r[9] = a[9] + b[9];
}

static void fiat_secp256k1_sub(uint32_t r[10], const uint32_t a[10], const uint32_t b[10]) {
  uint32_t t0 = 0x3FFFC2FUL * 2 * (1 + 1) - b[0];
  uint32_t t1 = 0x3FFFFBFUL * 2 * (1 + 1) - b[1];
  uint32_t t2 = 0x3FFFFFFUL * 2 * (1 + 1) - b[2];
  uint32_t t3 = 0x3FFFFFFUL * 2 * (1 + 1) - b[3];
  uint32_t t4 = 0x3FFFFFFUL * 2 * (1 + 1) - b[4];
  uint32_t t5 = 0x3FFFFFFUL * 2 * (1 + 1) - b[5];
  uint32_t t6 = 0x3FFFFFFUL * 2 * (1 + 1) - b[6];
  uint32_t t7 = 0x3FFFFFFUL * 2 * (1 + 1) - b[7];
  uint32_t t8 = 0x3FFFFFFUL * 2 * (1 + 1) - b[8];
  uint32_t t9 = 0x03FFFFFUL * 2 * (1 + 1) - b[9];

  r[0] = a[0] + t0;
  r[1] = a[1] + t1;
  r[2] = a[2] + t2;
  r[3] = a[3] + t3;
  r[4] = a[4] + t4;
  r[5] = a[5] + t5;
  r[6] = a[6] + t6;
  r[7] = a[7] + t7;
  r[8] = a[8] + t8;
  r[9] = a[9] + t9;
}

static void fiat_secp256k1_opp(uint32_t r[10], const uint32_t a[10]) {
  r[0] = 0x3FFFC2FUL * 2 * (1 + 1) - a[0];
  r[1] = 0x3FFFFBFUL * 2 * (1 + 1) - a[1];
  r[2] = 0x3FFFFFFUL * 2 * (1 + 1) - a[2];
  r[3] = 0x3FFFFFFUL * 2 * (1 + 1) - a[3];
  r[4] = 0x3FFFFFFUL * 2 * (1 + 1) - a[4];
  r[5] = 0x3FFFFFFUL * 2 * (1 + 1) - a[5];
  r[6] = 0x3FFFFFFUL * 2 * (1 + 1) - a[6];
  r[7] = 0x3FFFFFFUL * 2 * (1 + 1) - a[7];
  r[8] = 0x3FFFFFFUL * 2 * (1 + 1) - a[8];
  r[9] = 0x03FFFFFUL * 2 * (1 + 1) - a[9];
}

static void fiat_secp256k1_nonzero(uint32_t* r, const uint32_t a[10]) {
  uint32_t t0 = a[0];
  uint32_t t1 = a[1];
  uint32_t t2 = a[2];
  uint32_t t3 = a[3];
  uint32_t t4 = a[4];
  uint32_t t5 = a[5];
  uint32_t t6 = a[6];
  uint32_t t7 = a[7];
  uint32_t t8 = a[8];
  uint32_t t9 = a[9];
  uint32_t z0, z1;
  uint32_t x = t9 >> 22; t9 &= 0x03FFFFFUL;

  t0 += x * 0x3D1UL; t1 += (x << 6);
  t1 += (t0 >> 26); t0 &= 0x3FFFFFFUL; z0  = t0; z1  = t0 ^ 0x3D0UL;
  t2 += (t1 >> 26); t1 &= 0x3FFFFFFUL; z0 |= t1; z1 &= t1 ^ 0x40UL;
  t3 += (t2 >> 26); t2 &= 0x3FFFFFFUL; z0 |= t2; z1 &= t2;
  t4 += (t3 >> 26); t3 &= 0x3FFFFFFUL; z0 |= t3; z1 &= t3;
  t5 += (t4 >> 26); t4 &= 0x3FFFFFFUL; z0 |= t4; z1 &= t4;
  t6 += (t5 >> 26); t5 &= 0x3FFFFFFUL; z0 |= t5; z1 &= t5;
  t7 += (t6 >> 26); t6 &= 0x3FFFFFFUL; z0 |= t6; z1 &= t6;
  t8 += (t7 >> 26); t7 &= 0x3FFFFFFUL; z0 |= t7; z1 &= t7;
  t9 += (t8 >> 26); t8 &= 0x3FFFFFFUL; z0 |= t8; z1 &= t8;
                                       z0 |= t9; z1 &= t9 ^ 0x3C00000UL;

  *r = ((z0 == 0) | (z1 == 0x3FFFFFFUL)) ^ 1;
}

static void fiat_secp256k1_selectznz(uint32_t r[10], fiat_secp256k1_uint1 flag, const uint32_t a[10], const uint32_t b[10]) {
  uint32_t mask0, mask1;
  mask0 = flag + ~((uint32_t)0);
  mask1 = ~mask0;
  r[0] = (a[0] & mask0) | (b[0] & mask1);
  r[1] = (a[1] & mask0) | (b[1] & mask1);
  r[2] = (a[2] & mask0) | (b[2] & mask1);
  r[3] = (a[3] & mask0) | (b[3] & mask1);
  r[4] = (a[4] & mask0) | (b[4] & mask1);
  r[5] = (a[5] & mask0) | (b[5] & mask1);
  r[6] = (a[6] & mask0) | (b[6] & mask1);
  r[7] = (a[7] & mask0) | (b[7] & mask1);
  r[8] = (a[8] & mask0) | (b[8] & mask1);
  r[9] = (a[9] & mask0) | (b[9] & mask1);
}

static void fiat_secp256k1_to_bytes(uint8_t r[32], const uint32_t a[10]) {
  r[31] = (a[9] >> 14) & 0xff;
  r[30] = (a[9] >> 6) & 0xff;
  r[29] = ((a[9] & 0x3F) << 2) | ((a[8] >> 24) & 0x3);
  r[28] = (a[8] >> 16) & 0xff;
  r[27] = (a[8] >> 8) & 0xff;
  r[26] = a[8] & 0xff;
  r[25] = (a[7] >> 18) & 0xff;
  r[24] = (a[7] >> 10) & 0xff;
  r[23] = (a[7] >> 2) & 0xff;
  r[22] = ((a[7] & 0x3) << 6) | ((a[6] >> 20) & 0x3f);
  r[21] = (a[6] >> 12) & 0xff;
  r[20] = (a[6] >> 4) & 0xff;
  r[19] = ((a[6] & 0xf) << 4) | ((a[5] >> 22) & 0xf);
  r[18] = (a[5] >> 14) & 0xff;
  r[17] = (a[5] >> 6) & 0xff;
  r[16] = ((a[5] & 0x3f) << 2) | ((a[4] >> 24) & 0x3);
  r[15] = (a[4] >> 16) & 0xff;
  r[14] = (a[4] >> 8) & 0xff;
  r[13] = a[4] & 0xff;
  r[12] = (a[3] >> 18) & 0xff;
  r[11] = (a[3] >> 10) & 0xff;
  r[10] = (a[3] >> 2) & 0xff;
  r[9] = ((a[3] & 0x3) << 6) | ((a[2] >> 20) & 0x3f);
  r[8] = (a[2] >> 12) & 0xff;
  r[7] = (a[2] >> 4) & 0xff;
  r[6] = ((a[2] & 0xf) << 4) | ((a[1] >> 22) & 0xf);
  r[5] = (a[1] >> 14) & 0xff;
  r[4] = (a[1] >> 6) & 0xff;
  r[3] = ((a[1] & 0x3f) << 2) | ((a[0] >> 24) & 0x3);
  r[2] = (a[0] >> 16) & 0xff;
  r[1] = (a[0] >> 8) & 0xff;
  r[0] = a[0] & 0xff;
}

static void fiat_secp256k1_from_bytes(uint32_t r[10], const uint8_t a[32]) {
  r[0] = (uint32_t)a[0]
       | ((uint32_t)a[1] << 8)
       | ((uint32_t)a[2] << 16)
       | ((uint32_t)(a[3] & 0x3) << 24);
  r[1] = (uint32_t)((a[3] >> 2) & 0x3f)
       | ((uint32_t)a[4] << 6)
       | ((uint32_t)a[5] << 14)
       | ((uint32_t)(a[6] & 0xf) << 22);
  r[2] = (uint32_t)((a[6] >> 4) & 0xf)
       | ((uint32_t)a[7] << 4)
       | ((uint32_t)a[8] << 12)
       | ((uint32_t)(a[9] & 0x3f) << 20);
  r[3] = (uint32_t)((a[9] >> 6) & 0x3)
       | ((uint32_t)a[10] << 2)
       | ((uint32_t)a[11] << 10)
       | ((uint32_t)a[12] << 18);
  r[4] = (uint32_t)a[13]
       | ((uint32_t)a[14] << 8)
       | ((uint32_t)a[15] << 16)
       | ((uint32_t)(a[16] & 0x3) << 24);
  r[5] = (uint32_t)((a[16] >> 2) & 0x3f)
       | ((uint32_t)a[17] << 6)
       | ((uint32_t)a[18] << 14)
       | ((uint32_t)(a[19] & 0xf) << 22);
  r[6] = (uint32_t)((a[19] >> 4) & 0xf)
       | ((uint32_t)a[20] << 4)
       | ((uint32_t)a[21] << 12)
       | ((uint32_t)(a[22] & 0x3f) << 20);
  r[7] = (uint32_t)((a[22] >> 6) & 0x3)
       | ((uint32_t)a[23] << 2)
       | ((uint32_t)a[24] << 10)
       | ((uint32_t)a[25] << 18);
  r[8] = (uint32_t)a[26]
       | ((uint32_t)a[27] << 8)
       | ((uint32_t)a[28] << 16)
       | ((uint32_t)(a[29] & 0x3) << 24);
  r[9] = (uint32_t)((a[29] >> 2) & 0x3f)
       | ((uint32_t)a[30] << 6)
       | ((uint32_t)a[31] << 14);
}

TORSION_UNUSED static void
fiat_secp256k1_to_bytes_be(uint8_t r[32], const uint32_t a[10]) {
  r[0] = (a[9] >> 14) & 0xff;
  r[1] = (a[9] >> 6) & 0xff;
  r[2] = ((a[9] & 0x3F) << 2) | ((a[8] >> 24) & 0x3);
  r[3] = (a[8] >> 16) & 0xff;
  r[4] = (a[8] >> 8) & 0xff;
  r[5] = a[8] & 0xff;
  r[6] = (a[7] >> 18) & 0xff;
  r[7] = (a[7] >> 10) & 0xff;
  r[8] = (a[7] >> 2) & 0xff;
  r[9] = ((a[7] & 0x3) << 6) | ((a[6] >> 20) & 0x3f);
  r[10] = (a[6] >> 12) & 0xff;
  r[11] = (a[6] >> 4) & 0xff;
  r[12] = ((a[6] & 0xf) << 4) | ((a[5] >> 22) & 0xf);
  r[13] = (a[5] >> 14) & 0xff;
  r[14] = (a[5] >> 6) & 0xff;
  r[15] = ((a[5] & 0x3f) << 2) | ((a[4] >> 24) & 0x3);
  r[16] = (a[4] >> 16) & 0xff;
  r[17] = (a[4] >> 8) & 0xff;
  r[18] = a[4] & 0xff;
  r[19] = (a[3] >> 18) & 0xff;
  r[20] = (a[3] >> 10) & 0xff;
  r[21] = (a[3] >> 2) & 0xff;
  r[22] = ((a[3] & 0x3) << 6) | ((a[2] >> 20) & 0x3f);
  r[23] = (a[2] >> 12) & 0xff;
  r[24] = (a[2] >> 4) & 0xff;
  r[25] = ((a[2] & 0xf) << 4) | ((a[1] >> 22) & 0xf);
  r[26] = (a[1] >> 14) & 0xff;
  r[27] = (a[1] >> 6) & 0xff;
  r[28] = ((a[1] & 0x3f) << 2) | ((a[0] >> 24) & 0x3);
  r[29] = (a[0] >> 16) & 0xff;
  r[30] = (a[0] >> 8) & 0xff;
  r[31] = a[0] & 0xff;
}

TORSION_UNUSED static void
fiat_secp256k1_from_bytes_be(uint32_t r[10], const uint8_t a[32]) {
  r[0] = (uint32_t)a[31]
       | ((uint32_t)a[30] << 8)
       | ((uint32_t)a[29] << 16)
       | ((uint32_t)(a[28] & 0x3) << 24);
  r[1] = (uint32_t)((a[28] >> 2) & 0x3f)
       | ((uint32_t)a[27] << 6)
       | ((uint32_t)a[26] << 14)
       | ((uint32_t)(a[25] & 0xf) << 22);
  r[2] = (uint32_t)((a[25] >> 4) & 0xf)
       | ((uint32_t)a[24] << 4)
       | ((uint32_t)a[23] << 12)
       | ((uint32_t)(a[22] & 0x3f) << 20);
  r[3] = (uint32_t)((a[22] >> 6) & 0x3)
       | ((uint32_t)a[21] << 2)
       | ((uint32_t)a[20] << 10)
       | ((uint32_t)a[19] << 18);
  r[4] = (uint32_t)a[18]
       | ((uint32_t)a[17] << 8)
       | ((uint32_t)a[16] << 16)
       | ((uint32_t)(a[15] & 0x3) << 24);
  r[5] = (uint32_t)((a[15] >> 2) & 0x3f)
       | ((uint32_t)a[14] << 6)
       | ((uint32_t)a[13] << 14)
       | ((uint32_t)(a[12] & 0xf) << 22);
  r[6] = (uint32_t)((a[12] >> 4) & 0xf)
       | ((uint32_t)a[11] << 4)
       | ((uint32_t)a[10] << 12)
       | ((uint32_t)(a[9] & 0x3f) << 20);
  r[7] = (uint32_t)((a[9] >> 6) & 0x3)
       | ((uint32_t)a[8] << 2)
       | ((uint32_t)a[7] << 10)
       | ((uint32_t)a[6] << 18);
  r[8] = (uint32_t)a[5]
       | ((uint32_t)a[4] << 8)
       | ((uint32_t)a[3] << 16)
       | ((uint32_t)(a[2] & 0x3) << 24);
  r[9] = (uint32_t)((a[2] >> 2) & 0x3f)
       | ((uint32_t)a[1] << 6)
       | ((uint32_t)a[0] << 14);
}
