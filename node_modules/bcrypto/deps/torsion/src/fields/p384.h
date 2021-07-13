/*!
 * p384.h - p384 field element for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 *
 * Resources:
 *   https://briansmith.org/ecc-inversion-addition-chains-01#p384_field_inversion
 */

#if defined(TORSION_HAVE_INT128)
typedef uint64_t p384_fe_word_t;
#define P384_FIELD_WORDS 6
#include "p384_64.h"
#else
typedef uint32_t p384_fe_word_t;
#define P384_FIELD_WORDS 12
#include "p384_32.h"
#endif

typedef p384_fe_word_t p384_fe_t[P384_FIELD_WORDS];

#define p384_fe_add fiat_p384_add
#define p384_fe_sub fiat_p384_sub
#define p384_fe_neg fiat_p384_opp
#define p384_fe_mul fiat_p384_mul
#define p384_fe_sqr fiat_p384_square

static void
p384_fe_set(p384_fe_t z, const p384_fe_t x) {
  z[0] = x[0];
  z[1] = x[1];
  z[2] = x[2];
  z[3] = x[3];
  z[4] = x[4];
  z[5] = x[5];
#if P384_FIELD_WORDS == 12
  z[4] = x[4];
  z[5] = x[5];
  z[6] = x[6];
  z[7] = x[7];
  z[8] = x[8];
  z[9] = x[9];
  z[10] = x[10];
  z[11] = x[11];
#endif
}

static int
p384_fe_equal(const p384_fe_t x, const p384_fe_t y) {
  p384_fe_word_t z = 0;
  int i;

  for (i = 0; i < P384_FIELD_WORDS; i++)
    z |= x[i] ^ y[i];

  z = (z >> 1) | (z & 1);

  return (z - 1) >> (sizeof(z) * CHAR_BIT - 1);
}

static void
p384_fe_sqrn(p384_fe_t z, const p384_fe_t x, int n) {
  int i;

  p384_fe_sqr(z, x);

  for (i = 1; i < n; i++)
    p384_fe_sqr(z, z);
}

static void
p384_fe_pow_pm3d4(p384_fe_t z, const p384_fe_t x1) {
  /* Exponent: (p - 3) / 4 */
  /* Bits: 255x1 1x0 32x1 64x0 30x1 */
  p384_fe_t t1, t2, t3, t4, t5;

  /* x2 = x1^(2^1) * x1 */
  p384_fe_sqr(t1, x1);
  p384_fe_mul(t1, t1, x1);

  /* x3 = x2^(2^1) * x1 */
  p384_fe_sqr(t2, t1);
  p384_fe_mul(t2, t2, x1);

  /* x6 = x3^(2^3) * x3 */
  p384_fe_sqrn(t3, t2, 3);
  p384_fe_mul(t3, t3, t2);

  /* x12 = x6^(2^6) * x6 */
  p384_fe_sqrn(t4, t3, 6);
  p384_fe_mul(t4, t4, t3);

  /* x15 = x12^(2^3) * x3 */
  p384_fe_sqrn(t3, t4, 3);
  p384_fe_mul(t3, t3, t2);

  /* x30 = x15^(2^15) * x15 */
  p384_fe_sqrn(t2, t3, 15);
  p384_fe_mul(t2, t2, t3);

  /* x60 = x30^(2^30) * x30 */
  p384_fe_sqrn(t4, t2, 30);
  p384_fe_mul(t4, t4, t2);

  /* x120 = x60^(2^60) * x60 */
  p384_fe_sqrn(t5, t4, 60);
  p384_fe_mul(t5, t5, t4);

  /* x240 = x120^(2^120) * x120 */
  p384_fe_sqrn(z, t5, 120);
  p384_fe_mul(z, z, t5);

  /* x255 = x240^(2^15) * x15 */
  p384_fe_sqrn(z, z, 15);
  p384_fe_mul(z, z, t3);

  /* z = x255^(2^1) */
  p384_fe_sqr(z, z);

  /* z = z^(2^30) * x30 */
  p384_fe_sqrn(z, z, 30);
  p384_fe_mul(z, z, t2);

  /* z = z^(2^2) * x2 */
  p384_fe_sqrn(z, z, 2);
  p384_fe_mul(z, z, t1);

  /* z = z^(2^64) */
  p384_fe_sqrn(z, z, 64);

  /* z = z^(2^30) * x30 */
  p384_fe_sqrn(z, z, 30);
  p384_fe_mul(z, z, t2);
}

static void
p384_fe_invert(p384_fe_t z, const p384_fe_t x) {
  /* Exponent: p - 2 */
  /* Bits: 255x1 1x0 32x1 64x0 30x1 1x0 1x1 */
  p384_fe_t x1;

  /* x1 = x */
  p384_fe_set(x1, x);

  /* z = x1^((p - 3) / 4) */
  p384_fe_pow_pm3d4(z, x1);

  /* z = z^(2^1) */
  p384_fe_sqr(z, z);

  /* z = z^(2^1) * x1 */
  p384_fe_sqr(z, z);
  p384_fe_mul(z, z, x1);
}

static int
p384_fe_sqrt(p384_fe_t z, const p384_fe_t x) {
  /* Exponent: (p + 1) / 4 */
  /* Bits: 255x1 1x0 32x1 63x0 1x1 30x0 */
  p384_fe_t t0, t1, t2, t3, t4, t5;

  p384_fe_set(t0, x);

  /* x2 = x1^(2^1) * x1 */
  p384_fe_sqr(t1, t0);
  p384_fe_mul(t1, t1, t0);

  /* x3 = x2^(2^1) * x1 */
  p384_fe_sqr(t2, t1);
  p384_fe_mul(t2, t2, t0);

  /* x6 = x3^(2^3) * x3 */
  p384_fe_sqrn(t3, t2, 3);
  p384_fe_mul(t3, t3, t2);

  /* x12 = x6^(2^6) * x6 */
  p384_fe_sqrn(t4, t3, 6);
  p384_fe_mul(t4, t4, t3);

  /* x15 = x12^(2^3) * x3 */
  p384_fe_sqrn(t3, t4, 3);
  p384_fe_mul(t3, t3, t2);

  /* x30 = x15^(2^15) * x15 */
  p384_fe_sqrn(t2, t3, 15);
  p384_fe_mul(t2, t2, t3);

  /* x60 = x30^(2^30) * x30 */
  p384_fe_sqrn(t4, t2, 30);
  p384_fe_mul(t4, t4, t2);

  /* x120 = x60^(2^60) * x60 */
  p384_fe_sqrn(t5, t4, 60);
  p384_fe_mul(t5, t5, t4);

  /* x240 = x120^(2^120) * x120 */
  p384_fe_sqrn(z, t5, 120);
  p384_fe_mul(z, z, t5);

  /* x255 = x240^(2^15) * x15 */
  p384_fe_sqrn(z, z, 15);
  p384_fe_mul(z, z, t3);

  /* z = x255^(2^1) */
  p384_fe_sqr(z, z);

  /* z = z^(2^30) * x30 */
  p384_fe_sqrn(z, z, 30);
  p384_fe_mul(z, z, t2);

  /* z = z^(2^2) * x2 */
  p384_fe_sqrn(z, z, 2);
  p384_fe_mul(z, z, t1);

  /* z = z^(2^63) */
  p384_fe_sqrn(z, z, 63);

  /* z = z^(2^1) * x1 */
  p384_fe_sqr(z, z);
  p384_fe_mul(z, z, t0);

  /* z = z^(2^30) */
  p384_fe_sqrn(z, z, 30);

  /* z^2 == x1 */
  p384_fe_sqr(t1, z);

  return p384_fe_equal(t1, t0);
}

static int
p384_fe_isqrt(p384_fe_t z, const p384_fe_t u, const p384_fe_t v) {
  p384_fe_t t, x, c;
  int ret;

  /* x = u^3 * v * (u^5 * v^3)^((p - 3) / 4) mod p */
  p384_fe_sqr(t, u);       /* u^2 */
  p384_fe_mul(c, t, u);    /* u^3 */
  p384_fe_mul(t, t, c);    /* u^5 */
  p384_fe_sqr(x, v);       /* v^2 */
  p384_fe_mul(x, x, v);    /* v^3 */
  p384_fe_mul(x, x, t);    /* v^3 * u^5 */
  p384_fe_pow_pm3d4(x, x); /* (v^3 * u^5)^((p - 3) / 4) */
  p384_fe_mul(x, x, v);    /* (v^3 * u^5)^((p - 3) / 4) * v */
  p384_fe_mul(x, x, c);    /* (v^3 * u^5)^((p - 3) / 4) * v * u^3 */

  /* x^2 * v == u */
  p384_fe_sqr(c, x);
  p384_fe_mul(c, c, v);

  ret = p384_fe_equal(c, u);

  p384_fe_set(z, x);

  return ret;
}

static void
fiat_p384_scmul_3(p384_fe_t z, const p384_fe_t x) {
  p384_fe_t t;
  fiat_p384_add(t, x, x);
  fiat_p384_add(z, t, x);
}

static void
fiat_p384_scmul_4(p384_fe_t z, const p384_fe_t x) {
  fiat_p384_add(z, x, x);
  fiat_p384_add(z, z, z);
}

static void
fiat_p384_scmul_8(p384_fe_t z, const p384_fe_t x) {
  fiat_p384_add(z, x, x);
  fiat_p384_add(z, z, z);
  fiat_p384_add(z, z, z);
}
