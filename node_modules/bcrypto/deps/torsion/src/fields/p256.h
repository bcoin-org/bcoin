/*!
 * p256.h - p256 field element for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 *
 * Resources:
 *   https://briansmith.org/ecc-inversion-addition-chains-01#p256_field_inversion
 */

#if defined(TORSION_HAVE_INT128)
typedef uint64_t p256_fe_word_t;
#define P256_FIELD_WORDS 4
#include "p256_64.h"
#else
typedef uint32_t p256_fe_word_t;
#define P256_FIELD_WORDS 8
#include "p256_32.h"
#endif

typedef p256_fe_word_t p256_fe_t[P256_FIELD_WORDS];

#define p256_fe_add fiat_p256_add
#define p256_fe_sub fiat_p256_sub
#define p256_fe_neg fiat_p256_opp
#define p256_fe_mul fiat_p256_mul
#define p256_fe_sqr fiat_p256_square

static void
p256_fe_set(p256_fe_t z, const p256_fe_t x) {
  z[0] = x[0];
  z[1] = x[1];
  z[2] = x[2];
  z[3] = x[3];
#if P256_FIELD_WORDS == 8
  z[4] = x[4];
  z[5] = x[5];
  z[6] = x[6];
  z[7] = x[7];
#endif
}

static int
p256_fe_equal(const p256_fe_t x, const p256_fe_t y) {
  p256_fe_word_t z = 0;
  int i;

  for (i = 0; i < P256_FIELD_WORDS; i++)
    z |= x[i] ^ y[i];

  z = (z >> 1) | (z & 1);

  return (z - 1) >> (sizeof(z) * CHAR_BIT - 1);
}

static void
p256_fe_sqrn(p256_fe_t z, const p256_fe_t x, int n) {
  int i;

  p256_fe_sqr(z, x);

  for (i = 1; i < n; i++)
    p256_fe_sqr(z, z);
}

static void
p256_fe_pow_pm3d4(p256_fe_t z, const p256_fe_t x) {
  /* Exponent: (p - 3) / 4 */
  /* Bits: 32x1 31x0 1x1 96x0 94x1 */
  p256_fe_t t0, t1, t2, t3, t4;

  /* x1 = x */
  p256_fe_set(t0, x);

  /* x2 = x1^(2^1) * x1 */
  p256_fe_sqr(t1, t0);
  p256_fe_mul(t1, t1, t0);

  /* x3 = x2^(2^1) * x1 */
  p256_fe_sqr(t2, t1);
  p256_fe_mul(t2, t2, t0);

  /* x6 = x3^(2^3) * x3 */
  p256_fe_sqrn(t3, t2, 3);
  p256_fe_mul(t3, t3, t2);

  /* x12 = x6^(2^6) * x6 */
  p256_fe_sqrn(t4, t3, 6);
  p256_fe_mul(t4, t4, t3);

  /* x15 = x12^(2^3) * x3 */
  p256_fe_sqrn(t3, t4, 3);
  p256_fe_mul(t3, t3, t2);

  /* x30 = x15^(2^15) * x15 */
  p256_fe_sqrn(t2, t3, 15);
  p256_fe_mul(t2, t2, t3);

  /* x32 = x30^(2^2) * x2 */
  p256_fe_sqrn(t3, t2, 2);
  p256_fe_mul(t3, t3, t1);

  /* z = x32^(2^31) */
  p256_fe_sqrn(z, t3, 31);

  /* z = z^(2^1) * x1 */
  p256_fe_sqr(z, z);
  p256_fe_mul(z, z, t0);

  /* z = z^(2^96) */
  p256_fe_sqrn(z, z, 96);

  /* z = z^(2^32) * x32 */
  p256_fe_sqrn(z, z, 32);
  p256_fe_mul(z, z, t3);

  /* z = z^(2^32) * x32 */
  p256_fe_sqrn(z, z, 32);
  p256_fe_mul(z, z, t3);

  /* z = z^(2^30) * x30 */
  p256_fe_sqrn(z, z, 30);
  p256_fe_mul(z, z, t2);
}

static void
p256_fe_invert(p256_fe_t z, const p256_fe_t x) {
  /* Exponent: p - 2 */
  /* Bits: 32x1 31x0 1x1 96x0 94x1 1x0 1x1 */
  p256_fe_t x1;

  /* x1 = x */
  p256_fe_set(x1, x);

  /* z = x1^((p - 3) / 4) */
  p256_fe_pow_pm3d4(z, x1);

  /* z = z^(2^1) */
  p256_fe_sqr(z, z);

  /* z = z^(2^1) * x1 */
  p256_fe_sqr(z, z);
  p256_fe_mul(z, z, x1);
}

static int
p256_fe_sqrt(p256_fe_t z, const p256_fe_t x) {
  /* Exponent: (p + 1) / 4 */
  /* Bits: 32x1 31x0 1x1 95x0 1x1 94x0 */
  p256_fe_t t0, t1, t2;

  /* x1 = x */
  p256_fe_set(t0, x);

  /* x2 = x1^(2^1) * x1 */
  p256_fe_sqr(t1, t0);
  p256_fe_mul(t1, t1, t0);

  /* x4 = x2^(2^2) * x2 */
  p256_fe_sqrn(t2, t1, 2);
  p256_fe_mul(t2, t2, t1);

  /* x8 = x4^(2^4) * x4 */
  p256_fe_sqrn(t1, t2, 4);
  p256_fe_mul(t1, t1, t2);

  /* x16 = x8^(2^8) * x8 */
  p256_fe_sqrn(t2, t1, 8);
  p256_fe_mul(t2, t2, t1);

  /* x32 = x16^(2^16) * x16 */
  p256_fe_sqrn(z, t2, 16);
  p256_fe_mul(z, z, t2);

  /* z = x32^(2^31) */
  p256_fe_sqrn(z, z, 31);

  /* z = z^(2^1) * x1 */
  p256_fe_sqr(z, z);
  p256_fe_mul(z, z, t0);

  /* z = z^(2^95) */
  p256_fe_sqrn(z, z, 95);

  /* z = z^(2^1) * x1 */
  p256_fe_sqr(z, z);
  p256_fe_mul(z, z, t0);

  /* z = z^(2^94) */
  p256_fe_sqrn(z, z, 94);

  /* z^2 == x1 */
  p256_fe_sqr(t1, z);

  return p256_fe_equal(t1, t0);
}

static int
p256_fe_isqrt(p256_fe_t z, const p256_fe_t u, const p256_fe_t v) {
  p256_fe_t t, x, c;
  int ret;

  /* x = u^3 * v * (u^5 * v^3)^((p - 3) / 4) mod p */
  p256_fe_sqr(t, u);       /* u^2 */
  p256_fe_mul(c, t, u);    /* u^3 */
  p256_fe_mul(t, t, c);    /* u^5 */
  p256_fe_sqr(x, v);       /* v^2 */
  p256_fe_mul(x, x, v);    /* v^3 */
  p256_fe_mul(x, x, t);    /* v^3 * u^5 */
  p256_fe_pow_pm3d4(x, x); /* (v^3 * u^5)^((p - 3) / 4) */
  p256_fe_mul(x, x, v);    /* (v^3 * u^5)^((p - 3) / 4) * v */
  p256_fe_mul(x, x, c);    /* (v^3 * u^5)^((p - 3) / 4) * v * u^3 */

  /* x^2 * v == u */
  p256_fe_sqr(c, x);
  p256_fe_mul(c, c, v);

  ret = p256_fe_equal(c, u);

  p256_fe_set(z, x);

  return ret;
}

static void
fiat_p256_scmul_3(p256_fe_t z, const p256_fe_t x) {
  p256_fe_t t;
  fiat_p256_add(t, x, x);
  fiat_p256_add(z, t, x);
}

static void
fiat_p256_scmul_4(p256_fe_t z, const p256_fe_t x) {
  fiat_p256_add(z, x, x);
  fiat_p256_add(z, z, z);
}

static void
fiat_p256_scmul_8(p256_fe_t z, const p256_fe_t x) {
  fiat_p256_add(z, x, x);
  fiat_p256_add(z, z, z);
  fiat_p256_add(z, z, z);
}
