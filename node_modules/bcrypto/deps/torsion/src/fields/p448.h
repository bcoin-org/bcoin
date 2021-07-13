/*!
 * p448.h - p448 field element for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 */

#if defined(TORSION_HAVE_INT128)
typedef uint64_t p448_fe_word_t;
#define P448_FIELD_WORDS 8
#include "p448_64.h"
#else
typedef uint32_t p448_fe_word_t;
#define P448_FIELD_WORDS 18
#include "p448_32.h"
#endif

typedef p448_fe_word_t p448_fe_t[P448_FIELD_WORDS];

#define p448_fe_add fiat_p448_add
#define p448_fe_sub fiat_p448_sub
#define p448_fe_neg fiat_p448_opp
#define p448_fe_mul fiat_p448_carry_mul
#define p448_fe_sqr fiat_p448_carry_square

static void
p448_fe_set(p448_fe_t z, const p448_fe_t x) {
  z[0] = x[0];
  z[1] = x[1];
  z[2] = x[2];
  z[3] = x[3];
  z[4] = x[4];
  z[5] = x[5];
  z[6] = x[6];
  z[7] = x[7];
#if P448_FIELD_WORDS == 18
  z[8] = x[8];
  z[9] = x[9];
  z[10] = x[10];
  z[11] = x[11];
  z[12] = x[12];
  z[13] = x[13];
  z[14] = x[14];
  z[15] = x[15];
  z[16] = x[16];
  z[17] = x[17];
#endif
}

static int
p448_fe_equal(const p448_fe_t x, const p448_fe_t y) {
  uint32_t z = 0;
  uint8_t u[56];
  uint8_t v[56];
  int i;

  fiat_p448_to_bytes(u, x);
  fiat_p448_to_bytes(v, y);

  for (i = 0; i < 56; i++)
    z |= (uint32_t)u[i] ^ (uint32_t)v[i];

  return (z - 1) >> 31;
}

static void
p448_fe_sqrn(p448_fe_t z, const p448_fe_t x, int n) {
  int i;

  p448_fe_sqr(z, x);

  for (i = 1; i < n; i++)
    p448_fe_sqr(z, z);
}

static void
p448_fe_pow_core(p448_fe_t z, const p448_fe_t x1, const p448_fe_t x2) {
  /* Exponent: 2^222 - 1 */
  /* Bits: 222x1 */
  p448_fe_t t1, t2;

  /* x3 = x2^(2^1) * x1 */
  p448_fe_sqr(t1, x2);
  p448_fe_mul(t1, t1, x1);

  /* x6 = x3^(2^3) * x3 */
  p448_fe_sqrn(t2, t1, 3);
  p448_fe_mul(t2, t2, t1);

  /* x9 = x6^(2^3) * x3 */
  p448_fe_sqrn(t2, t2, 3);
  p448_fe_mul(t2, t2, t1);

  /* x11 = x9^(2^2) * x2 */
  p448_fe_sqrn(t1, t2, 2);
  p448_fe_mul(t1, t1, x2);

  /* x22 = x11^(2^11) * x11 */
  p448_fe_sqrn(t2, t1, 11);
  p448_fe_mul(t2, t2, t1);

  /* x44 = x22^(2^22) * x22 */
  p448_fe_sqrn(t1, t2, 22);
  p448_fe_mul(t1, t1, t2);

  /* x88 = x44^(2^44) * x44 */
  p448_fe_sqrn(t2, t1, 44);
  p448_fe_mul(t2, t2, t1);

  /* x176 = x88^(2^88) * x88 */
  p448_fe_sqrn(z, t2, 88);
  p448_fe_mul(z, z, t2);

  /* x220 = x176^(2^44) * x44 */
  p448_fe_sqrn(z, z, 44);
  p448_fe_mul(z, z, t1);

  /* x222 = x220^(2^2) * x2 */
  p448_fe_sqrn(z, z, 2);
  p448_fe_mul(z, z, x2);
}

static void
p448_fe_pow_pm3d4(p448_fe_t z, const p448_fe_t x) {
  /* Exponent: (p - 3) / 4 */
  /* Bits: 223x1 1x0 222x1 */
  p448_fe_t x1, x2, x222;

  /* x1 = x */
  p448_fe_set(x1, x);

  /* x2 = x1^(2^1) * x1 */
  p448_fe_sqr(x2, x1);
  p448_fe_mul(x2, x2, x1);

  /* x222 = x1^(2^222 - 1) */
  p448_fe_pow_core(x222, x1, x2);

  /* z = x222^(2^1) * x1 */
  p448_fe_sqr(z, x222);
  p448_fe_mul(z, z, x1);

  /* z = z^(2^1) */
  p448_fe_sqr(z, z);

  /* z = z^(2^222) * x222 */
  p448_fe_sqrn(z, z, 222);
  p448_fe_mul(z, z, x222);
}

static void
p448_fe_invert(p448_fe_t z, const p448_fe_t x) {
  /* Exponent: p - 2 */
  /* Bits: 223x1 1x0 222x1 1x0 1x1 */
  p448_fe_t x1;

  /* x1 = x */
  p448_fe_set(x1, x);

  /* z = x1^((p - 3) / 4) */
  p448_fe_pow_pm3d4(z, x1);

  /* z = z^(2^1) */
  p448_fe_sqr(z, z);

  /* z = z^(2^1) * x1 */
  p448_fe_sqr(z, z);
  p448_fe_mul(z, z, x1);
}

static int
p448_fe_sqrt(p448_fe_t z, const p448_fe_t x) {
  /* Exponent: (p + 1) / 4 */
  /* Bits: 224x1 222x0 */
  p448_fe_t x1, x2;

  /* x1 = x */
  p448_fe_set(x1, x);

  /* x2 = x1^(2^1) * x1 */
  p448_fe_sqr(x2, x1);
  p448_fe_mul(x2, x2, x1);

  /* z = x1^(2^222 - 1) */
  p448_fe_pow_core(z, x1, x2);

  /* z = z^(2^2) * x2 */
  p448_fe_sqrn(z, z, 2);
  p448_fe_mul(z, z, x2);

  /* z = z^(2^222) */
  p448_fe_sqrn(z, z, 222);

  /* z^2 == x1 */
  p448_fe_sqr(x2, z);

  return p448_fe_equal(x2, x1);
}

static int
p448_fe_isqrt(p448_fe_t z, const p448_fe_t u, const p448_fe_t v) {
  p448_fe_t t, x, c;
  int ret;

  /* x = u^3 * v * (u^5 * v^3)^((p - 3) / 4) mod p */
  p448_fe_sqr(t, u);       /* u^2 */
  p448_fe_mul(c, t, u);    /* u^3 */
  p448_fe_mul(t, t, c);    /* u^5 */
  p448_fe_sqr(x, v);       /* v^2 */
  p448_fe_mul(x, x, v);    /* v^3 */
  p448_fe_mul(x, x, t);    /* v^3 * u^5 */
  p448_fe_pow_pm3d4(x, x); /* (v^3 * u^5)^((p - 3) / 4) */
  p448_fe_mul(x, x, v);    /* (v^3 * u^5)^((p - 3) / 4) * v */
  p448_fe_mul(x, x, c);    /* (v^3 * u^5)^((p - 3) / 4) * v * u^3 */

  /* x^2 * v == u */
  p448_fe_sqr(c, x);
  p448_fe_mul(c, c, v);

  ret = p448_fe_equal(c, u);

  p448_fe_set(z, x);

  return ret;
}

static void
fiat_p448_carry_scmul_m39081(p448_fe_t z, const p448_fe_t x) {
  fiat_p448_opp(z, x);
  fiat_p448_carry_scmul_39081(z, z);
}
