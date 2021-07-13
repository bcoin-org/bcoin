/*!
 * p251.h - p251 field element for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 */

#ifdef TORSION_HAVE_INT128
typedef uint64_t p251_fe_word_t;
#define P251_FIELD_WORDS 5
#include "p251_64.h"
#else
typedef uint32_t p251_fe_word_t;
#define P251_FIELD_WORDS 10
#include "p251_32.h"
#endif

typedef p251_fe_word_t p251_fe_t[P251_FIELD_WORDS];

#define p251_fe_add fiat_p251_add
#define p251_fe_sub fiat_p251_sub
#define p251_fe_neg fiat_p251_opp
#define p251_fe_mul fiat_p251_carry_mul
#define p251_fe_sqr fiat_p251_carry_square

static void
p251_fe_set(p251_fe_t z, const p251_fe_t x) {
  z[0] = x[0];
  z[1] = x[1];
  z[2] = x[2];
  z[3] = x[3];
  z[4] = x[4];
#if P251_FIELD_WORDS == 10
  z[5] = x[5];
  z[6] = x[6];
  z[7] = x[7];
  z[8] = x[8];
  z[9] = x[9];
#endif
}

static int
p251_fe_equal(const p251_fe_t x, const p251_fe_t y) {
  uint32_t z = 0;
  uint8_t u[32];
  uint8_t v[32];
  int i;

  fiat_p251_to_bytes(u, x);
  fiat_p251_to_bytes(v, y);

  for (i = 0; i < 32; i++)
    z |= (uint32_t)u[i] ^ (uint32_t)v[i];

  return (z - 1) >> 31;
}

static void
p251_fe_sqrn(p251_fe_t z, const p251_fe_t x, int n) {
  int i;

  p251_fe_sqr(z, x);

  for (i = 1; i < n; i++)
    p251_fe_sqr(z, z);
}

static void
p251_fe_pow_core(p251_fe_t z, const p251_fe_t x1) {
  /* Exponent: 2^247 - 1 */
  /* Bits: 247x1 */
  p251_fe_t t1, t2, t3;

  /* x2 = x1^(2^1) * x1 */
  p251_fe_sqr(t1, x1);
  p251_fe_mul(t1, t1, x1);

  /* x3 = x2^(2^1) * x1 */
  p251_fe_sqr(t1, t1);
  p251_fe_mul(t1, t1, x1);

  /* x6 = x3^(2^3) * x3 */
  p251_fe_sqrn(t2, t1, 3);
  p251_fe_mul(t2, t2, t1);

  /* x12 = x6^(2^6) * x6 */
  p251_fe_sqrn(t1, t2, 6);
  p251_fe_mul(t1, t1, t2);

  /* x24 = x12^(2^12) * x12 */
  p251_fe_sqrn(t3, t1, 12);
  p251_fe_mul(t3, t3, t1);

  /* x48 = x24^(2^24) * x24 */
  p251_fe_sqrn(t1, t3, 24);
  p251_fe_mul(t1, t1, t3);

  /* x96 = x48^(2^48) * x48 */
  p251_fe_sqrn(t3, t1, 48);
  p251_fe_mul(t3, t3, t1);

  /* x192 = x96^(2^96) * x96 */
  p251_fe_sqrn(z, t3, 96);
  p251_fe_mul(z, z, t3);

  /* x240 = x192^(2^48) * x48 */
  p251_fe_sqrn(z, z, 48);
  p251_fe_mul(z, z, t1);

  /* x246 = x240^(2^6) * x6 */
  p251_fe_sqrn(z, z, 6);
  p251_fe_mul(z, z, t2);

  /* x247 = x246^(2^1) * x1 */
  p251_fe_sqr(z, z);
  p251_fe_mul(z, z, x1);
}

static void
p251_fe_pow_pm3d4(p251_fe_t z, const p251_fe_t x) {
  /* Exponent: (p - 3) / 4 */
  /* Bits: 247x1 1x0 1x1 */
  p251_fe_t x1;

  /* x1 = x */
  p251_fe_set(x1, x);

  /* z = x1^(2^247 - 1) */
  p251_fe_pow_core(z, x1);

  /* z = z^(2^1) */
  p251_fe_sqr(z, z);

  /* z = z^(2^1) * x1 */
  p251_fe_sqr(z, z);
  p251_fe_mul(z, z, x1);
}

static void
p251_fe_invert(p251_fe_t z, const p251_fe_t x) {
  /* Exponent: p - 2 */
  /* Bits: 247x1 1x0 1x1 1x0 1x1 */
  p251_fe_t x1;

  /* x1 = x */
  p251_fe_set(x1, x);

  /* z = x1^((p - 3) / 4) */
  p251_fe_pow_pm3d4(z, x1);

  /* z = z^(2^1) */
  p251_fe_sqr(z, z);

  /* z = z^(2^1) * x1 */
  p251_fe_sqr(z, z);
  p251_fe_mul(z, z, x1);
}

static int
p251_fe_sqrt(p251_fe_t z, const p251_fe_t x) {
  /* Exponent: (p + 1) / 4 */
  /* Bits: 248x1 1x0 */
  p251_fe_t x1, c;

  /* x1 = x */
  p251_fe_set(x1, x);

  /* z = x1^(2^247 - 1) */
  p251_fe_pow_core(z, x1);

  /* z = z^(2^1) * x1 */
  p251_fe_sqr(z, z);
  p251_fe_mul(z, z, x1);

  /* z = z^(2^1) */
  p251_fe_sqr(z, z);

  /* z^2 == x1 */
  p251_fe_sqr(c, z);

  return p251_fe_equal(c, x1);
}

static int
p251_fe_isqrt(p251_fe_t z, const p251_fe_t u, const p251_fe_t v) {
  p251_fe_t t, x, c;
  int ret;

  /* x = u^3 * v * (u^5 * v^3)^((p - 3) / 4) mod p */
  p251_fe_sqr(t, u);       /* u^2 */
  p251_fe_mul(c, t, u);    /* u^3 */
  p251_fe_mul(t, t, c);    /* u^5 */
  p251_fe_sqr(x, v);       /* v^2 */
  p251_fe_mul(x, x, v);    /* v^3 */
  p251_fe_mul(x, x, t);    /* v^3 * u^5 */
  p251_fe_pow_pm3d4(x, x); /* (v^3 * u^5)^((p - 3) / 4) */
  p251_fe_mul(x, x, v);    /* (v^3 * u^5)^((p - 3) / 4) * v */
  p251_fe_mul(x, x, c);    /* (v^3 * u^5)^((p - 3) / 4) * v * u^3 */

  /* x^2 * v == u */
  p251_fe_sqr(c, x);
  p251_fe_mul(c, c, v);

  ret = p251_fe_equal(c, u);

  p251_fe_set(z, x);

  return ret;
}

static void
fiat_p251_carry_scmul_m1174(p251_fe_t z, const p251_fe_t x) {
  fiat_p251_opp(z, x);
  fiat_p251_carry_scmul_1174(z, z);
}
