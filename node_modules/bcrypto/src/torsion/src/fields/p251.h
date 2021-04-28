/*!
 * p251.h - p251 field element for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 */

#ifdef TORSION_USE_64BIT
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
p251_fe_set(p251_fe_t out, const p251_fe_t in) {
  out[0] = in[0];
  out[1] = in[1];
  out[2] = in[2];
  out[3] = in[3];
  out[4] = in[4];
#if P251_FIELD_WORDS == 10
  out[5] = in[5];
  out[6] = in[6];
  out[7] = in[7];
  out[8] = in[8];
  out[9] = in[9];
#endif
}

static int
p251_fe_equal(const p251_fe_t a, const p251_fe_t b) {
  uint32_t z = 0;
  uint8_t u[32];
  uint8_t v[32];
  size_t i;

  fiat_p251_to_bytes(u, a);
  fiat_p251_to_bytes(v, b);

  for (i = 0; i < 32; i++)
    z |= (uint32_t)u[i] ^ (uint32_t)v[i];

  return (z - 1) >> 31;
}

static void
p251_fe_sqrn(p251_fe_t out, const p251_fe_t in, int rounds) {
  int i;

  p251_fe_sqr(out, in);

  for (i = 1; i < rounds; i++)
    p251_fe_sqr(out, out);
}

static void
p251_fe_invert(p251_fe_t out, const p251_fe_t in) {
  /* 247x1 1x0 1x1 1x0 1x1 */
  p251_fe_t x1, x2, x3, x6, x12, x24, x48, x96;

  p251_fe_set(x1, in);

  p251_fe_sqr(x2, x1);
  p251_fe_mul(x2, x2, x1);

  p251_fe_sqr(x3, x2);
  p251_fe_mul(x3, x3, x1);

  p251_fe_sqrn(x6, x3, 3);
  p251_fe_mul(x6, x6, x3);

  p251_fe_sqrn(x12, x6, 6);
  p251_fe_mul(x12, x12, x6);

  p251_fe_sqrn(x24, x12, 12);
  p251_fe_mul(x24, x24, x12);

  p251_fe_sqrn(x48, x24, 24);
  p251_fe_mul(x48, x48, x24);

  p251_fe_sqrn(x96, x48, 48);
  p251_fe_mul(x96, x96, x48);

  p251_fe_sqrn(out, x96, 96); /* x192 */
  p251_fe_mul(out, out, x96);

  p251_fe_sqrn(out, out, 48); /* x240 */
  p251_fe_mul(out, out, x48);

  p251_fe_sqrn(out, out, 6); /* x246 */
  p251_fe_mul(out, out, x6);

  p251_fe_sqr(out, out); /* x247 */
  p251_fe_mul(out, out, x1);

  p251_fe_sqr(out, out);

  p251_fe_sqr(out, out);
  p251_fe_mul(out, out, x1);

  p251_fe_sqr(out, out);

  p251_fe_sqr(out, out);
  p251_fe_mul(out, out, x1);
}

static int
p251_fe_sqrt(p251_fe_t out, const p251_fe_t in) {
  /* 248x1 1x0 */
  p251_fe_t x1, x2, x3, x6, x12, x24, x31, x62, x124;

  p251_fe_set(x1, in);

  p251_fe_sqr(x2, x1);
  p251_fe_mul(x2, x2, x1);

  p251_fe_sqr(x3, x2);
  p251_fe_mul(x3, x3, x1);

  p251_fe_sqrn(x6, x3, 3);
  p251_fe_mul(x6, x6, x3);

  p251_fe_sqrn(x12, x6, 6);
  p251_fe_mul(x12, x12, x6);

  p251_fe_sqrn(x24, x12, 12);
  p251_fe_mul(x24, x24, x12);

  p251_fe_sqrn(x31, x24, 6);
  p251_fe_mul(x31, x31, x6);
  p251_fe_sqr(x31, x31);
  p251_fe_mul(x31, x31, x1);

  p251_fe_sqrn(x62, x31, 31);
  p251_fe_mul(x62, x62, x31);

  p251_fe_sqrn(x124, x62, 62);
  p251_fe_mul(x124, x124, x62);

  p251_fe_sqrn(out, x124, 124); /* x248 */
  p251_fe_mul(out, out, x124);

  p251_fe_sqr(out, out);

  p251_fe_sqr(x2, out);

  return p251_fe_equal(x2, x1);
}

static void
p251_fe_pow_pm3d4(p251_fe_t out, const p251_fe_t in) {
  /* 247x1 1x0 1x1 */
  p251_fe_t x1, x2, x3, x6, x12, x24, x48, x96;

  p251_fe_set(x1, in);

  p251_fe_sqr(x2, x1);
  p251_fe_mul(x2, x2, x1);

  p251_fe_sqr(x3, x2);
  p251_fe_mul(x3, x3, x1);

  p251_fe_sqrn(x6, x3, 3);
  p251_fe_mul(x6, x6, x3);

  p251_fe_sqrn(x12, x6, 6);
  p251_fe_mul(x12, x12, x6);

  p251_fe_sqrn(x24, x12, 12);
  p251_fe_mul(x24, x24, x12);

  p251_fe_sqrn(x48, x24, 24);
  p251_fe_mul(x48, x48, x24);

  p251_fe_sqrn(x96, x48, 48);
  p251_fe_mul(x96, x96, x48);

  p251_fe_sqrn(out, x96, 96); /* x192 */
  p251_fe_mul(out, out, x96);

  p251_fe_sqrn(out, out, 48); /* x240 */
  p251_fe_mul(out, out, x48);

  p251_fe_sqrn(out, out, 6); /* x246 */
  p251_fe_mul(out, out, x6);

  p251_fe_sqr(out, out); /* x247 */
  p251_fe_mul(out, out, x1);

  p251_fe_sqr(out, out);

  p251_fe_sqr(out, out);
  p251_fe_mul(out, out, x1);
}

static int
p251_fe_isqrt(p251_fe_t r,
              const p251_fe_t u,
              const p251_fe_t v) {
  p251_fe_t u2, u3, u5, v3, p, x, c;
  int ret;

  /* x = u^3 * v * (u^5 * v^3)^((p - 3) / 4) mod p */
  p251_fe_sqr(u2, u);
  p251_fe_mul(u3, u2, u);
  p251_fe_mul(u5, u3, u2);
  p251_fe_sqr(v3, v);
  p251_fe_mul(v3, v3, v);
  p251_fe_mul(p, u5, v3);
  p251_fe_pow_pm3d4(p, p);
  p251_fe_mul(x, u3, v);
  p251_fe_mul(x, x, p);

  /* x^2 * v == u */
  p251_fe_sqr(c, x);
  p251_fe_mul(c, c, v);
  ret = p251_fe_equal(c, u);

  p251_fe_set(r, x);

  return ret;
}
