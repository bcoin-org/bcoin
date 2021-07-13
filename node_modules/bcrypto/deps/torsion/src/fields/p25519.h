/*!
 * p25519.h - p25519 field element for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 */

#if defined(TORSION_HAVE_INT128)
typedef uint64_t p25519_fe_word_t;
#define P25519_FIELD_WORDS 5
#include "p25519_64.h"
#else
typedef uint32_t p25519_fe_word_t;
#define P25519_FIELD_WORDS 10
#include "p25519_32.h"
#endif

typedef p25519_fe_word_t p25519_fe_t[P25519_FIELD_WORDS];

#define p25519_fe_add fiat_p25519_add
#define p25519_fe_sub fiat_p25519_sub
#define p25519_fe_neg fiat_p25519_opp
#define p25519_fe_mul fiat_p25519_carry_mul
#define p25519_fe_sqr fiat_p25519_carry_square
#define p25519_fe_carry fiat_p25519_carry
#define p25519_fe_select(z, x, y, flag) \
  fiat_p25519_selectznz(z, (flag) != 0, x, y)

#if defined(TORSION_HAVE_INT128)
static const p25519_fe_t p25519_sqrtneg1 = {
  UINT64_C(0x00061b274a0ea0b0), UINT64_C(0x0000d5a5fc8f189d),
  UINT64_C(0x0007ef5e9cbd0c60), UINT64_C(0x00078595a6804c9e),
  UINT64_C(0x0002b8324804fc1d)
};
#else
static const p25519_fe_t p25519_sqrtneg1 = {
  0x020ea0b0, 0x0186c9d2, 0x008f189d, 0x0035697f,
  0x00bd0c60, 0x01fbd7a7, 0x02804c9e, 0x01e16569,
  0x0004fc1d, 0x00ae0c92
};
#endif

static void
p25519_fe_set(p25519_fe_t z, const p25519_fe_t x) {
  z[0] = x[0];
  z[1] = x[1];
  z[2] = x[2];
  z[3] = x[3];
  z[4] = x[4];
#if P25519_FIELD_WORDS == 10
  z[5] = x[5];
  z[6] = x[6];
  z[7] = x[7];
  z[8] = x[8];
  z[9] = x[9];
#endif
}

static int
p25519_fe_equal(const p25519_fe_t x, const p25519_fe_t y) {
  uint32_t z = 0;
  uint8_t u[32];
  uint8_t v[32];
  int i;

  fiat_p25519_to_bytes(u, x);
  fiat_p25519_to_bytes(v, y);

  for (i = 0; i < 32; i++)
    z |= (uint32_t)u[i] ^ (uint32_t)v[i];

  return (z - 1) >> 31;
}

static void
p25519_fe_sqrn(p25519_fe_t z, const p25519_fe_t x, int n) {
  int i;

  p25519_fe_sqr(z, x);

  for (i = 1; i < n; i++)
    p25519_fe_sqr(z, z);
}

static void
p25519_fe_pow_core(p25519_fe_t z, const p25519_fe_t x1, const p25519_fe_t x2) {
  /* Exponent: 2^250 - 1 */
  /* Bits: 250x1 */
  p25519_fe_t t1, t2, t3;

  /* x4 = x2^(2^2) * x2 */
  p25519_fe_sqrn(t1, x2, 2);
  p25519_fe_mul(t1, t1, x2);

  /* x5 = x4^(2^1) * x1 */
  p25519_fe_sqr(t1, t1);
  p25519_fe_mul(t1, t1, x1);

  /* x10 = x5^(2^5) * x5 */
  p25519_fe_sqrn(t2, t1, 5);
  p25519_fe_mul(t2, t2, t1);

  /* x20 = x10^(2^10) * x10 */
  p25519_fe_sqrn(t1, t2, 10);
  p25519_fe_mul(t1, t1, t2);

  /* x40 = x20^(2^20) * x20 */
  p25519_fe_sqrn(t3, t1, 20);
  p25519_fe_mul(t3, t3, t1);

  /* x50 = x40^(2^10) * x10 */
  p25519_fe_sqrn(t1, t3, 10);
  p25519_fe_mul(t1, t1, t2);

  /* x100 = x50^(2^50) * x50 */
  p25519_fe_sqrn(t2, t1, 50);
  p25519_fe_mul(t2, t2, t1);

  /* x200 = x100^(2^100) * x100 */
  p25519_fe_sqrn(z, t2, 100);
  p25519_fe_mul(z, z, t2);

  /* x250 = x200^(2^50) * x50 */
  p25519_fe_sqrn(z, z, 50);
  p25519_fe_mul(z, z, t1);
}

static void
p25519_fe_pow_pm5d8(p25519_fe_t z, const p25519_fe_t x) {
  /* Exponent: (p - 5) / 8 */
  /* Bits: 250x1 1x0 1x1 */
  p25519_fe_t x1, x2;

  /* x1 = x */
  p25519_fe_set(x1, x);

  /* x2 = x1^(2^1) * x1 */
  p25519_fe_sqr(x2, x1);
  p25519_fe_mul(x2, x2, x1);

  /* z = x1^(2^250 - 1) */
  p25519_fe_pow_core(z, x1, x2);

  /* z = z^(2^1) */
  p25519_fe_sqr(z, z);

  /* z = z^(2^1) * x1 */
  p25519_fe_sqr(z, z);
  p25519_fe_mul(z, z, x1);
}

static void
p25519_fe_invert(p25519_fe_t z, const p25519_fe_t x) {
  /* Exponent: p - 2 */
  /* Bits: 250x1 1x0 1x1 1x0 2x1 */
  p25519_fe_t x1, x2;

  /* x1 = x */
  p25519_fe_set(x1, x);

  /* x2 = x1^(2^1) * x1 */
  p25519_fe_sqr(x2, x1);
  p25519_fe_mul(x2, x2, x1);

  /* z = x1^(2^250 - 1) */
  p25519_fe_pow_core(z, x1, x2);

  /* z = z^(2^1) */
  p25519_fe_sqr(z, z);

  /* z = z^(2^1) * x1 */
  p25519_fe_sqr(z, z);
  p25519_fe_mul(z, z, x1);

  /* z = z^(2^1) */
  p25519_fe_sqr(z, z);

  /* z = z^(2^2) * x2 */
  p25519_fe_sqrn(z, z, 2);
  p25519_fe_mul(z, z, x2);
}

static int
p25519_fe_sqrt(p25519_fe_t z, const p25519_fe_t x) {
  /* Exponent: (p + 3) / 8 */
  /* Bits: 251x1 1x0 */
  p25519_fe_t x1, x2, c, t;

  /* x1 = x */
  p25519_fe_set(x1, x);

  /* x2 = x1^(2^1) * x1 */
  p25519_fe_sqr(x2, x1);
  p25519_fe_mul(x2, x2, x1);

  /* z = x1^(2^250 - 1) */
  p25519_fe_pow_core(z, x1, x2);

  /* z = z^(2^1) * x1 */
  p25519_fe_sqr(z, z);
  p25519_fe_mul(z, z, x1);

  /* z = z^(2^1) */
  p25519_fe_sqr(z, z);

  /* z = z * sqrt(-1) if z^2 != x1 */
  p25519_fe_sqr(c, z);
  p25519_fe_mul(t, z, p25519_sqrtneg1);
  p25519_fe_select(z, z, t, p25519_fe_equal(c, x1) ^ 1);

  /* z^2 == x1 */
  p25519_fe_sqr(c, z);

  return p25519_fe_equal(c, x1);
}

static int
p25519_fe_isqrt(p25519_fe_t z, const p25519_fe_t u, const p25519_fe_t v) {
  p25519_fe_t t, x, c;
  int css, fss, fssi;

  /* x = u * v^3 * (u * v^7)^((p - 5) / 8) mod p */
  p25519_fe_sqr(t, v);       /* v^2 */
  p25519_fe_mul(t, t, v);    /* v^3 */
  p25519_fe_sqr(x, t);       /* v^6 */
  p25519_fe_mul(x, x, v);    /* v^7 */
  p25519_fe_mul(x, x, u);    /* v^7 * u */
  p25519_fe_pow_pm5d8(x, x); /* (v^7 * u)^((p - 5) / 8) */
  p25519_fe_mul(x, x, t);    /* (v^7 * u)^((p - 5) / 8) * v^3 */
  p25519_fe_mul(x, x, u);    /* (v^7 * u)^((p - 5) / 8) * v^3 * u */

  /* c = x^2 * v */
  p25519_fe_sqr(c, x);
  p25519_fe_mul(c, c, v);

  /* c == u */
  css = p25519_fe_equal(c, u);

  /* c == -u */
  p25519_fe_neg(c, c);
  p25519_fe_carry(c, c);

  fss = p25519_fe_equal(c, u);

  /* c == -u * sqrt(-1) */
  p25519_fe_mul(t, u, p25519_sqrtneg1);

  fssi = p25519_fe_equal(c, t);

  /* x = x * sqrt(-1) if c == -u */
  p25519_fe_mul(t, x, p25519_sqrtneg1);
  p25519_fe_select(z, x, t, fss | fssi);

  return css | fss;
}
