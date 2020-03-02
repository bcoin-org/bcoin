/*!
 * p25519.h - p25519 field element for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 *
 * Parts of this software are based on floodyberry/curve25519-donna:
 *   Placed into the public domain by Andrew Moon.
 *   https://github.com/floodyberry/curve25519-donna
 */

#ifdef TORSION_USE_64BIT
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
#define p25519_fe_select(r, a, b, flag) \
  fiat_p25519_selectznz(r, (flag) != 0, a, b)

#ifdef TORSION_USE_64BIT
static const p25519_fe_t p25519_sqrtneg1 = {
  0x00061b274a0ea0b0ull, 0x0000d5a5fc8f189dull,
  0x0007ef5e9cbd0c60ull, 0x00078595a6804c9eull,
  0x0002b8324804fc1dull
};
#else
static const p25519_fe_t p25519_sqrtneg1 = {
  0x020ea0b0ul, 0x0186c9d2ul, 0x008f189dul, 0x0035697ful,
  0x00bd0c60ul, 0x01fbd7a7ul, 0x02804c9eul, 0x01e16569ul,
  0x0004fc1dul, 0x00ae0c92ul
};
#endif

static void
p25519_fe_set(p25519_fe_t out, const p25519_fe_t in) {
  out[0] = in[0];
  out[1] = in[1];
  out[2] = in[2];
  out[3] = in[3];
  out[4] = in[4];
#if P25519_FIELD_WORDS == 10
  out[5] = in[5];
  out[6] = in[6];
  out[7] = in[7];
  out[8] = in[8];
  out[9] = in[9];
#endif
}

static int
p25519_fe_equal(const p25519_fe_t a, const p25519_fe_t b) {
  uint32_t z = 0;
  uint8_t u[32];
  uint8_t v[32];
  size_t i;

  fiat_p25519_to_bytes(u, a);
  fiat_p25519_to_bytes(v, b);

  for (i = 0; i < 32; i++)
    z |= (uint32_t)u[i] ^ (uint32_t)v[i];

  return (z - 1) >> 31;
}

static void
p25519_fe_sqrn(p25519_fe_t out, const p25519_fe_t in, int rounds) {
  int i;

  p25519_fe_sqr(out, in);

  for (i = 1; i < rounds; i++)
    p25519_fe_sqr(out, out);
}

static void
p25519_fe_pow_two5mtwo0_two250mtwo0(p25519_fe_t b) {
  p25519_fe_t t0, c;

  /* In:  b =   2^5 - 2^0 */
  /* Out: b = 2^250 - 2^0 */
  p25519_fe_sqrn(t0, b, 5);
  p25519_fe_mul(b, t0, b);
  p25519_fe_sqrn(t0, b, 10);
  p25519_fe_mul(c, t0, b);
  p25519_fe_sqrn(t0, c, 20);
  p25519_fe_mul(t0, t0, c);
  p25519_fe_sqrn(t0, t0, 10);
  p25519_fe_mul(b, t0, b);
  p25519_fe_sqrn(t0, b, 50);
  p25519_fe_mul(c, t0, b);
  p25519_fe_sqrn(t0, c, 100);
  p25519_fe_mul(t0, t0, c);
  p25519_fe_sqrn(t0, t0, 50);
  p25519_fe_mul(b, t0, b);
}

static void
p25519_fe_pow_two252m2(p25519_fe_t two252m2, const p25519_fe_t z) {
  p25519_fe_t b, c, t0;

  /* z^((p + 3) / 8) = z^(2^252 - 2) */
  p25519_fe_sqrn(c, z, 1);
  p25519_fe_sqrn(t0, c, 2);
  p25519_fe_mul(b, t0, z);
  p25519_fe_mul(c, b, c);
  p25519_fe_sqrn(t0, c, 1);
  p25519_fe_mul(b, t0, b);
  p25519_fe_pow_two5mtwo0_two250mtwo0(b);
  p25519_fe_sqrn(b, b, 1);
  p25519_fe_mul(b, b, z);
  p25519_fe_sqrn(two252m2, b, 1);
}

static void
p25519_fe_pow_two252m3(p25519_fe_t two252m3, const p25519_fe_t z) {
  p25519_fe_t b, c, t0;

  /* z^((p - 5) / 8) = z^(2^252 - 3) */
  p25519_fe_sqrn(c, z, 1);
  p25519_fe_sqrn(t0, c, 2);
  p25519_fe_mul(b, t0, z);
  p25519_fe_mul(c, b, c);
  p25519_fe_sqrn(t0, c, 1);
  p25519_fe_mul(b, t0, b);
  p25519_fe_pow_two5mtwo0_two250mtwo0(b);
  p25519_fe_sqrn(b, b, 2);
  p25519_fe_mul(two252m3, b, z);
}

static void
p25519_fe_invert(p25519_fe_t out, const p25519_fe_t z) {
  p25519_fe_t a, t0, b;

  /* z^(p - 2) = z(2^255 - 21) */
  p25519_fe_sqrn(a, z, 1);
  p25519_fe_sqrn(t0, a, 2);
  p25519_fe_mul(b, t0, z);
  p25519_fe_mul(a, b, a);
  p25519_fe_sqrn(t0, a, 1);
  p25519_fe_mul(b, t0, b);
  p25519_fe_pow_two5mtwo0_two250mtwo0(b);
  p25519_fe_sqrn(b, b, 5);
  p25519_fe_mul(out, b, a);
}

static int
p25519_fe_sqrt(p25519_fe_t out, const p25519_fe_t x) {
  p25519_fe_t a, b, c;
  int r;

  /* A = X^((p + 3) / 8) */
  p25519_fe_pow_two252m2(a, x);

  /* A = A * I (if A^2 != X) */
  p25519_fe_mul(b, a, p25519_sqrtneg1);
  p25519_fe_sqr(c, a);
  r = p25519_fe_equal(c, x);
  p25519_fe_select(a, a, b, r ^ 1);

  p25519_fe_sqr(c, a);
  r = p25519_fe_equal(c, x);

  p25519_fe_set(out, a);

  return r;
}

static int
p25519_fe_isqrt(p25519_fe_t out, const p25519_fe_t u, const p25519_fe_t v) {
  p25519_fe_t v3, x, c;
  int css, fss;

  /* V3 = V^2 * V */
  p25519_fe_sqr(c, v);
  p25519_fe_mul(v3, c, v);

  /* V7 = V3^2 * V */
  p25519_fe_sqr(c, v3);
  p25519_fe_mul(c, c, v);

  /* P = (U * V7)^((p - 5) / 8) */
  p25519_fe_mul(x, u, c);
  p25519_fe_pow_two252m3(x, x);

  /* X = U * V3 * P */
  p25519_fe_mul(x, x, v3);
  p25519_fe_mul(x, x, u);

  /* C = V * X^2 */
  p25519_fe_sqr(c, x);
  p25519_fe_mul(c, c, v);

  /* C = U */
  css = p25519_fe_equal(c, u);

  /* C = -U */
  p25519_fe_neg(c, c);
  p25519_fe_carry(c, c);
  fss = p25519_fe_equal(c, u);

  /* X = X * I if C = -U */
  p25519_fe_mul(c, x, p25519_sqrtneg1);
  p25519_fe_select(x, x, c, fss);
  p25519_fe_set(out, x);

  return css | fss;
}
