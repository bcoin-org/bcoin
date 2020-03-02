/*!
 * p521.h - p521 field element for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 */

#ifdef TORSION_USE_64BIT
typedef uint64_t p521_fe_word_t;
#define P521_FIELD_WORDS 9
#include "p521_64.h"
#else
typedef uint32_t p521_fe_word_t;
#define P521_FIELD_WORDS 19
#include "p521_32.h"
#endif

typedef p521_fe_word_t p521_fe_t[P521_FIELD_WORDS];

#define p521_fe_add fiat_p521_add
#define p521_fe_sub fiat_p521_sub
#define p521_fe_neg fiat_p521_opp
#define p521_fe_mul fiat_p521_carry_mul
#define p521_fe_sqr fiat_p521_carry_square

static void
p521_fe_set(p521_fe_t out, const p521_fe_t in) {
  out[0] = in[0];
  out[1] = in[1];
  out[2] = in[2];
  out[3] = in[3];
  out[4] = in[4];
  out[5] = in[5];
  out[6] = in[6];
  out[7] = in[7];
  out[8] = in[8];
#if P521_FIELD_WORDS == 19
  out[9] = in[9];
  out[10] = in[10];
  out[11] = in[11];
  out[12] = in[12];
  out[13] = in[13];
  out[14] = in[14];
  out[15] = in[15];
  out[16] = in[16];
  out[17] = in[17];
  out[18] = in[18];
#endif
}

static int
p521_fe_equal(const p521_fe_t a, const p521_fe_t b) {
  uint32_t z = 0;
  uint8_t u[66];
  uint8_t v[66];
  size_t i;

  fiat_p521_to_bytes(u, a);
  fiat_p521_to_bytes(v, b);

  for (i = 0; i < 66; i++)
    z |= (uint32_t)u[i] ^ (uint32_t)v[i];

  return (z - 1) >> 31;
}

static void
p521_fe_sqrn(p521_fe_t out, const p521_fe_t in, int rounds) {
  int i;

  p521_fe_sqr(out, in);

  for (i = 1; i < rounds; i++)
    p521_fe_sqr(out, out);
}

static void
p521_fe_invert(p521_fe_t out, const p521_fe_t in) {
  /* 519x1 1x0 1x1 */
  p521_fe_t x1, x2, x3, x6, x7, x8, x16, x32, x64, x128, x256;

  p521_fe_set(x1, in);

  p521_fe_sqr(x2, x1);
  p521_fe_mul(x2, x2, x1);

  p521_fe_sqr(x3, x2);
  p521_fe_mul(x3, x3, x1);

  p521_fe_sqrn(x6, x3, 3);
  p521_fe_mul(x6, x6, x3);

  p521_fe_sqr(x7, x6);
  p521_fe_mul(x7, x7, x1);

  p521_fe_sqr(x8, x7);
  p521_fe_mul(x8, x8, x1);

  p521_fe_sqrn(x16, x8, 8);
  p521_fe_mul(x16, x16, x8);

  p521_fe_sqrn(x32, x16, 16);
  p521_fe_mul(x32, x32, x16);

  p521_fe_sqrn(x64, x32, 32);
  p521_fe_mul(x64, x64, x32);

  p521_fe_sqrn(x128, x64, 64);
  p521_fe_mul(x128, x128, x64);

  p521_fe_sqrn(x256, x128, 128);
  p521_fe_mul(x256, x256, x128);

  p521_fe_sqrn(out, x256, 256); /* x512 */
  p521_fe_mul(out, out, x256);

  p521_fe_sqrn(out, out, 7); /* x519 */
  p521_fe_mul(out, out, x7);

  p521_fe_sqr(out, out);

  p521_fe_sqr(out, out);
  p521_fe_mul(out, out, x1);
}

static int
p521_fe_sqrt(p521_fe_t out, const p521_fe_t in) {
  /* See: Mathematical routines for the NIST prime elliptic curves
   *
   * http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.204.9073&rep=rep1&type=pdf
   *
   * Chain:
   *
   *   r <- c
   *   for i = 1 to 519 do
   *     r <- r^2
   *   end for
   */
  p521_fe_t c, t;

  p521_fe_set(c, in);
  p521_fe_sqrn(out, c, 519);
  p521_fe_sqr(t, out);

  return p521_fe_equal(t, c);
}
