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

  p521_fe_set(out, in);

  for (i = 0; i < rounds; i++)
    p521_fe_sqr(out, out);
}

/* https://eprint.iacr.org/2014/852.pdf */
/* https://github.com/randombit/botan/blob/master/src/lib/pubkey/ec_group/curve_gfp.cpp */
static void
p521_fe_invert(p521_fe_t out, const p521_fe_t in) {
  p521_fe_t r, rl, a7;

  p521_fe_sqr(r, in);
  p521_fe_mul(r, r, in);

  p521_fe_sqr(r, r);
  p521_fe_mul(r, r, in);

  p521_fe_set(rl, r);

  p521_fe_sqrn(r, r, 3);
  p521_fe_mul(r, r, rl);

  p521_fe_sqr(r, r);
  p521_fe_mul(r, r, in);
  p521_fe_set(a7, r);

  p521_fe_sqr(r, r);
  p521_fe_mul(r, r, in);

  p521_fe_set(rl, r);
  p521_fe_sqrn(r, r, 8);
  p521_fe_mul(r, r, rl);

  p521_fe_set(rl, r);
  p521_fe_sqrn(r, r, 16);
  p521_fe_mul(r, r, rl);

  p521_fe_set(rl, r);
  p521_fe_sqrn(r, r, 32);
  p521_fe_mul(r, r, rl);

  p521_fe_set(rl, r);
  p521_fe_sqrn(r, r, 64);
  p521_fe_mul(r, r, rl);

  p521_fe_set(rl, r);
  p521_fe_sqrn(r, r, 128);
  p521_fe_mul(r, r, rl);

  p521_fe_set(rl, r);
  p521_fe_sqrn(r, r, 256);
  p521_fe_mul(r, r, rl);

  p521_fe_sqrn(r, r, 7);
  p521_fe_mul(r, r, a7);

  p521_fe_sqrn(r, r, 2);
  p521_fe_mul(r, r, in);

  p521_fe_set(out, r);
}

/* Mathematical routines for the NIST prime elliptic curves
 *
 * See: http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.204.9073&rep=rep1&type=pdf
 *
 *   r <- c
 *   for i = 1 to 519 do
 *     r <- r^2
 *   end for
 */

static int
p521_fe_sqrt(p521_fe_t out, const p521_fe_t in) {
  p521_fe_t r, t;
  int ret;

  p521_fe_set(r, in);
  p521_fe_sqrn(r, r, 519);
  p521_fe_sqr(t, r);

  ret = p521_fe_equal(t, in);

  p521_fe_set(out, r);

  return ret;
}
