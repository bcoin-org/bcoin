/*!
 * p384.h - p384 field element for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 */

#ifdef TORSION_USE_64BIT
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
#define p384_fe_nonzero fiat_p384_nonzero

static void
p384_fe_set(p384_fe_t out, const p384_fe_t in) {
  out[0] = in[0];
  out[1] = in[1];
  out[2] = in[2];
  out[3] = in[3];
  out[4] = in[4];
  out[5] = in[5];
#if P384_FIELD_WORDS == 12
  out[4] = in[4];
  out[5] = in[5];
  out[6] = in[6];
  out[7] = in[7];
  out[8] = in[8];
  out[9] = in[9];
  out[10] = in[10];
  out[11] = in[11];
#endif
}

static void
p384_fe_sqrn(p384_fe_t out, const p384_fe_t in, int rounds) {
  int i;

  p384_fe_set(out, in);

  for (i = 0; i < rounds; i++)
    p384_fe_sqr(out, out);
}

/* https://briansmith.org/ecc-inversion-addition-chains-01 */
/* https://github.com/randombit/botan/blob/master/src/lib/pubkey/ec_group/curve_gfp.cpp */
static void
p384_fe_invert(p384_fe_t out, const p384_fe_t in) {
  p384_fe_t r, x2, x3, x15, x30, rl;

  p384_fe_set(r, in);
  p384_fe_sqr(r, r);
  p384_fe_mul(r, r, in);
  p384_fe_set(x2, r);

  p384_fe_sqr(r, r);
  p384_fe_mul(r, r, in);

  p384_fe_set(x3, r);

  p384_fe_sqrn(r, r, 3);
  p384_fe_mul(r, r, x3);

  p384_fe_set(rl, r);
  p384_fe_sqrn(r, r, 6);
  p384_fe_mul(r, r, rl);

  p384_fe_sqrn(r, r, 3);
  p384_fe_mul(r, r, x3);

  p384_fe_set(x15, r);
  p384_fe_sqrn(r, r, 15);
  p384_fe_mul(r, r, x15);

  p384_fe_set(x30, r);
  p384_fe_sqrn(r, r, 30);
  p384_fe_mul(r, r, x30);

  p384_fe_set(rl, r);
  p384_fe_sqrn(r, r, 60);
  p384_fe_mul(r, r, rl);

  p384_fe_set(rl, r);
  p384_fe_sqrn(r, r, 120);
  p384_fe_mul(r, r, rl);

  p384_fe_sqrn(r, r, 15);
  p384_fe_mul(r, r, x15);

  p384_fe_sqrn(r, r, 31);
  p384_fe_mul(r, r, x30);

  p384_fe_sqrn(r, r, 2);
  p384_fe_mul(r, r, x2);

  p384_fe_sqrn(r, r, 94);
  p384_fe_mul(r, r, x30);

  p384_fe_sqrn(r, r, 2);

  p384_fe_mul(r, r, in);
  p384_fe_set(out, r);
}

static int
p384_fe_sqrt(p384_fe_t out, const p384_fe_t in) {
  /* See: Mathematical routines for the NIST prime elliptic curves
   * http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.204.9073&rep=rep1&type=pdf
   *
   * Chain:
   *
   *    1: t1 <- c^2
   *       t1 <- t1 * c
   *    2: t2 <- t1^(2^2)
   *       t2 <- t2 * t1
   *    3: t2 <- t2^2
   *       t2 <- t2 * c
   *    4: t3 <- t2^(2^5)
   *       t3 <- t3 * t2
   *    5: t4 <- t3^(2^5)
   *       t4 <- t4 * t2
   *    6: t2 <- t4^(2^15)
   *       t2 <- t2 * t4
   *    7: t3 <- t2^(2^2)
   *    8: t1 <- t3 * t1
   *    9: t3 <- t3^(2^28)
   *       t2 <- t2 * t3
   *   10: t3 <- t2^(2^60)
   *       t3 <- t3 * t2
   *   11:  r <- t3^(2^120)
   *        r <- r * t3
   *   12:  r <- r^(2^15)
   *        r <- r * t4
   *   13:  r <- r^(2^33)
   *        r <- r * t1
   *   14:  r <- r^(2^64)
   *        r <- r * c
   *   15:  r <- r^(2^30)
   */
  p384_fe_t r, t1, t2, t3, t4;
  p384_fe_word_t ret;

  /* 1 */
  p384_fe_sqr(t1, in);
  p384_fe_mul(t1, t1, in);

  /* 2 */
  p384_fe_sqrn(t2, t1, 2);
  p384_fe_mul(t2, t2, t1);

  /* 3 */
  p384_fe_sqr(t2, t2);
  p384_fe_mul(t2, t2, in);

  /* 4 */
  p384_fe_sqrn(t3, t2, 5);
  p384_fe_mul(t3, t3, t2);

  /* 5 */
  p384_fe_sqrn(t4, t3, 5);
  p384_fe_mul(t4, t4, t2);

  /* 6 */
  p384_fe_sqrn(t2, t4, 15);
  p384_fe_mul(t2, t2, t4);

  /* 7 */
  p384_fe_sqrn(t3, t2, 2);

  /* 8 */
  p384_fe_mul(t1, t3, t1);

  /* 9 */
  p384_fe_sqrn(t3, t3, 28);
  p384_fe_mul(t2, t2, t3);

  /* 10 */
  p384_fe_sqrn(t3, t2, 60);
  p384_fe_mul(t3, t3, t2);

  /* 11 */
  p384_fe_sqrn(r, t3, 120);
  p384_fe_mul(r, r, t3);

  /* 12 */
  p384_fe_sqrn(r, r, 15);
  p384_fe_mul(r, r, t4);

  /* 13 */
  p384_fe_sqrn(r, r, 33);
  p384_fe_mul(r, r, t1);

  /* 14 */
  p384_fe_sqrn(r, r, 64);
  p384_fe_mul(r, r, in);

  /* 15 */
  p384_fe_sqrn(r, r, 30);

  /* Check. */
  p384_fe_sqr(t1, r);
  p384_fe_sub(t1, t1, in);
  fiat_p384_nonzero(&ret, t1);

  /* Output. */
  p384_fe_set(out, r);

  return ret == 0;
}
