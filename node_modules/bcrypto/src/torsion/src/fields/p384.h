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

static int
p384_fe_equal(const p384_fe_t a, const p384_fe_t b) {
  p384_fe_word_t z = 0;
  size_t i;

  for (i = 0; i < P384_FIELD_WORDS; i++)
    z |= a[i] ^ b[i];

  return z == 0;
}

static void
p384_fe_sqrn(p384_fe_t out, const p384_fe_t in, int rounds) {
  int i;

  p384_fe_sqr(out, in);

  for (i = 1; i < rounds; i++)
    p384_fe_sqr(out, out);
}

static void
p384_fe_invert(p384_fe_t out, const p384_fe_t in) {
  /* https://briansmith.org/ecc-inversion-addition-chains-01#p384_field_inversion */
  /* 255x1 1x0 32x1 64x0 30x1 1x0 1x1 */
  p384_fe_t x1, x2, x3, x6, x12, x15, x30, x60, x120;

  p384_fe_set(x1, in);

  p384_fe_sqr(x2, x1);
  p384_fe_mul(x2, x2, x1);

  p384_fe_sqr(x3, x2);
  p384_fe_mul(x3, x3, x1);

  p384_fe_sqrn(x6, x3, 3);
  p384_fe_mul(x6, x6, x3);

  p384_fe_sqrn(x12, x6, 6);
  p384_fe_mul(x12, x12, x6);

  p384_fe_sqrn(x15, x12, 3);
  p384_fe_mul(x15, x15, x3);

  p384_fe_sqrn(x30, x15, 15);
  p384_fe_mul(x30, x30, x15);

  p384_fe_sqrn(x60, x30, 30);
  p384_fe_mul(x60, x60, x30);

  p384_fe_sqrn(x120, x60, 60);
  p384_fe_mul(x120, x120, x60);

  p384_fe_sqrn(out, x120, 120); /* x240 */
  p384_fe_mul(out, out, x120);

  p384_fe_sqrn(out, out, 15); /* x255 */
  p384_fe_mul(out, out, x15);

  p384_fe_sqr(out, out);

  p384_fe_sqrn(out, out, 30);
  p384_fe_mul(out, out, x30);
  p384_fe_sqrn(out, out, 2);
  p384_fe_mul(out, out, x2);

  p384_fe_sqrn(out, out, 64);

  p384_fe_sqrn(out, out, 30);
  p384_fe_mul(out, out, x30);

  p384_fe_sqr(out, out);

  p384_fe_sqr(out, out);
  p384_fe_mul(out, out, x1);
}

static int
p384_fe_sqrt(p384_fe_t out, const p384_fe_t in) {
  /* See: Mathematical routines for the NIST prime elliptic curves
   *
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
  p384_fe_t c, t1, t2, t3, t4;

  /* 0 */
  p384_fe_set(c, in);

  /* 1 */
  p384_fe_sqr(t1, c);
  p384_fe_mul(t1, t1, c);

  /* 2 */
  p384_fe_sqrn(t2, t1, 2);
  p384_fe_mul(t2, t2, t1);

  /* 3 */
  p384_fe_sqr(t2, t2);
  p384_fe_mul(t2, t2, c);

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
  p384_fe_sqrn(out, t3, 120);
  p384_fe_mul(out, out, t3);

  /* 12 */
  p384_fe_sqrn(out, out, 15);
  p384_fe_mul(out, out, t4);

  /* 13 */
  p384_fe_sqrn(out, out, 33);
  p384_fe_mul(out, out, t1);

  /* 14 */
  p384_fe_sqrn(out, out, 64);
  p384_fe_mul(out, out, c);

  /* 15 */
  p384_fe_sqrn(out, out, 30);

  /* Check. */
  p384_fe_sqr(t1, out);

  return p384_fe_equal(t1, c);
}
