/*!
 * p192.h - p192 field element for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 */

#ifdef TORSION_USE_64BIT
typedef uint64_t p192_fe_word_t;
#define P192_FIELD_WORDS 4
#include "p192_64.h"
#else
typedef uint32_t p192_fe_word_t;
#define P192_FIELD_WORDS 9
#include "p192_32.h"
#endif

typedef p192_fe_word_t p192_fe_t[P192_FIELD_WORDS];

#define p192_fe_add fiat_p192_add
#define p192_fe_sub fiat_p192_sub
#define p192_fe_neg fiat_p192_opp
#define p192_fe_mul fiat_p192_carry_mul
#define p192_fe_sqr fiat_p192_carry_square

static void
p192_fe_set(p192_fe_t out, const p192_fe_t in) {
  out[0] = in[0];
  out[1] = in[1];
  out[2] = in[2];
  out[3] = in[3];
#if P192_FIELD_WORDS == 9
  out[4] = in[4];
  out[5] = in[5];
  out[6] = in[6];
  out[7] = in[7];
  out[8] = in[8];
#endif
}

static int
p192_fe_equal(const p192_fe_t a, const p192_fe_t b) {
  uint32_t z = 0;
  uint8_t u[24];
  uint8_t v[24];
  size_t i;

  fiat_p192_to_bytes(u, a);
  fiat_p192_to_bytes(v, b);

  for (i = 0; i < 24; i++)
    z |= (uint32_t)u[i] ^ (uint32_t)v[i];

  return (z - 1) >> 31;
}

static void
p192_fe_sqrn(p192_fe_t out, const p192_fe_t in, int rounds) {
  int i;

  p192_fe_set(out, in);

  for (i = 0; i < rounds; i++)
    p192_fe_sqr(out, out);
}

/* Mathematical routines for the NIST prime elliptic curves
 *
 * See: http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.204.9073&rep=rep1&type=pdf
 *
 *   1: t1 <- c^2
 *      t1 <- t1 * c
 *   2: t2 <- t1^(2^2)
 *      t2 <- t2 * t1
 *   3: t3 <- t2^(2^4)
 *      t3 <- t3 * t2
 *   4: t4 <- t3^(2^8)
 *      t4 <- t4 * t3
 *   5: t5 <- t4^(2^16)
 *      t5 <- t5 * t4
 *   6: t6 <- t5^(2^32)
 *      t6 <- t6 * t5
 *   7:  r <- t6^(2^64)
 *       r <- r * t6
 *   8:  r <- r^(2^62)
 */

static int
p192_fe_sqrt(p192_fe_t out, const p192_fe_t in) {
  p192_fe_t t1, t2, t3, t4, t5, t6, r;
  int ret;

  /* 1 */
  p192_fe_sqr(t1, in);
  p192_fe_mul(t1, t1, in);

  /* 2 */
  p192_fe_sqrn(t2, t1, 2);
  p192_fe_mul(t2, t2, t1);

  /* 3 */
  p192_fe_sqrn(t3, t2, 4);
  p192_fe_mul(t3, t3, t2);

  /* 4 */
  p192_fe_sqrn(t4, t3, 8);
  p192_fe_mul(t4, t4, t3);

  /* 5 */
  p192_fe_sqrn(t5, t4, 16);
  p192_fe_mul(t5, t5, t4);

  /* 6 */
  p192_fe_sqrn(t6, t5, 32);
  p192_fe_mul(t6, t6, t5);

  /* 7 */
  p192_fe_sqrn(r, t6, 64);
  p192_fe_mul(r, r, t6);

  /* 8 */
  p192_fe_sqrn(r, r, 62);

  p192_fe_sqr(t1, r);

  ret = p192_fe_equal(t1, in);

  p192_fe_set(out, r);

  return ret;
}
