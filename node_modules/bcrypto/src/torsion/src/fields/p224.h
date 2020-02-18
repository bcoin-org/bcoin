/*!
 * p224.h - p224 field element for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 *
 * Parts of this software are based on openssl/openssl:
 *  Copyright (c) 1998-2018 The OpenSSL Project. All rights reserved.
 *  https://github.com/openssl/openssl
 */

#ifdef TORSION_USE_64BIT
typedef uint64_t p224_fe_word_t;
#define P224_FIELD_WORDS 4
#include "p224_64.h"
#else
typedef uint32_t p224_fe_word_t;
#define P224_FIELD_WORDS 7
#include "p224_32.h"
#endif

typedef p224_fe_word_t p224_fe_t[P224_FIELD_WORDS];

#define p224_fe_add fiat_p224_add
#define p224_fe_sub fiat_p224_sub
#define p224_fe_neg fiat_p224_opp
#define p224_fe_mul fiat_p224_mul
#define p224_fe_sqr fiat_p224_square
#define p224_fe_nonzero fiat_p224_nonzero

#ifdef TORSION_USE_64BIT
static const p224_fe_t p224_zero = {0, 0, 0, 0};

static const p224_fe_t p224_one = {
  0xffffffff00000000ull, 0xffffffffffffffffull,
  0x0000000000000000ull, 0x0000000000000000ull
};

/* 11^(2^128 - 1) mod p */
/* mont: 0xa31b1da46d3e2af0dd915e4b7869be5d866c223b174131b85ee27c6c */
static const p224_fe_t p224_g = {
  0x174131b85ee27c6cull, 0x7869be5d866c223bull,
  0x6d3e2af0dd915e4bull, 0x00000000a31b1da4ull
};
#else
static const p224_fe_t p224_zero = {0, 0, 0, 0, 0, 0, 0};

static const p224_fe_t p224_one = {
  0xfffffffful, 0xfffffffful, 0xfffffffful, 0x00000000ul,
  0x00000000ul, 0x00000000ul, 0x00000000ul
};

/* 11^(2^128 - 1) mod p */
/* mont: 0xa11d8394a31b1da46d3e2af0dd915e4ad74c3ac9866c223b174131b9 */
static const p224_fe_t p224_g = {
  0x174131b9ul, 0x866c223bul, 0xd74c3ac9ul, 0xdd915e4aul,
  0x6d3e2af0ul, 0xa31b1da4ul, 0xa11d8394ul
};
#endif

static void
p224_fe_set(p224_fe_t out, const p224_fe_t in) {
  out[0] = in[0];
  out[1] = in[1];
  out[2] = in[2];
  out[3] = in[3];
#if P224_FIELD_WORDS == 7
  out[4] = in[4];
  out[5] = in[5];
  out[6] = in[6];
#endif
}

static int
p224_fe_equal(const p224_fe_t a, const p224_fe_t b) {
  p224_fe_t c;
  p224_fe_word_t ret;

  p224_fe_sub(c, a, b);
  fiat_p224_nonzero(&ret, c);

  return ret == 0;
}

static void
p224_fe_sqrn(p224_fe_t out, const p224_fe_t in, int rounds) {
  int i;

  p224_fe_set(out, in);

  for (i = 0; i < rounds; i++)
    p224_fe_sqr(out, out);
}

/* https://github.com/openssl/openssl/blob/master/crypto/ec/ecp_nistp224.c#L701 */
static void
p224_fe_invert(p224_fe_t out, const p224_fe_t in) {
  p224_fe_t t1, t2, t3, t4;

  p224_fe_sqr(t1, in);
  p224_fe_mul(t1, in, t1);
  p224_fe_sqr(t1, t1);
  p224_fe_mul(t1, in, t1);
  p224_fe_sqr(t2, t1);
  p224_fe_sqr(t2, t2);
  p224_fe_sqr(t2, t2);
  p224_fe_mul(t1, t2, t1);
  p224_fe_sqr(t2, t1);

  p224_fe_sqrn(t2, t2, 5);

  p224_fe_mul(t2, t2, t1);
  p224_fe_sqr(t3, t2);

  p224_fe_sqrn(t3, t3, 11);

  p224_fe_mul(t2, t3, t2);
  p224_fe_sqr(t3, t2);

  p224_fe_sqrn(t3, t3, 23);

  p224_fe_mul(t3, t3, t2);
  p224_fe_sqr(t4, t3);

  p224_fe_sqrn(t4, t4, 47);

  p224_fe_mul(t3, t3, t4);
  p224_fe_sqr(t4, t3);

  p224_fe_sqrn(t4, t4, 23);

  p224_fe_mul(t2, t2, t4);

  p224_fe_sqrn(t2, t2, 6);

  p224_fe_mul(t1, t2, t1);
  p224_fe_sqr(t1, t1);
  p224_fe_mul(t1, t1, in);

  p224_fe_sqrn(t1, t1, 97);

  p224_fe_mul(out, t1, t3);
}

static void
p224_fe_pow_s(p224_fe_t out, const p224_fe_t in) {
  /* Compute x^(2^128 - 1) mod p */
  p224_fe_t t;
  int i;

  p224_fe_set(t, in);

  for (i = 1; i < 128; i++) {
    p224_fe_sqr(t, t);
    p224_fe_mul(t, t, in);
  }

  p224_fe_set(out, t);
}

static void
p224_fe_pow_e(p224_fe_t out, const p224_fe_t in) {
  /* Compute x^(2^127) mod p */
  p224_fe_sqrn(out, in, 127);
}

static int
p224_fe_sqrt_var(p224_fe_t out, const p224_fe_t in) {
  /* Tonelli-Shanks for P224.
   *
   * Algorithm:
   *
   *   s = 2^128 - 1 (0xffffffffffffffffffffffffffffffff)
   *   n = 11
   *   e = 2^127 (0x80000000000000000000000000000000)
   *   y = x^e mod p
   *   b = x^s mod p
   *   g = n^s mod p (0x6a0fec678598a7920c55b2d40b2d6ffbbea3d8cef3fb3632dc691b74)
   *   k = 96
   *
   *   loop:
   *     m = 0
   *     t = b
   *
   *     while t != 1:
   *       t = t^2 mod p
   *       m += 1
   *
   *     if m == 0:
   *       break
   *
   *     if m >= k:
   *       fail
   *
   *     t = g^(2^(k - m - 1)) mod p
   *     g = t^2 mod p
   *     y = y * t mod p
   *     b = b * g mod p
   *     k = m
   *
   *   ret = y
   */
  p224_fe_t y, b, g, t;
  int k, m;

  p224_fe_pow_e(y, in);
  p224_fe_pow_s(b, in);
  p224_fe_set(g, p224_g);
  p224_fe_set(out, p224_zero);

  /* Note that b happens to be the first
   * step of Euler's criterion. Squaring
   * it 95 times more gives us the Legendre
   * symbol.
   */
  p224_fe_sqrn(t, b, 95);

  /* Zero. */
  if (p224_fe_equal(t, p224_zero))
    return 1;

  /* Quadratic non-residue. */
  if (!p224_fe_equal(t, p224_one))
    return 0;

  /* Loop until we find a solution. */
  k = 96;

  for (;;) {
    m = 0;
    p224_fe_set(t, b);

    while (!p224_fe_equal(t, p224_one) && m < k) {
      p224_fe_sqr(t, t);
      m += 1;
    }

    if (m == 0)
      break;

    if (m >= k)
      return 0;

    p224_fe_sqrn(t, g, k - m - 1);
    p224_fe_sqr(g, t);
    p224_fe_mul(y, y, t);
    p224_fe_mul(b, b, g);
    k = m;
  }

  p224_fe_set(out, y);

  return 1;
}
