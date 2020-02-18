/*!
 * p256.h - p256 field element for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 *
 * Parts of this software are based on google/boringssl:
 *  Copyright (c) 1998-2011 The OpenSSL Project.  All rights reserved.
 *  https://github.com/google/boringssl
 */

#ifdef TORSION_USE_64BIT
typedef uint64_t p256_fe_word_t;
#define P256_FIELD_WORDS 4
#include "p256_64.h"
#else
typedef uint32_t p256_fe_word_t;
#define P256_FIELD_WORDS 8
#include "p256_32.h"
#endif

typedef p256_fe_word_t p256_fe_t[P256_FIELD_WORDS];

#define p256_fe_add fiat_p256_add
#define p256_fe_sub fiat_p256_sub
#define p256_fe_neg fiat_p256_opp
#define p256_fe_mul fiat_p256_mul
#define p256_fe_sqr fiat_p256_square
#define p256_fe_nonzero fiat_p256_nonzero

static void
p256_fe_set(p256_fe_t out, const p256_fe_t in) {
  out[0] = in[0];
  out[1] = in[1];
  out[2] = in[2];
  out[3] = in[3];
#if P256_FIELD_WORDS == 8
  out[4] = in[4];
  out[5] = in[5];
  out[6] = in[6];
  out[7] = in[7];
#endif
}

static void
p256_fe_sqrn(p256_fe_t out, const p256_fe_t in, int rounds) {
  int i;

  p256_fe_set(out, in);

  for (i = 0; i < rounds; i++)
    p256_fe_sqr(out, out);
}

/* https://github.com/google/boringssl/blob/master/third_party/fiat/p256.c */
static void
p256_fe_invert(p256_fe_t out, const p256_fe_t in) {
  p256_fe_t t1, t2, e2, e4, e8, e16, e32, e64;

  p256_fe_sqr(t1, in); /* 2^1 */
  p256_fe_mul(t1, in, t1); /* 2^2 - 2^0 */
  p256_fe_set(e2, t1);
  p256_fe_sqr(t1, t1); /* 2^3 - 2^1 */
  p256_fe_sqr(t1, t1); /* 2^4 - 2^2 */
  p256_fe_mul(t1, t1, e2); /* 2^4 - 2^0 */
  p256_fe_set(e4, t1);
  p256_fe_sqr(t1, t1); /* 2^5 - 2^1 */
  p256_fe_sqr(t1, t1); /* 2^6 - 2^2 */
  p256_fe_sqr(t1, t1); /* 2^7 - 2^3 */
  p256_fe_sqr(t1, t1); /* 2^8 - 2^4 */
  p256_fe_mul(t1, t1, e4); /* 2^8 - 2^0 */
  p256_fe_set(e8, t1);
  p256_fe_sqrn(t1, t1, 8); /* 2^16 - 2^8 */
  p256_fe_mul(t1, t1, e8); /* 2^16 - 2^0 */
  p256_fe_set(e16, t1);
  p256_fe_sqrn(t1, t1, 16); /* 2^32 - 2^16 */
  p256_fe_mul(t1, t1, e16); /* 2^32 - 2^0 */
  p256_fe_set(e32, t1);
  p256_fe_sqrn(t1, t1, 32); /* 2^64 - 2^32 */
  p256_fe_set(e64, t1);
  p256_fe_mul(t1, t1, in); /* 2^64 - 2^32 + 2^0 */
  p256_fe_sqrn(t1, t1, 192); /* 2^256 - 2^224 + 2^192 */
  p256_fe_mul(t2, e64, e32); /* 2^64 - 2^0 */
  p256_fe_sqrn(t2, t2, 16); /* 2^80 - 2^16 */
  p256_fe_mul(t2, t2, e16); /* 2^80 - 2^0 */
  p256_fe_sqrn(t2, t2, 8); /* 2^88 - 2^8 */
  p256_fe_mul(t2, t2, e8); /* 2^88 - 2^0 */
  p256_fe_sqrn(t2, t2, 4); /* 2^92 - 2^4 */
  p256_fe_mul(t2, t2, e4); /* 2^92 - 2^0 */
  p256_fe_sqr(t2, t2); /* 2^93 - 2^1 */
  p256_fe_sqr(t2, t2); /* 2^94 - 2^2 */
  p256_fe_mul(t2, t2, e2); /* 2^94 - 2^0 */
  p256_fe_sqr(t2, t2); /* 2^95 - 2^1 */
  p256_fe_sqr(t2, t2); /* 2^96 - 2^2 */
  p256_fe_mul(t2, t2, in); /* 2^96 - 3 */
  p256_fe_mul(out, t2, t1); /* 2^256 - 2^224 + 2^192 + 2^96 - 3 */
}

/* https://github.com/dedis/kyber/blob/master/group/nist/p256.go */
static int
p256_fe_sqrt(p256_fe_t out, const p256_fe_t in) {
  p256_fe_word_t ret;
  p256_fe_t t1, t2, t3, t4, r;

  /* t1 = c^(2^2-1) */
  p256_fe_sqr(t1, in);
  p256_fe_mul(t1, t1, in);

  /* t2 = c^(2^4-1) */
  p256_fe_sqrn(t2, t1, 2);
  p256_fe_mul(t2, t2, t1);

  /* t3 = c^(2^8-1) */
  p256_fe_sqrn(t3, t2, 4);
  p256_fe_mul(t3, t3, t2);

  /* t4 = c^(2^16-1) */
  p256_fe_sqrn(t4, t3, 8);
  p256_fe_mul(t4, t4, t3);

  /* r = c^(2^32-1) */
  p256_fe_sqrn(r, t4, 16);
  p256_fe_mul(r, r, t4);

  /* r = c^(2^64-2^32+1) */
  p256_fe_sqrn(r, r, 32);
  p256_fe_mul(r, r, in);

  /* r = c^(2^160-2^128+2^96+1) */
  p256_fe_sqrn(r, r, 96);
  p256_fe_mul(r, r, in);

  p256_fe_sqrn(r, r, 94);

  /* r = c^(2^254-2^222+2^190+2^94) = sqrt(c) mod p256 */
  p256_fe_sqr(t1, r);
  p256_fe_sub(t1, t1, in);

  p256_fe_set(out, r);

  p256_fe_nonzero(&ret, t1);

  return ret == 0;
}
