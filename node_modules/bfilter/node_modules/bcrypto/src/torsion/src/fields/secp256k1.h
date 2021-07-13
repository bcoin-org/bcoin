/*!
 * secp256k1.h - secp256k1 for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 *
 * Parts of this software are based on bitcoin-core/secp256k1:
 *   Copyright (c) 2013 Pieter Wuille
 *   https://github.com/bitcoin-core/secp256k1
 */

#ifdef TORSION_USE_LIBSECP256K1
#ifdef TORSION_USE_64BIT
typedef uint64_t secp256k1_fe_word_t;
#define SECP256K1_FIELD_WORDS 5
#include "libsecp256k1_64.h"
#else
typedef uint32_t secp256k1_fe_word_t;
#define SECP256K1_FIELD_WORDS 10
#include "libsecp256k1_32.h"
#endif
#else /* TORSION_USE_LIBSECP256K1 */
#ifdef TORSION_USE_64BIT
typedef uint64_t secp256k1_fe_word_t;
#define SECP256K1_FIELD_WORDS 4
#include "secp256k1_64.h"
#else
typedef uint32_t secp256k1_fe_word_t;
#define SECP256K1_FIELD_WORDS 8
#include "secp256k1_32.h"
#endif
#endif

#ifdef TORSION_USE_LIBSECP256K1
#define fiat_secp256k1_mul fiat_secp256k1_carry_mul
#define fiat_secp256k1_square fiat_secp256k1_carry_square
#define fiat_secp256k1_from_montgomery NULL
#else
#define fiat_secp256k1_carry NULL
#endif

typedef secp256k1_fe_word_t secp256k1_fe_t[SECP256K1_FIELD_WORDS];

#define secp256k1_fe_add fiat_secp256k1_add
#define secp256k1_fe_sub fiat_secp256k1_sub
#define secp256k1_fe_neg fiat_secp256k1_opp
#define secp256k1_fe_mul fiat_secp256k1_mul
#define secp256k1_fe_sqr fiat_secp256k1_square
#define secp256k1_fe_nonzero fiat_secp256k1_nonzero

static void
secp256k1_fe_set(secp256k1_fe_t out, const secp256k1_fe_t in) {
#ifdef TORSION_USE_LIBSECP256K1
  out[0] = in[0];
  out[1] = in[1];
  out[2] = in[2];
  out[3] = in[3];
  out[4] = in[4];
#if SECP256K1_FIELD_WORDS == 10
  out[5] = in[5];
  out[6] = in[6];
  out[7] = in[7];
  out[8] = in[8];
  out[9] = in[9];
#endif
#else /* TORSION_USE_LIBSECP256K1 */
  out[0] = in[0];
  out[1] = in[1];
  out[2] = in[2];
  out[3] = in[3];
#if SECP256K1_FIELD_WORDS == 8
  out[4] = in[4];
  out[5] = in[5];
  out[6] = in[6];
  out[7] = in[7];
#endif
#endif
}

static int
secp256k1_fe_equal(const secp256k1_fe_t a, const secp256k1_fe_t b) {
#ifdef TORSION_USE_LIBSECP256K1
  secp256k1_fe_word_t z = 0;
  secp256k1_fe_t c;
  secp256k1_fe_sub(c, a, b);
  secp256k1_fe_nonzero(&z, c);
  return z == 0;
#else
  secp256k1_fe_word_t z = 0;
  size_t i;

  for (i = 0; i < SECP256K1_FIELD_WORDS; i++)
    z |= a[i] ^ b[i];

  return z == 0;
#endif
}

static void
secp256k1_fe_sqrn(secp256k1_fe_t out, const secp256k1_fe_t in, int rounds) {
  int i;

  secp256k1_fe_sqr(out, in);

  for (i = 1; i < rounds; i++)
    secp256k1_fe_sqr(out, out);
}

static void
secp256k1_fe_invert(secp256k1_fe_t out, const secp256k1_fe_t in) {
  /* https://briansmith.org/ecc-inversion-addition-chains-01#secp256k1_field_inversion */
  /* https://github.com/bitcoin-core/secp256k1/blob/master/src/field_impl.h */
  /* 15M + 255S */
  secp256k1_fe_t x1, x2, x3, x6, x9, x11, x22, x44, x88, x176, x220, x223;

  secp256k1_fe_set(x1, in);

  secp256k1_fe_sqr(x2, x1);
  secp256k1_fe_mul(x2, x2, x1);

  secp256k1_fe_sqr(x3, x2);
  secp256k1_fe_mul(x3, x3, x1);

  secp256k1_fe_sqrn(x6, x3, 3);
  secp256k1_fe_mul(x6, x6, x3);

  secp256k1_fe_sqrn(x9, x6, 3);
  secp256k1_fe_mul(x9, x9, x3);

  secp256k1_fe_sqrn(x11, x9, 2);
  secp256k1_fe_mul(x11, x11, x2);

  secp256k1_fe_sqrn(x22, x11, 11);
  secp256k1_fe_mul(x22, x22, x11);

  secp256k1_fe_sqrn(x44, x22, 22);
  secp256k1_fe_mul(x44, x44, x22);

  secp256k1_fe_sqrn(x88, x44, 44);
  secp256k1_fe_mul(x88, x88, x44);

  secp256k1_fe_sqrn(x176, x88, 88);
  secp256k1_fe_mul(x176, x176, x88);

  secp256k1_fe_sqrn(x220, x176, 44);
  secp256k1_fe_mul(x220, x220, x44);

  secp256k1_fe_sqrn(x223, x220, 3);
  secp256k1_fe_mul(x223, x223, x3);

  secp256k1_fe_sqrn(out, x223, 23);
  secp256k1_fe_mul(out, out, x22);
  secp256k1_fe_sqrn(out, out, 5);
  secp256k1_fe_mul(out, out, x1);
  secp256k1_fe_sqrn(out, out, 3);
  secp256k1_fe_mul(out, out, x2);
  secp256k1_fe_sqrn(out, out, 2);
  secp256k1_fe_mul(out, out, x1);
}

static int
secp256k1_fe_sqrt(secp256k1_fe_t out, const secp256k1_fe_t in) {
  /* https://github.com/bitcoin-core/secp256k1/blob/master/src/field_impl.h */
  /* 13M + 254S */
  secp256k1_fe_t x1, x2, x3, x6, x9, x11, x22, x44, x88, x176, x220, x223;

  secp256k1_fe_set(x1, in);

  secp256k1_fe_sqr(x2, x1);
  secp256k1_fe_mul(x2, x2, x1);

  secp256k1_fe_sqr(x3, x2);
  secp256k1_fe_mul(x3, x3, x1);

  secp256k1_fe_sqrn(x6, x3, 3);
  secp256k1_fe_mul(x6, x6, x3);

  secp256k1_fe_sqrn(x9, x6, 3);
  secp256k1_fe_mul(x9, x9, x3);

  secp256k1_fe_sqrn(x11, x9, 2);
  secp256k1_fe_mul(x11, x11, x2);

  secp256k1_fe_sqrn(x22, x11, 11);
  secp256k1_fe_mul(x22, x22, x11);

  secp256k1_fe_sqrn(x44, x22, 22);
  secp256k1_fe_mul(x44, x44, x22);

  secp256k1_fe_sqrn(x88, x44, 44);
  secp256k1_fe_mul(x88, x88, x44);

  secp256k1_fe_sqrn(x176, x88, 88);
  secp256k1_fe_mul(x176, x176, x88);

  secp256k1_fe_sqrn(x220, x176, 44);
  secp256k1_fe_mul(x220, x220, x44);

  secp256k1_fe_sqrn(x223, x220, 3);
  secp256k1_fe_mul(x223, x223, x3);

  secp256k1_fe_sqrn(out, x223, 23);
  secp256k1_fe_mul(out, out, x22);
  secp256k1_fe_sqrn(out, out, 6);
  secp256k1_fe_mul(out, out, x2);
  secp256k1_fe_sqrn(out, out, 2);

  secp256k1_fe_sqr(x2, out);

  return secp256k1_fe_equal(x2, x1);
}

static void
secp256k1_fe_pow_pm3d4(secp256k1_fe_t out, const secp256k1_fe_t in) {
  /* Compute a^((p - 3) / 4) with a modification of the square root chain. */
  /* 14M + 254S */
  secp256k1_fe_t x1, x2, x3, x6, x9, x11, x22, x44, x88, x176, x220, x223;

  secp256k1_fe_set(x1, in);

  secp256k1_fe_sqr(x2, x1);
  secp256k1_fe_mul(x2, x2, x1);

  secp256k1_fe_sqr(x3, x2);
  secp256k1_fe_mul(x3, x3, x1);

  secp256k1_fe_sqrn(x6, x3, 3);
  secp256k1_fe_mul(x6, x6, x3);

  secp256k1_fe_sqrn(x9, x6, 3);
  secp256k1_fe_mul(x9, x9, x3);

  secp256k1_fe_sqrn(x11, x9, 2);
  secp256k1_fe_mul(x11, x11, x2);

  secp256k1_fe_sqrn(x22, x11, 11);
  secp256k1_fe_mul(x22, x22, x11);

  secp256k1_fe_sqrn(x44, x22, 22);
  secp256k1_fe_mul(x44, x44, x22);

  secp256k1_fe_sqrn(x88, x44, 44);
  secp256k1_fe_mul(x88, x88, x44);

  secp256k1_fe_sqrn(x176, x88, 88);
  secp256k1_fe_mul(x176, x176, x88);

  secp256k1_fe_sqrn(x220, x176, 44);
  secp256k1_fe_mul(x220, x220, x44);

  secp256k1_fe_sqrn(x223, x220, 3);
  secp256k1_fe_mul(x223, x223, x3);

  secp256k1_fe_sqrn(out, x223, 23);
  secp256k1_fe_mul(out, out, x22);
  secp256k1_fe_sqrn(out, out, 5);
  secp256k1_fe_mul(out, out, x1);
  secp256k1_fe_sqrn(out, out, 3);
  secp256k1_fe_mul(out, out, x2);
}

static int
secp256k1_fe_isqrt(secp256k1_fe_t r,
                   const secp256k1_fe_t u,
                   const secp256k1_fe_t v) {
  /* 21M + 257S */
  secp256k1_fe_t u2, u3, u5, v3, p, x, c;
  int ret;

  /* x = u^3 * v * (u^5 * v^3)^((p - 3) / 4) mod p */
  secp256k1_fe_sqr(u2, u);
  secp256k1_fe_mul(u3, u2, u);
  secp256k1_fe_mul(u5, u3, u2);
  secp256k1_fe_sqr(v3, v);
  secp256k1_fe_mul(v3, v3, v);
  secp256k1_fe_mul(p, u5, v3);
  secp256k1_fe_pow_pm3d4(p, p);
  secp256k1_fe_mul(x, u3, v);
  secp256k1_fe_mul(x, x, p);

  /* x^2 * v == u */
  secp256k1_fe_sqr(c, x);
  secp256k1_fe_mul(c, c, v);
  ret = secp256k1_fe_equal(c, u);

  secp256k1_fe_set(r, x);

  return ret;
}
