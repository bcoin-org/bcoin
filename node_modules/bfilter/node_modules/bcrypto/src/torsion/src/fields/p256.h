/*!
 * p256.h - p256 field element for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
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

static int
p256_fe_equal(const p256_fe_t a, const p256_fe_t b) {
  p256_fe_word_t z = 0;
  size_t i;

  for (i = 0; i < P256_FIELD_WORDS; i++)
    z |= a[i] ^ b[i];

  return z == 0;
}

static void
p256_fe_sqrn(p256_fe_t out, const p256_fe_t in, int rounds) {
  int i;

  p256_fe_sqr(out, in);

  for (i = 1; i < rounds; i++)
    p256_fe_sqr(out, out);
}

static void
p256_fe_invert(p256_fe_t out, const p256_fe_t in) {
  /* https://briansmith.org/ecc-inversion-addition-chains-01#p256_field_inversion */
  /* 32x1 31x0 1x1 96x0 94x1 1x0 1x1 */
  p256_fe_t x1, x2, x3, x6, x12, x15, x30, x32;

  p256_fe_set(x1, in);

  p256_fe_sqr(x2, x1);
  p256_fe_mul(x2, x2, x1);

  p256_fe_sqr(x3, x2);
  p256_fe_mul(x3, x3, x1);

  p256_fe_sqrn(x6, x3, 3);
  p256_fe_mul(x6, x6, x3);

  p256_fe_sqrn(x12, x6, 6);
  p256_fe_mul(x12, x12, x6);

  p256_fe_sqrn(x15, x12, 3);
  p256_fe_mul(x15, x15, x3);

  p256_fe_sqrn(x30, x15, 15);
  p256_fe_mul(x30, x30, x15);

  p256_fe_sqrn(x32, x30, 2);
  p256_fe_mul(x32, x32, x2);

  p256_fe_sqrn(out, x32, 31);

  p256_fe_sqr(out, out);
  p256_fe_mul(out, out, x1);

  p256_fe_sqrn(out, out, 96);

  p256_fe_sqrn(out, out, 32);
  p256_fe_mul(out, out, x32);
  p256_fe_sqrn(out, out, 32);
  p256_fe_mul(out, out, x32);
  p256_fe_sqrn(out, out, 30);
  p256_fe_mul(out, out, x30);

  p256_fe_sqr(out, out);

  p256_fe_sqr(out, out);
  p256_fe_mul(out, out, x1);
}

static int
p256_fe_sqrt(p256_fe_t out, const p256_fe_t in) {
  /* 32x1 31x0 1x1 95x0 1x1 94x0 */
  p256_fe_t x1, x2, x4, x8, x16;

  p256_fe_set(x1, in);

  p256_fe_sqr(x2, x1);
  p256_fe_mul(x2, x2, x1);

  p256_fe_sqrn(x4, x2, 2);
  p256_fe_mul(x4, x4, x2);

  p256_fe_sqrn(x8, x4, 4);
  p256_fe_mul(x8, x8, x4);

  p256_fe_sqrn(x16, x8, 8);
  p256_fe_mul(x16, x16, x8);

  p256_fe_sqrn(out, x16, 16);
  p256_fe_mul(out, out, x16);

  p256_fe_sqrn(out, out, 32);
  p256_fe_mul(out, out, x1);

  p256_fe_sqrn(out, out, 95);

  p256_fe_sqr(out, out);
  p256_fe_mul(out, out, x1);

  p256_fe_sqrn(out, out, 94);

  p256_fe_sqr(x2, out);

  return p256_fe_equal(x2, x1);
}
