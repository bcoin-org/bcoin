/*!
 * scalar.h - scalar inversion chains for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 *
 * Parts of this software are based on bitcoin-core/secp256k1:
 *   Copyright (c) 2013 Pieter Wuille
 *   https://github.com/bitcoin-core/secp256k1
 */

static void
sc_montsqrn(const scalar_field_t *sc, sc_t r, const sc_t x, int rounds) {
  int i;

  sc_montsqr(sc, r, x);

  for (i = 1; i < rounds; i++)
    sc_montsqr(sc, r, r);
}

static void
q256_sc_invert(const scalar_field_t *sc, sc_t r, const sc_t x) {
  /* https://briansmith.org/ecc-inversion-addition-chains-01#p256_scalar_inversion */
  /* https://github.com/briansmith/ring/blob/master/src/ec/suite_b/ops/p256.rs#L169 */
  sc_t d0, d1, d2, d3, d4, d5, d6, d7;
  sc_t b10 /* 1010 */, b42 /* 101010 */, b63 /* 111111 */;
  sc_t x8 /* ff */, x16 /* ffff */, x32 /* ffffffff */;

  sc_mont(sc, d0, x);
  sc_montsqr(sc, d1, d0);
  sc_montmul(sc, d2, d1, d0);
  sc_montmul(sc, d3, d1, d2);
  sc_montmul(sc, d4, d3, d1);
  sc_montsqr(sc, b10, d3);
  sc_montmul(sc, d5, b10, d3);
  sc_montsqrn(sc, d6, b10, 0 + 1);
  sc_montmul(sc, d6, d6, d0);
  sc_montsqr(sc, b42, d6);
  sc_montmul(sc, d7, b42, d3);
  sc_montmul(sc, b63, b42, d6);

  sc_montsqrn(sc, x8, b63, 0 + 2);
  sc_montmul(sc, x8, x8, d2);
  sc_montsqrn(sc, x16, x8, 0 + 8);
  sc_montmul(sc, x16, x16, x8);
  sc_montsqrn(sc, x32, x16, 0 + 16);
  sc_montmul(sc, x32, x32, x16);

  sc_montsqrn(sc, r, x32, 32 + 32);
  sc_montmul(sc, r, r, x32);

  sc_montsqrn(sc, r, r, 0 + 32);
  sc_montmul(sc, r, r, x32);

  sc_montsqrn(sc, r, r, 6);
  sc_montmul(sc, r, r, d7);
  sc_montsqrn(sc, r, r, 2 + 3);
  sc_montmul(sc, r, r, d4);
  sc_montsqrn(sc, r, r, 2 + 2);
  sc_montmul(sc, r, r, d2);
  sc_montsqrn(sc, r, r, 1 + 4);
  sc_montmul(sc, r, r, d5);
  sc_montsqrn(sc, r, r, 5);
  sc_montmul(sc, r, r, d6);
  sc_montsqrn(sc, r, r, 1 + 3);
  sc_montmul(sc, r, r, d3);
  sc_montsqrn(sc, r, r, 3);
  sc_montmul(sc, r, r, d3);
  sc_montsqrn(sc, r, r, 3);
  sc_montmul(sc, r, r, d3);
  sc_montsqrn(sc, r, r, 2 + 3);
  sc_montmul(sc, r, r, d4);
  sc_montsqrn(sc, r, r, 3 + 6);
  sc_montmul(sc, r, r, d7);
  sc_montsqrn(sc, r, r, 2 + 4);
  sc_montmul(sc, r, r, d5);
  sc_montsqrn(sc, r, r, 1 + 1);
  sc_montmul(sc, r, r, d0);
  sc_montsqrn(sc, r, r, 4 + 1);
  sc_montmul(sc, r, r, d0);
  sc_montsqrn(sc, r, r, 2 + 4);
  sc_montmul(sc, r, r, d5);
  sc_montsqrn(sc, r, r, 2 + 3);
  sc_montmul(sc, r, r, d4);
  sc_montsqrn(sc, r, r, 1 + 3);
  sc_montmul(sc, r, r, d4);
  sc_montsqrn(sc, r, r, 2 + 3);
  sc_montmul(sc, r, r, d4);
  sc_montsqrn(sc, r, r, 2 + 3);
  sc_montmul(sc, r, r, d3);
  sc_montsqrn(sc, r, r, 1 + 2);
  sc_montmul(sc, r, r, d2);
  sc_montsqrn(sc, r, r, 4 + 6);
  sc_montmul(sc, r, r, d7);
  sc_montsqrn(sc, r, r, 2);
  sc_montmul(sc, r, r, d2);
  sc_montsqrn(sc, r, r, 3 + 2);
  sc_montmul(sc, r, r, d2);
  sc_montsqrn(sc, r, r, 3 + 2);
  sc_montmul(sc, r, r, d2);
  sc_montsqrn(sc, r, r, 2 + 1);
  sc_montmul(sc, r, r, d0);
  sc_montsqrn(sc, r, r, 2 + 5);
  sc_montmul(sc, r, r, d6);
  sc_montsqrn(sc, r, r, 2 + 4);
  sc_montmul(sc, r, r, d5);
  sc_normal(sc, r, r);

  sc_cleanse(sc, d0);
}

static void
q384_sc_invert(const scalar_field_t *sc, sc_t r, const sc_t x) {
  /* https://briansmith.org/ecc-inversion-addition-chains-01#p384_scalar_inversion */
  /* https://github.com/briansmith/ring/blob/master/src/ec/suite_b/ops/p384.rs#L193 */
  sc_t d0, d1, d2, d3, d4, d5, d6, d7;
  sc_t b2 /* 10 */;
  sc_t x8 /* ff */, x16 /* ffff */, x32 /* ffffffff */;
  sc_t x64 /* ffffffffffffffff */, x96 /* ffffffffffffffffffffffff */;

  sc_mont(sc, d0, x);
  sc_montsqr(sc, b2, d0);
  sc_montmul(sc, d1, d0, b2);
  sc_montmul(sc, d2, d1, b2);
  sc_montmul(sc, d3, d2, b2);
  sc_montmul(sc, d4, d3, b2);
  sc_montmul(sc, d5, d4, b2);
  sc_montmul(sc, d6, d5, b2);
  sc_montmul(sc, d7, d6, b2);

  sc_montsqrn(sc, x8, d7, 0 + 4);
  sc_montmul(sc, x8, x8, d7);
  sc_montsqrn(sc, x16, x8, 0 + 8);
  sc_montmul(sc, x16, x16, x8);
  sc_montsqrn(sc, x32, x16, 0 + 16);
  sc_montmul(sc, x32, x32, x16);
  sc_montsqrn(sc, x64, x32, 0 + 32);
  sc_montmul(sc, x64, x64, x32);
  sc_montsqrn(sc, x96, x64, 0 + 32);
  sc_montmul(sc, x96, x96, x32);

  sc_montsqrn(sc, r, x96, 0 + 96);
  sc_montmul(sc, r, r, x96);

  sc_montsqrn(sc, r, r, 2);
  sc_montmul(sc, r, r, d1);
  sc_montsqrn(sc, r, r, 3 + 3);
  sc_montmul(sc, r, r, d3);
  sc_montsqrn(sc, r, r, 1 + 2);
  sc_montmul(sc, r, r, d1);
  sc_montsqrn(sc, r, r, 3 + 2);
  sc_montmul(sc, r, r, d1);
  sc_montsqrn(sc, r, r, 1 + 4);
  sc_montmul(sc, r, r, d4);
  sc_montsqrn(sc, r, r, 4);
  sc_montmul(sc, r, r, d5);
  sc_montsqrn(sc, r, r, 6 + 4);
  sc_montmul(sc, r, r, d7);
  sc_montsqrn(sc, r, r, 3);
  sc_montmul(sc, r, r, d2);
  sc_montsqrn(sc, r, r, 4 + 1);
  sc_montmul(sc, r, r, d0);
  sc_montsqrn(sc, r, r, 4);
  sc_montmul(sc, r, r, d5);
  sc_montsqrn(sc, r, r, 4);
  sc_montmul(sc, r, r, d4);
  sc_montsqrn(sc, r, r, 1 + 4);
  sc_montmul(sc, r, r, d6);
  sc_montsqrn(sc, r, r, 4);
  sc_montmul(sc, r, r, d6);
  sc_montsqrn(sc, r, r, 4);
  sc_montmul(sc, r, r, d7);
  sc_montsqrn(sc, r, r, 1 + 4);
  sc_montmul(sc, r, r, d5);
  sc_montsqrn(sc, r, r, 6 + 4);
  sc_montmul(sc, r, r, d6);
  sc_montsqrn(sc, r, r, 5 + 4);
  sc_montmul(sc, r, r, d6);
  sc_montsqrn(sc, r, r, 4);
  sc_montmul(sc, r, r, d5);
  sc_montsqrn(sc, r, r, 2 + 4);
  sc_montmul(sc, r, r, d4);
  sc_montsqrn(sc, r, r, 2 + 1);
  sc_montmul(sc, r, r, d0);
  sc_montsqrn(sc, r, r, 3 + 4);
  sc_montmul(sc, r, r, d5);
  sc_montsqrn(sc, r, r, 4 + 3);
  sc_montmul(sc, r, r, d2);
  sc_montsqrn(sc, r, r, 2 + 3);
  sc_montmul(sc, r, r, d3);
  sc_montsqrn(sc, r, r, 1 + 4);
  sc_montmul(sc, r, r, d7);
  sc_montsqrn(sc, r, r, 1 + 4);
  sc_montmul(sc, r, r, d5);
  sc_montsqrn(sc, r, r, 4);
  sc_montmul(sc, r, r, d5);
  sc_montsqrn(sc, r, r, 2 + 3);
  sc_montmul(sc, r, r, d3);
  sc_montsqrn(sc, r, r, 1 + 2);
  sc_montmul(sc, r, r, d1);
  sc_montsqrn(sc, r, r, 5 + 2);
  sc_montmul(sc, r, r, d1);
  sc_montsqrn(sc, r, r, 2 + 4);
  sc_montmul(sc, r, r, d5);
  sc_montsqrn(sc, r, r, 1 + 3);
  sc_montmul(sc, r, r, d2);
  sc_montsqrn(sc, r, r, 1 + 2);
  sc_montmul(sc, r, r, d1);
  sc_montsqrn(sc, r, r, 2 + 2);
  sc_montmul(sc, r, r, d1);
  sc_montsqrn(sc, r, r, 2 + 2);
  sc_montmul(sc, r, r, d1);
  sc_montsqrn(sc, r, r, 3 + 3);
  sc_montmul(sc, r, r, d2);
  sc_montsqrn(sc, r, r, 2 + 3);
  sc_montmul(sc, r, r, d2);
  sc_montsqrn(sc, r, r, 2 + 3);
  sc_montmul(sc, r, r, d2);
  sc_montsqrn(sc, r, r, 2);
  sc_montmul(sc, r, r, d1);
  sc_montsqrn(sc, r, r, 3 + 1);
  sc_montmul(sc, r, r, d0);
  sc_normal(sc, r, r);

  sc_cleanse(sc, d0);
}

static void
q256k1_sc_invert(const scalar_field_t *sc, sc_t r, const sc_t x) {
  /* https://briansmith.org/ecc-inversion-addition-chains-01#secp256k1_scalar_inversion */
  /* https://github.com/bitcoin-core/secp256k1/blob/master/src/scalar_impl.h */
  sc_t x2, x3, x6, x8, x14, x28, x56, x112, x126;
  sc_t u1, u2, u5, u9, u11, u13;

  sc_mont(sc, u1, x);
  sc_montsqr(sc, u2, u1);
  sc_montmul(sc, x2, u2, u1);
  sc_montmul(sc, u5, u2, x2);
  sc_montmul(sc, x3, u5, u2);
  sc_montmul(sc, u9, x3, u2);
  sc_montmul(sc, u11, u9, u2);
  sc_montmul(sc, u13, u11, u2);

  sc_montsqr(sc, x6, u13);
  sc_montsqr(sc, x6, x6);
  sc_montmul(sc, x6, x6, u11);

  sc_montsqr(sc, x8, x6);
  sc_montsqr(sc, x8, x8);
  sc_montmul(sc, x8, x8,  x2);

  sc_montsqr(sc, x14, x8);
  sc_montsqrn(sc, x14, x14, 5);
  sc_montmul(sc, x14, x14, x6);

  sc_montsqr(sc, x28, x14);
  sc_montsqrn(sc, x28, x28, 13);
  sc_montmul(sc, x28, x28, x14);

  sc_montsqr(sc, x56, x28);
  sc_montsqrn(sc, x56, x56, 27);
  sc_montmul(sc, x56, x56, x28);

  sc_montsqr(sc, x112, x56);
  sc_montsqrn(sc, x112, x112, 55);
  sc_montmul(sc, x112, x112, x56);

  sc_montsqr(sc, x126, x112);
  sc_montsqrn(sc, x126, x126, 13);
  sc_montmul(sc, x126, x126, x14);

  sc_set(sc, r, x126);
  sc_montsqrn(sc, r, r, 3);
  sc_montmul(sc, r, r, u5); /* 101 */
  sc_montsqrn(sc, r, r, 4); /* 0 */
  sc_montmul(sc, r, r, x3); /* 111 */
  sc_montsqrn(sc, r, r, 4); /* 0 */
  sc_montmul(sc, r, r, u5); /* 101 */
  sc_montsqrn(sc, r, r, 5); /* 0 */
  sc_montmul(sc, r, r, u11); /* 1011 */
  sc_montsqrn(sc, r, r, 4);
  sc_montmul(sc, r, r, u11); /* 1011 */
  sc_montsqrn(sc, r, r, 4); /* 0 */
  sc_montmul(sc, r, r, x3); /* 111 */
  sc_montsqrn(sc, r, r, 5); /* 00 */
  sc_montmul(sc, r, r, x3); /* 111 */
  sc_montsqrn(sc, r, r, 6); /* 00 */
  sc_montmul(sc, r, r, u13); /* 1101 */
  sc_montsqrn(sc, r, r, 4); /* 0 */
  sc_montmul(sc, r, r, u5); /* 101 */
  sc_montsqrn(sc, r, r, 3);
  sc_montmul(sc, r, r, x3); /* 111 */
  sc_montsqrn(sc, r, r, 5); /* 0 */
  sc_montmul(sc, r, r, u9); /* 1001 */
  sc_montsqrn(sc, r, r, 6); /* 000 */
  sc_montmul(sc, r, r, u5); /* 101 */
  sc_montsqrn(sc, r, r, 10); /* 0000000 */
  sc_montmul(sc, r, r, x3); /* 111 */
  sc_montsqrn(sc, r, r, 4); /* 0 */
  sc_montmul(sc, r, r, x3); /* 111 */
  sc_montsqrn(sc, r, r, 9); /* 0 */
  sc_montmul(sc, r, r, x8); /* 11111111 */
  sc_montsqrn(sc, r, r, 5); /* 0 */
  sc_montmul(sc, r, r, u9); /* 1001 */
  sc_montsqrn(sc, r, r, 6); /* 00 */
  sc_montmul(sc, r, r, u11); /* 1011 */
  sc_montsqrn(sc, r, r, 4);
  sc_montmul(sc, r, r, u13); /* 1101 */
  sc_montsqrn(sc, r, r, 5);
  sc_montmul(sc, r, r, x2); /* 11 */
  sc_montsqrn(sc, r, r, 6); /* 00 */
  sc_montmul(sc, r, r, u13); /* 1101 */
  sc_montsqrn(sc, r, r, 10); /* 000000 */
  sc_montmul(sc, r, r, u13); /* 1101 */
  sc_montsqrn(sc, r, r, 4);
  sc_montmul(sc, r, r, u9); /* 1001 */
  sc_montsqrn(sc, r, r, 6); /* 00000 */
  sc_montmul(sc, r, r, u1); /* 1 */
  sc_montsqrn(sc, r, r, 8); /* 00 */
  sc_montmul(sc, r, r, x6); /* 111111 */
  sc_normal(sc, r, r);

  sc_cleanse(sc, u1);
}

static void
q25519_sc_invert(const scalar_field_t *sc, sc_t r, const sc_t x) {
  /* https://briansmith.org/ecc-inversion-addition-chains-01#curve25519_scalar_inversion */
  /* https://github.com/dalek-cryptography/curve25519-dalek/blob/master/src/scalar.rs */
  sc_t x1, x2 /* 10 */, x3 /* 11 */, x4 /* 100 */, x5 /* 101 */, x7 /* 111 */;
  sc_t x9 /* 1001 */, x11 /* 1011 */, x15 /* 1111 */;

  sc_mont(sc, x1, x);
  sc_montsqr(sc, x2, x1);
  sc_montsqr(sc, x4, x2);
  sc_montmul(sc, x3, x2, x1);
  sc_montmul(sc, x5, x2, x3);
  sc_montmul(sc, x7, x2, x5);
  sc_montmul(sc, x9, x2, x7);
  sc_montmul(sc, x11, x2, x9);
  sc_montmul(sc, x15, x4, x11);
  sc_montmul(sc, r, x15, x1);

  sc_montsqrn(sc, r, r, 123 + 3);
  sc_montmul(sc, r, r, x5);
  sc_montsqrn(sc, r, r, 2 + 2);
  sc_montmul(sc, r, r, x3);
  sc_montsqrn(sc, r, r, 1 + 4);
  sc_montmul(sc, r, r, x15);
  sc_montsqrn(sc, r, r, 1 + 4);
  sc_montmul(sc, r, r, x15);
  sc_montsqrn(sc, r, r, 4);
  sc_montmul(sc, r, r, x9);
  sc_montsqrn(sc, r, r, 2);
  sc_montmul(sc, r, r, x3);
  sc_montsqrn(sc, r, r, 1 + 4);
  sc_montmul(sc, r, r, x15);
  sc_montsqrn(sc, r, r, 1 + 3);
  sc_montmul(sc, r, r, x5);
  sc_montsqrn(sc, r, r, 3 + 3);
  sc_montmul(sc, r, r, x5);
  sc_montsqrn(sc, r, r, 3);
  sc_montmul(sc, r, r, x7);
  sc_montsqrn(sc, r, r, 1 + 4);
  sc_montmul(sc, r, r, x15);
  sc_montsqrn(sc, r, r, 2 + 3);
  sc_montmul(sc, r, r, x7);
  sc_montsqrn(sc, r, r, 2 + 2);
  sc_montmul(sc, r, r, x3);
  sc_montsqrn(sc, r, r, 1 + 4);
  sc_montmul(sc, r, r, x11);
  sc_montsqrn(sc, r, r, 2 + 4);
  sc_montmul(sc, r, r, x11);
  sc_montsqrn(sc, r, r, 6 + 4);
  sc_montmul(sc, r, r, x9);
  sc_montsqrn(sc, r, r, 2 + 2);
  sc_montmul(sc, r, r, x3);
  sc_montsqrn(sc, r, r, 3 + 2);
  sc_montmul(sc, r, r, x3);
  sc_montsqrn(sc, r, r, 3 + 2);
  sc_montmul(sc, r, r, x3);
  sc_montsqrn(sc, r, r, 1 + 4);
  sc_montmul(sc, r, r, x9);
  sc_montsqrn(sc, r, r, 1 + 3);
  sc_montmul(sc, r, r, x7);
  sc_montsqrn(sc, r, r, 2 + 4);
  sc_montmul(sc, r, r, x15);
  sc_montsqrn(sc, r, r, 1 + 4);
  sc_montmul(sc, r, r, x11);
  sc_montsqrn(sc, r, r, 3);
  sc_montmul(sc, r, r, x5);
  sc_montsqrn(sc, r, r, 2 + 4);
  sc_montmul(sc, r, r, x15);
  sc_montsqrn(sc, r, r, 3);
  sc_montmul(sc, r, r, x5);
  sc_montsqrn(sc, r, r, 1 + 2);
  sc_montmul(sc, r, r, x3);
  sc_normal(sc, r, r);
}
