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
q192_sc_invert(const scalar_field_t *sc, sc_t z, const sc_t x) {
  sc_t x1, x3, x5, x7, x9, x11, x13, x15, t1, t2;

  sc_mont(sc, x1, x);

  sc_montsqr(sc, t1, x1);
  sc_montmul(sc, x3, x1, t1);
  sc_montmul(sc, x5, x3, t1);
  sc_montmul(sc, x7, x5, t1);
  sc_montmul(sc, x9, x7, t1);
  sc_montmul(sc, x11, x9, t1);
  sc_montmul(sc, x13, x11, t1);
  sc_montmul(sc, x15, x13, t1);

  sc_montsqrn(sc, t1, x15, 4); /* x8 */
  sc_montmul(sc, t1, t1, x15);
  sc_montsqrn(sc, t2, t1, 8); /* x16 */
  sc_montmul(sc, t2, t2, t1);
  sc_montsqrn(sc, t1, t2, 16); /* x32 */
  sc_montmul(sc, t1, t1, t2);
  sc_montsqrn(sc, t2, t1, 32); /* x64 */
  sc_montmul(sc, t2, t2, t1);
  sc_montsqrn(sc, z, t2, 32); /* x96 */
  sc_montmul(sc, z, z, t1);

  sc_montsqrn(sc, z, z, 0 + 4); /* 1001 */
  sc_montmul(sc, z, z, x9);
  sc_montsqrn(sc, z, z, 0 + 4); /* 1001 */
  sc_montmul(sc, z, z, x9);
  sc_montsqrn(sc, z, z, 0 + 4); /* 1101 */
  sc_montmul(sc, z, z, x13);
  sc_montsqrn(sc, z, z, 0 + 3); /* 111 */
  sc_montmul(sc, z, z, x7);
  sc_montsqrn(sc, z, z, 1 + 2); /* 011 */
  sc_montmul(sc, z, z, x3);
  sc_montsqrn(sc, z, z, 0 + 3); /* 111 */
  sc_montmul(sc, z, z, x7);
  sc_montsqrn(sc, z, z, 5 + 2); /* 0000011 */
  sc_montmul(sc, z, z, x3);
  sc_montsqrn(sc, z, z, 1 + 2); /* 011 */
  sc_montmul(sc, z, z, x3);
  sc_montsqrn(sc, z, z, 4 + 3); /* 0000101 */
  sc_montmul(sc, z, z, x5);
  sc_montsqrn(sc, z, z, 3 + 4); /* 0001101 */
  sc_montmul(sc, z, z, x13);
  sc_montsqrn(sc, z, z, 1 + 4); /* 01111 */
  sc_montmul(sc, z, z, x15);
  sc_montsqrn(sc, z, z, 2 + 4); /* 001001 */
  sc_montmul(sc, z, z, x9);
  sc_montsqrn(sc, z, z, 0 + 4); /* 1011 */
  sc_montmul(sc, z, z, x11);
  sc_montsqrn(sc, z, z, 3 + 4); /* 0001101 */
  sc_montmul(sc, z, z, x13);
  sc_montsqrn(sc, z, z, 0 + 3); /* 101 */
  sc_montmul(sc, z, z, x5);
  sc_montsqrn(sc, z, z, 2 + 4); /* 001101 */
  sc_montmul(sc, z, z, x13);
  sc_montsqrn(sc, z, z, 2 + 1); /* 001 */
  sc_montmul(sc, z, z, x1);
  sc_montsqrn(sc, z, z, 3 + 3); /* 000101 */
  sc_montmul(sc, z, z, x5);
  sc_montsqrn(sc, z, z, 5 + 3); /* 00000101 */
  sc_montmul(sc, z, z, x5);
  sc_montsqrn(sc, z, z, 0 + 3); /* 111 */
  sc_montmul(sc, z, z, x7);

  sc_normal(sc, z, z);

  sc_cleanse(sc, x1);
}

static void
q224_sc_invert(const scalar_field_t *sc, sc_t z, const sc_t x) {
  sc_t x1, x3, x5, x7, x11, x15, x23, t1, t2;

  sc_mont(sc, x1, x);

  sc_montsqr(sc, t1, x1);
  sc_montsqr(sc, t2, t1);
  sc_montmul(sc, x3, x1, t1);
  sc_montmul(sc, x5, x3, t1);
  sc_montmul(sc, x7, x5, t1);
  sc_montmul(sc, x11, x7, t2);
  sc_montmul(sc, x15, x11, t2);
  sc_montsqr(sc, t2, t2);
  sc_montmul(sc, x23, x15, t2);

  sc_montmul(sc, t1, x23, t2); /* x5 */
  sc_montsqrn(sc, t1, t1, 2); /* x7 */
  sc_montmul(sc, t1, t1, x3);
  sc_montsqrn(sc, t2, t1, 7); /* x14 */
  sc_montmul(sc, t2, t2, t1);
  sc_montsqrn(sc, t1, t2, 14); /* x28 */
  sc_montmul(sc, t1, t1, t2);
  sc_montsqrn(sc, t2, t1, 28); /* x56 */
  sc_montmul(sc, t2, t2, t1);
  sc_montsqrn(sc, z, t2, 56); /* x112 */
  sc_montmul(sc, z, z, t2);

  sc_montsqrn(sc, z, z, 3 + 4); /* 0001011 */
  sc_montmul(sc, z, z, x11);
  sc_montsqrn(sc, z, z, 1 + 3); /* 0101 */
  sc_montmul(sc, z, z, x5);
  sc_montsqrn(sc, z, z, 3 + 5); /* 00010111 */
  sc_montmul(sc, z, z, x23);
  sc_montsqrn(sc, z, z, 5 + 5); /* 0000010111 */
  sc_montmul(sc, z, z, x23);
  sc_montsqrn(sc, z, z, 3 + 4); /* 0001111 */
  sc_montmul(sc, z, z, x15);
  sc_montsqrn(sc, z, z, 6 + 3); /* 000000111 */
  sc_montmul(sc, z, z, x7);
  sc_montsqrn(sc, z, z, 0 + 2); /* 11 */
  sc_montmul(sc, z, z, x3);
  sc_montsqrn(sc, z, z, 4 + 1); /* 00001 */
  sc_montmul(sc, z, z, x1);
  sc_montsqrn(sc, z, z, 2 + 3); /* 00111 */
  sc_montmul(sc, z, z, x7);
  sc_montsqrn(sc, z, z, 0 + 4); /* 1011 */
  sc_montmul(sc, z, z, x11);
  sc_montsqrn(sc, z, z, 0 + 3); /* 101 */
  sc_montmul(sc, z, z, x5);
  sc_montsqrn(sc, z, z, 2 + 3); /* 00101 */
  sc_montmul(sc, z, z, x5);
  sc_montsqrn(sc, z, z, 2 + 3); /* 00101 */
  sc_montmul(sc, z, z, x5);
  sc_montsqrn(sc, z, z, 3 + 3); /* 000101 */
  sc_montmul(sc, z, z, x5);
  sc_montsqrn(sc, z, z, 1 + 5); /* 010111 */
  sc_montmul(sc, z, z, x23);
  sc_montsqrn(sc, z, z, 3 + 5); /* 00010111 */
  sc_montmul(sc, z, z, x23);
  sc_montsqrn(sc, z, z, 4 + 3); /* 0000101 */
  sc_montmul(sc, z, z, x5);
  sc_montsqrn(sc, z, z, 1 + 1); /* 01 */
  sc_montmul(sc, z, z, x1);
  sc_montsqrn(sc, z, z, 3 + 2); /* 00011 */
  sc_montmul(sc, z, z, x3);
  sc_montsqrn(sc, z, z, 0 + 4); /* 1011 */
  sc_montmul(sc, z, z, x11);

  sc_normal(sc, z, z);

  sc_cleanse(sc, x1);
}

static void
q256_sc_invert(const scalar_field_t *sc, sc_t z, const sc_t x) {
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
  sc_montsqrn(sc, d6, b10, 1);
  sc_montmul(sc, d6, d6, d0);
  sc_montsqr(sc, b42, d6);
  sc_montmul(sc, d7, b42, d3);
  sc_montmul(sc, b63, b42, d6);

  sc_montsqrn(sc, x8, b63, 2);
  sc_montmul(sc, x8, x8, d2);
  sc_montsqrn(sc, x16, x8, 8);
  sc_montmul(sc, x16, x16, x8);
  sc_montsqrn(sc, x32, x16, 16);
  sc_montmul(sc, x32, x32, x16);

  sc_montsqrn(sc, z, x32, 32);

  sc_montsqrn(sc, z, z, 32);
  sc_montmul(sc, z, z, x32);

  sc_montsqrn(sc, z, z, 32);
  sc_montmul(sc, z, z, x32);

  sc_montsqrn(sc, z, z, 0 + 6); /* 101111 */
  sc_montmul(sc, z, z, d7);
  sc_montsqrn(sc, z, z, 2 + 3); /* 00111 */
  sc_montmul(sc, z, z, d4);
  sc_montsqrn(sc, z, z, 2 + 2); /* 0011 */
  sc_montmul(sc, z, z, d2);
  sc_montsqrn(sc, z, z, 1 + 4); /* 01111 */
  sc_montmul(sc, z, z, d5);
  sc_montsqrn(sc, z, z, 0 + 5); /* 10101 */
  sc_montmul(sc, z, z, d6);
  sc_montsqrn(sc, z, z, 1 + 3); /* 0101 */
  sc_montmul(sc, z, z, d3);
  sc_montsqrn(sc, z, z, 0 + 3); /* 101 */
  sc_montmul(sc, z, z, d3);
  sc_montsqrn(sc, z, z, 0 + 3); /* 101 */
  sc_montmul(sc, z, z, d3);
  sc_montsqrn(sc, z, z, 2 + 3); /* 00111 */
  sc_montmul(sc, z, z, d4);
  sc_montsqrn(sc, z, z, 3 + 6); /* 000101111 */
  sc_montmul(sc, z, z, d7);
  sc_montsqrn(sc, z, z, 2 + 4); /* 001111 */
  sc_montmul(sc, z, z, d5);
  sc_montsqrn(sc, z, z, 1 + 1); /* 01 */
  sc_montmul(sc, z, z, d0);
  sc_montsqrn(sc, z, z, 4 + 1); /* 00001 */
  sc_montmul(sc, z, z, d0);
  sc_montsqrn(sc, z, z, 2 + 4); /* 001111 */
  sc_montmul(sc, z, z, d5);
  sc_montsqrn(sc, z, z, 2 + 3); /* 00111 */
  sc_montmul(sc, z, z, d4);
  sc_montsqrn(sc, z, z, 1 + 3); /* 0111 */
  sc_montmul(sc, z, z, d4);
  sc_montsqrn(sc, z, z, 2 + 3); /* 00111 */
  sc_montmul(sc, z, z, d4);
  sc_montsqrn(sc, z, z, 2 + 3); /* 00101 */
  sc_montmul(sc, z, z, d3);
  sc_montsqrn(sc, z, z, 1 + 2); /* 011 */
  sc_montmul(sc, z, z, d2);
  sc_montsqrn(sc, z, z, 4 + 6); /* 0000101111 */
  sc_montmul(sc, z, z, d7);
  sc_montsqrn(sc, z, z, 0 + 2); /* 11 */
  sc_montmul(sc, z, z, d2);
  sc_montsqrn(sc, z, z, 3 + 2); /* 00011 */
  sc_montmul(sc, z, z, d2);
  sc_montsqrn(sc, z, z, 3 + 2); /* 00011 */
  sc_montmul(sc, z, z, d2);
  sc_montsqrn(sc, z, z, 2 + 1); /* 001 */
  sc_montmul(sc, z, z, d0);
  sc_montsqrn(sc, z, z, 2 + 5); /* 0010101 */
  sc_montmul(sc, z, z, d6);
  sc_montsqrn(sc, z, z, 2 + 4); /* 001111 */
  sc_montmul(sc, z, z, d5);

  sc_normal(sc, z, z);

  sc_cleanse(sc, d0);
}

static void
q384_sc_invert(const scalar_field_t *sc, sc_t z, const sc_t x) {
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

  sc_montsqrn(sc, x8, d7, 4);
  sc_montmul(sc, x8, x8, d7);
  sc_montsqrn(sc, x16, x8, 8);
  sc_montmul(sc, x16, x16, x8);
  sc_montsqrn(sc, x32, x16, 16);
  sc_montmul(sc, x32, x32, x16);
  sc_montsqrn(sc, x64, x32, 32);
  sc_montmul(sc, x64, x64, x32);
  sc_montsqrn(sc, x96, x64, 32);
  sc_montmul(sc, x96, x96, x32);

  sc_montsqrn(sc, z, x96, 96);
  sc_montmul(sc, z, z, x96);

  sc_montsqrn(sc, z, z, 0 + 2); /* 11 */
  sc_montmul(sc, z, z, d1);
  sc_montsqrn(sc, z, z, 3 + 3); /* 000111 */
  sc_montmul(sc, z, z, d3);
  sc_montsqrn(sc, z, z, 1 + 2); /* 011 */
  sc_montmul(sc, z, z, d1);
  sc_montsqrn(sc, z, z, 3 + 2); /* 00011 */
  sc_montmul(sc, z, z, d1);
  sc_montsqrn(sc, z, z, 1 + 4); /* 01001 */
  sc_montmul(sc, z, z, d4);
  sc_montsqrn(sc, z, z, 0 + 4); /* 1011 */
  sc_montmul(sc, z, z, d5);
  sc_montsqrn(sc, z, z, 6 + 4); /* 0000001111 */
  sc_montmul(sc, z, z, d7);
  sc_montsqrn(sc, z, z, 0 + 3); /* 101 */
  sc_montmul(sc, z, z, d2);
  sc_montsqrn(sc, z, z, 4 + 1); /* 00001 */
  sc_montmul(sc, z, z, d0);
  sc_montsqrn(sc, z, z, 0 + 4); /* 1011 */
  sc_montmul(sc, z, z, d5);
  sc_montsqrn(sc, z, z, 0 + 4); /* 1001 */
  sc_montmul(sc, z, z, d4);
  sc_montsqrn(sc, z, z, 1 + 4); /* 01101 */
  sc_montmul(sc, z, z, d6);
  sc_montsqrn(sc, z, z, 0 + 4); /* 1101 */
  sc_montmul(sc, z, z, d6);
  sc_montsqrn(sc, z, z, 0 + 4); /* 1111 */
  sc_montmul(sc, z, z, d7);
  sc_montsqrn(sc, z, z, 1 + 4); /* 01011 */
  sc_montmul(sc, z, z, d5);
  sc_montsqrn(sc, z, z, 6 + 4); /* 0000001101 */
  sc_montmul(sc, z, z, d6);
  sc_montsqrn(sc, z, z, 5 + 4); /* 000001101 */
  sc_montmul(sc, z, z, d6);
  sc_montsqrn(sc, z, z, 0 + 4); /* 1011 */
  sc_montmul(sc, z, z, d5);
  sc_montsqrn(sc, z, z, 2 + 4); /* 001001 */
  sc_montmul(sc, z, z, d4);
  sc_montsqrn(sc, z, z, 2 + 1); /* 001 */
  sc_montmul(sc, z, z, d0);
  sc_montsqrn(sc, z, z, 3 + 4); /* 0001011 */
  sc_montmul(sc, z, z, d5);
  sc_montsqrn(sc, z, z, 4 + 3); /* 0000101 */
  sc_montmul(sc, z, z, d2);
  sc_montsqrn(sc, z, z, 2 + 3); /* 00111 */
  sc_montmul(sc, z, z, d3);
  sc_montsqrn(sc, z, z, 1 + 4); /* 01111 */
  sc_montmul(sc, z, z, d7);
  sc_montsqrn(sc, z, z, 1 + 4); /* 01011 */
  sc_montmul(sc, z, z, d5);
  sc_montsqrn(sc, z, z, 0 + 4); /* 1011 */
  sc_montmul(sc, z, z, d5);
  sc_montsqrn(sc, z, z, 2 + 3); /* 00111 */
  sc_montmul(sc, z, z, d3);
  sc_montsqrn(sc, z, z, 1 + 2); /* 011 */
  sc_montmul(sc, z, z, d1);
  sc_montsqrn(sc, z, z, 5 + 2); /* 0000011 */
  sc_montmul(sc, z, z, d1);
  sc_montsqrn(sc, z, z, 2 + 4); /* 001011 */
  sc_montmul(sc, z, z, d5);
  sc_montsqrn(sc, z, z, 1 + 3); /* 0101 */
  sc_montmul(sc, z, z, d2);
  sc_montsqrn(sc, z, z, 1 + 2); /* 011 */
  sc_montmul(sc, z, z, d1);
  sc_montsqrn(sc, z, z, 2 + 2); /* 0011 */
  sc_montmul(sc, z, z, d1);
  sc_montsqrn(sc, z, z, 2 + 2); /* 0011 */
  sc_montmul(sc, z, z, d1);
  sc_montsqrn(sc, z, z, 3 + 3); /* 000101 */
  sc_montmul(sc, z, z, d2);
  sc_montsqrn(sc, z, z, 2 + 3); /* 00101 */
  sc_montmul(sc, z, z, d2);
  sc_montsqrn(sc, z, z, 2 + 3); /* 00101 */
  sc_montmul(sc, z, z, d2);
  sc_montsqrn(sc, z, z, 0 + 2); /* 11 */
  sc_montmul(sc, z, z, d1);
  sc_montsqrn(sc, z, z, 3 + 1); /* 0001 */
  sc_montmul(sc, z, z, d0);

  sc_normal(sc, z, z);

  sc_cleanse(sc, d0);
}

static void
q521_sc_invert(const scalar_field_t *sc, sc_t z, const sc_t x) {
  sc_t x1, x3, x5, x7, x9, x11, x13, x15, t1, t2;

  sc_mont(sc, x1, x);

  sc_montsqr(sc, t1, x1);
  sc_montmul(sc, x3, x1, t1);
  sc_montmul(sc, x5, x3, t1);
  sc_montmul(sc, x7, x5, t1);
  sc_montmul(sc, x9, x7, t1);
  sc_montmul(sc, x11, x9, t1);
  sc_montmul(sc, x13, x11, t1);
  sc_montmul(sc, x15, x13, t1);

  sc_montsqrn(sc, t1, x15, 4); /* x8 */
  sc_montmul(sc, t1, t1, x15);
  sc_montsqrn(sc, t2, t1, 8); /* x16 */
  sc_montmul(sc, t2, t2, t1);
  sc_montsqrn(sc, t1, t2, 16); /* x32 */
  sc_montmul(sc, t1, t1, t2);
  sc_montsqrn(sc, t2, t1, 32); /* x64 */
  sc_montmul(sc, t2, t2, t1);
  sc_montsqrn(sc, t1, t2, 64); /* x128 */
  sc_montmul(sc, t1, t1, t2);
  sc_montsqrn(sc, z, t1, 128); /* x256 */
  sc_montmul(sc, z, z, t1);

  sc_montsqrn(sc, z, z, 0 + 4); /* 1111 */
  sc_montmul(sc, z, z, x15);
  sc_montsqrn(sc, z, z, 0 + 4); /* 1101 */
  sc_montmul(sc, z, z, x13);
  sc_montsqrn(sc, z, z, 2 + 3); /* 00101 */
  sc_montmul(sc, z, z, x5);
  sc_montsqrn(sc, z, z, 3 + 2); /* 00011 */
  sc_montmul(sc, z, z, x3);
  sc_montsqrn(sc, z, z, 4 + 4); /* 00001101 */
  sc_montmul(sc, z, z, x13);
  sc_montsqrn(sc, z, z, 4 + 4); /* 00001111 */
  sc_montmul(sc, z, z, x15);
  sc_montsqrn(sc, z, z, 5 + 3); /* 00000111 */
  sc_montmul(sc, z, z, x7);
  sc_montsqrn(sc, z, z, 1 + 1); /* 01 */
  sc_montmul(sc, z, z, x1);
  sc_montsqrn(sc, z, z, 0 + 4); /* 1111 */
  sc_montmul(sc, z, z, x15);
  sc_montsqrn(sc, z, z, 0 + 4); /* 1001 */
  sc_montmul(sc, z, z, x9);
  sc_montsqrn(sc, z, z, 1 + 4); /* 01111 */
  sc_montmul(sc, z, z, x15);
  sc_montsqrn(sc, z, z, 0 + 4); /* 1001 */
  sc_montmul(sc, z, z, x9);
  sc_montsqrn(sc, z, z, 1 + 2); /* 011 */
  sc_montmul(sc, z, z, x3);
  sc_montsqrn(sc, z, z, 2 + 4); /* 001101 */
  sc_montmul(sc, z, z, x13);
  sc_montsqrn(sc, z, z, 1 + 4); /* 01101 */
  sc_montmul(sc, z, z, x13);
  sc_montsqrn(sc, z, z, 0 + 4); /* 1111 */
  sc_montmul(sc, z, z, x15);
  sc_montsqrn(sc, z, z, 0 + 4); /* 1111 */
  sc_montmul(sc, z, z, x15);
  sc_montsqrn(sc, z, z, 2 + 2); /* 0011 */
  sc_montmul(sc, z, z, x3);
  sc_montsqrn(sc, z, z, 9 + 3); /* 000000000101 */
  sc_montmul(sc, z, z, x5);
  sc_montsqrn(sc, z, z, 2 + 1); /* 001 */
  sc_montmul(sc, z, z, x1);
  sc_montsqrn(sc, z, z, 3 + 4); /* 0001111 */
  sc_montmul(sc, z, z, x15);
  sc_montsqrn(sc, z, z, 1 + 3); /* 0111 */
  sc_montmul(sc, z, z, x7);
  sc_montsqrn(sc, z, z, 4 + 4); /* 00001001 */
  sc_montmul(sc, z, z, x9);
  sc_montsqrn(sc, z, z, 0 + 3); /* 101 */
  sc_montmul(sc, z, z, x5);
  sc_montsqrn(sc, z, z, 2 + 3); /* 00101 */
  sc_montmul(sc, z, z, x5);
  sc_montsqrn(sc, z, z, 0 + 4); /* 1101 */
  sc_montmul(sc, z, z, x13);
  sc_montsqrn(sc, z, z, 6 + 3); /* 000000111 */
  sc_montmul(sc, z, z, x7);
  sc_montsqrn(sc, z, z, 1 + 3); /* 0111 */
  sc_montmul(sc, z, z, x7);
  sc_montsqrn(sc, z, z, 1 + 4); /* 01101 */
  sc_montmul(sc, z, z, x13);
  sc_montsqrn(sc, z, z, 1 + 3); /* 0111 */
  sc_montmul(sc, z, z, x7);
  sc_montsqrn(sc, z, z, 2 + 4); /* 001001 */
  sc_montmul(sc, z, z, x9);
  sc_montsqrn(sc, z, z, 0 + 3); /* 101 */
  sc_montmul(sc, z, z, x5);
  sc_montsqrn(sc, z, z, 0 + 2); /* 11 */
  sc_montmul(sc, z, z, x3);
  sc_montsqrn(sc, z, z, 3 + 1); /* 0001 */
  sc_montmul(sc, z, z, x1);
  sc_montsqrn(sc, z, z, 3 + 4); /* 0001001 */
  sc_montmul(sc, z, z, x9);
  sc_montsqrn(sc, z, z, 0 + 4); /* 1001 */
  sc_montmul(sc, z, z, x9);
  sc_montsqrn(sc, z, z, 0 + 2); /* 11 */
  sc_montmul(sc, z, z, x3);
  sc_montsqrn(sc, z, z, 3 + 1); /* 0001 */
  sc_montmul(sc, z, z, x1);
  sc_montsqrn(sc, z, z, 3 + 2); /* 00011 */
  sc_montmul(sc, z, z, x3);
  sc_montsqrn(sc, z, z, 0 + 4); /* 1101 */
  sc_montmul(sc, z, z, x13);
  sc_montsqrn(sc, z, z, 1 + 2); /* 011 */
  sc_montmul(sc, z, z, x3);
  sc_montsqrn(sc, z, z, 0 + 3); /* 101 */
  sc_montmul(sc, z, z, x5);
  sc_montsqrn(sc, z, z, 1 + 3); /* 0111 */
  sc_montmul(sc, z, z, x7);
  sc_montsqrn(sc, z, z, 1 + 2); /* 011 */
  sc_montmul(sc, z, z, x3);
  sc_montsqrn(sc, z, z, 1 + 4); /* 01101 */
  sc_montmul(sc, z, z, x13);
  sc_montsqrn(sc, z, z, 0 + 4); /* 1111 */
  sc_montmul(sc, z, z, x15);
  sc_montsqrn(sc, z, z, 1 + 4); /* 01101 */
  sc_montmul(sc, z, z, x13);
  sc_montsqrn(sc, z, z, 0 + 2); /* 11 */
  sc_montmul(sc, z, z, x3);
  sc_montsqrn(sc, z, z, 3 + 4); /* 0001111 */
  sc_montmul(sc, z, z, x15);
  sc_montsqrn(sc, z, z, 1 + 4); /* 01001 */
  sc_montmul(sc, z, z, x9);
  sc_montsqrn(sc, z, z, 3 + 4); /* 0001001 */
  sc_montmul(sc, z, z, x9);
  sc_montsqrn(sc, z, z, 0 + 2); /* 11 */
  sc_montmul(sc, z, z, x3);
  sc_montsqrn(sc, z, z, 4 + 2); /* 000011 */
  sc_montmul(sc, z, z, x3);
  sc_montsqrn(sc, z, z, 2 + 1); /* 001 */
  sc_montmul(sc, z, z, x1);
  sc_montsqrn(sc, z, z, 7 + 3); /* 0000000111 */
  sc_montmul(sc, z, z, x7);

  sc_normal(sc, z, z);

  sc_cleanse(sc, x1);
}

static void
secq256k1_sc_invert(const scalar_field_t *sc, sc_t z, const sc_t x) {
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
  sc_montmul(sc, z, x126, x14);

  sc_montsqrn(sc, z, z, 0 + 3); /* 101 */
  sc_montmul(sc, z, z, u5);
  sc_montsqrn(sc, z, z, 1 + 3); /* 0111 */
  sc_montmul(sc, z, z, x3);
  sc_montsqrn(sc, z, z, 1 + 3); /* 0101 */
  sc_montmul(sc, z, z, u5);
  sc_montsqrn(sc, z, z, 1 + 4); /* 01011 */
  sc_montmul(sc, z, z, u11);
  sc_montsqrn(sc, z, z, 0 + 4); /* 1011 */
  sc_montmul(sc, z, z, u11);
  sc_montsqrn(sc, z, z, 1 + 3); /* 0111 */
  sc_montmul(sc, z, z, x3);
  sc_montsqrn(sc, z, z, 2 + 3); /* 00111 */
  sc_montmul(sc, z, z, x3);
  sc_montsqrn(sc, z, z, 2 + 4); /* 001101 */
  sc_montmul(sc, z, z, u13);
  sc_montsqrn(sc, z, z, 1 + 3); /* 0101 */
  sc_montmul(sc, z, z, u5);
  sc_montsqrn(sc, z, z, 0 + 3); /* 111 */
  sc_montmul(sc, z, z, x3);
  sc_montsqrn(sc, z, z, 1 + 4); /* 01001 */
  sc_montmul(sc, z, z, u9);
  sc_montsqrn(sc, z, z, 3 + 3); /* 000101 */
  sc_montmul(sc, z, z, u5);
  sc_montsqrn(sc, z, z, 7 + 3); /* 0000000111 */
  sc_montmul(sc, z, z, x3);
  sc_montsqrn(sc, z, z, 1 + 3); /* 0111 */
  sc_montmul(sc, z, z, x3);
  sc_montsqrn(sc, z, z, 1 + 8); /* 011111111 */
  sc_montmul(sc, z, z, x8);
  sc_montsqrn(sc, z, z, 1 + 4); /* 01001 */
  sc_montmul(sc, z, z, u9);
  sc_montsqrn(sc, z, z, 2 + 4); /* 001011 */
  sc_montmul(sc, z, z, u11);
  sc_montsqrn(sc, z, z, 0 + 4); /* 1101 */
  sc_montmul(sc, z, z, u13);
  sc_montsqrn(sc, z, z, 0 + 5); /* 11 */
  sc_montmul(sc, z, z, x2);
  sc_montsqrn(sc, z, z, 2 + 4); /* 001101 */
  sc_montmul(sc, z, z, u13);
  sc_montsqrn(sc, z, z, 6 + 4); /* 0000001101 */
  sc_montmul(sc, z, z, u13);
  sc_montsqrn(sc, z, z, 0 + 4); /* 1001 */
  sc_montmul(sc, z, z, u9);
  sc_montsqrn(sc, z, z, 5 + 1); /* 000001 */
  sc_montmul(sc, z, z, u1);
  sc_montsqrn(sc, z, z, 2 + 6); /* 00111111 */
  sc_montmul(sc, z, z, x6);

  sc_normal(sc, z, z);

  sc_cleanse(sc, u1);
}

static void
q25519_sc_invert(const scalar_field_t *sc, sc_t z, const sc_t x) {
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
  sc_montmul(sc, z, x15, x1);

  sc_montsqrn(sc, z, z, 123 + 3); /* 123x0 101 */
  sc_montmul(sc, z, z, x5);
  sc_montsqrn(sc, z, z, 2 + 2); /* 0011 */
  sc_montmul(sc, z, z, x3);
  sc_montsqrn(sc, z, z, 1 + 4); /* 01111 */
  sc_montmul(sc, z, z, x15);
  sc_montsqrn(sc, z, z, 1 + 4); /* 01111 */
  sc_montmul(sc, z, z, x15);
  sc_montsqrn(sc, z, z, 0 + 4); /* 1001 */
  sc_montmul(sc, z, z, x9);
  sc_montsqrn(sc, z, z, 0 + 2); /* 11 */
  sc_montmul(sc, z, z, x3);
  sc_montsqrn(sc, z, z, 1 + 4); /* 01111 */
  sc_montmul(sc, z, z, x15);
  sc_montsqrn(sc, z, z, 1 + 3); /* 0101 */
  sc_montmul(sc, z, z, x5);
  sc_montsqrn(sc, z, z, 3 + 3); /* 000101 */
  sc_montmul(sc, z, z, x5);
  sc_montsqrn(sc, z, z, 0 + 3); /* 111 */
  sc_montmul(sc, z, z, x7);
  sc_montsqrn(sc, z, z, 1 + 4); /* 01111 */
  sc_montmul(sc, z, z, x15);
  sc_montsqrn(sc, z, z, 2 + 3); /* 00111 */
  sc_montmul(sc, z, z, x7);
  sc_montsqrn(sc, z, z, 2 + 2); /* 0011 */
  sc_montmul(sc, z, z, x3);
  sc_montsqrn(sc, z, z, 1 + 4); /* 01011 */
  sc_montmul(sc, z, z, x11);
  sc_montsqrn(sc, z, z, 2 + 4); /* 001011 */
  sc_montmul(sc, z, z, x11);
  sc_montsqrn(sc, z, z, 6 + 4); /* 0000001001 */
  sc_montmul(sc, z, z, x9);
  sc_montsqrn(sc, z, z, 2 + 2); /* 0011 */
  sc_montmul(sc, z, z, x3);
  sc_montsqrn(sc, z, z, 3 + 2); /* 00011 */
  sc_montmul(sc, z, z, x3);
  sc_montsqrn(sc, z, z, 3 + 2); /* 00011 */
  sc_montmul(sc, z, z, x3);
  sc_montsqrn(sc, z, z, 1 + 4); /* 01001 */
  sc_montmul(sc, z, z, x9);
  sc_montsqrn(sc, z, z, 1 + 3); /* 0111 */
  sc_montmul(sc, z, z, x7);
  sc_montsqrn(sc, z, z, 2 + 4); /* 001111 */
  sc_montmul(sc, z, z, x15);
  sc_montsqrn(sc, z, z, 1 + 4); /* 01011 */
  sc_montmul(sc, z, z, x11);
  sc_montsqrn(sc, z, z, 0 + 3); /* 101 */
  sc_montmul(sc, z, z, x5);
  sc_montsqrn(sc, z, z, 2 + 4); /* 001111 */
  sc_montmul(sc, z, z, x15);
  sc_montsqrn(sc, z, z, 0 + 3); /* 101 */
  sc_montmul(sc, z, z, x5);
  sc_montsqrn(sc, z, z, 1 + 2); /* 011 */
  sc_montmul(sc, z, z, x3);

  sc_normal(sc, z, z);

  sc_cleanse(sc, x1);
}

static void
q448_sc_invert(const scalar_field_t *sc, sc_t z, const sc_t x) {
  sc_t x1, x3, x5, x7, x9, x11, x13, x15, t1, t2;

  sc_mont(sc, x1, x);

  sc_montsqr(sc, t1, x1);
  sc_montmul(sc, x3, x1, t1);
  sc_montmul(sc, x5, x3, t1);
  sc_montmul(sc, x7, x5, t1);
  sc_montmul(sc, x9, x7, t1);
  sc_montmul(sc, x11, x9, t1);
  sc_montmul(sc, x13, x11, t1);
  sc_montmul(sc, x15, x13, t1);

  sc_montsqrn(sc, t1, x15, 2); /* x6 */
  sc_montmul(sc, t1, t1, x3);
  sc_montsqrn(sc, t2, t1, 6); /* x12 */
  sc_montmul(sc, t2, t2, t1);
  sc_montsqrn(sc, t1, t2, 12); /* x24 */
  sc_montmul(sc, t1, t1, t2);
  sc_montsqrn(sc, t1, t1, 3); /* x27 */
  sc_montmul(sc, t1, t1, x7);
  sc_montsqrn(sc, t2, t1, 27); /* x54 */
  sc_montmul(sc, t2, t2, t1);
  sc_montsqrn(sc, t1, t2, 54); /* x108 */
  sc_montmul(sc, t1, t1, t2);
  sc_montsqrn(sc, t1, t1, 3); /* x111 */
  sc_montmul(sc, t1, t1, x7);
  sc_montsqrn(sc, z, t1, 111); /* x222 */
  sc_montmul(sc, z, z, t1);

  sc_montsqrn(sc, z, z, 1 + 4); /* 01111 */
  sc_montmul(sc, z, z, x15);
  sc_montsqrn(sc, z, z, 0 + 4); /* 1001 */
  sc_montmul(sc, z, z, x9);
  sc_montsqrn(sc, z, z, 0 + 4); /* 1001 */
  sc_montmul(sc, z, z, x9);
  sc_montsqrn(sc, z, z, 1 + 1); /* 01 */
  sc_montmul(sc, z, z, x1);
  sc_montsqrn(sc, z, z, 3 + 1); /* 0001 */
  sc_montmul(sc, z, z, x1);
  sc_montsqrn(sc, z, z, 3 + 1); /* 0001 */
  sc_montmul(sc, z, z, x1);
  sc_montsqrn(sc, z, z, 0 + 4); /* 1111 */
  sc_montmul(sc, z, z, x15);
  sc_montsqrn(sc, z, z, 1 + 4); /* 01001 */
  sc_montmul(sc, z, z, x9);
  sc_montsqrn(sc, z, z, 0 + 2); /* 11 */
  sc_montmul(sc, z, z, x3);
  sc_montsqrn(sc, z, z, 3 + 1); /* 0001 */
  sc_montmul(sc, z, z, x1);
  sc_montsqrn(sc, z, z, 3 + 4); /* 0001001 */
  sc_montmul(sc, z, z, x9);
  sc_montsqrn(sc, z, z, 0 + 4); /* 1101 */
  sc_montmul(sc, z, z, x13);
  sc_montsqrn(sc, z, z, 0 + 4); /* 1011 */
  sc_montmul(sc, z, z, x11);
  sc_montsqrn(sc, z, z, 1 + 4); /* 01101 */
  sc_montmul(sc, z, z, x13);
  sc_montsqrn(sc, z, z, 2 + 4); /* 001001 */
  sc_montmul(sc, z, z, x9);
  sc_montsqrn(sc, z, z, 0 + 3); /* 101 */
  sc_montmul(sc, z, z, x5);
  sc_montsqrn(sc, z, z, 1 + 3); /* 0111 */
  sc_montmul(sc, z, z, x7);
  sc_montsqrn(sc, z, z, 1 + 4); /* 01101 */
  sc_montmul(sc, z, z, x13);
  sc_montsqrn(sc, z, z, 1 + 2); /* 011 */
  sc_montmul(sc, z, z, x3);
  sc_montsqrn(sc, z, z, 3 + 4); /* 0001101 */
  sc_montmul(sc, z, z, x13);
  sc_montsqrn(sc, z, z, 0 + 3); /* 101 */
  sc_montmul(sc, z, z, x5);
  sc_montsqrn(sc, z, z, 2 + 1); /* 001 */
  sc_montmul(sc, z, z, x1);
  sc_montsqrn(sc, z, z, 6 + 1); /* 0000001 */
  sc_montmul(sc, z, z, x1);
  sc_montsqrn(sc, z, z, 4 + 4); /* 00001011 */
  sc_montmul(sc, z, z, x11);
  sc_montsqrn(sc, z, z, 1 + 2); /* 011 */
  sc_montmul(sc, z, z, x3);
  sc_montsqrn(sc, z, z, 2 + 2); /* 0011 */
  sc_montmul(sc, z, z, x3);
  sc_montsqrn(sc, z, z, 4 + 1); /* 00001 */
  sc_montmul(sc, z, z, x1);
  sc_montsqrn(sc, z, z, 2 + 3); /* 00111 */
  sc_montmul(sc, z, z, x7);
  sc_montsqrn(sc, z, z, 2 + 3); /* 00101 */
  sc_montmul(sc, z, z, x5);
  sc_montsqrn(sc, z, z, 3 + 4); /* 0001101 */
  sc_montmul(sc, z, z, x13);
  sc_montsqrn(sc, z, z, 0 + 2); /* 11 */
  sc_montmul(sc, z, z, x3);
  sc_montsqrn(sc, z, z, 3 + 4); /* 0001011 */
  sc_montmul(sc, z, z, x11);
  sc_montsqrn(sc, z, z, 3 + 4); /* 0001111 */
  sc_montmul(sc, z, z, x15);
  sc_montsqrn(sc, z, z, 1 + 3); /* 0101 */
  sc_montmul(sc, z, z, x5);
  sc_montsqrn(sc, z, z, 1 + 3); /* 0101 */
  sc_montmul(sc, z, z, x5);
  sc_montsqrn(sc, z, z, 2 + 1); /* 001 */
  sc_montmul(sc, z, z, x1);
  sc_montsqrn(sc, z, z, 3 + 4); /* 0001101 */
  sc_montmul(sc, z, z, x13);
  sc_montsqrn(sc, z, z, 0 + 3); /* 111 */
  sc_montmul(sc, z, z, x7);
  sc_montsqrn(sc, z, z, 3 + 2); /* 00011 */
  sc_montmul(sc, z, z, x3);
  sc_montsqrn(sc, z, z, 4 + 3); /* 0000101 */
  sc_montmul(sc, z, z, x5);
  sc_montsqrn(sc, z, z, 2 + 1); /* 001 */
  sc_montmul(sc, z, z, x1);
  sc_montsqrn(sc, z, z, 2 + 3); /* 00101 */
  sc_montmul(sc, z, z, x5);
  sc_montsqrn(sc, z, z, 1 + 3); /* 0101 */
  sc_montmul(sc, z, z, x5);
  sc_montsqrn(sc, z, z, 1 + 4); /* 01101 */
  sc_montmul(sc, z, z, x13);
  sc_montsqrn(sc, z, z, 1 + 2); /* 011 */
  sc_montmul(sc, z, z, x3);
  sc_montsqrn(sc, z, z, 4 + 1); /* 00001 */
  sc_montmul(sc, z, z, x1);
  sc_montsqrn(sc, z, z, 3 + 4); /* 0001001 */
  sc_montmul(sc, z, z, x9);
  sc_montsqrn(sc, z, z, 0 + 3); /* 111 */
  sc_montmul(sc, z, z, x7);
  sc_montsqrn(sc, z, z, 3 + 1); /* 0001 */
  sc_montmul(sc, z, z, x1);

  sc_normal(sc, z, z);

  sc_cleanse(sc, x1);
}

static void
q251_sc_invert(const scalar_field_t *sc, sc_t z, const sc_t x) {
  sc_t x1, x3, x5, x7, x9, x11, x13, x15, t1, t2;

  sc_mont(sc, x1, x);

  sc_montsqr(sc, t1, x1);
  sc_montmul(sc, x3, x1, t1);
  sc_montmul(sc, x5, x3, t1);
  sc_montmul(sc, x7, x5, t1);
  sc_montmul(sc, x9, x7, t1);
  sc_montmul(sc, x11, x9, t1);
  sc_montmul(sc, x13, x11, t1);
  sc_montmul(sc, x15, x13, t1);

  sc_montsqrn(sc, t1, x15, 2); /* x6 */
  sc_montmul(sc, t1, t1, x3);
  sc_montsqrn(sc, t2, t1, 6); /* x12 */
  sc_montmul(sc, t2, t2, t1);
  sc_montsqrn(sc, t2, t2, 3); /* x15 */
  sc_montmul(sc, t2, t2, x7);
  sc_montsqrn(sc, t1, t2, 15); /* x30 */
  sc_montmul(sc, t1, t1, t2);
  sc_montsqrn(sc, t2, t1, 30); /* x60 */
  sc_montmul(sc, t2, t2, t1);
  sc_montsqrn(sc, z, t2, 60); /* x120 */
  sc_montmul(sc, z, z, t2);

  sc_montsqrn(sc, z, z, 0 + 4); /* 1111 */
  sc_montmul(sc, z, z, x15);
  sc_montsqrn(sc, z, z, 0 + 3); /* 101 */
  sc_montmul(sc, z, z, x5);
  sc_montsqrn(sc, z, z, 0 + 4); /* 1101 */
  sc_montmul(sc, z, z, x13);
  sc_montsqrn(sc, z, z, 0 + 3); /* 111 */
  sc_montmul(sc, z, z, x7);
  sc_montsqrn(sc, z, z, 2 + 3); /* 00101 */
  sc_montmul(sc, z, z, x5);
  sc_montsqrn(sc, z, z, 0 + 4); /* 1001 */
  sc_montmul(sc, z, z, x9);
  sc_montsqrn(sc, z, z, 1 + 3); /* 0111 */
  sc_montmul(sc, z, z, x7);
  sc_montsqrn(sc, z, z, 3 + 4); /* 0001001 */
  sc_montmul(sc, z, z, x9);
  sc_montsqrn(sc, z, z, 0 + 4); /* 1011 */
  sc_montmul(sc, z, z, x11);
  sc_montsqrn(sc, z, z, 0 + 4); /* 1111 */
  sc_montmul(sc, z, z, x15);
  sc_montsqrn(sc, z, z, 0 + 3); /* 101 */
  sc_montmul(sc, z, z, x5);
  sc_montsqrn(sc, z, z, 2 + 2); /* 0011 */
  sc_montmul(sc, z, z, x3);
  sc_montsqrn(sc, z, z, 5 + 3); /* 00000111 */
  sc_montmul(sc, z, z, x7);
  sc_montsqrn(sc, z, z, 2 + 2); /* 0011 */
  sc_montmul(sc, z, z, x3);
  sc_montsqrn(sc, z, z, 1 + 4); /* 01001 */
  sc_montmul(sc, z, z, x9);
  sc_montsqrn(sc, z, z, 3 + 1); /* 0001 */
  sc_montmul(sc, z, z, x1);
  sc_montsqrn(sc, z, z, 2 + 3); /* 00101 */
  sc_montmul(sc, z, z, x5);
  sc_montsqrn(sc, z, z, 3 + 4); /* 0001001 */
  sc_montmul(sc, z, z, x9);
  sc_montsqrn(sc, z, z, 0 + 3); /* 101 */
  sc_montmul(sc, z, z, x5);
  sc_montsqrn(sc, z, z, 1 + 1); /* 01 */
  sc_montmul(sc, z, z, x1);
  sc_montsqrn(sc, z, z, 3 + 4); /* 0001011 */
  sc_montmul(sc, z, z, x11);
  sc_montsqrn(sc, z, z, 0 + 4); /* 1111 */
  sc_montmul(sc, z, z, x15);
  sc_montsqrn(sc, z, z, 0 + 3); /* 101 */
  sc_montmul(sc, z, z, x5);
  sc_montsqrn(sc, z, z, 3 + 3); /* 000101 */
  sc_montmul(sc, z, z, x5);
  sc_montsqrn(sc, z, z, 0 + 4); /* 1001 */
  sc_montmul(sc, z, z, x9);
  sc_montsqrn(sc, z, z, 0 + 4); /* 1011 */
  sc_montmul(sc, z, z, x11);
  sc_montsqrn(sc, z, z, 2 + 4); /* 001001 */
  sc_montmul(sc, z, z, x9);
  sc_montsqrn(sc, z, z, 1 + 2); /* 011 */
  sc_montmul(sc, z, z, x3);
  sc_montsqrn(sc, z, z, 1 + 4); /* 01111 */
  sc_montmul(sc, z, z, x15);

  sc_normal(sc, z, z);

  sc_cleanse(sc, x1);
}
