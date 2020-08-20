/*
 * main_impl.h - helpers module for libsecp256k1
 * Copyright (c) 2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on bitcoin-core/secp256k1:
 *   Copyright (c) 2013, Pieter Wuille
 *   https://github.com/bitcoin-core/secp256k1
 */

#ifndef SECP256K1_MODULE_EXTRA_MAIN_H
#define SECP256K1_MODULE_EXTRA_MAIN_H

#include "../../../include/secp256k1_extra.h"

int
secp256k1_ec_privkey_generate(const secp256k1_context *ctx,
                              unsigned char *output,
                              const unsigned char *entropy) {
  secp256k1_rfc6979_hmac_sha256 rng;
  secp256k1_scalar sec;
  int overflow;

  VERIFY_CHECK(ctx != NULL);
  ARG_CHECK(output != NULL);
  ARG_CHECK(entropy != NULL);

  secp256k1_rfc6979_hmac_sha256_initialize(&rng, entropy, 32);

  for (;;) {
    secp256k1_rfc6979_hmac_sha256_generate(&rng, output, 32);
    secp256k1_scalar_set_b32(&sec, output, &overflow);

    if (overflow || secp256k1_scalar_is_zero(&sec))
      continue;

    break;
  }

  secp256k1_rfc6979_hmac_sha256_finalize(&rng);
  secp256k1_scalar_clear(&sec);

  return 1;
}

/* Use this until #668 gets merged: */
/* https://github.com/bitcoin-core/secp256k1/pull/668 */
int
secp256k1_ec_privkey_negate_safe(const secp256k1_context *ctx,
                                 unsigned char *seckey) {
  secp256k1_scalar sec;
  int overflow;

  VERIFY_CHECK(ctx != NULL);
  ARG_CHECK(seckey != NULL);

  secp256k1_scalar_set_b32(&sec, seckey, &overflow);

  if (overflow || secp256k1_scalar_is_zero(&sec))
    return 0;

  secp256k1_scalar_negate(&sec, &sec);
  secp256k1_scalar_get_b32(seckey, &sec);
  secp256k1_scalar_clear(&sec);

  return 1;
}

int
secp256k1_ec_privkey_invert(const secp256k1_context *ctx,
                            unsigned char *seckey) {
  secp256k1_scalar sec;
  int overflow;

  VERIFY_CHECK(ctx != NULL);
  ARG_CHECK(seckey != NULL);

  secp256k1_scalar_set_b32(&sec, seckey, &overflow);

  if (overflow || secp256k1_scalar_is_zero(&sec))
    return 0;

  secp256k1_scalar_inverse(&sec, &sec);
  secp256k1_scalar_get_b32(seckey, &sec);
  secp256k1_scalar_clear(&sec);

  return 1;
}

int
secp256k1_ec_privkey_reduce(const secp256k1_context *ctx,
                            unsigned char *output,
                            const unsigned char *bytes,
                            size_t len) {
  secp256k1_scalar sec;

  VERIFY_CHECK(ctx != NULL);
  ARG_CHECK(output != NULL);

  if (len > 32)
    len = 32;

  memset(output, 0x00, 32 - len);
  memcpy(output + 32 - len, bytes, len);

  secp256k1_scalar_set_b32(&sec, output, NULL);

  if (secp256k1_scalar_is_zero(&sec))
    return 0;

  secp256k1_scalar_get_b32(output, &sec);
  secp256k1_scalar_clear(&sec);

  return 1;
}

int
secp256k1_ec_privkey_export(const secp256k1_context *ctx,
                            unsigned char *output,
                            const unsigned char *seckey) {
  secp256k1_scalar sec;
  int overflow;

  VERIFY_CHECK(ctx != NULL);
  ARG_CHECK(output != NULL);
  ARG_CHECK(seckey != NULL);

  secp256k1_scalar_set_b32(&sec, seckey, &overflow);

  if (overflow || secp256k1_scalar_is_zero(&sec))
    return 0;

  secp256k1_scalar_get_b32(output, &sec);
  secp256k1_scalar_clear(&sec);

  return 1;
}

int
secp256k1_ec_privkey_import(const secp256k1_context *ctx,
                            unsigned char *output,
                            const unsigned char *bytes,
                            size_t len) {
  secp256k1_scalar sec;
  int overflow;

  VERIFY_CHECK(ctx != NULL);
  ARG_CHECK(output != NULL);

  while (len > 0 && bytes[0] == 0x00) {
    len -= 1;
    bytes += 1;
  }

  if (len > 32)
    return 0;

  memset(output, 0x00, 32 - len);
  memcpy(output + 32 - len, bytes, len);

  secp256k1_scalar_set_b32(&sec, output, &overflow);

  if (overflow || secp256k1_scalar_is_zero(&sec))
    return 0;

  secp256k1_scalar_get_b32(output, &sec);
  secp256k1_scalar_clear(&sec);

  return 1;
}

int
secp256k1_ec_pubkey_export(const secp256k1_context *ctx,
                           unsigned char *x,
                           unsigned char *y,
                           const secp256k1_pubkey *pubkey) {
  secp256k1_ge A;

  VERIFY_CHECK(ctx != NULL);
  ARG_CHECK(x != NULL);
  ARG_CHECK(y != NULL);
  ARG_CHECK(pubkey != NULL);

  if (!secp256k1_pubkey_load(ctx, &A, pubkey))
    return 0;

  secp256k1_fe_get_b32(x, &A.x);
  secp256k1_fe_get_b32(y, &A.y);

  return 1;
}

int
secp256k1_ec_pubkey_import(const secp256k1_context *ctx,
                           secp256k1_pubkey *pubkey,
                           const unsigned char *x,
                           size_t x_len,
                           const unsigned char *y,
                           size_t y_len,
                           int sign) {
  unsigned char xp[32];
  unsigned char yp[32];
  int has_y = (y_len > 0);
  secp256k1_fe x0, y0;
  secp256k1_ge A;

  VERIFY_CHECK(ctx != NULL);
  ARG_CHECK(pubkey != NULL);

  while (x_len > 0 && x[0] == 0x00) {
    x_len -= 1;
    x += 1;
  }

  while (y_len > 0 && y[0] == 0x00) {
    y_len -= 1;
    y += 1;
  }

  if (x_len > 32 || y_len > 32)
    return 0;

  memset(xp, 0x00, 32 - x_len);
  memcpy(xp + 32 - x_len, x, x_len);

  memset(yp, 0x00, 32 - y_len);
  memcpy(yp + 32 - y_len, y, y_len);

  if (!secp256k1_fe_set_b32(&x0, xp))
    return 0;

  if (!secp256k1_fe_set_b32(&y0, yp))
    return 0;

  if (has_y) {
    secp256k1_ge_set_xy(&A, &x0, &y0);

    if (!secp256k1_ge_is_valid_var(&A))
      return 0;
  } else if (sign != -1) {
    if (!secp256k1_ge_set_xo_var(&A, &x0, sign))
      return 0;
  } else {
    if (!secp256k1_ge_set_xquad(&A, &x0))
      return 0;
  }

  secp256k1_pubkey_save(pubkey, &A);

  return 1;
}

#ifdef BCRYPTO_USE_SECP256K1_LATEST
int
secp256k1_xonly_pubkey_export(const secp256k1_context *ctx,
                              unsigned char *x,
                              unsigned char *y,
                              const secp256k1_xonly_pubkey *pubkey) {
  return secp256k1_ec_pubkey_export(ctx, x, y,
                                    (const secp256k1_pubkey *)pubkey);
}

int
secp256k1_xonly_pubkey_import(const secp256k1_context *ctx,
                              secp256k1_xonly_pubkey *pubkey,
                              const unsigned char *x,
                              size_t x_len,
                              const unsigned char *y,
                              size_t y_len) {
  if (!secp256k1_ec_pubkey_import(ctx, (secp256k1_pubkey *)pubkey,
                                  x, x_len, y, y_len, -1)) {
    return 0;
  }

  secp256k1_ec_pubkey_even_y(ctx, (secp256k1_pubkey *)pubkey, NULL);

  return 1;
}
#endif

void
secp256k1_ecdsa_reduce(const secp256k1_context *ctx,
                       unsigned char *output,
                       const unsigned char *msg,
                       size_t len) {
  VERIFY_CHECK(ctx != NULL);
  VERIFY_CHECK(output != NULL);

  if (len > 32)
    len = 32;

  memset(output, 0x00, 32 - len);
  memcpy(output + 32 - len, msg, len);
}

#endif /* SECP256K1_MODULE_EXTRA_MAIN_H */
