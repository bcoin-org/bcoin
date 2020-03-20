/**********************************************************************
 * Copyright (c) 2018 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_MODULE_SCHNORRLEG_MAIN_
#define _SECP256K1_MODULE_SCHNORRLEG_MAIN_

#include "../../../include/secp256k1.h"
#include "../../../include/secp256k1_schnorrleg.h"
#include "../../hash.h"

static int
secp256k1_nonce_function_schnorrleg(unsigned char *nonce32,
                                    const unsigned char *msg,
                                    size_t msg_len,
                                    const unsigned char *key32) {
  secp256k1_sha256 sha;

  /* Hash x||msg as per the spec */
  secp256k1_sha256_initialize(&sha);
  secp256k1_sha256_write(&sha, key32, 32);
  secp256k1_sha256_write(&sha, msg, msg_len);
  secp256k1_sha256_finalize(&sha, nonce32);

  return 1;
}

int
secp256k1_schnorrleg_serialize(const secp256k1_context *ctx,
                               unsigned char *out64,
                               const secp256k1_schnorrleg *sig) {
  VERIFY_CHECK(ctx != NULL);
  ARG_CHECK(out64 != NULL);
  ARG_CHECK(sig != NULL);

  memcpy(out64, sig->data, 64);

  return 1;
}

int
secp256k1_schnorrleg_parse(const secp256k1_context *ctx,
                           secp256k1_schnorrleg *sig,
                           const unsigned char *in64) {
  VERIFY_CHECK(ctx != NULL);
  ARG_CHECK(sig != NULL);
  ARG_CHECK(in64 != NULL);

  memcpy(sig->data, in64, 64);

  return 1;
}

int
secp256k1_schnorrleg_sign(const secp256k1_context *ctx,
                          secp256k1_schnorrleg *sig,
                          const unsigned char *msg,
                          size_t msg_len,
                          const unsigned char *seckey) {
  secp256k1_scalar x;
  secp256k1_scalar e;
  secp256k1_scalar k;
  secp256k1_gej pkj;
  secp256k1_gej rj;
  secp256k1_ge pk;
  secp256k1_ge r;
  secp256k1_sha256 sha;
  int overflow;
  unsigned char buf[33];
  size_t buflen = sizeof(buf);

  VERIFY_CHECK(ctx != NULL);
  ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
  ARG_CHECK(sig != NULL);
  ARG_CHECK(seckey != NULL);

  memset(sig, 0, sizeof(*sig));

  secp256k1_scalar_set_b32(&x, seckey, &overflow);

  if (overflow || secp256k1_scalar_is_zero(&x))
    return 0;

  secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &pkj, &x);
  secp256k1_ge_set_gej(&pk, &pkj);

  if (!secp256k1_nonce_function_schnorrleg(buf, msg, msg_len, seckey))
    return 0;

  secp256k1_scalar_set_b32(&k, buf, NULL);

  if (secp256k1_scalar_is_zero(&k))
    return 0;

  secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &rj, &k);
  secp256k1_ge_set_gej(&r, &rj);

  if (!secp256k1_fe_is_quad_var(&r.y))
    secp256k1_scalar_negate(&k, &k);

  secp256k1_fe_normalize(&r.x);
  secp256k1_fe_get_b32(&sig->data[0], &r.x);

  secp256k1_sha256_initialize(&sha);
  secp256k1_sha256_write(&sha, &sig->data[0], 32);
  secp256k1_eckey_pubkey_serialize(&pk, buf, &buflen, 1);
  secp256k1_sha256_write(&sha, buf, buflen);
  secp256k1_sha256_write(&sha, msg, msg_len);
  secp256k1_sha256_finalize(&sha, buf);

  secp256k1_scalar_set_b32(&e, buf, NULL);
  secp256k1_scalar_mul(&e, &e, &x);
  secp256k1_scalar_add(&e, &e, &k);

  secp256k1_scalar_get_b32(&sig->data[32], &e);
  secp256k1_scalar_clear(&k);
  secp256k1_scalar_clear(&x);

  return 1;
}

static int
secp256k1_schnorrleg_real_verify(const secp256k1_context *ctx,
                                 secp256k1_gej *rj,
                                 const secp256k1_scalar *s,
                                 const secp256k1_scalar *e,
                                 const secp256k1_pubkey *pk) {
  /* Compute R = sG - eP. */
  secp256k1_scalar nege;
  secp256k1_ge pkp;
  secp256k1_gej pkj;

  secp256k1_scalar_negate(&nege, e);

  if (!secp256k1_pubkey_load(ctx, &pkp, pk))
    return 0;

  secp256k1_gej_set_ge(&pkj, &pkp);

  /* rj =  s*G + (-e)*pkj */
  secp256k1_ecmult(&ctx->ecmult_ctx, rj, &pkj, &nege, s);

  return 1;
}

int
secp256k1_schnorrleg_verify(const secp256k1_context *ctx,
                            const secp256k1_schnorrleg *sig,
                            const unsigned char *msg,
                            size_t msg_len,
                            const secp256k1_pubkey *pk) {
  secp256k1_scalar s;
  secp256k1_scalar e;
  secp256k1_gej rj;
  secp256k1_fe rx;
  secp256k1_sha256 sha;
  unsigned char buf[33];
  size_t buflen = sizeof(buf);
  int overflow;

  VERIFY_CHECK(ctx != NULL);
  ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
  ARG_CHECK(sig != NULL);
  ARG_CHECK(pk != NULL);

  if (!secp256k1_fe_set_b32(&rx, &sig->data[0]))
    return 0;

  secp256k1_scalar_set_b32(&s, &sig->data[32], &overflow);

  if (overflow)
    return 0;

  secp256k1_sha256_initialize(&sha);
  secp256k1_sha256_write(&sha, &sig->data[0], 32);
  secp256k1_ec_pubkey_serialize(ctx, buf, &buflen, pk, SECP256K1_EC_COMPRESSED);
  secp256k1_sha256_write(&sha, buf, buflen);
  secp256k1_sha256_write(&sha, msg, msg_len);
  secp256k1_sha256_finalize(&sha, buf);
  secp256k1_scalar_set_b32(&e, buf, NULL);

  if (!secp256k1_schnorrleg_real_verify(ctx, &rj, &s, &e, pk)
      || !secp256k1_gej_has_quad_y_var(&rj) /* fails if rj is infinity */
      || !secp256k1_gej_eq_x_var(&rx, &rj)) {
    return 0;
  }

  return 1;
}

typedef struct {
  const secp256k1_context *ctx;
  unsigned char chacha_seed[32];
  secp256k1_scalar randomizer_cache[2];
  const secp256k1_schnorrleg *const *sig;
  const unsigned char *const *msg;
  const size_t *msg_len;
  const secp256k1_pubkey *const *pk;
  size_t n_sigs;
} secp256k1_schnorrleg_verify_ecmult_context;

static int
secp256k1_schnorrleg_verify_batch_ecmult_callback(secp256k1_scalar *sc,
                                                  secp256k1_ge *pt,
                                                  size_t idx,
                                                  void *data) {
  secp256k1_schnorrleg_verify_ecmult_context *ecmult_context =
    (secp256k1_schnorrleg_verify_ecmult_context *)data;

  if (idx % 4 == 2) {
    secp256k1_scalar_chacha20(&ecmult_context->randomizer_cache[0],
                              &ecmult_context->randomizer_cache[1],
                              ecmult_context->chacha_seed, idx / 4);
  }

  if (idx % 2 == 0) {
    /* R */
    secp256k1_fe rx;
    *sc = ecmult_context->randomizer_cache[(idx / 2) % 2];
    if (!secp256k1_fe_set_b32(&rx, &ecmult_context->sig[idx / 2]->data[0]))
      return 0;

    if (!secp256k1_ge_set_xquad(pt, &rx))
      return 0;
  } else {
    /* eP */
    unsigned char buf[33];
    size_t buflen = sizeof(buf);
    secp256k1_sha256 sha;

    secp256k1_ec_pubkey_serialize(ecmult_context->ctx, buf, &buflen,
                                  ecmult_context->pk[idx / 2],
                                  SECP256K1_EC_COMPRESSED);

    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, &ecmult_context->sig[idx / 2]->data[0], 32);
    secp256k1_sha256_write(&sha, buf, buflen);
    secp256k1_sha256_write(&sha, ecmult_context->msg[idx / 2],
                                 ecmult_context->msg_len[idx / 2]);
    secp256k1_sha256_finalize(&sha, buf);

    secp256k1_scalar_set_b32(sc, buf, NULL);
    secp256k1_scalar_mul(sc, sc,
                         &ecmult_context->randomizer_cache[(idx / 2) % 2]);

    if (!secp256k1_pubkey_load(ecmult_context->ctx, pt,
                               ecmult_context->pk[idx / 2])) {
      return 0;
    }
  }

  return 1;
}

static int
secp256k1_schnorrleg_verify_batch_init_randomizer(
  const secp256k1_context *ctx,
  secp256k1_schnorrleg_verify_ecmult_context *ecmult_context,
  secp256k1_sha256 *sha,
  const secp256k1_schnorrleg *const *sig,
  const unsigned char *const *msg,
  const size_t *msg_len,
  const secp256k1_pubkey *const *pk,
  size_t n_sigs
) {
  secp256k1_sha256 inner;
  size_t i;

  if (n_sigs > 0) {
    ARG_CHECK(sig != NULL);
    ARG_CHECK(msg != NULL);
    ARG_CHECK(msg_len != NULL);
    ARG_CHECK(pk != NULL);
  }

  for (i = 0; i < n_sigs; i++) {
    unsigned char buf[33];
    size_t buflen = sizeof(buf);

    secp256k1_sha256_initialize(&inner);
    secp256k1_sha256_write(&inner, msg[i], msg_len[i]);
    secp256k1_sha256_finalize(&inner, buf);

    secp256k1_sha256_write(sha, sig[i]->data, 64);
    secp256k1_sha256_write(sha, buf, 32);
    secp256k1_ec_pubkey_serialize(ctx, buf, &buflen, pk[i],
                                  SECP256K1_EC_COMPRESSED);
    secp256k1_sha256_write(sha, buf, buflen);
  }

  ecmult_context->ctx = ctx;
  ecmult_context->sig = sig;
  ecmult_context->msg = msg;
  ecmult_context->msg_len = msg_len;
  ecmult_context->pk = pk;
  ecmult_context->n_sigs = n_sigs;

  return 1;
}

static int
secp256k1_schnorrleg_verify_batch_sum_s(secp256k1_scalar *s,
                                        unsigned char *chacha_seed,
                                        const secp256k1_schnorrleg *const *sig,
                                        size_t n_sigs) {
  secp256k1_scalar randomizer_cache[2];
  size_t i;

  secp256k1_scalar_set_int(&randomizer_cache[0], 1);

  for (i = 0; i < n_sigs; i++) {
    int overflow;
    secp256k1_scalar term;

    if (i % 2 == 1) {
      secp256k1_scalar_chacha20(&randomizer_cache[0],
                                &randomizer_cache[1],
                                chacha_seed, i / 2);
    }

    secp256k1_scalar_set_b32(&term, &sig[i]->data[32], &overflow);

    if (overflow)
      return 0;

    secp256k1_scalar_mul(&term, &term, &randomizer_cache[i % 2]);
    secp256k1_scalar_add(s, s, &term);
  }

  return 1;
}

int
secp256k1_schnorrleg_verify_batch(const secp256k1_context *ctx,
                                  secp256k1_scratch *scratch,
                                  const secp256k1_schnorrleg *const *sig,
                                  const unsigned char *const *msg,
                                  const size_t *msg_len,
                                  const secp256k1_pubkey *const *pk,
                                  size_t n_sigs) {
  secp256k1_schnorrleg_verify_ecmult_context ecmult_context;
  secp256k1_sha256 sha;
  secp256k1_scalar s;
  secp256k1_gej rj;

  VERIFY_CHECK(ctx != NULL);
  ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
  ARG_CHECK(scratch != NULL);
  ARG_CHECK(n_sigs <= SIZE_MAX / 2);
  ARG_CHECK(n_sigs < ((uint32_t)1 << 31));

  secp256k1_sha256_initialize(&sha);

  if (!secp256k1_schnorrleg_verify_batch_init_randomizer(ctx, &ecmult_context,
                                                         &sha, sig, msg,
                                                         msg_len, pk, n_sigs)) {
    return 0;
  }

  secp256k1_sha256_finalize(&sha, ecmult_context.chacha_seed);
  secp256k1_scalar_set_int(&ecmult_context.randomizer_cache[0], 1);

  secp256k1_scalar_clear(&s);

  if (!secp256k1_schnorrleg_verify_batch_sum_s(&s, ecmult_context.chacha_seed,
                                               sig, n_sigs)) {
    return 0;
  }

  secp256k1_scalar_negate(&s, &s);

#ifdef BCRYPTO_USE_SECP256K1_LATEST
  if (!secp256k1_ecmult_multi_var(&ctx->error_callback, &ctx->ecmult_ctx,
                                  scratch, &rj, &s,
                                  secp256k1_schnorrleg_verify_batch_ecmult_callback,
                                  (void *)&ecmult_context,
                                  2 * n_sigs)) {
    return 0;
  }
#else
  if (!secp256k1_ecmult_multi_var(&ctx->ecmult_ctx, scratch, &rj, &s,
                                  secp256k1_schnorrleg_verify_batch_ecmult_callback,
                                  (void *)&ecmult_context,
                                  2 * n_sigs)) {
    return 0;
  }
#endif

  return secp256k1_gej_is_infinity(&rj);
}

#endif
