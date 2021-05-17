/**********************************************************************
 * Copyright (c) 2018 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_MODULE_SCHNORRLEG_MAIN_
#define _SECP256K1_MODULE_SCHNORRLEG_MAIN_

#include "include/secp256k1.h"
#include "include/secp256k1_schnorrleg.h"
#include "hash.h"

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
  unsigned char buf[33];
  size_t buflen = sizeof(buf);

  VERIFY_CHECK(ctx != NULL);
  ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
  ARG_CHECK(sig != NULL);
  ARG_CHECK(seckey != NULL);

  memset(sig, 0, sizeof(*sig));

  if (!secp256k1_scalar_set_b32_seckey(&x, seckey))
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

#ifdef WORDS_BIGENDIAN
#define LE32(p) ((((p) & 0x000000FF) << 24)  \
               | (((p) & 0x0000FF00) <<  8)  \
               | (((p) & 0x00FF0000) >>  8)  \
               | (((p) & 0xFF000000) >> 24))
#else
#define LE32(p) (p)
#endif

#define ROTL32(x, n) ((x) << (n) | (x) >> (32 - (n)))

#define QUARTERROUND(a, b, c, d) \
  a += b; d = ROTL32(d ^ a, 16); \
  c += d; b = ROTL32(b ^ c, 12); \
  a += b; d = ROTL32(d ^ a, 8);  \
  c += d; b = ROTL32(b ^ c, 7);

static void
secp256k1_schnorrleg_scalar_chacha20(secp256k1_scalar *r1,
                                     secp256k1_scalar *r2,
                                     const unsigned char *seed,
                                     uint64_t idx) {
#if defined(EXHAUSTIVE_TEST_ORDER)
  *r1 = (seed[0] + idx) % EXHAUSTIVE_TEST_ORDER;
  *r2 = (seed[1] + idx) % EXHAUSTIVE_TEST_ORDER;
#else
  size_t n;
  size_t over_count = 0;
  uint32_t seed32[8];
  uint32_t x0, x1, x2, x3, x4, x5, x6, x7;
  uint32_t x8, x9, x10, x11, x12, x13, x14, x15;
  int over1, over2;

  memcpy((void *)seed32, (const void *)seed, 32);

  do {
    x0 = 0x61707865;
    x1 = 0x3320646e;
    x2 = 0x79622d32;
    x3 = 0x6b206574;
    x4 = LE32(seed32[0]);
    x5 = LE32(seed32[1]);
    x6 = LE32(seed32[2]);
    x7 = LE32(seed32[3]);
    x8 = LE32(seed32[4]);
    x9 = LE32(seed32[5]);
    x10 = LE32(seed32[6]);
    x11 = LE32(seed32[7]);
    x12 = idx;
    x13 = idx >> 32;
    x14 = 0;
    x15 = over_count;

    n = 10;

    while (n--) {
      QUARTERROUND(x0, x4,  x8, x12)
      QUARTERROUND(x1, x5,  x9, x13)
      QUARTERROUND(x2, x6, x10, x14)
      QUARTERROUND(x3, x7, x11, x15)
      QUARTERROUND(x0, x5, x10, x15)
      QUARTERROUND(x1, x6, x11, x12)
      QUARTERROUND(x2, x7,  x8, x13)
      QUARTERROUND(x3, x4,  x9, x14)
    }

    x0 += 0x61707865;
    x1 += 0x3320646e;
    x2 += 0x79622d32;
    x3 += 0x6b206574;
    x4 += LE32(seed32[0]);
    x5 += LE32(seed32[1]);
    x6 += LE32(seed32[2]);
    x7 += LE32(seed32[3]);
    x8 += LE32(seed32[4]);
    x9 += LE32(seed32[5]);
    x10 += LE32(seed32[6]);
    x11 += LE32(seed32[7]);
    x12 += idx;
    x13 += idx >> 32;
    x14 += 0;
    x15 += over_count;

#if defined(USE_SCALAR_4X64)
    r1->d[3] = (((uint64_t) x0) << 32) |  x1;
    r1->d[2] = (((uint64_t) x2) << 32) |  x3;
    r1->d[1] = (((uint64_t) x4) << 32) |  x5;
    r1->d[0] = (((uint64_t) x6) << 32) |  x7;
    r2->d[3] = (((uint64_t) x8) << 32) |  x9;
    r2->d[2] = (((uint64_t)x10) << 32) | x11;
    r2->d[1] = (((uint64_t)x12) << 32) | x13;
    r2->d[0] = (((uint64_t)x14) << 32) | x15;
#elif defined(USE_SCALAR_8X32)
    r1->d[7] = x0;
    r1->d[6] = x1;
    r1->d[5] = x2;
    r1->d[4] = x3;
    r1->d[3] = x4;
    r1->d[2] = x5;
    r1->d[1] = x6;
    r1->d[0] = x7;
    r2->d[7] = x8;
    r2->d[6] = x9;
    r2->d[5] = x10;
    r2->d[4] = x11;
    r2->d[3] = x12;
    r2->d[2] = x13;
    r2->d[1] = x14;
    r2->d[0] = x15;
#else
#error "Please select scalar implementation"
#endif

    over1 = secp256k1_scalar_check_overflow(r1);
    over2 = secp256k1_scalar_check_overflow(r2);
    over_count++;
  } while (over1 | over2);
#endif
}

#undef ROTL32
#undef QUARTERROUND
#undef LE32

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
    secp256k1_schnorrleg_scalar_chacha20(&ecmult_context->randomizer_cache[0],
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
      secp256k1_schnorrleg_scalar_chacha20(&randomizer_cache[0],
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

  if (!secp256k1_ecmult_multi_var(&ctx->error_callback, &ctx->ecmult_ctx,
                                  scratch, &rj, &s,
                                  secp256k1_schnorrleg_verify_batch_ecmult_callback,
                                  (void *)&ecmult_context,
                                  2 * n_sigs)) {
    return 0;
  }

  return secp256k1_gej_is_infinity(&rj);
}

#endif
