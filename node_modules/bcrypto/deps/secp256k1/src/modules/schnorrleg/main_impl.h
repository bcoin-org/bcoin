/*!
 * main_impl.h - schnorr legacy module for libsecp256k1
 * Copyright (c) 2018, Andrew Poelstra (MIT License).
 * https://github.com/bitcoin-core/secp256k1
 *
 * Modified and refactored for bcrypto:
 *   Copyright (c) 2020, Christopher Jeffrey (MIT License).
 *   https://github.com/bcoin-org/bcrypto
 */

#ifndef _SECP256K1_MODULE_SCHNORRLEG_MAIN_
#define _SECP256K1_MODULE_SCHNORRLEG_MAIN_

#include "include/secp256k1.h"
#include "include/secp256k1_schnorrleg.h"
#include "hash.h"

/*
 * Helpers
 */

static void
secp256k1_schnorrleg_hash_nonce(unsigned char *nonce32,
                                const unsigned char *msg,
                                size_t msg_len,
                                const unsigned char *key32) {
  secp256k1_sha256 sha;
  secp256k1_sha256_initialize(&sha);
  secp256k1_sha256_write(&sha, key32, 32);
  secp256k1_sha256_write(&sha, msg, msg_len);
  secp256k1_sha256_finalize(&sha, nonce32);
}

static void
secp256k1_schnorrleg_hash_challenge(unsigned char *challenge32,
                                    const unsigned char *R,
                                    const unsigned char *A,
                                    const unsigned char *msg,
                                    size_t msg_len) {
  secp256k1_sha256 sha;
  secp256k1_sha256_initialize(&sha);
  secp256k1_sha256_write(&sha, R, 32);
  secp256k1_sha256_write(&sha, A, 33);
  secp256k1_sha256_write(&sha, msg, msg_len);
  secp256k1_sha256_finalize(&sha, challenge32);
}

/*
 * Signing
 */

int
secp256k1_schnorrleg_sign(const secp256k1_context *ctx,
                          unsigned char *sig,
                          const unsigned char *msg,
                          size_t msg_len,
                          const unsigned char *seckey) {
  unsigned char *Rraw = sig;
  unsigned char *sraw = sig + 32;
  unsigned char bytes[32];
  unsigned char Araw[33];
  secp256k1_scalar a, e, k;
  secp256k1_gej Aj, Rj;
  secp256k1_ge A, R;
  size_t Alen = 33;

  VERIFY_CHECK(ctx != NULL);
  ARG_CHECK(sig != NULL);
  ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
  ARG_CHECK(seckey != NULL);

  /* Import a. */
  if (!secp256k1_scalar_set_b32_seckey(&a, seckey))
    goto fail;

  /* A = G * a */
  secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &Aj, &a);
  secp256k1_ge_set_gej(&A, &Aj);

  /* k = H(m, a) mod n */
  secp256k1_schnorrleg_hash_nonce(bytes, msg, msg_len, seckey);
  secp256k1_scalar_set_b32(&k, bytes, NULL);

  /* Fail if k = 0 */
  if (secp256k1_scalar_is_zero(&k))
    goto fail;

  /* R = G * k */
  secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &Rj, &k);
  secp256k1_ge_set_gej(&R, &Rj);

  /* k = -k mod n if y(R) is not square in F(p) */
  if (!secp256k1_fe_is_quad_var(&R.y))
    secp256k1_scalar_negate(&k, &k);

  /* Output r. */
  secp256k1_fe_normalize(&R.x);
  secp256k1_fe_get_b32(Rraw, &R.x);

  /* e = H(R, A, m) mod n */
  secp256k1_eckey_pubkey_serialize(&A, Araw, &Alen, 1);
  secp256k1_schnorrleg_hash_challenge(bytes, Rraw, Araw, msg, msg_len);
  secp256k1_scalar_set_b32(&e, bytes, NULL);

  /* s = e * a + k */
  secp256k1_scalar_mul(&e, &e, &a);
  secp256k1_scalar_add(&e, &e, &k);

  /* Output s. */
  secp256k1_scalar_get_b32(sraw, &e);

  secp256k1_scalar_clear(&k);
  secp256k1_scalar_clear(&a);

  return 1;
fail:
  memset(sig, 0, 64);
  return 0;
}

/*
 * Verification
 */

int
secp256k1_schnorrleg_verify(const secp256k1_context *ctx,
                            const unsigned char *sig,
                            const unsigned char *msg,
                            size_t msg_len,
                            const secp256k1_pubkey *pk) {
  const unsigned char *Rraw = sig;
  const unsigned char *sraw = sig + 32;
  unsigned char bytes[32];
  unsigned char Araw[33];
  secp256k1_scalar s;
  secp256k1_scalar e;
  secp256k1_gej J, R;
  size_t Alen = 33;
  secp256k1_fe r;
  secp256k1_ge A;
  int overflow;

  VERIFY_CHECK(ctx != NULL);
  ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
  ARG_CHECK(sig != NULL);
  ARG_CHECK(pk != NULL);

  /* Import r. */
  if (!secp256k1_fe_set_b32(&r, Rraw))
    return 0;

  /* Import s. */
  secp256k1_scalar_set_b32(&s, sraw, &overflow);

  if (overflow)
    return 0;

  /* A = (x, sqrt(x^3 + a * x + b)) */
  if (!secp256k1_pubkey_load(ctx, &A, pk))
    return 0;

  secp256k1_gej_set_ge(&J, &A);

  /* e = H(R, A, m) mod n */
  secp256k1_ec_pubkey_serialize(ctx, Araw, &Alen, pk, SECP256K1_EC_COMPRESSED);
  secp256k1_schnorrleg_hash_challenge(bytes, sig, Araw, msg, msg_len);
  secp256k1_scalar_set_b32(&e, bytes, NULL);

  /* R = G * s - A * e */
  secp256k1_scalar_negate(&e, &e);
  secp256k1_ecmult(&ctx->ecmult_ctx, &R, &J, &e, &s);

  /* Fail if R = O or y(R) is not square in F(p) */
  if (!secp256k1_gej_has_quad_y_var(&R))
    return 0;

  /* Fail if r != x(R) */
  if (!secp256k1_gej_eq_x_var(&r, &R))
    return 0;

  return 1;
}

/*
 * ChaCha20
 */

#ifdef SECP256K1_BIG_ENDIAN
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
  uint32_t x0, x1, x2, x3, x4, x5, x6, x7;
  uint32_t x8, x9, x10, x11, x12, x13, x14, x15;
  size_t over_count = 0;
  uint32_t seed32[8];
  int over1, over2;
  size_t n;

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

#if defined(SECP256K1_WIDEMUL_INT128)
    r1->d[3] = (((uint64_t) x0) << 32) |  x1;
    r1->d[2] = (((uint64_t) x2) << 32) |  x3;
    r1->d[1] = (((uint64_t) x4) << 32) |  x5;
    r1->d[0] = (((uint64_t) x6) << 32) |  x7;
    r2->d[3] = (((uint64_t) x8) << 32) |  x9;
    r2->d[2] = (((uint64_t)x10) << 32) | x11;
    r2->d[1] = (((uint64_t)x12) << 32) | x13;
    r2->d[0] = (((uint64_t)x14) << 32) | x15;
#elif defined(SECP256K1_WIDEMUL_INT64)
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
#error "Please select wide multiplication implementation"
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

/*
 * Batch Verification
 */

typedef struct {
  const secp256k1_context *ctx;
  unsigned char chacha_seed[32];
  secp256k1_scalar randomizer_cache[2];
  const unsigned char *const *sigs;
  const unsigned char *const *msgs;
  const size_t *msg_lens;
  const secp256k1_pubkey *const *pks;
  size_t len;
} secp256k1_schnorrleg_batch_t;

static int
secp256k1_schnorrleg_batch_callback(secp256k1_scalar *scalar,
                                    secp256k1_ge *point,
                                    size_t idx,
                                    void *data) {
  secp256k1_schnorrleg_batch_t *batch = data;
  secp256k1_scalar *a = &batch->randomizer_cache[(idx / 2) % 2];
  const unsigned char *Rraw = batch->sigs[idx / 2];

  if (idx % 4 == 2) {
    secp256k1_schnorrleg_scalar_chacha20(&batch->randomizer_cache[0],
                                         &batch->randomizer_cache[1],
                                         batch->chacha_seed, idx / 4);
  }

  if (idx % 2 == 0) {
    /* rhs = rhs + Ri * ai */
    secp256k1_fe r;

    /* ai = random integer in [1,n-1] */
    *scalar = *a;

    /* Import ri. */
    if (!secp256k1_fe_set_b32(&r, Rraw))
      return 0;

    /* Ri = (ri, sqrt(ri^3 + a * ri + b)) */
    if (!secp256k1_ge_set_xquad(point, &r))
      return 0;
  } else {
    /* rhs = rhs + Ai * (ei * ai mod n) + ... */
    const secp256k1_pubkey *pk = batch->pks[idx / 2];
    const unsigned char *msg = batch->msgs[idx / 2];
    size_t msg_len = batch->msg_lens[idx / 2];
    unsigned char bytes[32];
    unsigned char Araw[33];
    size_t Alen = 33;

    /* ei = H(ri, Ai, mi) mod n */
    secp256k1_ec_pubkey_serialize(batch->ctx, Araw, &Alen, pk,
                                  SECP256K1_EC_COMPRESSED);
    secp256k1_schnorrleg_hash_challenge(bytes, Rraw, Araw, msg, msg_len);
    secp256k1_scalar_set_b32(scalar, bytes, NULL);

    /* ei * ai mod n */
    secp256k1_scalar_mul(scalar, scalar, a);

    /* Ai = (xi, sqrt(xi^3 + a * xi + b)) */
    if (!secp256k1_pubkey_load(batch->ctx, point, pk))
      return 0;
  }

  return 1;
}

static int
secp256k1_schnorrleg_batch_init_randomizer(const secp256k1_context *ctx,
                                           secp256k1_schnorrleg_batch_t *batch,
                                           secp256k1_sha256 *sha,
                                           const unsigned char *const *sigs,
                                           const unsigned char *const *msgs,
                                           const size_t *msg_lens,
                                           const secp256k1_pubkey *const *pks,
                                           size_t len) {
  secp256k1_sha256 inner;
  size_t i;

  if (len > 0) {
    ARG_CHECK(sigs != NULL);
    ARG_CHECK(msgs != NULL);
    ARG_CHECK(msg_lens != NULL);
    ARG_CHECK(pks != NULL);
  }

  /* preimage = ri || si || H(mi) || Ai */
  for (i = 0; i < len; i++) {
    unsigned char bytes[32];
    unsigned char Araw[33];
    size_t Alen = 33;

    secp256k1_sha256_initialize(&inner);
    secp256k1_sha256_write(&inner, msgs[i], msg_lens[i]);
    secp256k1_sha256_finalize(&inner, bytes);

    secp256k1_sha256_write(sha, sigs[i], 64);
    secp256k1_sha256_write(sha, bytes, 32);
    secp256k1_ec_pubkey_serialize(ctx, Araw, &Alen, pks[i],
                                  SECP256K1_EC_COMPRESSED);
    secp256k1_sha256_write(sha, Araw, Alen);
  }

  batch->ctx = ctx;
  batch->sigs = sigs;
  batch->msgs = msgs;
  batch->msg_lens = msg_lens;
  batch->pks = pks;
  batch->len = len;

  return 1;
}

static int
secp256k1_schnorrleg_batch_sum_s(secp256k1_scalar *sum,
                                 unsigned char *chacha_seed,
                                 const unsigned char *const *sigs,
                                 size_t len) {
  secp256k1_scalar randomizer_cache[2];
  size_t i;

  secp256k1_scalar_set_int(&randomizer_cache[0], 1);

  for (i = 0; i < len; i++) {
    const unsigned char *sraw = sigs[i] + 32;
    secp256k1_scalar s;
    int overflow;

    if (i % 2 == 1) {
      secp256k1_schnorrleg_scalar_chacha20(&randomizer_cache[0],
                                           &randomizer_cache[1],
                                           chacha_seed, i / 2);
    }

    /* Import si. */
    secp256k1_scalar_set_b32(&s, sraw, &overflow);

    if (overflow)
      return 0;

    /* lhs = lhs + si * ai mod n */
    secp256k1_scalar_mul(&s, &s, &randomizer_cache[i % 2]);
    secp256k1_scalar_add(sum, sum, &s);
  }

  return 1;
}

int
secp256k1_schnorrleg_verify_batch(const secp256k1_context *ctx,
                                  secp256k1_scratch *scratch,
                                  const unsigned char *const *sigs,
                                  const unsigned char *const *msgs,
                                  const size_t *msg_lens,
                                  const secp256k1_pubkey *const *pks,
                                  size_t len) {
  secp256k1_schnorrleg_batch_t batch;
  secp256k1_sha256 sha;
  secp256k1_scalar sum;
  secp256k1_gej R;

  VERIFY_CHECK(ctx != NULL);
  ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
  ARG_CHECK(scratch != NULL);
  ARG_CHECK(len <= SIZE_MAX / 2);
  ARG_CHECK(len < ((uint32_t)1 << 31));

  /* seed = H(ri, si, H(mi), Ai, ...) */
  secp256k1_sha256_initialize(&sha);

  if (!secp256k1_schnorrleg_batch_init_randomizer(ctx, &batch,
                                                  &sha, sigs, msgs,
                                                  msg_lens, pks, len)) {
    return 0;
  }

  secp256k1_sha256_finalize(&sha, batch.chacha_seed);
  secp256k1_scalar_set_int(&batch.randomizer_cache[0], 1);

  /* lhs = si * ai + ... mod n */
  secp256k1_scalar_clear(&sum);

  if (!secp256k1_schnorrleg_batch_sum_s(&sum, batch.chacha_seed, sigs, len))
    return 0;

  /* rhs = Ri * ai + Ai * (ei * ai mod n) + ... */
  secp256k1_scalar_negate(&sum, &sum);

  /* R = G * -lhs + rhs */
  if (!secp256k1_ecmult_multi_var(&ctx->error_callback,
                                  &ctx->ecmult_ctx,
                                  scratch,
                                  &R,
                                  &sum,
                                  secp256k1_schnorrleg_batch_callback,
                                  (void *)&batch,
                                  len * 2)) {
    return 0;
  }

  /* R == O */
  return secp256k1_gej_is_infinity(&R);
}

#endif /* _SECP256K1_MODULE_SCHNORRLEG_MAIN_ */
