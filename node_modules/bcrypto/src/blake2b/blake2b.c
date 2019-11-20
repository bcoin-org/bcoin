/**
 * Parts of this software are based on BLAKE2:
 * https://github.com/BLAKE2/BLAKE2
 *
 * BLAKE2 reference source code package - reference C implementations
 *
 * Copyright 2012, Samuel Neves <sneves@dei.uc.pt>.  You may use this under
 * the terms of the CC0, the OpenSSL Licence, or the Apache Public License
 * 2.0, at your option.  The terms of these licenses can be found at:
 *
 * - CC0 1.0 Universal : http://creativecommons.org/publicdomain/zero/1.0
 * - OpenSSL license   : https://www.openssl.org/source/license.html
 * - Apache 2.0        : http://www.apache.org/licenses/LICENSE-2.0
 *
 * More information about the BLAKE2 hash function can be found at
 * https://blake2.net.
 */

#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "blake2b.h"
#include "blake2b-impl.h"

#ifdef BCRYPTO_USE_SSE
#if defined(BCRYPTO_USE_SSE41) \
  && defined(__GNUC__) \
  && ((__GNUC__ > 4) || (__GNUC__ == 4 && __GNUC_MINOR__ >= 4))
#pragma GCC target("sse4.1")
#endif

#include "blake2b-config.h"

#ifdef HAVE_SSE2
#ifdef _MSC_VER
#include <intrin.h> /* for _mm_set_epi64x */
#endif
#include <emmintrin.h>
#if defined(HAVE_SSSE3)
#include <tmmintrin.h>
#endif
#if defined(HAVE_SSE41)
#include <smmintrin.h>
#endif
#if defined(HAVE_AVX)
#include <immintrin.h>
#endif
#if defined(HAVE_XOP)
#include <x86intrin.h>
#endif
#include "blake2b-round.h"
#endif // HAVE_SSE2
#endif // BCRYPTO_USE_SSE

static const uint64_t bcrypto_blake2b_IV[8] = {
  0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
  0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
  0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
  0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

#if !defined(BCRYPTO_USE_SSE) || !defined(HAVE_SSE2)
static const uint8_t bcrypto_blake2b_sigma[12][16] = {
  {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
  { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
  { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
  {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
  {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
  {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
  { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
  { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
  {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
  { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 },
  {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
  { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 }
};

#define G(r, i, a, b, c, d)                             \
  do {                                                  \
    a = a + b + m[bcrypto_blake2b_sigma[r][2 * i + 0]]; \
    d = rotr64(d ^ a, 32);                              \
    c = c + d;                                          \
    b = rotr64(b ^ c, 24);                              \
    a = a + b + m[bcrypto_blake2b_sigma[r][2 * i + 1]]; \
    d = rotr64(d ^ a, 16);                              \
    c = c + d;                                          \
    b = rotr64(b ^ c, 63);                              \
  } while (0)

#define ROUND(r)                       \
  do {                                 \
    G(r, 0, v[0], v[4], v[8], v[12]);  \
    G(r, 1, v[1], v[5], v[9], v[13]);  \
    G(r, 2, v[2], v[6], v[10], v[14]); \
    G(r, 3, v[3], v[7], v[11], v[15]); \
    G(r, 4, v[0], v[5], v[10], v[15]); \
    G(r, 5, v[1], v[6], v[11], v[12]); \
    G(r, 6, v[2], v[7], v[8], v[13]);  \
    G(r, 7, v[3], v[4], v[9], v[14]);  \
  } while (0)
#endif

static void
bcrypto_blake2b_set_lastnode(bcrypto_blake2b_ctx *ctx) {
  ctx->f[1] = (uint64_t)-1;
}

static int
bcrypto_blake2b_is_lastblock(const bcrypto_blake2b_ctx *ctx) {
  return ctx->f[0] != 0;
}

static void
bcrypto_blake2b_set_lastblock(bcrypto_blake2b_ctx *ctx) {
  if (ctx->last_node)
    bcrypto_blake2b_set_lastnode(ctx);

  ctx->f[0] = (uint64_t)-1;
}

static void
bcrypto_blake2b_increment_counter(bcrypto_blake2b_ctx *ctx, const uint64_t inc) {
  ctx->t[0] += inc;
  ctx->t[1] += (ctx->t[0] < inc);
}

static void
bcrypto_blake2b_init0(bcrypto_blake2b_ctx *ctx) {
  size_t i;

  memset(ctx, 0, sizeof(bcrypto_blake2b_ctx));

  for (i = 0; i < 8; i++)
    ctx->h[i] = bcrypto_blake2b_IV[i];
}

int
bcrypto_blake2b_init_param(bcrypto_blake2b_ctx *ctx, const bcrypto_blake2b_param *P) {
  const uint8_t *p = (const uint8_t *)(P);
  size_t i;

  bcrypto_blake2b_init0(ctx);

  for (i = 0; i < 8; i++)
    ctx->h[i] ^= load64(p + sizeof(ctx->h[i]) * i);

  ctx->outlen = P->digest_length;

  return 0;
}

int
bcrypto_blake2b_init(bcrypto_blake2b_ctx *ctx, size_t outlen) {
  bcrypto_blake2b_param P[1];

  if ((!outlen) || (outlen > BCRYPTO_BLAKE2B_OUTBYTES))
    return -1;

  P->digest_length = (uint8_t)outlen;
  P->key_length = 0;
  P->fanout = 1;
  P->depth = 1;
  store32(&P->leaf_length, 0);
  store32(&P->node_offset, 0);
  store32(&P->xof_length, 0);
  P->node_depth = 0;
  P->inner_length = 0;
  memset(P->reserved, 0, sizeof(P->reserved));
  memset(P->salt, 0, sizeof(P->salt));
  memset(P->personal, 0, sizeof(P->personal));

  return bcrypto_blake2b_init_param(ctx, P);
}

int
bcrypto_blake2b_init_key(
  bcrypto_blake2b_ctx *ctx,
  size_t outlen,
  const void *key,
  size_t keylen
) {
  bcrypto_blake2b_param P[1];

  if ((!outlen) || (outlen > BCRYPTO_BLAKE2B_OUTBYTES))
    return -1;

  if (!key || !keylen || keylen > BCRYPTO_BLAKE2B_KEYBYTES)
    return -1;

  P->digest_length = (uint8_t)outlen;
  P->key_length = (uint8_t)keylen;
  P->fanout = 1;
  P->depth = 1;
  store32(&P->leaf_length, 0);
  store32(&P->node_offset, 0);
  store32(&P->xof_length, 0);
  P->node_depth = 0;
  P->inner_length = 0;
  memset(P->reserved, 0, sizeof(P->reserved));
  memset(P->salt, 0, sizeof(P->salt));
  memset(P->personal, 0, sizeof(P->personal));

  if (bcrypto_blake2b_init_param(ctx, P) < 0)
    return -1;

  {
    uint8_t block[BCRYPTO_BLAKE2B_BLOCKBYTES];
    memset(block, 0, BCRYPTO_BLAKE2B_BLOCKBYTES);
    memcpy(block, key, keylen);
    bcrypto_blake2b_update(ctx, block, BCRYPTO_BLAKE2B_BLOCKBYTES);
    secure_zero_memory(block, BCRYPTO_BLAKE2B_BLOCKBYTES);
  }

  return 0;
}

static void
bcrypto_blake2b_compress(
  bcrypto_blake2b_ctx *ctx,
  const uint8_t block[BCRYPTO_BLAKE2B_BLOCKBYTES]
) {
#if defined(BCRYPTO_USE_SSE) && defined(HAVE_SSE2)
  __m128i row1l, row1h;
  __m128i row2l, row2h;
  __m128i row3l, row3h;
  __m128i row4l, row4h;
  __m128i b0, b1;
  __m128i t0, t1;
#if defined(HAVE_SSSE3) && !defined(HAVE_XOP)
  const __m128i r16 = _mm_setr_epi8(
    2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9);
  const __m128i r24 = _mm_setr_epi8(
    3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10);
#endif
#if defined(HAVE_SSE41)
  const __m128i m0 = LOADU(block + 0);
  const __m128i m1 = LOADU(block + 16);
  const __m128i m2 = LOADU(block + 32);
  const __m128i m3 = LOADU(block + 48);
  const __m128i m4 = LOADU(block + 64);
  const __m128i m5 = LOADU(block + 80);
  const __m128i m6 = LOADU(block + 96);
  const __m128i m7 = LOADU(block + 112);
#else
  const uint64_t m0 = load64(block + 0 * sizeof(uint64_t));
  const uint64_t m1 = load64(block + 1 * sizeof(uint64_t));
  const uint64_t m2 = load64(block + 2 * sizeof(uint64_t));
  const uint64_t m3 = load64(block + 3 * sizeof(uint64_t));
  const uint64_t m4 = load64(block + 4 * sizeof(uint64_t));
  const uint64_t m5 = load64(block + 5 * sizeof(uint64_t));
  const uint64_t m6 = load64(block + 6 * sizeof(uint64_t));
  const uint64_t m7 = load64(block + 7 * sizeof(uint64_t));
  const uint64_t m8 = load64(block + 8 * sizeof(uint64_t));
  const uint64_t m9 = load64(block + 9 * sizeof(uint64_t));
  const uint64_t m10 = load64(block + 10 * sizeof(uint64_t));
  const uint64_t m11 = load64(block + 11 * sizeof(uint64_t));
  const uint64_t m12 = load64(block + 12 * sizeof(uint64_t));
  const uint64_t m13 = load64(block + 13 * sizeof(uint64_t));
  const uint64_t m14 = load64(block + 14 * sizeof(uint64_t));
  const uint64_t m15 = load64(block + 15 * sizeof(uint64_t));
#endif
  row1l = LOADU(&ctx->h[0]);
  row1h = LOADU(&ctx->h[2]);
  row2l = LOADU(&ctx->h[4]);
  row2h = LOADU(&ctx->h[6]);
  row3l = LOADU(&bcrypto_blake2b_IV[0]);
  row3h = LOADU(&bcrypto_blake2b_IV[2]);
  row4l = _mm_xor_si128(LOADU(&bcrypto_blake2b_IV[4]), LOADU(&ctx->t[0]));
  row4h = _mm_xor_si128(LOADU(&bcrypto_blake2b_IV[6]), LOADU(&ctx->f[0]));
  ROUND(0);
  ROUND(1);
  ROUND(2);
  ROUND(3);
  ROUND(4);
  ROUND(5);
  ROUND(6);
  ROUND(7);
  ROUND(8);
  ROUND(9);
  ROUND(10);
  ROUND(11);
  row1l = _mm_xor_si128(row3l, row1l);
  row1h = _mm_xor_si128(row3h, row1h);
  STOREU(&ctx->h[0], _mm_xor_si128(LOADU(&ctx->h[0]), row1l));
  STOREU(&ctx->h[2], _mm_xor_si128(LOADU(&ctx->h[2]), row1h));
  row2l = _mm_xor_si128(row4l, row2l);
  row2h = _mm_xor_si128(row4h, row2h);
  STOREU(&ctx->h[4], _mm_xor_si128(LOADU(&ctx->h[4]), row2l));
  STOREU(&ctx->h[6], _mm_xor_si128(LOADU(&ctx->h[6]), row2h));
#else
  uint64_t m[16];
  uint64_t v[16];
  size_t i;

  for (i = 0; i < 16; i++)
    m[i] = load64(block + i * sizeof(m[i]));

  for (i = 0; i < 8; i++)
    v[i] = ctx->h[i];

  v[8] = bcrypto_blake2b_IV[0];
  v[9] = bcrypto_blake2b_IV[1];
  v[10] = bcrypto_blake2b_IV[2];
  v[11] = bcrypto_blake2b_IV[3];
  v[12] = bcrypto_blake2b_IV[4] ^ ctx->t[0];
  v[13] = bcrypto_blake2b_IV[5] ^ ctx->t[1];
  v[14] = bcrypto_blake2b_IV[6] ^ ctx->f[0];
  v[15] = bcrypto_blake2b_IV[7] ^ ctx->f[1];

  ROUND(0);
  ROUND(1);
  ROUND(2);
  ROUND(3);
  ROUND(4);
  ROUND(5);
  ROUND(6);
  ROUND(7);
  ROUND(8);
  ROUND(9);
  ROUND(10);
  ROUND(11);

  for (i = 0; i < 8; i++)
    ctx->h[i] = ctx->h[i] ^ v[i] ^ v[i + 8];
#undef G
#undef ROUND
#endif
}

int
bcrypto_blake2b_update(bcrypto_blake2b_ctx *ctx, const void *pin, size_t inlen) {
  const unsigned char * in = (const unsigned char *)pin;

  if (inlen > 0) {
    size_t left = ctx->buflen;
    size_t fill = BCRYPTO_BLAKE2B_BLOCKBYTES - left;

    if (inlen > fill) {
      ctx->buflen = 0;
      memcpy(ctx->buf + left, in, fill);

      bcrypto_blake2b_increment_counter(ctx, BCRYPTO_BLAKE2B_BLOCKBYTES);
      bcrypto_blake2b_compress(ctx, ctx->buf);

      in += fill;
      inlen -= fill;

      while (inlen > BCRYPTO_BLAKE2B_BLOCKBYTES) {
        bcrypto_blake2b_increment_counter(ctx, BCRYPTO_BLAKE2B_BLOCKBYTES);
        bcrypto_blake2b_compress(ctx, in);
        in += BCRYPTO_BLAKE2B_BLOCKBYTES;
        inlen -= BCRYPTO_BLAKE2B_BLOCKBYTES;
      }
    }

    memcpy(ctx->buf + ctx->buflen, in, inlen);
    ctx->buflen += inlen;
  }

  return 0;
}

int
bcrypto_blake2b_final(bcrypto_blake2b_ctx *ctx, void *out, size_t outlen) {
  uint8_t buffer[BCRYPTO_BLAKE2B_OUTBYTES] = {0};
  size_t i;

  if (out == NULL || outlen < ctx->outlen)
    return -1;

  if (bcrypto_blake2b_is_lastblock(ctx))
    return -1;

  bcrypto_blake2b_increment_counter(ctx, ctx->buflen);
  bcrypto_blake2b_set_lastblock(ctx);
  memset(ctx->buf + ctx->buflen, 0, BCRYPTO_BLAKE2B_BLOCKBYTES - ctx->buflen);
  bcrypto_blake2b_compress(ctx, ctx->buf);

  for (i = 0; i < 8; i++)
    store64(buffer + sizeof(ctx->h[i]) * i, ctx->h[i]);

  memcpy(out, buffer, ctx->outlen);
  secure_zero_memory(buffer, sizeof(buffer));

  return 0;
}

int
bcrypto_blake2b(
  void *out,
  size_t outlen,
  const void *in,
  size_t inlen,
  const void *key,
  size_t keylen
) {
  bcrypto_blake2b_ctx ctx;

  if (in == NULL && inlen > 0)
    return -1;

  if (out == NULL)
    return -1;

  if (key == NULL && keylen > 0)
    return -1;

  if (!outlen || outlen > BCRYPTO_BLAKE2B_OUTBYTES)
    return -1;

  if (keylen > BCRYPTO_BLAKE2B_KEYBYTES)
    return -1;

  if (keylen > 0) {
    if (bcrypto_blake2b_init_key(&ctx, outlen, key, keylen) < 0)
      return -1;
  } else {
    if (bcrypto_blake2b_init(&ctx, outlen) < 0)
      return -1;
  }

  bcrypto_blake2b_update(&ctx, (const uint8_t *)in, inlen);
  bcrypto_blake2b_final(&ctx, out, outlen);

  return 0;
}
