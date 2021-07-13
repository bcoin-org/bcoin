/*!
 * hash.c - hash functions for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 *
 * Parts of this software are based on BLAKE2/BLAKE2:
 *   CC0 1.0 Universal
 *   https://github.com/BLAKE2/BLAKE2
 *
 * Unrolled loops generated with:
 *   https://gist.github.com/chjj/338a5ee212eefdff4431e4da65a2d4f7
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <torsion/hash.h>
#include <torsion/util.h>
#include "bio.h"
#include "internal.h"

/*
 * Macros
 */

#define ROTL32(w, b) (((w) << (b)) | ((w) >> (32 - (b))))
#define ROTL64(w, b) (((w) << (b)) | ((w) >> (64 - (b))))
#define ROTR32(w, b) (((w) >> (b)) | ((w) << (32 - (b))))
#define ROTR64(w, b) (((w) >> (b)) | ((w) << (64 - (b))))

/*
 * BLAKE2b
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/BLAKE_(hash_function)
 *   https://tools.ietf.org/html/rfc7693
 *   https://github.com/BLAKE2/BLAKE2/blob/master/ref/blake2b-ref.c
 */

static const uint64_t blake2b_iv[8] = {
  UINT64_C(0x6a09e667f3bcc908), UINT64_C(0xbb67ae8584caa73b),
  UINT64_C(0x3c6ef372fe94f82b), UINT64_C(0xa54ff53a5f1d36f1),
  UINT64_C(0x510e527fade682d1), UINT64_C(0x9b05688c2b3e6c1f),
  UINT64_C(0x1f83d9abfb41bd6b), UINT64_C(0x5be0cd19137e2179)
};

void
blake2b_init(blake2b_t *ctx,
             size_t len,
             const unsigned char *key,
             size_t keylen) {
  int i;

  CHECK(len >= 1 && len <= 64);
  CHECK(keylen <= 64);

  memset(ctx, 0, sizeof(*ctx));

  ctx->len = len;

  for (i = 0; i < 8; i++)
    ctx->h[i] = blake2b_iv[i];

  ctx->h[0] ^= 0x01010000 | (keylen << 8) | len;

  if (keylen > 0) {
    unsigned char block[128];

    memcpy(block, key, keylen);
    memset(block + keylen, 0x00, 128 - keylen);

    blake2b_update(ctx, block, 128);

    torsion_cleanse(block, 128);
  }
}

static void
blake2b_increment(blake2b_t *ctx, uint64_t x) {
  ctx->t[0] += x;
  ctx->t[1] += (ctx->t[0] < x);
}

static void
blake2b_compress(blake2b_t *ctx, const unsigned char *chunk, uint64_t f0) {
  static const uint8_t S[12][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
    {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
    {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}
  };

  uint64_t W[16], V[16];
  int i;

  for (i = 0; i < 16; i++)
    W[i] = read64le(chunk + i * 8);

  V[ 0] = ctx->h[0];
  V[ 1] = ctx->h[1];
  V[ 2] = ctx->h[2];
  V[ 3] = ctx->h[3];
  V[ 4] = ctx->h[4];
  V[ 5] = ctx->h[5];
  V[ 6] = ctx->h[6];
  V[ 7] = ctx->h[7];
  V[ 8] = blake2b_iv[0];
  V[ 9] = blake2b_iv[1];
  V[10] = blake2b_iv[2];
  V[11] = blake2b_iv[3];
  V[12] = blake2b_iv[4] ^ ctx->t[0];
  V[13] = blake2b_iv[5] ^ ctx->t[1];
  V[14] = blake2b_iv[6] ^ f0;
  V[15] = blake2b_iv[7];

#define G(r, i, a, b, c, d) do { \
  a += b + W[S[r][2 * i + 0]];   \
  d ^= a;                        \
  d = ROTR64(d, 32);             \
  c += d;                        \
  b ^= c;                        \
  b = ROTR64(b, 24);             \
  a += b + W[S[r][2 * i + 1]];   \
  d ^= a;                        \
  d = ROTR64(d, 16);             \
  c += d;                        \
  b ^= c;                        \
  b = ROTR64(b, 63);             \
} while (0)

#define R(r) do {                      \
  G(r, 0, V[ 0], V[ 4], V[ 8], V[12]); \
  G(r, 1, V[ 1], V[ 5], V[ 9], V[13]); \
  G(r, 2, V[ 2], V[ 6], V[10], V[14]); \
  G(r, 3, V[ 3], V[ 7], V[11], V[15]); \
  G(r, 4, V[ 0], V[ 5], V[10], V[15]); \
  G(r, 5, V[ 1], V[ 6], V[11], V[12]); \
  G(r, 6, V[ 2], V[ 7], V[ 8], V[13]); \
  G(r, 7, V[ 3], V[ 4], V[ 9], V[14]); \
} while (0)

  R(0);
  R(1);
  R(2);
  R(3);
  R(4);
  R(5);
  R(6);
  R(7);
  R(8);
  R(9);
  R(10);
  R(11);

  for (i = 0; i < 8; i++)
    ctx->h[i] ^= V[i] ^ V[i + 8];

#undef G
#undef R
}

static void
blake2b_transform(blake2b_t *ctx, const unsigned char *chunk) {
  blake2b_increment(ctx, 128);
  blake2b_compress(ctx, chunk, 0);
}

void
blake2b_update(blake2b_t *ctx, const void *data, size_t len) {
  const unsigned char *raw = (const unsigned char *)data;
  size_t pos = ctx->pos;
  size_t want = 128 - pos;

  if (len == 0)
    return;

  if (len > want) {
    memcpy(ctx->block + pos, raw, want);

    raw += want;
    len -= want;

    blake2b_transform(ctx, ctx->block);

    while (len > 128) {
      blake2b_transform(ctx, raw);
      raw += 128;
      len -= 128;
    }

    ctx->pos = 0;
  }

  memcpy(ctx->block + ctx->pos, raw, len);

  ctx->pos += len;
}

void
blake2b_final(blake2b_t *ctx, unsigned char *out) {
  size_t count = ctx->len >> 3;
  size_t i;

  memset(ctx->block + ctx->pos, 0x00, 128 - ctx->pos);

  blake2b_increment(ctx, ctx->pos);
  blake2b_compress(ctx, ctx->block, UINT64_MAX);

  for (i = 0; i < count; i++)
    write64le(out + i * 8, ctx->h[i]);

  for (i = count * 8; i < ctx->len; i++)
    out[i] = (ctx->h[i >> 3] >> (8 * (i & 7))) & 0xff;
}

/*
 * BLAKE2b-{160,256,384,512}
 */

#define DEFINE_BLAKE2(name, bits)                                      \
void                                                                   \
torsion_##name##bits##_init(name##_t *ctx,                             \
                            const unsigned char *key, size_t keylen) { \
  name##_init(ctx, (bits) / 8, key, keylen);                           \
}                                                                      \
                                                                       \
void                                                                   \
torsion_##name##bits##_update(name##_t *ctx,                           \
                              const void *data, size_t len) {          \
  name##_update(ctx, data, len);                                       \
}                                                                      \
                                                                       \
void                                                                   \
torsion_##name##bits##_final(name##_t *ctx, unsigned char *out) {      \
  name##_final(ctx, out);                                              \
}

DEFINE_BLAKE2(blake2b, 160)
DEFINE_BLAKE2(blake2b, 256)
DEFINE_BLAKE2(blake2b, 384)
DEFINE_BLAKE2(blake2b, 512)

/*
 * BLAKE2s
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/BLAKE_(hash_function)
 *   https://tools.ietf.org/html/rfc7693
 *   https://github.com/BLAKE2/BLAKE2/blob/master/ref/blake2s-ref.c
 */

static const uint32_t blake2s_iv[8] = {
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

void
blake2s_init(blake2s_t *ctx,
             size_t len,
             const unsigned char *key,
             size_t keylen) {
  int i;

  CHECK(len >= 1 && len <= 32);
  CHECK(keylen <= 32);

  memset(ctx, 0, sizeof(*ctx));

  ctx->len = len;

  for (i = 0; i < 8; i++)
    ctx->h[i] = blake2s_iv[i];

  ctx->h[0] ^= 0x01010000 | (keylen << 8) | len;

  if (keylen > 0) {
    unsigned char block[64];

    memcpy(block, key, keylen);
    memset(block + keylen, 0x00, 64 - keylen);

    blake2s_update(ctx, block, 64);

    torsion_cleanse(block, 64);
  }
}

static void
blake2s_increment(blake2s_t *ctx, uint32_t x) {
  ctx->t[0] += x;
  ctx->t[1] += (ctx->t[0] < x);
}

static void
blake2s_compress(blake2s_t *ctx, const unsigned char *chunk, uint32_t f0) {
  static const uint8_t S[10][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
    {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
    {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
  };

  uint32_t W[16], V[16];
  int i;

  for (i = 0; i < 16; i++)
    W[i] = read32le(chunk + i * 4);

  V[ 0] = ctx->h[0];
  V[ 1] = ctx->h[1];
  V[ 2] = ctx->h[2];
  V[ 3] = ctx->h[3];
  V[ 4] = ctx->h[4];
  V[ 5] = ctx->h[5];
  V[ 6] = ctx->h[6];
  V[ 7] = ctx->h[7];
  V[ 8] = blake2s_iv[0];
  V[ 9] = blake2s_iv[1];
  V[10] = blake2s_iv[2];
  V[11] = blake2s_iv[3];
  V[12] = blake2s_iv[4] ^ ctx->t[0];
  V[13] = blake2s_iv[5] ^ ctx->t[1];
  V[14] = blake2s_iv[6] ^ f0;
  V[15] = blake2s_iv[7];

#define G(r, i, a, b, c, d) do { \
  a += b + W[S[r][2 * i + 0]];   \
  d ^= a;                        \
  d = ROTR32(d, 16);             \
  c += d;                        \
  b ^= c;                        \
  b = ROTR32(b, 12);             \
  a += b + W[S[r][2 * i + 1]];   \
  d ^= a;                        \
  d = ROTR32(d, 8);              \
  c += d;                        \
  b ^= c;                        \
  b = ROTR32(b, 7);              \
} while (0)

#define R(r) do {                      \
  G(r, 0, V[ 0], V[ 4], V[ 8], V[12]); \
  G(r, 1, V[ 1], V[ 5], V[ 9], V[13]); \
  G(r, 2, V[ 2], V[ 6], V[10], V[14]); \
  G(r, 3, V[ 3], V[ 7], V[11], V[15]); \
  G(r, 4, V[ 0], V[ 5], V[10], V[15]); \
  G(r, 5, V[ 1], V[ 6], V[11], V[12]); \
  G(r, 6, V[ 2], V[ 7], V[ 8], V[13]); \
  G(r, 7, V[ 3], V[ 4], V[ 9], V[14]); \
} while (0)

  R(0);
  R(1);
  R(2);
  R(3);
  R(4);
  R(5);
  R(6);
  R(7);
  R(8);
  R(9);

  for (i = 0; i < 8; i++)
    ctx->h[i] ^= V[i] ^ V[i + 8];

#undef G
#undef R
}

static void
blake2s_transform(blake2s_t *ctx, const unsigned char *chunk) {
  blake2s_increment(ctx, 64);
  blake2s_compress(ctx, chunk, 0);
}

void
blake2s_update(blake2s_t *ctx, const void *data, size_t len) {
  const unsigned char *raw = (const unsigned char *)data;
  size_t pos = ctx->pos;
  size_t want = 64 - pos;

  if (len == 0)
    return;

  if (len > want) {
    memcpy(ctx->block + pos, raw, want);

    raw += want;
    len -= want;

    blake2s_transform(ctx, ctx->block);

    while (len > 64) {
      blake2s_transform(ctx, raw);
      raw += 64;
      len -= 64;
    }

    ctx->pos = 0;
  }

  memcpy(ctx->block + ctx->pos, raw, len);

  ctx->pos += len;
}

void
blake2s_final(blake2s_t *ctx, unsigned char *out) {
  size_t count = ctx->len >> 2;
  size_t i;

  memset(ctx->block + ctx->pos, 0x00, 64 - ctx->pos);

  blake2s_increment(ctx, ctx->pos);
  blake2s_compress(ctx, ctx->block, UINT32_MAX);

  for (i = 0; i < count; i++)
    write32le(out + i * 4, ctx->h[i]);

  for (i = count * 4; i < ctx->len; i++)
    out[i] = (ctx->h[i >> 2] >> (8 * (i & 3))) & 0xff;
}

/*
 * BLAKE2s-{128,160,224,256}
 */

DEFINE_BLAKE2(blake2s, 128)
DEFINE_BLAKE2(blake2s, 160)
DEFINE_BLAKE2(blake2s, 224)
DEFINE_BLAKE2(blake2s, 256)

/*
 * GOST94
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/GOST_(hash_function)
 *   https://tools.ietf.org/html/rfc4357
 *   https://tools.ietf.org/html/rfc5831
 *   https://github.com/RustCrypto/hashes/blob/master/gost94/src/gost94.rs
 */

static uint32_t
gost94_g(uint32_t x, uint32_t y) {
  static const uint8_t S[8][16] = { /* CryptoPro */
    {10, 4, 5, 6, 8, 1, 3, 7, 13, 12, 14, 0, 9, 2, 11, 15},
    {5, 15, 4, 0, 2, 13, 11, 9, 1, 7, 6, 3, 12, 14, 10, 8},
    {7, 15, 12, 14, 9, 4, 1, 0, 3, 11, 5, 2, 6, 10, 8, 13},
    {4, 10, 7, 12, 0, 15, 2, 8, 14, 1, 6, 5, 13, 11, 9, 3},
    {7, 6, 4, 11, 9, 12, 2, 10, 1, 8, 0, 14, 15, 13, 3, 5},
    {7, 6, 2, 4, 13, 9, 15, 0, 10, 1, 5, 11, 8, 14, 12, 3},
    {13, 14, 4, 1, 7, 0, 5, 10, 3, 12, 8, 15, 6, 2, 9, 11},
    {1, 3, 10, 9, 5, 11, 4, 15, 8, 6, 7, 14, 13, 0, 2, 12}
  };

  uint32_t t = x + y;
  uint32_t z = ((uint32_t)S[7][(t >> 28) & 15] << 28)
             | ((uint32_t)S[6][(t >> 24) & 15] << 24)
             | ((uint32_t)S[5][(t >> 20) & 15] << 20)
             | ((uint32_t)S[4][(t >> 16) & 15] << 16)
             | ((uint32_t)S[3][(t >> 12) & 15] << 12)
             | ((uint32_t)S[2][(t >>  8) & 15] <<  8)
             | ((uint32_t)S[1][(t >>  4) & 15] <<  4)
             | ((uint32_t)S[0][(t >>  0) & 15] <<  0);

  return ROTL32(z, 11);
}

static void
gost94_e(unsigned char *msg, const unsigned char *key) {
  uint32_t a = read32le(msg + 0);
  uint32_t b = read32le(msg + 4);
  uint32_t k[8];
  uint32_t t;
  int i, x;

  for (i = 0; i < 8; i++)
    k[i] = read32le(key + i * 4);

  for (x = 0; x < 3; x++) {
    for (i = 0; i < 8; i++) {
      t = b ^ gost94_g(a, k[i]);
      b = a;
      a = t;
    }
  }

  for (i = 8 - 1; i >= 0; i--) {
    t = b ^ gost94_g(a, k[i]);
    b = a;
    a = t;
  }

  write32le(msg + 0, b);
  write32le(msg + 4, a);
}

static void
gost94_x(uint8_t *zp, const uint8_t *xp, const uint8_t *yp) {
  int i;

  for (i = 0; i < 32; i++)
    zp[i] = xp[i] ^ yp[i];
}

static void
gost94_a(uint8_t *zp, const uint8_t *xp) {
  uint8_t tp[32];
  int i;

  for (i = 0; i < 32; i++)
    tp[i] = xp[i];

  for (i = 0; i < 24; i++)
    zp[i] = tp[8 + i];

  for (i = 0; i < 8; i++)
    zp[24 + i] = tp[i] ^ tp[i + 8];
}

static void
gost94_p(uint8_t *zp, const uint8_t *xp) {
  uint8_t tp[32];
  int i, k;

  for (i = 0; i < 32; i++)
    tp[i] = xp[i];

  for (i = 0; i < 4; i++) {
    for (k = 0; k < 8; k++)
      zp[i + 4 * k] = tp[8 * i + k];
  }
}

static void
gost94_s(uint8_t *zp, const uint8_t *xp) {
  uint8_t z30 = xp[0] ^ xp[2] ^ xp[4] ^ xp[6] ^ xp[24] ^ xp[30];
  uint8_t z31 = xp[1] ^ xp[3] ^ xp[5] ^ xp[7] ^ xp[25] ^ xp[31];
  int i;

  for (i = 0; i < 30; i++)
    zp[i] = xp[2 + i];

  zp[30] = z30;
  zp[31] = z31;
}

static void
gost94_compress(gost94_t *ctx, const uint8_t *mp) {
  static const uint8_t cp[32] = {
    0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff,
    0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00,
    0x00, 0xff, 0xff, 0x00, 0xff, 0x00, 0x00, 0xff,
    0xff, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0xff
  };

  uint8_t tp[32], kp[32], up[32], vp[32];
  uint8_t *sp = ctx->state;
  int i;

  for (i = 0; i < 32; i++)
    tp[i] = sp[i];

  gost94_x(kp, sp, mp);
  gost94_p(kp, kp);
  gost94_e(tp + 0, kp);

  gost94_a(up, sp);
  gost94_a(vp, mp);
  gost94_a(vp, vp);
  gost94_x(kp, up, vp);
  gost94_p(kp, kp);
  gost94_e(tp + 8, kp);

  gost94_a(up, up);
  gost94_x(up, up, cp);
  gost94_a(vp, vp);
  gost94_a(vp, vp);
  gost94_x(kp, up, vp);
  gost94_p(kp, kp);
  gost94_e(tp + 16, kp);

  gost94_a(up, up);
  gost94_a(vp, vp);
  gost94_a(vp, vp);
  gost94_x(kp, up, vp);
  gost94_p(kp, kp);
  gost94_e(tp + 24, kp);

  for (i = 0; i < 12; i++)
    gost94_s(tp, tp);

  gost94_x(tp, tp, mp);
  gost94_s(tp, tp);
  gost94_x(sp, sp, tp);

  for (i = 0; i < 61; i++)
    gost94_s(sp, sp);
}

static void
gost94_sum(gost94_t *ctx, const uint8_t *mp) {
  unsigned int c = 0;
  int i;

  for (i = 0; i < 32; i++) {
    c += ctx->sigma[i] + mp[i];
    ctx->sigma[i] = c;
    c >>= 8;
  }
}

void
gost94_init(gost94_t *ctx) {
  memset(ctx, 0, sizeof(*ctx));
}

static void
gost94_transform(gost94_t *ctx, const unsigned char *chunk) {
  gost94_compress(ctx, chunk);
  gost94_sum(ctx, chunk);
}

void
gost94_update(gost94_t *ctx, const void *data, size_t len) {
  const unsigned char *raw = (const unsigned char *)data;
  size_t pos = ctx->size & 31;

  if (len == 0)
    return;

  ctx->size += len;

  if (pos > 0) {
    size_t want = 32 - pos;

    if (want > len)
      want = len;

    memcpy(ctx->block + pos, raw, want);

    pos += want;
    len -= want;
    raw += want;

    if (pos < 32)
      return;

    gost94_transform(ctx, ctx->block);
  }

  while (len >= 32) {
    gost94_transform(ctx, raw);
    raw += 32;
    len -= 32;
  }

  if (len > 0)
    memcpy(ctx->block, raw, len);
}

void
gost94_final(gost94_t *ctx, unsigned char *out) {
  uint64_t bits = ctx->size << 3;
  size_t pos = ctx->size & 31;
  unsigned char D[32];

  memset(D, 0x00, 32);

  if (pos != 0)
    gost94_update(ctx, D, 32 - pos);

  write64le(D, bits);

  gost94_compress(ctx, D);
  gost94_compress(ctx, ctx->sigma);

  memcpy(out, ctx->state, 32);
}

/*
 * Hash160
 *
 * Resources:
 *   https://github.com/bitcoin/bitcoin/blob/master/src/hash.h
 */

void
hash160_init(hash160_t *ctx) {
  sha256_init(ctx);
}

void
hash160_update(hash160_t *ctx, const void *data, size_t len) {
  sha256_update(ctx, data, len);
}

void
hash160_final(hash160_t *ctx, unsigned char *out) {
  unsigned char tmp[32];
  ripemd160_t rmd;

  sha256_final(ctx, tmp);

  ripemd160_init(&rmd);
  ripemd160_update(&rmd, tmp, 32);
  ripemd160_final(&rmd, out);

  torsion_cleanse(tmp, sizeof(tmp));
}

/*
 * Hash256
 *
 * Resources:
 *   https://github.com/bitcoin/bitcoin/blob/master/src/hash.h
 */

void
hash256_init(hash256_t *ctx) {
  sha256_init(ctx);
}

void
hash256_update(hash256_t *ctx, const void *data, size_t len) {
  sha256_update(ctx, data, len);
}

void
hash256_final(hash256_t *ctx, unsigned char *out) {
  sha256_final(ctx, out);
  sha256_init(ctx);
  sha256_update(ctx, out, 32);
  sha256_final(ctx, out);
}

/*
 * Keccak
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/SHA-3
 *   https://keccak.team/specifications.html
 *   https://csrc.nist.gov/projects/hash-functions/sha-3-project/sha-3-standardization
 *   http://dx.doi.org/10.6028/NIST.FIPS.202
 */

void
keccak_init(keccak_t *ctx, unsigned int bits) {
  unsigned int rate = 1600 - bits * 2;

  CHECK(bits >= 32);
  CHECK(bits <= 768);
  CHECK((rate & 63) == 0);

  ctx->bs = rate >> 3;
  ctx->pos = 0;
  ctx->std = (bits == 128
           || bits == 160
           || bits == 192
           || bits == 224
           || bits == 256
           || bits == 384
           || bits == 512);

  memset(ctx->state, 0, sizeof(ctx->state));
}

static void
keccak_compress(keccak_t *ctx) {
  static const uint64_t RC[24] = {
    UINT64_C(0x0000000000000001), UINT64_C(0x0000000000008082),
    UINT64_C(0x800000000000808a), UINT64_C(0x8000000080008000),
    UINT64_C(0x000000000000808b), UINT64_C(0x0000000080000001),
    UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008009),
    UINT64_C(0x000000000000008a), UINT64_C(0x0000000000000088),
    UINT64_C(0x0000000080008009), UINT64_C(0x000000008000000a),
    UINT64_C(0x000000008000808b), UINT64_C(0x800000000000008b),
    UINT64_C(0x8000000000008089), UINT64_C(0x8000000000008003),
    UINT64_C(0x8000000000008002), UINT64_C(0x8000000000000080),
    UINT64_C(0x000000000000800a), UINT64_C(0x800000008000000a),
    UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008080),
    UINT64_C(0x0000000080000001), UINT64_C(0x8000000080008008)
  };

  uint64_t C[5], D[5];
  int t;

#define A (ctx->state)

  for (t = 0; t < 24; t++) {
    /* Theta (Step 1) */
    C[0] = A[0] ^ A[5] ^ A[10] ^ A[15] ^ A[20];
    C[1] = A[1] ^ A[6] ^ A[11] ^ A[16] ^ A[21];
    C[2] = A[2] ^ A[7] ^ A[12] ^ A[17] ^ A[22];
    C[3] = A[3] ^ A[8] ^ A[13] ^ A[18] ^ A[23];
    C[4] = A[4] ^ A[9] ^ A[14] ^ A[19] ^ A[24];

    /* Theta (Step 2) */
    D[0] = C[4] ^ ROTL64(C[1], 1);
    D[1] = C[0] ^ ROTL64(C[2], 1);
    D[2] = C[1] ^ ROTL64(C[3], 1);
    D[3] = C[2] ^ ROTL64(C[4], 1);
    D[4] = C[3] ^ ROTL64(C[0], 1);

    /* Theta (Step 3) */
    A[ 0] ^= D[0];
    A[ 1] ^= D[1];
    A[ 2] ^= D[2];
    A[ 3] ^= D[3];
    A[ 4] ^= D[4];
    A[ 5] ^= D[0];
    A[ 6] ^= D[1];
    A[ 7] ^= D[2];
    A[ 8] ^= D[3];
    A[ 9] ^= D[4];
    A[10] ^= D[0];
    A[11] ^= D[1];
    A[12] ^= D[2];
    A[13] ^= D[3];
    A[14] ^= D[4];
    A[15] ^= D[0];
    A[16] ^= D[1];
    A[17] ^= D[2];
    A[18] ^= D[3];
    A[19] ^= D[4];
    A[20] ^= D[0];
    A[21] ^= D[1];
    A[22] ^= D[2];
    A[23] ^= D[3];
    A[24] ^= D[4];

    /* Rho */
    A[ 1] = ROTL64(A[ 1],  1);
    A[10] = ROTL64(A[10],  3);
    A[ 7] = ROTL64(A[ 7],  6);
    A[11] = ROTL64(A[11], 10);
    A[17] = ROTL64(A[17], 15);
    A[18] = ROTL64(A[18], 21);
    A[ 3] = ROTL64(A[ 3], 28);
    A[ 5] = ROTL64(A[ 5], 36);
    A[16] = ROTL64(A[16], 45);
    A[ 8] = ROTL64(A[ 8], 55);
    A[21] = ROTL64(A[21],  2);
    A[24] = ROTL64(A[24], 14);
    A[ 4] = ROTL64(A[ 4], 27);
    A[15] = ROTL64(A[15], 41);
    A[23] = ROTL64(A[23], 56);
    A[19] = ROTL64(A[19],  8);
    A[13] = ROTL64(A[13], 25);
    A[12] = ROTL64(A[12], 43);
    A[ 2] = ROTL64(A[ 2], 62);
    A[20] = ROTL64(A[20], 18);
    A[14] = ROTL64(A[14], 39);
    A[22] = ROTL64(A[22], 61);
    A[ 9] = ROTL64(A[ 9], 20);
    A[ 6] = ROTL64(A[ 6], 44);

    /* Pi */
    C[ 0] = A[ 1];
    A[ 1] = A[ 6];
    A[ 6] = A[ 9];
    A[ 9] = A[22];
    A[22] = A[14];
    A[14] = A[20];
    A[20] = A[ 2];
    A[ 2] = A[12];
    A[12] = A[13];
    A[13] = A[19];
    A[19] = A[23];
    A[23] = A[15];
    A[15] = A[ 4];
    A[ 4] = A[24];
    A[24] = A[21];
    A[21] = A[ 8];
    A[ 8] = A[16];
    A[16] = A[ 5];
    A[ 5] = A[ 3];
    A[ 3] = A[18];
    A[18] = A[17];
    A[17] = A[11];
    A[11] = A[ 7];
    A[ 7] = A[10];
    A[10] = C[ 0];

    /* Chi */
    C[0] = (~A[1] & A[2]);
    C[1] = (~A[2] & A[3]);
    C[2] = (~A[3] & A[4]);
    C[3] = (~A[4] & A[0]);
    C[4] = (~A[0] & A[1]);

    A[0] ^= C[0];
    A[1] ^= C[1];
    A[2] ^= C[2];
    A[3] ^= C[3];
    A[4] ^= C[4];

    C[0] = (~A[6] & A[7]);
    C[1] = (~A[7] & A[8]);
    C[2] = (~A[8] & A[9]);
    C[3] = (~A[9] & A[5]);
    C[4] = (~A[5] & A[6]);

    A[5] ^= C[0];
    A[6] ^= C[1];
    A[7] ^= C[2];
    A[8] ^= C[3];
    A[9] ^= C[4];

    C[0] = (~A[11] & A[12]);
    C[1] = (~A[12] & A[13]);
    C[2] = (~A[13] & A[14]);
    C[3] = (~A[14] & A[10]);
    C[4] = (~A[10] & A[11]);

    A[10] ^= C[0];
    A[11] ^= C[1];
    A[12] ^= C[2];
    A[13] ^= C[3];
    A[14] ^= C[4];

    C[0] = (~A[16] & A[17]);
    C[1] = (~A[17] & A[18]);
    C[2] = (~A[18] & A[19]);
    C[3] = (~A[19] & A[15]);
    C[4] = (~A[15] & A[16]);

    A[15] ^= C[0];
    A[16] ^= C[1];
    A[17] ^= C[2];
    A[18] ^= C[3];
    A[19] ^= C[4];

    C[0] = (~A[21] & A[22]);
    C[1] = (~A[22] & A[23]);
    C[2] = (~A[23] & A[24]);
    C[3] = (~A[24] & A[20]);
    C[4] = (~A[20] & A[21]);

    A[20] ^= C[0];
    A[21] ^= C[1];
    A[22] ^= C[2];
    A[23] ^= C[3];
    A[24] ^= C[4];

    /* Iota */
    A[0] ^= RC[t];
  }

#undef A
}

static TORSION_INLINE void
keccak_transform0(keccak_t *ctx, const unsigned char *chunk) {
  /* 512 (bs=72) */
  ctx->state[ 0] ^= read64le(chunk +   0);
  ctx->state[ 1] ^= read64le(chunk +   8);
  ctx->state[ 2] ^= read64le(chunk +  16);
  ctx->state[ 3] ^= read64le(chunk +  24);
  ctx->state[ 4] ^= read64le(chunk +  32);
  ctx->state[ 5] ^= read64le(chunk +  40);
  ctx->state[ 6] ^= read64le(chunk +  48);
  ctx->state[ 7] ^= read64le(chunk +  56);
  ctx->state[ 8] ^= read64le(chunk +  64);

  if (ctx->bs < 104)
    goto done;

  /* 384 (bs=104) */
  ctx->state[ 9] ^= read64le(chunk +  72);
  ctx->state[10] ^= read64le(chunk +  80);
  ctx->state[11] ^= read64le(chunk +  88);
  ctx->state[12] ^= read64le(chunk +  96);

  if (ctx->bs < 136)
    goto done;

  /* 256 (bs=136) */
  ctx->state[13] ^= read64le(chunk + 104);
  ctx->state[14] ^= read64le(chunk + 112);
  ctx->state[15] ^= read64le(chunk + 120);
  ctx->state[16] ^= read64le(chunk + 128);

  if (ctx->bs < 144)
    goto done;

  /* 224 (bs=144) */
  ctx->state[17] ^= read64le(chunk + 136);

  if (ctx->bs < 152)
    goto done;

  /* 192 (bs=152) */
  ctx->state[18] ^= read64le(chunk + 144);

  if (ctx->bs < 160)
    goto done;

  /* 160 (bs=160) */
  ctx->state[19] ^= read64le(chunk + 152);

  if (ctx->bs < 168)
    goto done;

  /* 128 (bs=168) */
  ctx->state[20] ^= read64le(chunk + 160);

done:
  keccak_compress(ctx);
}

static TORSION_INLINE void
keccak_transform1(keccak_t *ctx, const unsigned char *chunk) {
  size_t count = ctx->bs >> 3;
  size_t i;

  for (i = 0; i < count; i++)
    ctx->state[i] ^= read64le(chunk + i * 8);

  keccak_compress(ctx);
}

static void
keccak_transform(keccak_t *ctx, const unsigned char *chunk) {
  /* Use an unrolled loop for standard block sizes. */
  if (LIKELY(ctx->std))
    keccak_transform0(ctx, chunk);
  else
    keccak_transform1(ctx, chunk);
}

void
keccak_update(keccak_t *ctx, const void *data, size_t len) {
  const unsigned char *raw = (const unsigned char *)data;
  size_t pos = ctx->pos;

  if (len == 0)
    return;

  if (pos > 0) {
    size_t want = ctx->bs - pos;

    if (want > len)
      want = len;

    memcpy(ctx->block + pos, raw, want);

    pos += want;
    len -= want;
    raw += want;

    if (pos < ctx->bs) {
      ctx->pos = pos;
      return;
    }

    keccak_transform(ctx, ctx->block);
  }

  while (len >= ctx->bs) {
    keccak_transform(ctx, raw);
    raw += ctx->bs;
    len -= ctx->bs;
  }

  if (len > 0)
    memcpy(ctx->block, raw, len);

  ctx->pos = len;
}

void
keccak_final(keccak_t *ctx, unsigned char *out, unsigned int pad, size_t len) {
  size_t i, count;

  if (pad == 0)
    pad = 0x01;

  if (len == 0)
    len = 100 - (ctx->bs >> 1);

  CHECK(len <= 200);

  memset(ctx->block + ctx->pos, 0x00, ctx->bs - ctx->pos);

  ctx->block[ctx->pos] |= (pad & 0xff);
  ctx->block[ctx->bs - 1] |= 0x80;

  keccak_transform(ctx, ctx->block);

  count = len >> 3;

  for (i = 0; i < count; i++)
    write64le(out + i * 8, ctx->state[i]);

  for (i = count * 8; i < len; i++)
    out[i] = (ctx->state[i >> 3] >> (8 * (i & 7))) & 0xff;
}

/*
 * Keccak{224,256,384,512}
 */

#define DEFINE_KECCAK(name, bits, pad)                               \
void                                                                 \
torsion_##name##_init(sha3_t *ctx) {                                 \
  keccak_init(ctx, bits);                                            \
}                                                                    \
                                                                     \
void                                                                 \
torsion_##name##_update(sha3_t *ctx, const void *data, size_t len) { \
  keccak_update(ctx, data, len);                                     \
}                                                                    \
                                                                     \
void                                                                 \
torsion_##name##_final(sha3_t *ctx, unsigned char *out) {            \
  keccak_final(ctx, out, pad, 0);                                    \
}

DEFINE_KECCAK(keccak224, 224, 0x01)
DEFINE_KECCAK(keccak256, 256, 0x01)
DEFINE_KECCAK(keccak384, 384, 0x01)
DEFINE_KECCAK(keccak512, 512, 0x01)

/*
 * MD2
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/MD2_(hash_function)
 *   https://tools.ietf.org/html/rfc1319
 */

void
md2_init(md2_t *ctx) {
  memset(ctx, 0, sizeof(*ctx));
}

static void
md2_transform(md2_t *ctx, const unsigned char *chunk) {
  static const uint8_t K[256] = {
    0x29, 0x2e, 0x43, 0xc9, 0xa2, 0xd8, 0x7c, 0x01,
    0x3d, 0x36, 0x54, 0xa1, 0xec, 0xf0, 0x06, 0x13,
    0x62, 0xa7, 0x05, 0xf3, 0xc0, 0xc7, 0x73, 0x8c,
    0x98, 0x93, 0x2b, 0xd9, 0xbc, 0x4c, 0x82, 0xca,
    0x1e, 0x9b, 0x57, 0x3c, 0xfd, 0xd4, 0xe0, 0x16,
    0x67, 0x42, 0x6f, 0x18, 0x8a, 0x17, 0xe5, 0x12,
    0xbe, 0x4e, 0xc4, 0xd6, 0xda, 0x9e, 0xde, 0x49,
    0xa0, 0xfb, 0xf5, 0x8e, 0xbb, 0x2f, 0xee, 0x7a,
    0xa9, 0x68, 0x79, 0x91, 0x15, 0xb2, 0x07, 0x3f,
    0x94, 0xc2, 0x10, 0x89, 0x0b, 0x22, 0x5f, 0x21,
    0x80, 0x7f, 0x5d, 0x9a, 0x5a, 0x90, 0x32, 0x27,
    0x35, 0x3e, 0xcc, 0xe7, 0xbf, 0xf7, 0x97, 0x03,
    0xff, 0x19, 0x30, 0xb3, 0x48, 0xa5, 0xb5, 0xd1,
    0xd7, 0x5e, 0x92, 0x2a, 0xac, 0x56, 0xaa, 0xc6,
    0x4f, 0xb8, 0x38, 0xd2, 0x96, 0xa4, 0x7d, 0xb6,
    0x76, 0xfc, 0x6b, 0xe2, 0x9c, 0x74, 0x04, 0xf1,
    0x45, 0x9d, 0x70, 0x59, 0x64, 0x71, 0x87, 0x20,
    0x86, 0x5b, 0xcf, 0x65, 0xe6, 0x2d, 0xa8, 0x02,
    0x1b, 0x60, 0x25, 0xad, 0xae, 0xb0, 0xb9, 0xf6,
    0x1c, 0x46, 0x61, 0x69, 0x34, 0x40, 0x7e, 0x0f,
    0x55, 0x47, 0xa3, 0x23, 0xdd, 0x51, 0xaf, 0x3a,
    0xc3, 0x5c, 0xf9, 0xce, 0xba, 0xc5, 0xea, 0x26,
    0x2c, 0x53, 0x0d, 0x6e, 0x85, 0x28, 0x84, 0x09,
    0xd3, 0xdf, 0xcd, 0xf4, 0x41, 0x81, 0x4d, 0x52,
    0x6a, 0xdc, 0x37, 0xc8, 0x6c, 0xc1, 0xab, 0xfa,
    0x24, 0xe1, 0x7b, 0x08, 0x0c, 0xbd, 0xb1, 0x4a,
    0x78, 0x88, 0x95, 0x8b, 0xe3, 0x63, 0xe8, 0x6d,
    0xe9, 0xcb, 0xd5, 0xfe, 0x3b, 0x00, 0x1d, 0x39,
    0xf2, 0xef, 0xb7, 0x0e, 0x66, 0x58, 0xd0, 0xe4,
    0xa6, 0x77, 0x72, 0xf8, 0xeb, 0x75, 0x4b, 0x0a,
    0x31, 0x44, 0x50, 0xb4, 0x8f, 0xed, 0x1f, 0x1a,
    0xdb, 0x99, 0x8d, 0x33, 0x9f, 0x11, 0x83, 0x14
  };

  unsigned int l, j, c, t, k;

#define S (ctx->state)
#define C (ctx->checksum)
#define W ((uint8_t *)(chunk))

  /* The RFC doesn't describe the specifics
     of XOR'ing the checksum, but OpenSSL
     seems to do this. */
  l = C[15];

  for (j = 0; j < 16; j++) {
    c = W[j];
    l = C[j] ^ K[c ^ l];

    C[j] = l;

    S[16 + j] = c;
    S[32 + j] = c ^ S[j];
  }

  t = 0;

  for (j = 0; j < 18; j++) {
    for (k = 0; k < 48; k++) {
      t = S[k] ^ K[t];
      S[k] = t;
    }

    t = (t + j) & 0xff;
  }

#undef S
#undef C
#undef W
}

void
md2_update(md2_t *ctx, const void *data, size_t len) {
  const unsigned char *raw = (const unsigned char *)data;
  size_t pos = ctx->pos;

  if (len == 0)
    return;

  if (pos > 0) {
    size_t want = 16 - pos;

    if (want > len)
      want = len;

    memcpy(ctx->block + pos, raw, want);

    pos += want;
    len -= want;
    raw += want;

    if (pos < 16) {
      ctx->pos = pos;
      return;
    }

    md2_transform(ctx, ctx->block);
  }

  while (len >= 16) {
    md2_transform(ctx, raw);
    raw += 16;
    len -= 16;
  }

  if (len > 0)
    memcpy(ctx->block, raw, len);

  ctx->pos = len;
}

void
md2_final(md2_t *ctx, unsigned char *out) {
  size_t left = 16 - ctx->pos;
  unsigned char pad[16];
  size_t i;

  for (i = 0; i < left; i++)
    pad[i] = left;

  md2_update(ctx, pad, left);
  md2_update(ctx, ctx->checksum, 16);

  memcpy(out, ctx->state, 16);
}

/*
 * MD4
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/MD4
 *   https://tools.ietf.org/html/rfc1320
 */

void
md4_init(md4_t *ctx) {
  ctx->state[0] = 0x67452301;
  ctx->state[1] = 0xefcdab89;
  ctx->state[2] = 0x98badcfe;
  ctx->state[3] = 0x10325476;
  ctx->size = 0;
}

static void
md4_transform(md4_t *ctx, const unsigned char *chunk) {
  uint32_t A, B, C, D;
  uint32_t W[16];
  int i;

  for (i = 0; i < 16; i++)
    W[i] = read32le(chunk + i * 4);

  A = ctx->state[0];
  B = ctx->state[1];
  C = ctx->state[2];
  D = ctx->state[3];

#define K1 0x00000000
#define K2 0x5a827999
#define K3 0x6ed9eba1

#define F1(x, y, z) ((x & y) | (~x & z))          /* F */
#define F2(x, y, z) ((x & y) | (x & z) | (y & z)) /* G */
#define F3(x, y, z) (x ^ y ^ z)                   /* H */

/* Round: a = (a + F(b, c, d) + X[k] + [constant]) <<< s */
#define R(F, a, b, c, d, i, k, s) do { \
  a += F(b, c, d) + W[i] + k;          \
  a = ROTL32(a, s);                    \
} while (0)

  R(F1, A, B, C, D,  0, K1,  3);
  R(F1, D, A, B, C,  1, K1,  7);
  R(F1, C, D, A, B,  2, K1, 11);
  R(F1, B, C, D, A,  3, K1, 19);
  R(F1, A, B, C, D,  4, K1,  3);
  R(F1, D, A, B, C,  5, K1,  7);
  R(F1, C, D, A, B,  6, K1, 11);
  R(F1, B, C, D, A,  7, K1, 19);
  R(F1, A, B, C, D,  8, K1,  3);
  R(F1, D, A, B, C,  9, K1,  7);
  R(F1, C, D, A, B, 10, K1, 11);
  R(F1, B, C, D, A, 11, K1, 19);
  R(F1, A, B, C, D, 12, K1,  3);
  R(F1, D, A, B, C, 13, K1,  7);
  R(F1, C, D, A, B, 14, K1, 11);
  R(F1, B, C, D, A, 15, K1, 19);

  R(F2, A, B, C, D,  0, K2,  3);
  R(F2, D, A, B, C,  4, K2,  5);
  R(F2, C, D, A, B,  8, K2,  9);
  R(F2, B, C, D, A, 12, K2, 13);
  R(F2, A, B, C, D,  1, K2,  3);
  R(F2, D, A, B, C,  5, K2,  5);
  R(F2, C, D, A, B,  9, K2,  9);
  R(F2, B, C, D, A, 13, K2, 13);
  R(F2, A, B, C, D,  2, K2,  3);
  R(F2, D, A, B, C,  6, K2,  5);
  R(F2, C, D, A, B, 10, K2,  9);
  R(F2, B, C, D, A, 14, K2, 13);
  R(F2, A, B, C, D,  3, K2,  3);
  R(F2, D, A, B, C,  7, K2,  5);
  R(F2, C, D, A, B, 11, K2,  9);
  R(F2, B, C, D, A, 15, K2, 13);

  R(F3, A, B, C, D,  0, K3,  3);
  R(F3, D, A, B, C,  8, K3,  9);
  R(F3, C, D, A, B,  4, K3, 11);
  R(F3, B, C, D, A, 12, K3, 15);
  R(F3, A, B, C, D,  2, K3,  3);
  R(F3, D, A, B, C, 10, K3,  9);
  R(F3, C, D, A, B,  6, K3, 11);
  R(F3, B, C, D, A, 14, K3, 15);
  R(F3, A, B, C, D,  1, K3,  3);
  R(F3, D, A, B, C,  9, K3,  9);
  R(F3, C, D, A, B,  5, K3, 11);
  R(F3, B, C, D, A, 13, K3, 15);
  R(F3, A, B, C, D,  3, K3,  3);
  R(F3, D, A, B, C, 11, K3,  9);
  R(F3, C, D, A, B,  7, K3, 11);
  R(F3, B, C, D, A, 15, K3, 15);

#undef K1
#undef K2
#undef K3
#undef F1
#undef F2
#undef F3
#undef R

  ctx->state[0] += A;
  ctx->state[1] += B;
  ctx->state[2] += C;
  ctx->state[3] += D;
}

void
md4_update(md4_t *ctx, const void *data, size_t len) {
  const unsigned char *raw = (const unsigned char *)data;
  size_t pos = ctx->size & 63;

  if (len == 0)
    return;

  ctx->size += len;

  if (pos > 0) {
    size_t want = 64 - pos;

    if (want > len)
      want = len;

    memcpy(ctx->block + pos, raw, want);

    pos += want;
    len -= want;
    raw += want;

    if (pos < 64)
      return;

    md4_transform(ctx, ctx->block);
  }

  while (len >= 64) {
    md4_transform(ctx, raw);
    raw += 64;
    len -= 64;
  }

  if (len > 0)
    memcpy(ctx->block, raw, len);
}

void
md4_final(md4_t *ctx, unsigned char *out) {
  static const unsigned char P[64] = { 0x80, 0x00 };
  size_t pos = ctx->size & 63;
  unsigned char D[8];
  int i;

  write64le(D, ctx->size << 3);

  md4_update(ctx, P, 1 + ((119 - pos) & 63));
  md4_update(ctx, D, 8);

  for (i = 0; i < 4; i++)
    write32le(out + i * 4, ctx->state[i]);
}

/*
 * MD5
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/MD5
 *   https://tools.ietf.org/html/rfc1321
 */

void
md5_init(md5_t *ctx) {
  ctx->state[0] = 0x67452301;
  ctx->state[1] = 0xefcdab89;
  ctx->state[2] = 0x98badcfe;
  ctx->state[3] = 0x10325476;
  ctx->size = 0;
}

static void
md5_transform(md5_t *ctx, const unsigned char *chunk) {
  uint32_t A, B, C, D;
  uint32_t W[16];
  int i;

  for (i = 0; i < 16; i++)
    W[i] = read32le(chunk + i * 4);

  A = ctx->state[0];
  B = ctx->state[1];
  C = ctx->state[2];
  D = ctx->state[3];

#define F1(x, y, z) ((x & y) | (~x & z)) /* F */
#define F2(x, y, z) ((x & z) | (y & ~z)) /* G */
#define F3(x, y, z) (x ^ y ^ z)          /* H */
#define F4(x, y, z) (y ^ (x | ~z))       /* I */

/* Round: a = b + ((a + F(b, c, d) + X[k] + T[i]) <<< s) */
#define R(F, a, b, c, d, i, k, s) do { \
  a += F(b, c, d) + W[i] + k;          \
  a = b + ROTL32(a, s);                \
} while (0)

  R(F1, A, B, C, D,  0, 0xd76aa478,  7);
  R(F1, D, A, B, C,  1, 0xe8c7b756, 12);
  R(F1, C, D, A, B,  2, 0x242070db, 17);
  R(F1, B, C, D, A,  3, 0xc1bdceee, 22);
  R(F1, A, B, C, D,  4, 0xf57c0faf,  7);
  R(F1, D, A, B, C,  5, 0x4787c62a, 12);
  R(F1, C, D, A, B,  6, 0xa8304613, 17);
  R(F1, B, C, D, A,  7, 0xfd469501, 22);
  R(F1, A, B, C, D,  8, 0x698098d8,  7);
  R(F1, D, A, B, C,  9, 0x8b44f7af, 12);
  R(F1, C, D, A, B, 10, 0xffff5bb1, 17);
  R(F1, B, C, D, A, 11, 0x895cd7be, 22);
  R(F1, A, B, C, D, 12, 0x6b901122,  7);
  R(F1, D, A, B, C, 13, 0xfd987193, 12);
  R(F1, C, D, A, B, 14, 0xa679438e, 17);
  R(F1, B, C, D, A, 15, 0x49b40821, 22);

  R(F2, A, B, C, D,  1, 0xf61e2562,  5);
  R(F2, D, A, B, C,  6, 0xc040b340,  9);
  R(F2, C, D, A, B, 11, 0x265e5a51, 14);
  R(F2, B, C, D, A,  0, 0xe9b6c7aa, 20);
  R(F2, A, B, C, D,  5, 0xd62f105d,  5);
  R(F2, D, A, B, C, 10, 0x02441453,  9);
  R(F2, C, D, A, B, 15, 0xd8a1e681, 14);
  R(F2, B, C, D, A,  4, 0xe7d3fbc8, 20);
  R(F2, A, B, C, D,  9, 0x21e1cde6,  5);
  R(F2, D, A, B, C, 14, 0xc33707d6,  9);
  R(F2, C, D, A, B,  3, 0xf4d50d87, 14);
  R(F2, B, C, D, A,  8, 0x455a14ed, 20);
  R(F2, A, B, C, D, 13, 0xa9e3e905,  5);
  R(F2, D, A, B, C,  2, 0xfcefa3f8,  9);
  R(F2, C, D, A, B,  7, 0x676f02d9, 14);
  R(F2, B, C, D, A, 12, 0x8d2a4c8a, 20);

  R(F3, A, B, C, D,  5, 0xfffa3942,  4);
  R(F3, D, A, B, C,  8, 0x8771f681, 11);
  R(F3, C, D, A, B, 11, 0x6d9d6122, 16);
  R(F3, B, C, D, A, 14, 0xfde5380c, 23);
  R(F3, A, B, C, D,  1, 0xa4beea44,  4);
  R(F3, D, A, B, C,  4, 0x4bdecfa9, 11);
  R(F3, C, D, A, B,  7, 0xf6bb4b60, 16);
  R(F3, B, C, D, A, 10, 0xbebfbc70, 23);
  R(F3, A, B, C, D, 13, 0x289b7ec6,  4);
  R(F3, D, A, B, C,  0, 0xeaa127fa, 11);
  R(F3, C, D, A, B,  3, 0xd4ef3085, 16);
  R(F3, B, C, D, A,  6, 0x04881d05, 23);
  R(F3, A, B, C, D,  9, 0xd9d4d039,  4);
  R(F3, D, A, B, C, 12, 0xe6db99e5, 11);
  R(F3, C, D, A, B, 15, 0x1fa27cf8, 16);
  R(F3, B, C, D, A,  2, 0xc4ac5665, 23);

  R(F4, A, B, C, D,  0, 0xf4292244,  6);
  R(F4, D, A, B, C,  7, 0x432aff97, 10);
  R(F4, C, D, A, B, 14, 0xab9423a7, 15);
  R(F4, B, C, D, A,  5, 0xfc93a039, 21);
  R(F4, A, B, C, D, 12, 0x655b59c3,  6);
  R(F4, D, A, B, C,  3, 0x8f0ccc92, 10);
  R(F4, C, D, A, B, 10, 0xffeff47d, 15);
  R(F4, B, C, D, A,  1, 0x85845dd1, 21);
  R(F4, A, B, C, D,  8, 0x6fa87e4f,  6);
  R(F4, D, A, B, C, 15, 0xfe2ce6e0, 10);
  R(F4, C, D, A, B,  6, 0xa3014314, 15);
  R(F4, B, C, D, A, 13, 0x4e0811a1, 21);
  R(F4, A, B, C, D,  4, 0xf7537e82,  6);
  R(F4, D, A, B, C, 11, 0xbd3af235, 10);
  R(F4, C, D, A, B,  2, 0x2ad7d2bb, 15);
  R(F4, B, C, D, A,  9, 0xeb86d391, 21);

#undef F1
#undef F2
#undef F3
#undef F4
#undef R

  ctx->state[0] += A;
  ctx->state[1] += B;
  ctx->state[2] += C;
  ctx->state[3] += D;
}

void
md5_update(md5_t *ctx, const void *data, size_t len) {
  const unsigned char *raw = (const unsigned char *)data;
  size_t pos = ctx->size & 63;

  if (len == 0)
    return;

  ctx->size += len;

  if (pos > 0) {
    size_t want = 64 - pos;

    if (want > len)
      want = len;

    memcpy(ctx->block + pos, raw, want);

    pos += want;
    len -= want;
    raw += want;

    if (pos < 64)
      return;

    md5_transform(ctx, ctx->block);
  }

  while (len >= 64) {
    md5_transform(ctx, raw);
    raw += 64;
    len -= 64;
  }

  if (len > 0)
    memcpy(ctx->block, raw, len);
}

void
md5_final(md5_t *ctx, unsigned char *out) {
  static const unsigned char P[64] = { 0x80, 0x00 };
  size_t pos = ctx->size & 63;
  unsigned char D[8];
  int i;

  write64le(D, ctx->size << 3);

  md5_update(ctx, P, 1 + ((119 - pos) & 63));
  md5_update(ctx, D, 8);

  for (i = 0; i < 4; i++)
    write32le(out + i * 4, ctx->state[i]);
}

/*
 * MD5SHA1
 */

void
md5sha1_init(md5sha1_t *ctx) {
  md5_init(&ctx->md5);
  sha1_init(&ctx->sha1);
}

void
md5sha1_update(md5sha1_t *ctx, const void *data, size_t len) {
  md5_update(&ctx->md5, data, len);
  sha1_update(&ctx->sha1, data, len);
}

void
md5sha1_final(md5sha1_t *ctx, unsigned char *out) {
  md5_final(&ctx->md5, out);
  sha1_final(&ctx->sha1, out + 16);
}

/*
 * RIPEMD160
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/RIPEMD-160
 *   https://homes.esat.kuleuven.be/~bosselae/ripemd160/pdf/AB-9601/AB-9601.pdf
 */

void
ripemd160_init(ripemd160_t *ctx) {
  ctx->state[0] = 0x67452301;
  ctx->state[1] = 0xefcdab89;
  ctx->state[2] = 0x98badcfe;
  ctx->state[3] = 0x10325476;
  ctx->state[4] = 0xc3d2e1f0;
  ctx->size = 0;
}

static void
ripemd160_transform(ripemd160_t *ctx, const unsigned char *chunk) {
  uint32_t AH, BH, CH, DH, EH;
  uint32_t A, B, C, D, E, T;
  uint32_t W[16];
  int i;

  for (i = 0; i < 16; i++)
    W[i] = read32le(chunk + i * 4);

  A = ctx->state[0];
  B = ctx->state[1];
  C = ctx->state[2];
  D = ctx->state[3];
  E = ctx->state[4];

  AH = A;
  BH = B;
  CH = C;
  DH = D;
  EH = E;

#define K1 0x00000000
#define K2 0x5a827999
#define K3 0x6ed9eba1
#define K4 0x8f1bbcdc
#define K5 0xa953fd4e

#define KH1 0x50a28be6
#define KH2 0x5c4dd124
#define KH3 0x6d703ef3
#define KH4 0x7a6d76e9
#define KH5 0x00000000

#define F1(x, y, z) (x ^ y ^ z)
#define F2(x, y, z) ((x & y) | (~x & z))
#define F3(x, y, z) ((x | ~y) ^ z)
#define F4(x, y, z) ((x & z) | (y & ~z))
#define F5(x, y, z) (x ^ (y | ~z))

/* Operations in one step:
 *
 *   A = ((A + F(B, C, D) + X + K) <<< s) + E
 *   C = C <<< 10
 *
 * Loop body:
 *
 *   T = rol(A + F(j, B, C, D) + X[r(j)] + K(j), s[j]) + E
 *   A = E
 *   E = D
 *   D = rol(C, 10)
 *   C = B
 *   B = T
 */
#define R(F, a, b, c, d, e, i, k, s) do { \
  a += F(b, c, d) + W[i] + k;             \
  a = ROTL32(a, s) + e;                   \
  c = ROTL32(c, 10);                      \
} while (0)

  R(F1, A, B, C, D, E,  0, K1, 11);
  R(F1, E, A, B, C, D,  1, K1, 14);
  R(F1, D, E, A, B, C,  2, K1, 15);
  R(F1, C, D, E, A, B,  3, K1, 12);
  R(F1, B, C, D, E, A,  4, K1,  5);
  R(F1, A, B, C, D, E,  5, K1,  8);
  R(F1, E, A, B, C, D,  6, K1,  7);
  R(F1, D, E, A, B, C,  7, K1,  9);
  R(F1, C, D, E, A, B,  8, K1, 11);
  R(F1, B, C, D, E, A,  9, K1, 13);
  R(F1, A, B, C, D, E, 10, K1, 14);
  R(F1, E, A, B, C, D, 11, K1, 15);
  R(F1, D, E, A, B, C, 12, K1,  6);
  R(F1, C, D, E, A, B, 13, K1,  7);
  R(F1, B, C, D, E, A, 14, K1,  9);
  R(F1, A, B, C, D, E, 15, K1,  8);
  R(F2, E, A, B, C, D,  7, K2,  7);
  R(F2, D, E, A, B, C,  4, K2,  6);
  R(F2, C, D, E, A, B, 13, K2,  8);
  R(F2, B, C, D, E, A,  1, K2, 13);
  R(F2, A, B, C, D, E, 10, K2, 11);
  R(F2, E, A, B, C, D,  6, K2,  9);
  R(F2, D, E, A, B, C, 15, K2,  7);
  R(F2, C, D, E, A, B,  3, K2, 15);
  R(F2, B, C, D, E, A, 12, K2,  7);
  R(F2, A, B, C, D, E,  0, K2, 12);
  R(F2, E, A, B, C, D,  9, K2, 15);
  R(F2, D, E, A, B, C,  5, K2,  9);
  R(F2, C, D, E, A, B,  2, K2, 11);
  R(F2, B, C, D, E, A, 14, K2,  7);
  R(F2, A, B, C, D, E, 11, K2, 13);
  R(F2, E, A, B, C, D,  8, K2, 12);
  R(F3, D, E, A, B, C,  3, K3, 11);
  R(F3, C, D, E, A, B, 10, K3, 13);
  R(F3, B, C, D, E, A, 14, K3,  6);
  R(F3, A, B, C, D, E,  4, K3,  7);
  R(F3, E, A, B, C, D,  9, K3, 14);
  R(F3, D, E, A, B, C, 15, K3,  9);
  R(F3, C, D, E, A, B,  8, K3, 13);
  R(F3, B, C, D, E, A,  1, K3, 15);
  R(F3, A, B, C, D, E,  2, K3, 14);
  R(F3, E, A, B, C, D,  7, K3,  8);
  R(F3, D, E, A, B, C,  0, K3, 13);
  R(F3, C, D, E, A, B,  6, K3,  6);
  R(F3, B, C, D, E, A, 13, K3,  5);
  R(F3, A, B, C, D, E, 11, K3, 12);
  R(F3, E, A, B, C, D,  5, K3,  7);
  R(F3, D, E, A, B, C, 12, K3,  5);
  R(F4, C, D, E, A, B,  1, K4, 11);
  R(F4, B, C, D, E, A,  9, K4, 12);
  R(F4, A, B, C, D, E, 11, K4, 14);
  R(F4, E, A, B, C, D, 10, K4, 15);
  R(F4, D, E, A, B, C,  0, K4, 14);
  R(F4, C, D, E, A, B,  8, K4, 15);
  R(F4, B, C, D, E, A, 12, K4,  9);
  R(F4, A, B, C, D, E,  4, K4,  8);
  R(F4, E, A, B, C, D, 13, K4,  9);
  R(F4, D, E, A, B, C,  3, K4, 14);
  R(F4, C, D, E, A, B,  7, K4,  5);
  R(F4, B, C, D, E, A, 15, K4,  6);
  R(F4, A, B, C, D, E, 14, K4,  8);
  R(F4, E, A, B, C, D,  5, K4,  6);
  R(F4, D, E, A, B, C,  6, K4,  5);
  R(F4, C, D, E, A, B,  2, K4, 12);
  R(F5, B, C, D, E, A,  4, K5,  9);
  R(F5, A, B, C, D, E,  0, K5, 15);
  R(F5, E, A, B, C, D,  5, K5,  5);
  R(F5, D, E, A, B, C,  9, K5, 11);
  R(F5, C, D, E, A, B,  7, K5,  6);
  R(F5, B, C, D, E, A, 12, K5,  8);
  R(F5, A, B, C, D, E,  2, K5, 13);
  R(F5, E, A, B, C, D, 10, K5, 12);
  R(F5, D, E, A, B, C, 14, K5,  5);
  R(F5, C, D, E, A, B,  1, K5, 12);
  R(F5, B, C, D, E, A,  3, K5, 13);
  R(F5, A, B, C, D, E,  8, K5, 14);
  R(F5, E, A, B, C, D, 11, K5, 11);
  R(F5, D, E, A, B, C,  6, K5,  8);
  R(F5, C, D, E, A, B, 15, K5,  5);
  R(F5, B, C, D, E, A, 13, K5,  6);

  R(F5, AH, BH, CH, DH, EH,  5, KH1,  8);
  R(F5, EH, AH, BH, CH, DH, 14, KH1,  9);
  R(F5, DH, EH, AH, BH, CH,  7, KH1,  9);
  R(F5, CH, DH, EH, AH, BH,  0, KH1, 11);
  R(F5, BH, CH, DH, EH, AH,  9, KH1, 13);
  R(F5, AH, BH, CH, DH, EH,  2, KH1, 15);
  R(F5, EH, AH, BH, CH, DH, 11, KH1, 15);
  R(F5, DH, EH, AH, BH, CH,  4, KH1,  5);
  R(F5, CH, DH, EH, AH, BH, 13, KH1,  7);
  R(F5, BH, CH, DH, EH, AH,  6, KH1,  7);
  R(F5, AH, BH, CH, DH, EH, 15, KH1,  8);
  R(F5, EH, AH, BH, CH, DH,  8, KH1, 11);
  R(F5, DH, EH, AH, BH, CH,  1, KH1, 14);
  R(F5, CH, DH, EH, AH, BH, 10, KH1, 14);
  R(F5, BH, CH, DH, EH, AH,  3, KH1, 12);
  R(F5, AH, BH, CH, DH, EH, 12, KH1,  6);
  R(F4, EH, AH, BH, CH, DH,  6, KH2,  9);
  R(F4, DH, EH, AH, BH, CH, 11, KH2, 13);
  R(F4, CH, DH, EH, AH, BH,  3, KH2, 15);
  R(F4, BH, CH, DH, EH, AH,  7, KH2,  7);
  R(F4, AH, BH, CH, DH, EH,  0, KH2, 12);
  R(F4, EH, AH, BH, CH, DH, 13, KH2,  8);
  R(F4, DH, EH, AH, BH, CH,  5, KH2,  9);
  R(F4, CH, DH, EH, AH, BH, 10, KH2, 11);
  R(F4, BH, CH, DH, EH, AH, 14, KH2,  7);
  R(F4, AH, BH, CH, DH, EH, 15, KH2,  7);
  R(F4, EH, AH, BH, CH, DH,  8, KH2, 12);
  R(F4, DH, EH, AH, BH, CH, 12, KH2,  7);
  R(F4, CH, DH, EH, AH, BH,  4, KH2,  6);
  R(F4, BH, CH, DH, EH, AH,  9, KH2, 15);
  R(F4, AH, BH, CH, DH, EH,  1, KH2, 13);
  R(F4, EH, AH, BH, CH, DH,  2, KH2, 11);
  R(F3, DH, EH, AH, BH, CH, 15, KH3,  9);
  R(F3, CH, DH, EH, AH, BH,  5, KH3,  7);
  R(F3, BH, CH, DH, EH, AH,  1, KH3, 15);
  R(F3, AH, BH, CH, DH, EH,  3, KH3, 11);
  R(F3, EH, AH, BH, CH, DH,  7, KH3,  8);
  R(F3, DH, EH, AH, BH, CH, 14, KH3,  6);
  R(F3, CH, DH, EH, AH, BH,  6, KH3,  6);
  R(F3, BH, CH, DH, EH, AH,  9, KH3, 14);
  R(F3, AH, BH, CH, DH, EH, 11, KH3, 12);
  R(F3, EH, AH, BH, CH, DH,  8, KH3, 13);
  R(F3, DH, EH, AH, BH, CH, 12, KH3,  5);
  R(F3, CH, DH, EH, AH, BH,  2, KH3, 14);
  R(F3, BH, CH, DH, EH, AH, 10, KH3, 13);
  R(F3, AH, BH, CH, DH, EH,  0, KH3, 13);
  R(F3, EH, AH, BH, CH, DH,  4, KH3,  7);
  R(F3, DH, EH, AH, BH, CH, 13, KH3,  5);
  R(F2, CH, DH, EH, AH, BH,  8, KH4, 15);
  R(F2, BH, CH, DH, EH, AH,  6, KH4,  5);
  R(F2, AH, BH, CH, DH, EH,  4, KH4,  8);
  R(F2, EH, AH, BH, CH, DH,  1, KH4, 11);
  R(F2, DH, EH, AH, BH, CH,  3, KH4, 14);
  R(F2, CH, DH, EH, AH, BH, 11, KH4, 14);
  R(F2, BH, CH, DH, EH, AH, 15, KH4,  6);
  R(F2, AH, BH, CH, DH, EH,  0, KH4, 14);
  R(F2, EH, AH, BH, CH, DH,  5, KH4,  6);
  R(F2, DH, EH, AH, BH, CH, 12, KH4,  9);
  R(F2, CH, DH, EH, AH, BH,  2, KH4, 12);
  R(F2, BH, CH, DH, EH, AH, 13, KH4,  9);
  R(F2, AH, BH, CH, DH, EH,  9, KH4, 12);
  R(F2, EH, AH, BH, CH, DH,  7, KH4,  5);
  R(F2, DH, EH, AH, BH, CH, 10, KH4, 15);
  R(F2, CH, DH, EH, AH, BH, 14, KH4,  8);
  R(F1, BH, CH, DH, EH, AH, 12, KH5,  8);
  R(F1, AH, BH, CH, DH, EH, 15, KH5,  5);
  R(F1, EH, AH, BH, CH, DH, 10, KH5, 12);
  R(F1, DH, EH, AH, BH, CH,  4, KH5,  9);
  R(F1, CH, DH, EH, AH, BH,  1, KH5, 12);
  R(F1, BH, CH, DH, EH, AH,  5, KH5,  5);
  R(F1, AH, BH, CH, DH, EH,  8, KH5, 14);
  R(F1, EH, AH, BH, CH, DH,  7, KH5,  6);
  R(F1, DH, EH, AH, BH, CH,  6, KH5,  8);
  R(F1, CH, DH, EH, AH, BH,  2, KH5, 13);
  R(F1, BH, CH, DH, EH, AH, 13, KH5,  6);
  R(F1, AH, BH, CH, DH, EH, 14, KH5,  5);
  R(F1, EH, AH, BH, CH, DH,  0, KH5, 15);
  R(F1, DH, EH, AH, BH, CH,  3, KH5, 13);
  R(F1, CH, DH, EH, AH, BH,  9, KH5, 11);
  R(F1, BH, CH, DH, EH, AH, 11, KH5, 11);

#undef K1
#undef K2
#undef K3
#undef K4
#undef K5
#undef KH1
#undef KH2
#undef KH3
#undef KH4
#undef KH5
#undef F1
#undef F2
#undef F3
#undef F4
#undef F5
#undef R

  T = ctx->state[1] + C + DH;

  ctx->state[1] = ctx->state[2] + D + EH;
  ctx->state[2] = ctx->state[3] + E + AH;
  ctx->state[3] = ctx->state[4] + A + BH;
  ctx->state[4] = ctx->state[0] + B + CH;
  ctx->state[0] = T;
}

void
ripemd160_update(ripemd160_t *ctx, const void *data, size_t len) {
  const unsigned char *raw = (const unsigned char *)data;
  size_t pos = ctx->size & 63;

  if (len == 0)
    return;

  ctx->size += len;

  if (pos > 0) {
    size_t want = 64 - pos;

    if (want > len)
      want = len;

    memcpy(ctx->block + pos, raw, want);

    pos += want;
    len -= want;
    raw += want;

    if (pos < 64)
      return;

    ripemd160_transform(ctx, ctx->block);
  }

  while (len >= 64) {
    ripemd160_transform(ctx, raw);
    raw += 64;
    len -= 64;
  }

  if (len > 0)
    memcpy(ctx->block, raw, len);
}

void
ripemd160_final(ripemd160_t *ctx, unsigned char *out) {
  static const unsigned char P[64] = { 0x80, 0x00 };
  size_t pos = ctx->size & 63;
  unsigned char D[8];
  int i;

  write64le(D, ctx->size << 3);

  ripemd160_update(ctx, P, 1 + ((119 - pos) & 63));
  ripemd160_update(ctx, D, 8);

  for (i = 0; i < 5; i++)
    write32le(out + i * 4, ctx->state[i]);
}

/*
 * SHA1
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/SHA-1
 *   https://tools.ietf.org/html/rfc3174
 *   http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf
 */

void
sha1_init(sha1_t *ctx) {
  ctx->state[0] = 0x67452301;
  ctx->state[1] = 0xefcdab89;
  ctx->state[2] = 0x98badcfe;
  ctx->state[3] = 0x10325476;
  ctx->state[4] = 0xc3d2e1f0;
  ctx->size = 0;
}

static void
sha1_transform(sha1_t *ctx, const unsigned char *chunk) {
  uint32_t A = ctx->state[0];
  uint32_t B = ctx->state[1];
  uint32_t C = ctx->state[2];
  uint32_t D = ctx->state[3];
  uint32_t E = ctx->state[4];
  uint32_t W[16];
  uint32_t w;

#define K1 0x5a827999
#define K2 0x6ed9eba1
#define K3 0x8f1bbcdc
#define K4 0xca62c1d6

/* Note: F1 is Ch, and F3 is Maj. We can utilize the
 * trick from the SHA-2 RFC C code to optimize them.
 *
 * Original:
 *
 *   #define F1(x, y, z) ((x & y) ^ (~x & z))
 *   #define F3(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
 */
#define F1(x, y, z) ((x & (y ^ z)) ^ z)
#define F2(x, y, z) (x ^ y ^ z)
#define F3(x, y, z) ((x & (y | z)) | (y & z))
#define F4(x, y, z) (x ^ y ^ z)

/* Modulo by 16 to avoid allocating a large array. */
/* This trick is mentioned in the above RFC. */
#define WORD(i) (W[(i -  3) & 15] ^ W[(i -  8) & 15] \
               ^ W[(i - 14) & 15] ^ W[(i - 16) & 15])

/* Loop body:
 *
 *   T = S^5(A) + F(B, C, D) + E + W(t) + K(t)
 *   E = D
 *   D = C
 *   C = S^30(B)
 *   B = A
 *   A = T
 *
 * Reduces to:
 *
 *   T = S^5(A) + F(B, C, D) + E + W(t) + K(t)
 *   E = T
 *   B = S^30(B)
 *
 * Which further reduces to:
 *
 *   E = E + S^5(A) + F(B, C, D) + W(t) + K(t)
 *   B = S^30(B)
 */
#define R(F, a, b, c, d, e, i, k) do {    \
  if (i < 16) { /* Optimized out. */      \
    w = read32be(chunk + i * 4);          \
  } else {                                \
    w = WORD(i);                          \
    w = ROTL32(w, 1);                     \
  }                                       \
                                          \
  W[i & 15] = w;                          \
                                          \
  e += ROTL32(a, 5) + F(b, c, d) + w + k; \
  b = ROTL32(b, 30);                      \
} while (0)

  R(F1, A, B, C, D, E,  0, K1);
  R(F1, E, A, B, C, D,  1, K1);
  R(F1, D, E, A, B, C,  2, K1);
  R(F1, C, D, E, A, B,  3, K1);
  R(F1, B, C, D, E, A,  4, K1);
  R(F1, A, B, C, D, E,  5, K1);
  R(F1, E, A, B, C, D,  6, K1);
  R(F1, D, E, A, B, C,  7, K1);
  R(F1, C, D, E, A, B,  8, K1);
  R(F1, B, C, D, E, A,  9, K1);
  R(F1, A, B, C, D, E, 10, K1);
  R(F1, E, A, B, C, D, 11, K1);
  R(F1, D, E, A, B, C, 12, K1);
  R(F1, C, D, E, A, B, 13, K1);
  R(F1, B, C, D, E, A, 14, K1);
  R(F1, A, B, C, D, E, 15, K1);
  R(F1, E, A, B, C, D, 16, K1);
  R(F1, D, E, A, B, C, 17, K1);
  R(F1, C, D, E, A, B, 18, K1);
  R(F1, B, C, D, E, A, 19, K1);

  R(F2, A, B, C, D, E, 20, K2);
  R(F2, E, A, B, C, D, 21, K2);
  R(F2, D, E, A, B, C, 22, K2);
  R(F2, C, D, E, A, B, 23, K2);
  R(F2, B, C, D, E, A, 24, K2);
  R(F2, A, B, C, D, E, 25, K2);
  R(F2, E, A, B, C, D, 26, K2);
  R(F2, D, E, A, B, C, 27, K2);
  R(F2, C, D, E, A, B, 28, K2);
  R(F2, B, C, D, E, A, 29, K2);
  R(F2, A, B, C, D, E, 30, K2);
  R(F2, E, A, B, C, D, 31, K2);
  R(F2, D, E, A, B, C, 32, K2);
  R(F2, C, D, E, A, B, 33, K2);
  R(F2, B, C, D, E, A, 34, K2);
  R(F2, A, B, C, D, E, 35, K2);
  R(F2, E, A, B, C, D, 36, K2);
  R(F2, D, E, A, B, C, 37, K2);
  R(F2, C, D, E, A, B, 38, K2);
  R(F2, B, C, D, E, A, 39, K2);

  R(F3, A, B, C, D, E, 40, K3);
  R(F3, E, A, B, C, D, 41, K3);
  R(F3, D, E, A, B, C, 42, K3);
  R(F3, C, D, E, A, B, 43, K3);
  R(F3, B, C, D, E, A, 44, K3);
  R(F3, A, B, C, D, E, 45, K3);
  R(F3, E, A, B, C, D, 46, K3);
  R(F3, D, E, A, B, C, 47, K3);
  R(F3, C, D, E, A, B, 48, K3);
  R(F3, B, C, D, E, A, 49, K3);
  R(F3, A, B, C, D, E, 50, K3);
  R(F3, E, A, B, C, D, 51, K3);
  R(F3, D, E, A, B, C, 52, K3);
  R(F3, C, D, E, A, B, 53, K3);
  R(F3, B, C, D, E, A, 54, K3);
  R(F3, A, B, C, D, E, 55, K3);
  R(F3, E, A, B, C, D, 56, K3);
  R(F3, D, E, A, B, C, 57, K3);
  R(F3, C, D, E, A, B, 58, K3);
  R(F3, B, C, D, E, A, 59, K3);

  R(F4, A, B, C, D, E, 60, K4);
  R(F4, E, A, B, C, D, 61, K4);
  R(F4, D, E, A, B, C, 62, K4);
  R(F4, C, D, E, A, B, 63, K4);
  R(F4, B, C, D, E, A, 64, K4);
  R(F4, A, B, C, D, E, 65, K4);
  R(F4, E, A, B, C, D, 66, K4);
  R(F4, D, E, A, B, C, 67, K4);
  R(F4, C, D, E, A, B, 68, K4);
  R(F4, B, C, D, E, A, 69, K4);
  R(F4, A, B, C, D, E, 70, K4);
  R(F4, E, A, B, C, D, 71, K4);
  R(F4, D, E, A, B, C, 72, K4);
  R(F4, C, D, E, A, B, 73, K4);
  R(F4, B, C, D, E, A, 74, K4);
  R(F4, A, B, C, D, E, 75, K4);
  R(F4, E, A, B, C, D, 76, K4);
  R(F4, D, E, A, B, C, 77, K4);
  R(F4, C, D, E, A, B, 78, K4);
  R(F4, B, C, D, E, A, 79, K4);

#undef K1
#undef K2
#undef K3
#undef K4
#undef F1
#undef F2
#undef F3
#undef F4
#undef WORD
#undef R

  ctx->state[0] += A;
  ctx->state[1] += B;
  ctx->state[2] += C;
  ctx->state[3] += D;
  ctx->state[4] += E;
}

void
sha1_update(sha1_t *ctx, const void *data, size_t len) {
  const unsigned char *raw = (const unsigned char *)data;
  size_t pos = ctx->size & 63;

  if (len == 0)
    return;

  ctx->size += len;

  if (pos > 0) {
    size_t want = 64 - pos;

    if (want > len)
      want = len;

    memcpy(ctx->block + pos, raw, want);

    pos += want;
    len -= want;
    raw += want;

    if (pos < 64)
      return;

    sha1_transform(ctx, ctx->block);
  }

  while (len >= 64) {
    sha1_transform(ctx, raw);
    raw += 64;
    len -= 64;
  }

  if (len > 0)
    memcpy(ctx->block, raw, len);
}

void
sha1_final(sha1_t *ctx, unsigned char *out) {
  static const unsigned char P[64] = { 0x80, 0x00 };
  size_t pos = ctx->size & 63;
  unsigned char D[8];
  int i;

  write64be(D, ctx->size << 3);

  sha1_update(ctx, P, 1 + ((119 - pos) & 63));
  sha1_update(ctx, D, 8);

  for (i = 0; i < 5; i++)
    write32be(out + i * 4, ctx->state[i]);
}

/*
 * SHA224
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/SHA-2
 *   https://tools.ietf.org/html/rfc4634
 */

void
sha224_init(sha224_t *ctx) {
  ctx->state[0] = 0xc1059ed8;
  ctx->state[1] = 0x367cd507;
  ctx->state[2] = 0x3070dd17;
  ctx->state[3] = 0xf70e5939;
  ctx->state[4] = 0xffc00b31;
  ctx->state[5] = 0x68581511;
  ctx->state[6] = 0x64f98fa7;
  ctx->state[7] = 0xbefa4fa4;
  ctx->size = 0;
}

void
sha224_update(sha224_t *ctx, const void *data, size_t len) {
  sha256_update(ctx, data, len);
}

void
sha224_final(sha224_t *ctx, unsigned char *out) {
  unsigned char tmp[32];

  sha256_final(ctx, tmp);

  memcpy(out, tmp, 28);

  torsion_cleanse(tmp, sizeof(tmp));
}

/*
 * SHA256
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/SHA-2
 *   https://tools.ietf.org/html/rfc4634
 */

void
sha256_init(sha256_t *ctx) {
  ctx->state[0] = 0x6a09e667;
  ctx->state[1] = 0xbb67ae85;
  ctx->state[2] = 0x3c6ef372;
  ctx->state[3] = 0xa54ff53a;
  ctx->state[4] = 0x510e527f;
  ctx->state[5] = 0x9b05688c;
  ctx->state[6] = 0x1f83d9ab;
  ctx->state[7] = 0x5be0cd19;
  ctx->size = 0;
}

static void
sha256_transform(sha256_t *ctx, const unsigned char *chunk) {
  uint32_t A = ctx->state[0];
  uint32_t B = ctx->state[1];
  uint32_t C = ctx->state[2];
  uint32_t D = ctx->state[3];
  uint32_t E = ctx->state[4];
  uint32_t F = ctx->state[5];
  uint32_t G = ctx->state[6];
  uint32_t H = ctx->state[7];
  uint32_t W[16];
  uint32_t w;

/* Note: the code in the RFC points out that Ch and Maj
 * can be optimized to use less bitwise ops.
 *
 * Original:
 *
 *   #define Ch(x, y, z) ((x & y) ^ (~x & z))
 *   #define Maj(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
 */
#define Ch(x, y, z) ((x & (y ^ z)) ^ z)
#define Maj(x, y, z) ((x & (y | z)) | (y & z))
#define Sigma0(x) (ROTR32(x,  2) ^ ROTR32(x, 13) ^ ROTR32(x, 22))
#define Sigma1(x) (ROTR32(x,  6) ^ ROTR32(x, 11) ^ ROTR32(x, 25))
#define sigma0(x) (ROTR32(x,  7) ^ ROTR32(x, 18) ^ (x >>  3))
#define sigma1(x) (ROTR32(x, 17) ^ ROTR32(x, 19) ^ (x >> 10))

/* Modulo by 16 to avoid allocating a large array. */
/* This trick is mentioned by the SHA1 RFC. */
#define WORD(i) (sigma1(W[(i -  2) & 15]) + W[(i -  7) & 15]  \
               + sigma0(W[(i - 15) & 15]) + W[(i - 16) & 15])

/* Loop body:
 *
 *   T1 = h + Sigma1(e) + Ch(e, f, g) + Kt + Wt
 *   T2 = Sigma0(a) + Maj(a, b, c)
 *   h = g
 *   g = f
 *   f = e
 *   e = d + T1
 *   d = c
 *   c = b
 *   b = a
 *   a = T1 + T2
 *
 * Reduces to:
 *
 *   T1 = h + Sigma1(e) + Ch(e, f, g) + Kt + Wt
 *   T2 = Sigma0(a) + Maj(a, b, c)
 *   d = d + T1
 *   h = T1 + T2
 *
 * Which further reduces to:
 *
 *   h = h + Sigma1(e) + Ch(e, f, g) + Kt + Wt
 *   d = d + h
 *   h = h + Sigma0(a) + Maj(a, b, c)
 */
#define R(a, b, c, d, e, f, g, h, i, k) do { \
  if (i < 16) /* Optimized out. */           \
    w = read32be(chunk + i * 4);             \
  else                                       \
    w = WORD(i);                             \
                                             \
  W[i & 15] = w;                             \
                                             \
  h += Sigma1(e) + Ch(e, f, g) + k + w;      \
  d += h;                                    \
  h += Sigma0(a) + Maj(a, b, c);             \
} while (0)

  R(A, B, C, D, E, F, G, H,  0, 0x428a2f98);
  R(H, A, B, C, D, E, F, G,  1, 0x71374491);
  R(G, H, A, B, C, D, E, F,  2, 0xb5c0fbcf);
  R(F, G, H, A, B, C, D, E,  3, 0xe9b5dba5);
  R(E, F, G, H, A, B, C, D,  4, 0x3956c25b);
  R(D, E, F, G, H, A, B, C,  5, 0x59f111f1);
  R(C, D, E, F, G, H, A, B,  6, 0x923f82a4);
  R(B, C, D, E, F, G, H, A,  7, 0xab1c5ed5);
  R(A, B, C, D, E, F, G, H,  8, 0xd807aa98);
  R(H, A, B, C, D, E, F, G,  9, 0x12835b01);
  R(G, H, A, B, C, D, E, F, 10, 0x243185be);
  R(F, G, H, A, B, C, D, E, 11, 0x550c7dc3);
  R(E, F, G, H, A, B, C, D, 12, 0x72be5d74);
  R(D, E, F, G, H, A, B, C, 13, 0x80deb1fe);
  R(C, D, E, F, G, H, A, B, 14, 0x9bdc06a7);
  R(B, C, D, E, F, G, H, A, 15, 0xc19bf174);
  R(A, B, C, D, E, F, G, H, 16, 0xe49b69c1);
  R(H, A, B, C, D, E, F, G, 17, 0xefbe4786);
  R(G, H, A, B, C, D, E, F, 18, 0x0fc19dc6);
  R(F, G, H, A, B, C, D, E, 19, 0x240ca1cc);
  R(E, F, G, H, A, B, C, D, 20, 0x2de92c6f);
  R(D, E, F, G, H, A, B, C, 21, 0x4a7484aa);
  R(C, D, E, F, G, H, A, B, 22, 0x5cb0a9dc);
  R(B, C, D, E, F, G, H, A, 23, 0x76f988da);
  R(A, B, C, D, E, F, G, H, 24, 0x983e5152);
  R(H, A, B, C, D, E, F, G, 25, 0xa831c66d);
  R(G, H, A, B, C, D, E, F, 26, 0xb00327c8);
  R(F, G, H, A, B, C, D, E, 27, 0xbf597fc7);
  R(E, F, G, H, A, B, C, D, 28, 0xc6e00bf3);
  R(D, E, F, G, H, A, B, C, 29, 0xd5a79147);
  R(C, D, E, F, G, H, A, B, 30, 0x06ca6351);
  R(B, C, D, E, F, G, H, A, 31, 0x14292967);
  R(A, B, C, D, E, F, G, H, 32, 0x27b70a85);
  R(H, A, B, C, D, E, F, G, 33, 0x2e1b2138);
  R(G, H, A, B, C, D, E, F, 34, 0x4d2c6dfc);
  R(F, G, H, A, B, C, D, E, 35, 0x53380d13);
  R(E, F, G, H, A, B, C, D, 36, 0x650a7354);
  R(D, E, F, G, H, A, B, C, 37, 0x766a0abb);
  R(C, D, E, F, G, H, A, B, 38, 0x81c2c92e);
  R(B, C, D, E, F, G, H, A, 39, 0x92722c85);
  R(A, B, C, D, E, F, G, H, 40, 0xa2bfe8a1);
  R(H, A, B, C, D, E, F, G, 41, 0xa81a664b);
  R(G, H, A, B, C, D, E, F, 42, 0xc24b8b70);
  R(F, G, H, A, B, C, D, E, 43, 0xc76c51a3);
  R(E, F, G, H, A, B, C, D, 44, 0xd192e819);
  R(D, E, F, G, H, A, B, C, 45, 0xd6990624);
  R(C, D, E, F, G, H, A, B, 46, 0xf40e3585);
  R(B, C, D, E, F, G, H, A, 47, 0x106aa070);
  R(A, B, C, D, E, F, G, H, 48, 0x19a4c116);
  R(H, A, B, C, D, E, F, G, 49, 0x1e376c08);
  R(G, H, A, B, C, D, E, F, 50, 0x2748774c);
  R(F, G, H, A, B, C, D, E, 51, 0x34b0bcb5);
  R(E, F, G, H, A, B, C, D, 52, 0x391c0cb3);
  R(D, E, F, G, H, A, B, C, 53, 0x4ed8aa4a);
  R(C, D, E, F, G, H, A, B, 54, 0x5b9cca4f);
  R(B, C, D, E, F, G, H, A, 55, 0x682e6ff3);
  R(A, B, C, D, E, F, G, H, 56, 0x748f82ee);
  R(H, A, B, C, D, E, F, G, 57, 0x78a5636f);
  R(G, H, A, B, C, D, E, F, 58, 0x84c87814);
  R(F, G, H, A, B, C, D, E, 59, 0x8cc70208);
  R(E, F, G, H, A, B, C, D, 60, 0x90befffa);
  R(D, E, F, G, H, A, B, C, 61, 0xa4506ceb);
  R(C, D, E, F, G, H, A, B, 62, 0xbef9a3f7);
  R(B, C, D, E, F, G, H, A, 63, 0xc67178f2);

#undef Ch
#undef Maj
#undef Sigma0
#undef Sigma1
#undef sigma0
#undef sigma1
#undef WORD
#undef R

  ctx->state[0] += A;
  ctx->state[1] += B;
  ctx->state[2] += C;
  ctx->state[3] += D;
  ctx->state[4] += E;
  ctx->state[5] += F;
  ctx->state[6] += G;
  ctx->state[7] += H;
}

void
sha256_update(sha256_t *ctx, const void *data, size_t len) {
  const unsigned char *raw = (const unsigned char *)data;
  size_t pos = ctx->size & 63;

  if (len == 0)
    return;

  ctx->size += len;

  if (pos > 0) {
    size_t want = 64 - pos;

    if (want > len)
      want = len;

    memcpy(ctx->block + pos, raw, want);

    pos += want;
    len -= want;
    raw += want;

    if (pos < 64)
      return;

    sha256_transform(ctx, ctx->block);
  }

  while (len >= 64) {
    sha256_transform(ctx, raw);
    raw += 64;
    len -= 64;
  }

  if (len > 0)
    memcpy(ctx->block, raw, len);
}

void
sha256_final(sha256_t *ctx, unsigned char *out) {
  static const unsigned char P[64] = { 0x80, 0x00 };
  size_t pos = ctx->size & 63;
  unsigned char D[8];
  int i;

  write64be(D, ctx->size << 3);

  sha256_update(ctx, P, 1 + ((119 - pos) & 63));
  sha256_update(ctx, D, 8);

  for (i = 0; i < 8; i++)
    write32be(out + i * 4, ctx->state[i]);
}

/*
 * SHA384
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/SHA-2
 *   https://tools.ietf.org/html/rfc4634
 */

void
sha384_init(sha384_t *ctx) {
  ctx->state[0] = UINT64_C(0xcbbb9d5dc1059ed8);
  ctx->state[1] = UINT64_C(0x629a292a367cd507);
  ctx->state[2] = UINT64_C(0x9159015a3070dd17);
  ctx->state[3] = UINT64_C(0x152fecd8f70e5939);
  ctx->state[4] = UINT64_C(0x67332667ffc00b31);
  ctx->state[5] = UINT64_C(0x8eb44a8768581511);
  ctx->state[6] = UINT64_C(0xdb0c2e0d64f98fa7);
  ctx->state[7] = UINT64_C(0x47b5481dbefa4fa4);
  ctx->size = 0;
}

void
sha384_update(sha384_t *ctx, const void *data, size_t len) {
  sha512_update(ctx, data, len);
}

void
sha384_final(sha384_t *ctx, unsigned char *out) {
  unsigned char tmp[64];

  sha512_final(ctx, tmp);

  memcpy(out, tmp, 48);

  torsion_cleanse(tmp, sizeof(tmp));
}

/*
 * SHA512
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/SHA-2
 *   https://tools.ietf.org/html/rfc4634
 */

void
sha512_init(sha512_t *ctx) {
  ctx->state[0] = UINT64_C(0x6a09e667f3bcc908);
  ctx->state[1] = UINT64_C(0xbb67ae8584caa73b);
  ctx->state[2] = UINT64_C(0x3c6ef372fe94f82b);
  ctx->state[3] = UINT64_C(0xa54ff53a5f1d36f1);
  ctx->state[4] = UINT64_C(0x510e527fade682d1);
  ctx->state[5] = UINT64_C(0x9b05688c2b3e6c1f);
  ctx->state[6] = UINT64_C(0x1f83d9abfb41bd6b);
  ctx->state[7] = UINT64_C(0x5be0cd19137e2179);
  ctx->size = 0;
}

static void
sha512_transform(sha512_t *ctx, const unsigned char *chunk) {
  uint64_t A = ctx->state[0];
  uint64_t B = ctx->state[1];
  uint64_t C = ctx->state[2];
  uint64_t D = ctx->state[3];
  uint64_t E = ctx->state[4];
  uint64_t F = ctx->state[5];
  uint64_t G = ctx->state[6];
  uint64_t H = ctx->state[7];
  uint64_t W[16];
  uint64_t w;

/* Note: the code in the RFC points out that Ch and Maj
 * can be optimized to use less bitwise ops.
 *
 * Original:
 *
 *   #define Ch(x, y, z) ((x & y) ^ (~x & z))
 *   #define Maj(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
 */
#define Ch(x, y, z) ((x & (y ^ z)) ^ z)
#define Maj(x, y, z) ((x & (y | z)) | (y & z))
#define Sigma0(x) (ROTR64(x, 28) ^ ROTR64(x, 34) ^ ROTR64(x, 39))
#define Sigma1(x) (ROTR64(x, 14) ^ ROTR64(x, 18) ^ ROTR64(x, 41))
#define sigma0(x) (ROTR64(x,  1) ^ ROTR64(x,  8) ^ (x >> 7))
#define sigma1(x) (ROTR64(x, 19) ^ ROTR64(x, 61) ^ (x >> 6))

/* Modulo by 16 to avoid allocating a large array. */
/* This trick is mentioned by the SHA1 RFC. */
#define WORD(i) (sigma1(W[(i -  2) & 15]) + W[(i -  7) & 15]  \
               + sigma0(W[(i - 15) & 15]) + W[(i - 16) & 15])

/* Loop body:
 *
 *   T1 = h + Sigma1(e) + Ch(e, f, g) + Kt + Wt
 *   T2 = Sigma0(a) + Maj(a, b, c)
 *   h = g
 *   g = f
 *   f = e
 *   e = d + T1
 *   d = c
 *   c = b
 *   b = a
 *   a = T1 + T2
 *
 * Reduces to:
 *
 *   T1 = h + Sigma1(e) + Ch(e, f, g) + Kt + Wt
 *   T2 = Sigma0(a) + Maj(a, b, c)
 *   d = d + T1
 *   h = T1 + T2
 *
 * Which further reduces to:
 *
 *   h = h + Sigma1(e) + Ch(e, f, g) + Kt + Wt
 *   d = d + h
 *   h = h + Sigma0(a) + Maj(a, b, c)
 */
#define R(a, b, c, d, e, f, g, h, i, k) do { \
  if (i < 16) /* Optimized out. */           \
    w = read64be(chunk + i * 8);             \
  else                                       \
    w = WORD(i);                             \
                                             \
  W[i & 15] = w;                             \
                                             \
  h += Sigma1(e) + Ch(e, f, g) + k + w;      \
  d += h;                                    \
  h += Sigma0(a) + Maj(a, b, c);             \
} while (0)

  R(A, B, C, D, E, F, G, H,  0, UINT64_C(0x428a2f98d728ae22));
  R(H, A, B, C, D, E, F, G,  1, UINT64_C(0x7137449123ef65cd));
  R(G, H, A, B, C, D, E, F,  2, UINT64_C(0xb5c0fbcfec4d3b2f));
  R(F, G, H, A, B, C, D, E,  3, UINT64_C(0xe9b5dba58189dbbc));
  R(E, F, G, H, A, B, C, D,  4, UINT64_C(0x3956c25bf348b538));
  R(D, E, F, G, H, A, B, C,  5, UINT64_C(0x59f111f1b605d019));
  R(C, D, E, F, G, H, A, B,  6, UINT64_C(0x923f82a4af194f9b));
  R(B, C, D, E, F, G, H, A,  7, UINT64_C(0xab1c5ed5da6d8118));
  R(A, B, C, D, E, F, G, H,  8, UINT64_C(0xd807aa98a3030242));
  R(H, A, B, C, D, E, F, G,  9, UINT64_C(0x12835b0145706fbe));
  R(G, H, A, B, C, D, E, F, 10, UINT64_C(0x243185be4ee4b28c));
  R(F, G, H, A, B, C, D, E, 11, UINT64_C(0x550c7dc3d5ffb4e2));
  R(E, F, G, H, A, B, C, D, 12, UINT64_C(0x72be5d74f27b896f));
  R(D, E, F, G, H, A, B, C, 13, UINT64_C(0x80deb1fe3b1696b1));
  R(C, D, E, F, G, H, A, B, 14, UINT64_C(0x9bdc06a725c71235));
  R(B, C, D, E, F, G, H, A, 15, UINT64_C(0xc19bf174cf692694));
  R(A, B, C, D, E, F, G, H, 16, UINT64_C(0xe49b69c19ef14ad2));
  R(H, A, B, C, D, E, F, G, 17, UINT64_C(0xefbe4786384f25e3));
  R(G, H, A, B, C, D, E, F, 18, UINT64_C(0x0fc19dc68b8cd5b5));
  R(F, G, H, A, B, C, D, E, 19, UINT64_C(0x240ca1cc77ac9c65));
  R(E, F, G, H, A, B, C, D, 20, UINT64_C(0x2de92c6f592b0275));
  R(D, E, F, G, H, A, B, C, 21, UINT64_C(0x4a7484aa6ea6e483));
  R(C, D, E, F, G, H, A, B, 22, UINT64_C(0x5cb0a9dcbd41fbd4));
  R(B, C, D, E, F, G, H, A, 23, UINT64_C(0x76f988da831153b5));
  R(A, B, C, D, E, F, G, H, 24, UINT64_C(0x983e5152ee66dfab));
  R(H, A, B, C, D, E, F, G, 25, UINT64_C(0xa831c66d2db43210));
  R(G, H, A, B, C, D, E, F, 26, UINT64_C(0xb00327c898fb213f));
  R(F, G, H, A, B, C, D, E, 27, UINT64_C(0xbf597fc7beef0ee4));
  R(E, F, G, H, A, B, C, D, 28, UINT64_C(0xc6e00bf33da88fc2));
  R(D, E, F, G, H, A, B, C, 29, UINT64_C(0xd5a79147930aa725));
  R(C, D, E, F, G, H, A, B, 30, UINT64_C(0x06ca6351e003826f));
  R(B, C, D, E, F, G, H, A, 31, UINT64_C(0x142929670a0e6e70));
  R(A, B, C, D, E, F, G, H, 32, UINT64_C(0x27b70a8546d22ffc));
  R(H, A, B, C, D, E, F, G, 33, UINT64_C(0x2e1b21385c26c926));
  R(G, H, A, B, C, D, E, F, 34, UINT64_C(0x4d2c6dfc5ac42aed));
  R(F, G, H, A, B, C, D, E, 35, UINT64_C(0x53380d139d95b3df));
  R(E, F, G, H, A, B, C, D, 36, UINT64_C(0x650a73548baf63de));
  R(D, E, F, G, H, A, B, C, 37, UINT64_C(0x766a0abb3c77b2a8));
  R(C, D, E, F, G, H, A, B, 38, UINT64_C(0x81c2c92e47edaee6));
  R(B, C, D, E, F, G, H, A, 39, UINT64_C(0x92722c851482353b));
  R(A, B, C, D, E, F, G, H, 40, UINT64_C(0xa2bfe8a14cf10364));
  R(H, A, B, C, D, E, F, G, 41, UINT64_C(0xa81a664bbc423001));
  R(G, H, A, B, C, D, E, F, 42, UINT64_C(0xc24b8b70d0f89791));
  R(F, G, H, A, B, C, D, E, 43, UINT64_C(0xc76c51a30654be30));
  R(E, F, G, H, A, B, C, D, 44, UINT64_C(0xd192e819d6ef5218));
  R(D, E, F, G, H, A, B, C, 45, UINT64_C(0xd69906245565a910));
  R(C, D, E, F, G, H, A, B, 46, UINT64_C(0xf40e35855771202a));
  R(B, C, D, E, F, G, H, A, 47, UINT64_C(0x106aa07032bbd1b8));
  R(A, B, C, D, E, F, G, H, 48, UINT64_C(0x19a4c116b8d2d0c8));
  R(H, A, B, C, D, E, F, G, 49, UINT64_C(0x1e376c085141ab53));
  R(G, H, A, B, C, D, E, F, 50, UINT64_C(0x2748774cdf8eeb99));
  R(F, G, H, A, B, C, D, E, 51, UINT64_C(0x34b0bcb5e19b48a8));
  R(E, F, G, H, A, B, C, D, 52, UINT64_C(0x391c0cb3c5c95a63));
  R(D, E, F, G, H, A, B, C, 53, UINT64_C(0x4ed8aa4ae3418acb));
  R(C, D, E, F, G, H, A, B, 54, UINT64_C(0x5b9cca4f7763e373));
  R(B, C, D, E, F, G, H, A, 55, UINT64_C(0x682e6ff3d6b2b8a3));
  R(A, B, C, D, E, F, G, H, 56, UINT64_C(0x748f82ee5defb2fc));
  R(H, A, B, C, D, E, F, G, 57, UINT64_C(0x78a5636f43172f60));
  R(G, H, A, B, C, D, E, F, 58, UINT64_C(0x84c87814a1f0ab72));
  R(F, G, H, A, B, C, D, E, 59, UINT64_C(0x8cc702081a6439ec));
  R(E, F, G, H, A, B, C, D, 60, UINT64_C(0x90befffa23631e28));
  R(D, E, F, G, H, A, B, C, 61, UINT64_C(0xa4506cebde82bde9));
  R(C, D, E, F, G, H, A, B, 62, UINT64_C(0xbef9a3f7b2c67915));
  R(B, C, D, E, F, G, H, A, 63, UINT64_C(0xc67178f2e372532b));
  R(A, B, C, D, E, F, G, H, 64, UINT64_C(0xca273eceea26619c));
  R(H, A, B, C, D, E, F, G, 65, UINT64_C(0xd186b8c721c0c207));
  R(G, H, A, B, C, D, E, F, 66, UINT64_C(0xeada7dd6cde0eb1e));
  R(F, G, H, A, B, C, D, E, 67, UINT64_C(0xf57d4f7fee6ed178));
  R(E, F, G, H, A, B, C, D, 68, UINT64_C(0x06f067aa72176fba));
  R(D, E, F, G, H, A, B, C, 69, UINT64_C(0x0a637dc5a2c898a6));
  R(C, D, E, F, G, H, A, B, 70, UINT64_C(0x113f9804bef90dae));
  R(B, C, D, E, F, G, H, A, 71, UINT64_C(0x1b710b35131c471b));
  R(A, B, C, D, E, F, G, H, 72, UINT64_C(0x28db77f523047d84));
  R(H, A, B, C, D, E, F, G, 73, UINT64_C(0x32caab7b40c72493));
  R(G, H, A, B, C, D, E, F, 74, UINT64_C(0x3c9ebe0a15c9bebc));
  R(F, G, H, A, B, C, D, E, 75, UINT64_C(0x431d67c49c100d4c));
  R(E, F, G, H, A, B, C, D, 76, UINT64_C(0x4cc5d4becb3e42b6));
  R(D, E, F, G, H, A, B, C, 77, UINT64_C(0x597f299cfc657e2a));
  R(C, D, E, F, G, H, A, B, 78, UINT64_C(0x5fcb6fab3ad6faec));
  R(B, C, D, E, F, G, H, A, 79, UINT64_C(0x6c44198c4a475817));

#undef Ch
#undef Maj
#undef Sigma0
#undef Sigma1
#undef sigma0
#undef sigma1
#undef WORD
#undef R

  ctx->state[0] += A;
  ctx->state[1] += B;
  ctx->state[2] += C;
  ctx->state[3] += D;
  ctx->state[4] += E;
  ctx->state[5] += F;
  ctx->state[6] += G;
  ctx->state[7] += H;
}

void
sha512_update(sha512_t *ctx, const void *data, size_t len) {
  const unsigned char *raw = (const unsigned char *)data;
  size_t pos = ctx->size & 127;

  if (len == 0)
    return;

  ctx->size += len;

  if (pos > 0) {
    size_t want = 128 - pos;

    if (want > len)
      want = len;

    memcpy(ctx->block + pos, raw, want);

    pos += want;
    len -= want;
    raw += want;

    if (pos < 128)
      return;

    sha512_transform(ctx, ctx->block);
  }

  while (len >= 128) {
    sha512_transform(ctx, raw);
    raw += 128;
    len -= 128;
  }

  if (len > 0)
    memcpy(ctx->block, raw, len);
}

void
sha512_final(sha512_t *ctx, unsigned char *out) {
  static const unsigned char P[128] = { 0x80, 0x00 };
  size_t pos = ctx->size & 127;
  unsigned char D[16];
  int i;

  write64be(D + 0, ctx->size >> (64 - 3));
  write64be(D + 8, ctx->size << 3);

  sha512_update(ctx, P, 1 + ((239 - pos) & 127));
  sha512_update(ctx, D, 16);

  for (i = 0; i < 8; i++)
    write64be(out + i * 8, ctx->state[i]);
}

/*
 * SHA3-{224,256,384,512}
 */

DEFINE_KECCAK(sha3_224, 224, 0x06)
DEFINE_KECCAK(sha3_256, 256, 0x06)
DEFINE_KECCAK(sha3_384, 384, 0x06)
DEFINE_KECCAK(sha3_512, 512, 0x06)

/*
 * SHAKE{128,256}
 */

#define DEFINE_SHAKE(name, bits)                                      \
void                                                                  \
torsion_##name##_init(sha3_t *ctx) {                                  \
  keccak_init(ctx, bits);                                             \
}                                                                     \
                                                                      \
void                                                                  \
torsion_##name##_update(sha3_t *ctx, const void *data, size_t len) {  \
  keccak_update(ctx, data, len);                                      \
}                                                                     \
                                                                      \
void                                                                  \
torsion_##name##_final(sha3_t *ctx, unsigned char *out, size_t len) { \
  keccak_final(ctx, out, 0x1f, len);                                  \
}

DEFINE_SHAKE(shake128, 128)
DEFINE_SHAKE(shake256, 256)

/*
 * Whirlpool
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/Whirlpool_(hash_function)
 *   https://www.iso.org/standard/39876.html
 *   https://web.archive.org/web/20171129084214/http://www.larc.usp.br/~pbarreto/WhirlpoolPage.html
 *   https://gist.github.com/chjj/c7a3f4bc517275197dc81914e2dc46f6
 */

static const uint64_t whirlpool_RC[10] = {
  UINT64_C(0x1823c6e887b8014f),
  UINT64_C(0x36a6d2f5796f9152),
  UINT64_C(0x60bc9b8ea30c7b35),
  UINT64_C(0x1de0d7c22e4bfe57),
  UINT64_C(0x157737e59ff04ada),
  UINT64_C(0x58c9290ab1a06b85),
  UINT64_C(0xbd5d10f4cb3e0567),
  UINT64_C(0xe427418ba77d95d8),
  UINT64_C(0xfbee7c66dd17479e),
  UINT64_C(0xca2dbf07ad5a8333)
};

static const uint64_t whirlpool_C0[256] = {
  UINT64_C(0x18186018c07830d8), UINT64_C(0x23238c2305af4626),
  UINT64_C(0xc6c63fc67ef991b8), UINT64_C(0xe8e887e8136fcdfb),
  UINT64_C(0x878726874ca113cb), UINT64_C(0xb8b8dab8a9626d11),
  UINT64_C(0x0101040108050209), UINT64_C(0x4f4f214f426e9e0d),
  UINT64_C(0x3636d836adee6c9b), UINT64_C(0xa6a6a2a6590451ff),
  UINT64_C(0xd2d26fd2debdb90c), UINT64_C(0xf5f5f3f5fb06f70e),
  UINT64_C(0x7979f979ef80f296), UINT64_C(0x6f6fa16f5fcede30),
  UINT64_C(0x91917e91fcef3f6d), UINT64_C(0x52525552aa07a4f8),
  UINT64_C(0x60609d6027fdc047), UINT64_C(0xbcbccabc89766535),
  UINT64_C(0x9b9b569baccd2b37), UINT64_C(0x8e8e028e048c018a),
  UINT64_C(0xa3a3b6a371155bd2), UINT64_C(0x0c0c300c603c186c),
  UINT64_C(0x7b7bf17bff8af684), UINT64_C(0x3535d435b5e16a80),
  UINT64_C(0x1d1d741de8693af5), UINT64_C(0xe0e0a7e05347ddb3),
  UINT64_C(0xd7d77bd7f6acb321), UINT64_C(0xc2c22fc25eed999c),
  UINT64_C(0x2e2eb82e6d965c43), UINT64_C(0x4b4b314b627a9629),
  UINT64_C(0xfefedffea321e15d), UINT64_C(0x575741578216aed5),
  UINT64_C(0x15155415a8412abd), UINT64_C(0x7777c1779fb6eee8),
  UINT64_C(0x3737dc37a5eb6e92), UINT64_C(0xe5e5b3e57b56d79e),
  UINT64_C(0x9f9f469f8cd92313), UINT64_C(0xf0f0e7f0d317fd23),
  UINT64_C(0x4a4a354a6a7f9420), UINT64_C(0xdada4fda9e95a944),
  UINT64_C(0x58587d58fa25b0a2), UINT64_C(0xc9c903c906ca8fcf),
  UINT64_C(0x2929a429558d527c), UINT64_C(0x0a0a280a5022145a),
  UINT64_C(0xb1b1feb1e14f7f50), UINT64_C(0xa0a0baa0691a5dc9),
  UINT64_C(0x6b6bb16b7fdad614), UINT64_C(0x85852e855cab17d9),
  UINT64_C(0xbdbdcebd8173673c), UINT64_C(0x5d5d695dd234ba8f),
  UINT64_C(0x1010401080502090), UINT64_C(0xf4f4f7f4f303f507),
  UINT64_C(0xcbcb0bcb16c08bdd), UINT64_C(0x3e3ef83eedc67cd3),
  UINT64_C(0x0505140528110a2d), UINT64_C(0x676781671fe6ce78),
  UINT64_C(0xe4e4b7e47353d597), UINT64_C(0x27279c2725bb4e02),
  UINT64_C(0x4141194132588273), UINT64_C(0x8b8b168b2c9d0ba7),
  UINT64_C(0xa7a7a6a7510153f6), UINT64_C(0x7d7de97dcf94fab2),
  UINT64_C(0x95956e95dcfb3749), UINT64_C(0xd8d847d88e9fad56),
  UINT64_C(0xfbfbcbfb8b30eb70), UINT64_C(0xeeee9fee2371c1cd),
  UINT64_C(0x7c7ced7cc791f8bb), UINT64_C(0x6666856617e3cc71),
  UINT64_C(0xdddd53dda68ea77b), UINT64_C(0x17175c17b84b2eaf),
  UINT64_C(0x4747014702468e45), UINT64_C(0x9e9e429e84dc211a),
  UINT64_C(0xcaca0fca1ec589d4), UINT64_C(0x2d2db42d75995a58),
  UINT64_C(0xbfbfc6bf9179632e), UINT64_C(0x07071c07381b0e3f),
  UINT64_C(0xadad8ead012347ac), UINT64_C(0x5a5a755aea2fb4b0),
  UINT64_C(0x838336836cb51bef), UINT64_C(0x3333cc3385ff66b6),
  UINT64_C(0x636391633ff2c65c), UINT64_C(0x02020802100a0412),
  UINT64_C(0xaaaa92aa39384993), UINT64_C(0x7171d971afa8e2de),
  UINT64_C(0xc8c807c80ecf8dc6), UINT64_C(0x19196419c87d32d1),
  UINT64_C(0x494939497270923b), UINT64_C(0xd9d943d9869aaf5f),
  UINT64_C(0xf2f2eff2c31df931), UINT64_C(0xe3e3abe34b48dba8),
  UINT64_C(0x5b5b715be22ab6b9), UINT64_C(0x88881a8834920dbc),
  UINT64_C(0x9a9a529aa4c8293e), UINT64_C(0x262698262dbe4c0b),
  UINT64_C(0x3232c8328dfa64bf), UINT64_C(0xb0b0fab0e94a7d59),
  UINT64_C(0xe9e983e91b6acff2), UINT64_C(0x0f0f3c0f78331e77),
  UINT64_C(0xd5d573d5e6a6b733), UINT64_C(0x80803a8074ba1df4),
  UINT64_C(0xbebec2be997c6127), UINT64_C(0xcdcd13cd26de87eb),
  UINT64_C(0x3434d034bde46889), UINT64_C(0x48483d487a759032),
  UINT64_C(0xffffdbffab24e354), UINT64_C(0x7a7af57af78ff48d),
  UINT64_C(0x90907a90f4ea3d64), UINT64_C(0x5f5f615fc23ebe9d),
  UINT64_C(0x202080201da0403d), UINT64_C(0x6868bd6867d5d00f),
  UINT64_C(0x1a1a681ad07234ca), UINT64_C(0xaeae82ae192c41b7),
  UINT64_C(0xb4b4eab4c95e757d), UINT64_C(0x54544d549a19a8ce),
  UINT64_C(0x93937693ece53b7f), UINT64_C(0x222288220daa442f),
  UINT64_C(0x64648d6407e9c863), UINT64_C(0xf1f1e3f1db12ff2a),
  UINT64_C(0x7373d173bfa2e6cc), UINT64_C(0x12124812905a2482),
  UINT64_C(0x40401d403a5d807a), UINT64_C(0x0808200840281048),
  UINT64_C(0xc3c32bc356e89b95), UINT64_C(0xecec97ec337bc5df),
  UINT64_C(0xdbdb4bdb9690ab4d), UINT64_C(0xa1a1bea1611f5fc0),
  UINT64_C(0x8d8d0e8d1c830791), UINT64_C(0x3d3df43df5c97ac8),
  UINT64_C(0x97976697ccf1335b), UINT64_C(0x0000000000000000),
  UINT64_C(0xcfcf1bcf36d483f9), UINT64_C(0x2b2bac2b4587566e),
  UINT64_C(0x7676c57697b3ece1), UINT64_C(0x8282328264b019e6),
  UINT64_C(0xd6d67fd6fea9b128), UINT64_C(0x1b1b6c1bd87736c3),
  UINT64_C(0xb5b5eeb5c15b7774), UINT64_C(0xafaf86af112943be),
  UINT64_C(0x6a6ab56a77dfd41d), UINT64_C(0x50505d50ba0da0ea),
  UINT64_C(0x45450945124c8a57), UINT64_C(0xf3f3ebf3cb18fb38),
  UINT64_C(0x3030c0309df060ad), UINT64_C(0xefef9bef2b74c3c4),
  UINT64_C(0x3f3ffc3fe5c37eda), UINT64_C(0x55554955921caac7),
  UINT64_C(0xa2a2b2a2791059db), UINT64_C(0xeaea8fea0365c9e9),
  UINT64_C(0x656589650fecca6a), UINT64_C(0xbabad2bab9686903),
  UINT64_C(0x2f2fbc2f65935e4a), UINT64_C(0xc0c027c04ee79d8e),
  UINT64_C(0xdede5fdebe81a160), UINT64_C(0x1c1c701ce06c38fc),
  UINT64_C(0xfdfdd3fdbb2ee746), UINT64_C(0x4d4d294d52649a1f),
  UINT64_C(0x92927292e4e03976), UINT64_C(0x7575c9758fbceafa),
  UINT64_C(0x06061806301e0c36), UINT64_C(0x8a8a128a249809ae),
  UINT64_C(0xb2b2f2b2f940794b), UINT64_C(0xe6e6bfe66359d185),
  UINT64_C(0x0e0e380e70361c7e), UINT64_C(0x1f1f7c1ff8633ee7),
  UINT64_C(0x6262956237f7c455), UINT64_C(0xd4d477d4eea3b53a),
  UINT64_C(0xa8a89aa829324d81), UINT64_C(0x96966296c4f43152),
  UINT64_C(0xf9f9c3f99b3aef62), UINT64_C(0xc5c533c566f697a3),
  UINT64_C(0x2525942535b14a10), UINT64_C(0x59597959f220b2ab),
  UINT64_C(0x84842a8454ae15d0), UINT64_C(0x7272d572b7a7e4c5),
  UINT64_C(0x3939e439d5dd72ec), UINT64_C(0x4c4c2d4c5a619816),
  UINT64_C(0x5e5e655eca3bbc94), UINT64_C(0x7878fd78e785f09f),
  UINT64_C(0x3838e038ddd870e5), UINT64_C(0x8c8c0a8c14860598),
  UINT64_C(0xd1d163d1c6b2bf17), UINT64_C(0xa5a5aea5410b57e4),
  UINT64_C(0xe2e2afe2434dd9a1), UINT64_C(0x616199612ff8c24e),
  UINT64_C(0xb3b3f6b3f1457b42), UINT64_C(0x2121842115a54234),
  UINT64_C(0x9c9c4a9c94d62508), UINT64_C(0x1e1e781ef0663cee),
  UINT64_C(0x4343114322528661), UINT64_C(0xc7c73bc776fc93b1),
  UINT64_C(0xfcfcd7fcb32be54f), UINT64_C(0x0404100420140824),
  UINT64_C(0x51515951b208a2e3), UINT64_C(0x99995e99bcc72f25),
  UINT64_C(0x6d6da96d4fc4da22), UINT64_C(0x0d0d340d68391a65),
  UINT64_C(0xfafacffa8335e979), UINT64_C(0xdfdf5bdfb684a369),
  UINT64_C(0x7e7ee57ed79bfca9), UINT64_C(0x242490243db44819),
  UINT64_C(0x3b3bec3bc5d776fe), UINT64_C(0xabab96ab313d4b9a),
  UINT64_C(0xcece1fce3ed181f0), UINT64_C(0x1111441188552299),
  UINT64_C(0x8f8f068f0c890383), UINT64_C(0x4e4e254e4a6b9c04),
  UINT64_C(0xb7b7e6b7d1517366), UINT64_C(0xebeb8beb0b60cbe0),
  UINT64_C(0x3c3cf03cfdcc78c1), UINT64_C(0x81813e817cbf1ffd),
  UINT64_C(0x94946a94d4fe3540), UINT64_C(0xf7f7fbf7eb0cf31c),
  UINT64_C(0xb9b9deb9a1676f18), UINT64_C(0x13134c13985f268b),
  UINT64_C(0x2c2cb02c7d9c5851), UINT64_C(0xd3d36bd3d6b8bb05),
  UINT64_C(0xe7e7bbe76b5cd38c), UINT64_C(0x6e6ea56e57cbdc39),
  UINT64_C(0xc4c437c46ef395aa), UINT64_C(0x03030c03180f061b),
  UINT64_C(0x565645568a13acdc), UINT64_C(0x44440d441a49885e),
  UINT64_C(0x7f7fe17fdf9efea0), UINT64_C(0xa9a99ea921374f88),
  UINT64_C(0x2a2aa82a4d825467), UINT64_C(0xbbbbd6bbb16d6b0a),
  UINT64_C(0xc1c123c146e29f87), UINT64_C(0x53535153a202a6f1),
  UINT64_C(0xdcdc57dcae8ba572), UINT64_C(0x0b0b2c0b58271653),
  UINT64_C(0x9d9d4e9d9cd32701), UINT64_C(0x6c6cad6c47c1d82b),
  UINT64_C(0x3131c43195f562a4), UINT64_C(0x7474cd7487b9e8f3),
  UINT64_C(0xf6f6fff6e309f115), UINT64_C(0x464605460a438c4c),
  UINT64_C(0xacac8aac092645a5), UINT64_C(0x89891e893c970fb5),
  UINT64_C(0x14145014a04428b4), UINT64_C(0xe1e1a3e15b42dfba),
  UINT64_C(0x16165816b04e2ca6), UINT64_C(0x3a3ae83acdd274f7),
  UINT64_C(0x6969b9696fd0d206), UINT64_C(0x09092409482d1241),
  UINT64_C(0x7070dd70a7ade0d7), UINT64_C(0xb6b6e2b6d954716f),
  UINT64_C(0xd0d067d0ceb7bd1e), UINT64_C(0xeded93ed3b7ec7d6),
  UINT64_C(0xcccc17cc2edb85e2), UINT64_C(0x424215422a578468),
  UINT64_C(0x98985a98b4c22d2c), UINT64_C(0xa4a4aaa4490e55ed),
  UINT64_C(0x2828a0285d885075), UINT64_C(0x5c5c6d5cda31b886),
  UINT64_C(0xf8f8c7f8933fed6b), UINT64_C(0x8686228644a411c2)
};

static const uint64_t whirlpool_C1[256] = {
  UINT64_C(0xd818186018c07830), UINT64_C(0x2623238c2305af46),
  UINT64_C(0xb8c6c63fc67ef991), UINT64_C(0xfbe8e887e8136fcd),
  UINT64_C(0xcb878726874ca113), UINT64_C(0x11b8b8dab8a9626d),
  UINT64_C(0x0901010401080502), UINT64_C(0x0d4f4f214f426e9e),
  UINT64_C(0x9b3636d836adee6c), UINT64_C(0xffa6a6a2a6590451),
  UINT64_C(0x0cd2d26fd2debdb9), UINT64_C(0x0ef5f5f3f5fb06f7),
  UINT64_C(0x967979f979ef80f2), UINT64_C(0x306f6fa16f5fcede),
  UINT64_C(0x6d91917e91fcef3f), UINT64_C(0xf852525552aa07a4),
  UINT64_C(0x4760609d6027fdc0), UINT64_C(0x35bcbccabc897665),
  UINT64_C(0x379b9b569baccd2b), UINT64_C(0x8a8e8e028e048c01),
  UINT64_C(0xd2a3a3b6a371155b), UINT64_C(0x6c0c0c300c603c18),
  UINT64_C(0x847b7bf17bff8af6), UINT64_C(0x803535d435b5e16a),
  UINT64_C(0xf51d1d741de8693a), UINT64_C(0xb3e0e0a7e05347dd),
  UINT64_C(0x21d7d77bd7f6acb3), UINT64_C(0x9cc2c22fc25eed99),
  UINT64_C(0x432e2eb82e6d965c), UINT64_C(0x294b4b314b627a96),
  UINT64_C(0x5dfefedffea321e1), UINT64_C(0xd5575741578216ae),
  UINT64_C(0xbd15155415a8412a), UINT64_C(0xe87777c1779fb6ee),
  UINT64_C(0x923737dc37a5eb6e), UINT64_C(0x9ee5e5b3e57b56d7),
  UINT64_C(0x139f9f469f8cd923), UINT64_C(0x23f0f0e7f0d317fd),
  UINT64_C(0x204a4a354a6a7f94), UINT64_C(0x44dada4fda9e95a9),
  UINT64_C(0xa258587d58fa25b0), UINT64_C(0xcfc9c903c906ca8f),
  UINT64_C(0x7c2929a429558d52), UINT64_C(0x5a0a0a280a502214),
  UINT64_C(0x50b1b1feb1e14f7f), UINT64_C(0xc9a0a0baa0691a5d),
  UINT64_C(0x146b6bb16b7fdad6), UINT64_C(0xd985852e855cab17),
  UINT64_C(0x3cbdbdcebd817367), UINT64_C(0x8f5d5d695dd234ba),
  UINT64_C(0x9010104010805020), UINT64_C(0x07f4f4f7f4f303f5),
  UINT64_C(0xddcbcb0bcb16c08b), UINT64_C(0xd33e3ef83eedc67c),
  UINT64_C(0x2d0505140528110a), UINT64_C(0x78676781671fe6ce),
  UINT64_C(0x97e4e4b7e47353d5), UINT64_C(0x0227279c2725bb4e),
  UINT64_C(0x7341411941325882), UINT64_C(0xa78b8b168b2c9d0b),
  UINT64_C(0xf6a7a7a6a7510153), UINT64_C(0xb27d7de97dcf94fa),
  UINT64_C(0x4995956e95dcfb37), UINT64_C(0x56d8d847d88e9fad),
  UINT64_C(0x70fbfbcbfb8b30eb), UINT64_C(0xcdeeee9fee2371c1),
  UINT64_C(0xbb7c7ced7cc791f8), UINT64_C(0x716666856617e3cc),
  UINT64_C(0x7bdddd53dda68ea7), UINT64_C(0xaf17175c17b84b2e),
  UINT64_C(0x454747014702468e), UINT64_C(0x1a9e9e429e84dc21),
  UINT64_C(0xd4caca0fca1ec589), UINT64_C(0x582d2db42d75995a),
  UINT64_C(0x2ebfbfc6bf917963), UINT64_C(0x3f07071c07381b0e),
  UINT64_C(0xacadad8ead012347), UINT64_C(0xb05a5a755aea2fb4),
  UINT64_C(0xef838336836cb51b), UINT64_C(0xb63333cc3385ff66),
  UINT64_C(0x5c636391633ff2c6), UINT64_C(0x1202020802100a04),
  UINT64_C(0x93aaaa92aa393849), UINT64_C(0xde7171d971afa8e2),
  UINT64_C(0xc6c8c807c80ecf8d), UINT64_C(0xd119196419c87d32),
  UINT64_C(0x3b49493949727092), UINT64_C(0x5fd9d943d9869aaf),
  UINT64_C(0x31f2f2eff2c31df9), UINT64_C(0xa8e3e3abe34b48db),
  UINT64_C(0xb95b5b715be22ab6), UINT64_C(0xbc88881a8834920d),
  UINT64_C(0x3e9a9a529aa4c829), UINT64_C(0x0b262698262dbe4c),
  UINT64_C(0xbf3232c8328dfa64), UINT64_C(0x59b0b0fab0e94a7d),
  UINT64_C(0xf2e9e983e91b6acf), UINT64_C(0x770f0f3c0f78331e),
  UINT64_C(0x33d5d573d5e6a6b7), UINT64_C(0xf480803a8074ba1d),
  UINT64_C(0x27bebec2be997c61), UINT64_C(0xebcdcd13cd26de87),
  UINT64_C(0x893434d034bde468), UINT64_C(0x3248483d487a7590),
  UINT64_C(0x54ffffdbffab24e3), UINT64_C(0x8d7a7af57af78ff4),
  UINT64_C(0x6490907a90f4ea3d), UINT64_C(0x9d5f5f615fc23ebe),
  UINT64_C(0x3d202080201da040), UINT64_C(0x0f6868bd6867d5d0),
  UINT64_C(0xca1a1a681ad07234), UINT64_C(0xb7aeae82ae192c41),
  UINT64_C(0x7db4b4eab4c95e75), UINT64_C(0xce54544d549a19a8),
  UINT64_C(0x7f93937693ece53b), UINT64_C(0x2f222288220daa44),
  UINT64_C(0x6364648d6407e9c8), UINT64_C(0x2af1f1e3f1db12ff),
  UINT64_C(0xcc7373d173bfa2e6), UINT64_C(0x8212124812905a24),
  UINT64_C(0x7a40401d403a5d80), UINT64_C(0x4808082008402810),
  UINT64_C(0x95c3c32bc356e89b), UINT64_C(0xdfecec97ec337bc5),
  UINT64_C(0x4ddbdb4bdb9690ab), UINT64_C(0xc0a1a1bea1611f5f),
  UINT64_C(0x918d8d0e8d1c8307), UINT64_C(0xc83d3df43df5c97a),
  UINT64_C(0x5b97976697ccf133), UINT64_C(0x0000000000000000),
  UINT64_C(0xf9cfcf1bcf36d483), UINT64_C(0x6e2b2bac2b458756),
  UINT64_C(0xe17676c57697b3ec), UINT64_C(0xe68282328264b019),
  UINT64_C(0x28d6d67fd6fea9b1), UINT64_C(0xc31b1b6c1bd87736),
  UINT64_C(0x74b5b5eeb5c15b77), UINT64_C(0xbeafaf86af112943),
  UINT64_C(0x1d6a6ab56a77dfd4), UINT64_C(0xea50505d50ba0da0),
  UINT64_C(0x5745450945124c8a), UINT64_C(0x38f3f3ebf3cb18fb),
  UINT64_C(0xad3030c0309df060), UINT64_C(0xc4efef9bef2b74c3),
  UINT64_C(0xda3f3ffc3fe5c37e), UINT64_C(0xc755554955921caa),
  UINT64_C(0xdba2a2b2a2791059), UINT64_C(0xe9eaea8fea0365c9),
  UINT64_C(0x6a656589650fecca), UINT64_C(0x03babad2bab96869),
  UINT64_C(0x4a2f2fbc2f65935e), UINT64_C(0x8ec0c027c04ee79d),
  UINT64_C(0x60dede5fdebe81a1), UINT64_C(0xfc1c1c701ce06c38),
  UINT64_C(0x46fdfdd3fdbb2ee7), UINT64_C(0x1f4d4d294d52649a),
  UINT64_C(0x7692927292e4e039), UINT64_C(0xfa7575c9758fbcea),
  UINT64_C(0x3606061806301e0c), UINT64_C(0xae8a8a128a249809),
  UINT64_C(0x4bb2b2f2b2f94079), UINT64_C(0x85e6e6bfe66359d1),
  UINT64_C(0x7e0e0e380e70361c), UINT64_C(0xe71f1f7c1ff8633e),
  UINT64_C(0x556262956237f7c4), UINT64_C(0x3ad4d477d4eea3b5),
  UINT64_C(0x81a8a89aa829324d), UINT64_C(0x5296966296c4f431),
  UINT64_C(0x62f9f9c3f99b3aef), UINT64_C(0xa3c5c533c566f697),
  UINT64_C(0x102525942535b14a), UINT64_C(0xab59597959f220b2),
  UINT64_C(0xd084842a8454ae15), UINT64_C(0xc57272d572b7a7e4),
  UINT64_C(0xec3939e439d5dd72), UINT64_C(0x164c4c2d4c5a6198),
  UINT64_C(0x945e5e655eca3bbc), UINT64_C(0x9f7878fd78e785f0),
  UINT64_C(0xe53838e038ddd870), UINT64_C(0x988c8c0a8c148605),
  UINT64_C(0x17d1d163d1c6b2bf), UINT64_C(0xe4a5a5aea5410b57),
  UINT64_C(0xa1e2e2afe2434dd9), UINT64_C(0x4e616199612ff8c2),
  UINT64_C(0x42b3b3f6b3f1457b), UINT64_C(0x342121842115a542),
  UINT64_C(0x089c9c4a9c94d625), UINT64_C(0xee1e1e781ef0663c),
  UINT64_C(0x6143431143225286), UINT64_C(0xb1c7c73bc776fc93),
  UINT64_C(0x4ffcfcd7fcb32be5), UINT64_C(0x2404041004201408),
  UINT64_C(0xe351515951b208a2), UINT64_C(0x2599995e99bcc72f),
  UINT64_C(0x226d6da96d4fc4da), UINT64_C(0x650d0d340d68391a),
  UINT64_C(0x79fafacffa8335e9), UINT64_C(0x69dfdf5bdfb684a3),
  UINT64_C(0xa97e7ee57ed79bfc), UINT64_C(0x19242490243db448),
  UINT64_C(0xfe3b3bec3bc5d776), UINT64_C(0x9aabab96ab313d4b),
  UINT64_C(0xf0cece1fce3ed181), UINT64_C(0x9911114411885522),
  UINT64_C(0x838f8f068f0c8903), UINT64_C(0x044e4e254e4a6b9c),
  UINT64_C(0x66b7b7e6b7d15173), UINT64_C(0xe0ebeb8beb0b60cb),
  UINT64_C(0xc13c3cf03cfdcc78), UINT64_C(0xfd81813e817cbf1f),
  UINT64_C(0x4094946a94d4fe35), UINT64_C(0x1cf7f7fbf7eb0cf3),
  UINT64_C(0x18b9b9deb9a1676f), UINT64_C(0x8b13134c13985f26),
  UINT64_C(0x512c2cb02c7d9c58), UINT64_C(0x05d3d36bd3d6b8bb),
  UINT64_C(0x8ce7e7bbe76b5cd3), UINT64_C(0x396e6ea56e57cbdc),
  UINT64_C(0xaac4c437c46ef395), UINT64_C(0x1b03030c03180f06),
  UINT64_C(0xdc565645568a13ac), UINT64_C(0x5e44440d441a4988),
  UINT64_C(0xa07f7fe17fdf9efe), UINT64_C(0x88a9a99ea921374f),
  UINT64_C(0x672a2aa82a4d8254), UINT64_C(0x0abbbbd6bbb16d6b),
  UINT64_C(0x87c1c123c146e29f), UINT64_C(0xf153535153a202a6),
  UINT64_C(0x72dcdc57dcae8ba5), UINT64_C(0x530b0b2c0b582716),
  UINT64_C(0x019d9d4e9d9cd327), UINT64_C(0x2b6c6cad6c47c1d8),
  UINT64_C(0xa43131c43195f562), UINT64_C(0xf37474cd7487b9e8),
  UINT64_C(0x15f6f6fff6e309f1), UINT64_C(0x4c464605460a438c),
  UINT64_C(0xa5acac8aac092645), UINT64_C(0xb589891e893c970f),
  UINT64_C(0xb414145014a04428), UINT64_C(0xbae1e1a3e15b42df),
  UINT64_C(0xa616165816b04e2c), UINT64_C(0xf73a3ae83acdd274),
  UINT64_C(0x066969b9696fd0d2), UINT64_C(0x4109092409482d12),
  UINT64_C(0xd77070dd70a7ade0), UINT64_C(0x6fb6b6e2b6d95471),
  UINT64_C(0x1ed0d067d0ceb7bd), UINT64_C(0xd6eded93ed3b7ec7),
  UINT64_C(0xe2cccc17cc2edb85), UINT64_C(0x68424215422a5784),
  UINT64_C(0x2c98985a98b4c22d), UINT64_C(0xeda4a4aaa4490e55),
  UINT64_C(0x752828a0285d8850), UINT64_C(0x865c5c6d5cda31b8),
  UINT64_C(0x6bf8f8c7f8933fed), UINT64_C(0xc28686228644a411)
};

static const uint64_t whirlpool_C2[256] = {
  UINT64_C(0x30d818186018c078), UINT64_C(0x462623238c2305af),
  UINT64_C(0x91b8c6c63fc67ef9), UINT64_C(0xcdfbe8e887e8136f),
  UINT64_C(0x13cb878726874ca1), UINT64_C(0x6d11b8b8dab8a962),
  UINT64_C(0x0209010104010805), UINT64_C(0x9e0d4f4f214f426e),
  UINT64_C(0x6c9b3636d836adee), UINT64_C(0x51ffa6a6a2a65904),
  UINT64_C(0xb90cd2d26fd2debd), UINT64_C(0xf70ef5f5f3f5fb06),
  UINT64_C(0xf2967979f979ef80), UINT64_C(0xde306f6fa16f5fce),
  UINT64_C(0x3f6d91917e91fcef), UINT64_C(0xa4f852525552aa07),
  UINT64_C(0xc04760609d6027fd), UINT64_C(0x6535bcbccabc8976),
  UINT64_C(0x2b379b9b569baccd), UINT64_C(0x018a8e8e028e048c),
  UINT64_C(0x5bd2a3a3b6a37115), UINT64_C(0x186c0c0c300c603c),
  UINT64_C(0xf6847b7bf17bff8a), UINT64_C(0x6a803535d435b5e1),
  UINT64_C(0x3af51d1d741de869), UINT64_C(0xddb3e0e0a7e05347),
  UINT64_C(0xb321d7d77bd7f6ac), UINT64_C(0x999cc2c22fc25eed),
  UINT64_C(0x5c432e2eb82e6d96), UINT64_C(0x96294b4b314b627a),
  UINT64_C(0xe15dfefedffea321), UINT64_C(0xaed5575741578216),
  UINT64_C(0x2abd15155415a841), UINT64_C(0xeee87777c1779fb6),
  UINT64_C(0x6e923737dc37a5eb), UINT64_C(0xd79ee5e5b3e57b56),
  UINT64_C(0x23139f9f469f8cd9), UINT64_C(0xfd23f0f0e7f0d317),
  UINT64_C(0x94204a4a354a6a7f), UINT64_C(0xa944dada4fda9e95),
  UINT64_C(0xb0a258587d58fa25), UINT64_C(0x8fcfc9c903c906ca),
  UINT64_C(0x527c2929a429558d), UINT64_C(0x145a0a0a280a5022),
  UINT64_C(0x7f50b1b1feb1e14f), UINT64_C(0x5dc9a0a0baa0691a),
  UINT64_C(0xd6146b6bb16b7fda), UINT64_C(0x17d985852e855cab),
  UINT64_C(0x673cbdbdcebd8173), UINT64_C(0xba8f5d5d695dd234),
  UINT64_C(0x2090101040108050), UINT64_C(0xf507f4f4f7f4f303),
  UINT64_C(0x8bddcbcb0bcb16c0), UINT64_C(0x7cd33e3ef83eedc6),
  UINT64_C(0x0a2d050514052811), UINT64_C(0xce78676781671fe6),
  UINT64_C(0xd597e4e4b7e47353), UINT64_C(0x4e0227279c2725bb),
  UINT64_C(0x8273414119413258), UINT64_C(0x0ba78b8b168b2c9d),
  UINT64_C(0x53f6a7a7a6a75101), UINT64_C(0xfab27d7de97dcf94),
  UINT64_C(0x374995956e95dcfb), UINT64_C(0xad56d8d847d88e9f),
  UINT64_C(0xeb70fbfbcbfb8b30), UINT64_C(0xc1cdeeee9fee2371),
  UINT64_C(0xf8bb7c7ced7cc791), UINT64_C(0xcc716666856617e3),
  UINT64_C(0xa77bdddd53dda68e), UINT64_C(0x2eaf17175c17b84b),
  UINT64_C(0x8e45474701470246), UINT64_C(0x211a9e9e429e84dc),
  UINT64_C(0x89d4caca0fca1ec5), UINT64_C(0x5a582d2db42d7599),
  UINT64_C(0x632ebfbfc6bf9179), UINT64_C(0x0e3f07071c07381b),
  UINT64_C(0x47acadad8ead0123), UINT64_C(0xb4b05a5a755aea2f),
  UINT64_C(0x1bef838336836cb5), UINT64_C(0x66b63333cc3385ff),
  UINT64_C(0xc65c636391633ff2), UINT64_C(0x041202020802100a),
  UINT64_C(0x4993aaaa92aa3938), UINT64_C(0xe2de7171d971afa8),
  UINT64_C(0x8dc6c8c807c80ecf), UINT64_C(0x32d119196419c87d),
  UINT64_C(0x923b494939497270), UINT64_C(0xaf5fd9d943d9869a),
  UINT64_C(0xf931f2f2eff2c31d), UINT64_C(0xdba8e3e3abe34b48),
  UINT64_C(0xb6b95b5b715be22a), UINT64_C(0x0dbc88881a883492),
  UINT64_C(0x293e9a9a529aa4c8), UINT64_C(0x4c0b262698262dbe),
  UINT64_C(0x64bf3232c8328dfa), UINT64_C(0x7d59b0b0fab0e94a),
  UINT64_C(0xcff2e9e983e91b6a), UINT64_C(0x1e770f0f3c0f7833),
  UINT64_C(0xb733d5d573d5e6a6), UINT64_C(0x1df480803a8074ba),
  UINT64_C(0x6127bebec2be997c), UINT64_C(0x87ebcdcd13cd26de),
  UINT64_C(0x68893434d034bde4), UINT64_C(0x903248483d487a75),
  UINT64_C(0xe354ffffdbffab24), UINT64_C(0xf48d7a7af57af78f),
  UINT64_C(0x3d6490907a90f4ea), UINT64_C(0xbe9d5f5f615fc23e),
  UINT64_C(0x403d202080201da0), UINT64_C(0xd00f6868bd6867d5),
  UINT64_C(0x34ca1a1a681ad072), UINT64_C(0x41b7aeae82ae192c),
  UINT64_C(0x757db4b4eab4c95e), UINT64_C(0xa8ce54544d549a19),
  UINT64_C(0x3b7f93937693ece5), UINT64_C(0x442f222288220daa),
  UINT64_C(0xc86364648d6407e9), UINT64_C(0xff2af1f1e3f1db12),
  UINT64_C(0xe6cc7373d173bfa2), UINT64_C(0x248212124812905a),
  UINT64_C(0x807a40401d403a5d), UINT64_C(0x1048080820084028),
  UINT64_C(0x9b95c3c32bc356e8), UINT64_C(0xc5dfecec97ec337b),
  UINT64_C(0xab4ddbdb4bdb9690), UINT64_C(0x5fc0a1a1bea1611f),
  UINT64_C(0x07918d8d0e8d1c83), UINT64_C(0x7ac83d3df43df5c9),
  UINT64_C(0x335b97976697ccf1), UINT64_C(0x0000000000000000),
  UINT64_C(0x83f9cfcf1bcf36d4), UINT64_C(0x566e2b2bac2b4587),
  UINT64_C(0xece17676c57697b3), UINT64_C(0x19e68282328264b0),
  UINT64_C(0xb128d6d67fd6fea9), UINT64_C(0x36c31b1b6c1bd877),
  UINT64_C(0x7774b5b5eeb5c15b), UINT64_C(0x43beafaf86af1129),
  UINT64_C(0xd41d6a6ab56a77df), UINT64_C(0xa0ea50505d50ba0d),
  UINT64_C(0x8a5745450945124c), UINT64_C(0xfb38f3f3ebf3cb18),
  UINT64_C(0x60ad3030c0309df0), UINT64_C(0xc3c4efef9bef2b74),
  UINT64_C(0x7eda3f3ffc3fe5c3), UINT64_C(0xaac755554955921c),
  UINT64_C(0x59dba2a2b2a27910), UINT64_C(0xc9e9eaea8fea0365),
  UINT64_C(0xca6a656589650fec), UINT64_C(0x6903babad2bab968),
  UINT64_C(0x5e4a2f2fbc2f6593), UINT64_C(0x9d8ec0c027c04ee7),
  UINT64_C(0xa160dede5fdebe81), UINT64_C(0x38fc1c1c701ce06c),
  UINT64_C(0xe746fdfdd3fdbb2e), UINT64_C(0x9a1f4d4d294d5264),
  UINT64_C(0x397692927292e4e0), UINT64_C(0xeafa7575c9758fbc),
  UINT64_C(0x0c3606061806301e), UINT64_C(0x09ae8a8a128a2498),
  UINT64_C(0x794bb2b2f2b2f940), UINT64_C(0xd185e6e6bfe66359),
  UINT64_C(0x1c7e0e0e380e7036), UINT64_C(0x3ee71f1f7c1ff863),
  UINT64_C(0xc4556262956237f7), UINT64_C(0xb53ad4d477d4eea3),
  UINT64_C(0x4d81a8a89aa82932), UINT64_C(0x315296966296c4f4),
  UINT64_C(0xef62f9f9c3f99b3a), UINT64_C(0x97a3c5c533c566f6),
  UINT64_C(0x4a102525942535b1), UINT64_C(0xb2ab59597959f220),
  UINT64_C(0x15d084842a8454ae), UINT64_C(0xe4c57272d572b7a7),
  UINT64_C(0x72ec3939e439d5dd), UINT64_C(0x98164c4c2d4c5a61),
  UINT64_C(0xbc945e5e655eca3b), UINT64_C(0xf09f7878fd78e785),
  UINT64_C(0x70e53838e038ddd8), UINT64_C(0x05988c8c0a8c1486),
  UINT64_C(0xbf17d1d163d1c6b2), UINT64_C(0x57e4a5a5aea5410b),
  UINT64_C(0xd9a1e2e2afe2434d), UINT64_C(0xc24e616199612ff8),
  UINT64_C(0x7b42b3b3f6b3f145), UINT64_C(0x42342121842115a5),
  UINT64_C(0x25089c9c4a9c94d6), UINT64_C(0x3cee1e1e781ef066),
  UINT64_C(0x8661434311432252), UINT64_C(0x93b1c7c73bc776fc),
  UINT64_C(0xe54ffcfcd7fcb32b), UINT64_C(0x0824040410042014),
  UINT64_C(0xa2e351515951b208), UINT64_C(0x2f2599995e99bcc7),
  UINT64_C(0xda226d6da96d4fc4), UINT64_C(0x1a650d0d340d6839),
  UINT64_C(0xe979fafacffa8335), UINT64_C(0xa369dfdf5bdfb684),
  UINT64_C(0xfca97e7ee57ed79b), UINT64_C(0x4819242490243db4),
  UINT64_C(0x76fe3b3bec3bc5d7), UINT64_C(0x4b9aabab96ab313d),
  UINT64_C(0x81f0cece1fce3ed1), UINT64_C(0x2299111144118855),
  UINT64_C(0x03838f8f068f0c89), UINT64_C(0x9c044e4e254e4a6b),
  UINT64_C(0x7366b7b7e6b7d151), UINT64_C(0xcbe0ebeb8beb0b60),
  UINT64_C(0x78c13c3cf03cfdcc), UINT64_C(0x1ffd81813e817cbf),
  UINT64_C(0x354094946a94d4fe), UINT64_C(0xf31cf7f7fbf7eb0c),
  UINT64_C(0x6f18b9b9deb9a167), UINT64_C(0x268b13134c13985f),
  UINT64_C(0x58512c2cb02c7d9c), UINT64_C(0xbb05d3d36bd3d6b8),
  UINT64_C(0xd38ce7e7bbe76b5c), UINT64_C(0xdc396e6ea56e57cb),
  UINT64_C(0x95aac4c437c46ef3), UINT64_C(0x061b03030c03180f),
  UINT64_C(0xacdc565645568a13), UINT64_C(0x885e44440d441a49),
  UINT64_C(0xfea07f7fe17fdf9e), UINT64_C(0x4f88a9a99ea92137),
  UINT64_C(0x54672a2aa82a4d82), UINT64_C(0x6b0abbbbd6bbb16d),
  UINT64_C(0x9f87c1c123c146e2), UINT64_C(0xa6f153535153a202),
  UINT64_C(0xa572dcdc57dcae8b), UINT64_C(0x16530b0b2c0b5827),
  UINT64_C(0x27019d9d4e9d9cd3), UINT64_C(0xd82b6c6cad6c47c1),
  UINT64_C(0x62a43131c43195f5), UINT64_C(0xe8f37474cd7487b9),
  UINT64_C(0xf115f6f6fff6e309), UINT64_C(0x8c4c464605460a43),
  UINT64_C(0x45a5acac8aac0926), UINT64_C(0x0fb589891e893c97),
  UINT64_C(0x28b414145014a044), UINT64_C(0xdfbae1e1a3e15b42),
  UINT64_C(0x2ca616165816b04e), UINT64_C(0x74f73a3ae83acdd2),
  UINT64_C(0xd2066969b9696fd0), UINT64_C(0x124109092409482d),
  UINT64_C(0xe0d77070dd70a7ad), UINT64_C(0x716fb6b6e2b6d954),
  UINT64_C(0xbd1ed0d067d0ceb7), UINT64_C(0xc7d6eded93ed3b7e),
  UINT64_C(0x85e2cccc17cc2edb), UINT64_C(0x8468424215422a57),
  UINT64_C(0x2d2c98985a98b4c2), UINT64_C(0x55eda4a4aaa4490e),
  UINT64_C(0x50752828a0285d88), UINT64_C(0xb8865c5c6d5cda31),
  UINT64_C(0xed6bf8f8c7f8933f), UINT64_C(0x11c28686228644a4)
};

static const uint64_t whirlpool_C3[256] = {
  UINT64_C(0x7830d818186018c0), UINT64_C(0xaf462623238c2305),
  UINT64_C(0xf991b8c6c63fc67e), UINT64_C(0x6fcdfbe8e887e813),
  UINT64_C(0xa113cb878726874c), UINT64_C(0x626d11b8b8dab8a9),
  UINT64_C(0x0502090101040108), UINT64_C(0x6e9e0d4f4f214f42),
  UINT64_C(0xee6c9b3636d836ad), UINT64_C(0x0451ffa6a6a2a659),
  UINT64_C(0xbdb90cd2d26fd2de), UINT64_C(0x06f70ef5f5f3f5fb),
  UINT64_C(0x80f2967979f979ef), UINT64_C(0xcede306f6fa16f5f),
  UINT64_C(0xef3f6d91917e91fc), UINT64_C(0x07a4f852525552aa),
  UINT64_C(0xfdc04760609d6027), UINT64_C(0x766535bcbccabc89),
  UINT64_C(0xcd2b379b9b569bac), UINT64_C(0x8c018a8e8e028e04),
  UINT64_C(0x155bd2a3a3b6a371), UINT64_C(0x3c186c0c0c300c60),
  UINT64_C(0x8af6847b7bf17bff), UINT64_C(0xe16a803535d435b5),
  UINT64_C(0x693af51d1d741de8), UINT64_C(0x47ddb3e0e0a7e053),
  UINT64_C(0xacb321d7d77bd7f6), UINT64_C(0xed999cc2c22fc25e),
  UINT64_C(0x965c432e2eb82e6d), UINT64_C(0x7a96294b4b314b62),
  UINT64_C(0x21e15dfefedffea3), UINT64_C(0x16aed55757415782),
  UINT64_C(0x412abd15155415a8), UINT64_C(0xb6eee87777c1779f),
  UINT64_C(0xeb6e923737dc37a5), UINT64_C(0x56d79ee5e5b3e57b),
  UINT64_C(0xd923139f9f469f8c), UINT64_C(0x17fd23f0f0e7f0d3),
  UINT64_C(0x7f94204a4a354a6a), UINT64_C(0x95a944dada4fda9e),
  UINT64_C(0x25b0a258587d58fa), UINT64_C(0xca8fcfc9c903c906),
  UINT64_C(0x8d527c2929a42955), UINT64_C(0x22145a0a0a280a50),
  UINT64_C(0x4f7f50b1b1feb1e1), UINT64_C(0x1a5dc9a0a0baa069),
  UINT64_C(0xdad6146b6bb16b7f), UINT64_C(0xab17d985852e855c),
  UINT64_C(0x73673cbdbdcebd81), UINT64_C(0x34ba8f5d5d695dd2),
  UINT64_C(0x5020901010401080), UINT64_C(0x03f507f4f4f7f4f3),
  UINT64_C(0xc08bddcbcb0bcb16), UINT64_C(0xc67cd33e3ef83eed),
  UINT64_C(0x110a2d0505140528), UINT64_C(0xe6ce78676781671f),
  UINT64_C(0x53d597e4e4b7e473), UINT64_C(0xbb4e0227279c2725),
  UINT64_C(0x5882734141194132), UINT64_C(0x9d0ba78b8b168b2c),
  UINT64_C(0x0153f6a7a7a6a751), UINT64_C(0x94fab27d7de97dcf),
  UINT64_C(0xfb374995956e95dc), UINT64_C(0x9fad56d8d847d88e),
  UINT64_C(0x30eb70fbfbcbfb8b), UINT64_C(0x71c1cdeeee9fee23),
  UINT64_C(0x91f8bb7c7ced7cc7), UINT64_C(0xe3cc716666856617),
  UINT64_C(0x8ea77bdddd53dda6), UINT64_C(0x4b2eaf17175c17b8),
  UINT64_C(0x468e454747014702), UINT64_C(0xdc211a9e9e429e84),
  UINT64_C(0xc589d4caca0fca1e), UINT64_C(0x995a582d2db42d75),
  UINT64_C(0x79632ebfbfc6bf91), UINT64_C(0x1b0e3f07071c0738),
  UINT64_C(0x2347acadad8ead01), UINT64_C(0x2fb4b05a5a755aea),
  UINT64_C(0xb51bef838336836c), UINT64_C(0xff66b63333cc3385),
  UINT64_C(0xf2c65c636391633f), UINT64_C(0x0a04120202080210),
  UINT64_C(0x384993aaaa92aa39), UINT64_C(0xa8e2de7171d971af),
  UINT64_C(0xcf8dc6c8c807c80e), UINT64_C(0x7d32d119196419c8),
  UINT64_C(0x70923b4949394972), UINT64_C(0x9aaf5fd9d943d986),
  UINT64_C(0x1df931f2f2eff2c3), UINT64_C(0x48dba8e3e3abe34b),
  UINT64_C(0x2ab6b95b5b715be2), UINT64_C(0x920dbc88881a8834),
  UINT64_C(0xc8293e9a9a529aa4), UINT64_C(0xbe4c0b262698262d),
  UINT64_C(0xfa64bf3232c8328d), UINT64_C(0x4a7d59b0b0fab0e9),
  UINT64_C(0x6acff2e9e983e91b), UINT64_C(0x331e770f0f3c0f78),
  UINT64_C(0xa6b733d5d573d5e6), UINT64_C(0xba1df480803a8074),
  UINT64_C(0x7c6127bebec2be99), UINT64_C(0xde87ebcdcd13cd26),
  UINT64_C(0xe468893434d034bd), UINT64_C(0x75903248483d487a),
  UINT64_C(0x24e354ffffdbffab), UINT64_C(0x8ff48d7a7af57af7),
  UINT64_C(0xea3d6490907a90f4), UINT64_C(0x3ebe9d5f5f615fc2),
  UINT64_C(0xa0403d202080201d), UINT64_C(0xd5d00f6868bd6867),
  UINT64_C(0x7234ca1a1a681ad0), UINT64_C(0x2c41b7aeae82ae19),
  UINT64_C(0x5e757db4b4eab4c9), UINT64_C(0x19a8ce54544d549a),
  UINT64_C(0xe53b7f93937693ec), UINT64_C(0xaa442f222288220d),
  UINT64_C(0xe9c86364648d6407), UINT64_C(0x12ff2af1f1e3f1db),
  UINT64_C(0xa2e6cc7373d173bf), UINT64_C(0x5a24821212481290),
  UINT64_C(0x5d807a40401d403a), UINT64_C(0x2810480808200840),
  UINT64_C(0xe89b95c3c32bc356), UINT64_C(0x7bc5dfecec97ec33),
  UINT64_C(0x90ab4ddbdb4bdb96), UINT64_C(0x1f5fc0a1a1bea161),
  UINT64_C(0x8307918d8d0e8d1c), UINT64_C(0xc97ac83d3df43df5),
  UINT64_C(0xf1335b97976697cc), UINT64_C(0x0000000000000000),
  UINT64_C(0xd483f9cfcf1bcf36), UINT64_C(0x87566e2b2bac2b45),
  UINT64_C(0xb3ece17676c57697), UINT64_C(0xb019e68282328264),
  UINT64_C(0xa9b128d6d67fd6fe), UINT64_C(0x7736c31b1b6c1bd8),
  UINT64_C(0x5b7774b5b5eeb5c1), UINT64_C(0x2943beafaf86af11),
  UINT64_C(0xdfd41d6a6ab56a77), UINT64_C(0x0da0ea50505d50ba),
  UINT64_C(0x4c8a574545094512), UINT64_C(0x18fb38f3f3ebf3cb),
  UINT64_C(0xf060ad3030c0309d), UINT64_C(0x74c3c4efef9bef2b),
  UINT64_C(0xc37eda3f3ffc3fe5), UINT64_C(0x1caac75555495592),
  UINT64_C(0x1059dba2a2b2a279), UINT64_C(0x65c9e9eaea8fea03),
  UINT64_C(0xecca6a656589650f), UINT64_C(0x686903babad2bab9),
  UINT64_C(0x935e4a2f2fbc2f65), UINT64_C(0xe79d8ec0c027c04e),
  UINT64_C(0x81a160dede5fdebe), UINT64_C(0x6c38fc1c1c701ce0),
  UINT64_C(0x2ee746fdfdd3fdbb), UINT64_C(0x649a1f4d4d294d52),
  UINT64_C(0xe0397692927292e4), UINT64_C(0xbceafa7575c9758f),
  UINT64_C(0x1e0c360606180630), UINT64_C(0x9809ae8a8a128a24),
  UINT64_C(0x40794bb2b2f2b2f9), UINT64_C(0x59d185e6e6bfe663),
  UINT64_C(0x361c7e0e0e380e70), UINT64_C(0x633ee71f1f7c1ff8),
  UINT64_C(0xf7c4556262956237), UINT64_C(0xa3b53ad4d477d4ee),
  UINT64_C(0x324d81a8a89aa829), UINT64_C(0xf4315296966296c4),
  UINT64_C(0x3aef62f9f9c3f99b), UINT64_C(0xf697a3c5c533c566),
  UINT64_C(0xb14a102525942535), UINT64_C(0x20b2ab59597959f2),
  UINT64_C(0xae15d084842a8454), UINT64_C(0xa7e4c57272d572b7),
  UINT64_C(0xdd72ec3939e439d5), UINT64_C(0x6198164c4c2d4c5a),
  UINT64_C(0x3bbc945e5e655eca), UINT64_C(0x85f09f7878fd78e7),
  UINT64_C(0xd870e53838e038dd), UINT64_C(0x8605988c8c0a8c14),
  UINT64_C(0xb2bf17d1d163d1c6), UINT64_C(0x0b57e4a5a5aea541),
  UINT64_C(0x4dd9a1e2e2afe243), UINT64_C(0xf8c24e616199612f),
  UINT64_C(0x457b42b3b3f6b3f1), UINT64_C(0xa542342121842115),
  UINT64_C(0xd625089c9c4a9c94), UINT64_C(0x663cee1e1e781ef0),
  UINT64_C(0x5286614343114322), UINT64_C(0xfc93b1c7c73bc776),
  UINT64_C(0x2be54ffcfcd7fcb3), UINT64_C(0x1408240404100420),
  UINT64_C(0x08a2e351515951b2), UINT64_C(0xc72f2599995e99bc),
  UINT64_C(0xc4da226d6da96d4f), UINT64_C(0x391a650d0d340d68),
  UINT64_C(0x35e979fafacffa83), UINT64_C(0x84a369dfdf5bdfb6),
  UINT64_C(0x9bfca97e7ee57ed7), UINT64_C(0xb44819242490243d),
  UINT64_C(0xd776fe3b3bec3bc5), UINT64_C(0x3d4b9aabab96ab31),
  UINT64_C(0xd181f0cece1fce3e), UINT64_C(0x5522991111441188),
  UINT64_C(0x8903838f8f068f0c), UINT64_C(0x6b9c044e4e254e4a),
  UINT64_C(0x517366b7b7e6b7d1), UINT64_C(0x60cbe0ebeb8beb0b),
  UINT64_C(0xcc78c13c3cf03cfd), UINT64_C(0xbf1ffd81813e817c),
  UINT64_C(0xfe354094946a94d4), UINT64_C(0x0cf31cf7f7fbf7eb),
  UINT64_C(0x676f18b9b9deb9a1), UINT64_C(0x5f268b13134c1398),
  UINT64_C(0x9c58512c2cb02c7d), UINT64_C(0xb8bb05d3d36bd3d6),
  UINT64_C(0x5cd38ce7e7bbe76b), UINT64_C(0xcbdc396e6ea56e57),
  UINT64_C(0xf395aac4c437c46e), UINT64_C(0x0f061b03030c0318),
  UINT64_C(0x13acdc565645568a), UINT64_C(0x49885e44440d441a),
  UINT64_C(0x9efea07f7fe17fdf), UINT64_C(0x374f88a9a99ea921),
  UINT64_C(0x8254672a2aa82a4d), UINT64_C(0x6d6b0abbbbd6bbb1),
  UINT64_C(0xe29f87c1c123c146), UINT64_C(0x02a6f153535153a2),
  UINT64_C(0x8ba572dcdc57dcae), UINT64_C(0x2716530b0b2c0b58),
  UINT64_C(0xd327019d9d4e9d9c), UINT64_C(0xc1d82b6c6cad6c47),
  UINT64_C(0xf562a43131c43195), UINT64_C(0xb9e8f37474cd7487),
  UINT64_C(0x09f115f6f6fff6e3), UINT64_C(0x438c4c464605460a),
  UINT64_C(0x2645a5acac8aac09), UINT64_C(0x970fb589891e893c),
  UINT64_C(0x4428b414145014a0), UINT64_C(0x42dfbae1e1a3e15b),
  UINT64_C(0x4e2ca616165816b0), UINT64_C(0xd274f73a3ae83acd),
  UINT64_C(0xd0d2066969b9696f), UINT64_C(0x2d12410909240948),
  UINT64_C(0xade0d77070dd70a7), UINT64_C(0x54716fb6b6e2b6d9),
  UINT64_C(0xb7bd1ed0d067d0ce), UINT64_C(0x7ec7d6eded93ed3b),
  UINT64_C(0xdb85e2cccc17cc2e), UINT64_C(0x578468424215422a),
  UINT64_C(0xc22d2c98985a98b4), UINT64_C(0x0e55eda4a4aaa449),
  UINT64_C(0x8850752828a0285d), UINT64_C(0x31b8865c5c6d5cda),
  UINT64_C(0x3fed6bf8f8c7f893), UINT64_C(0xa411c28686228644)
};

static const uint64_t whirlpool_C4[256] = {
  UINT64_C(0xc07830d818186018), UINT64_C(0x05af462623238c23),
  UINT64_C(0x7ef991b8c6c63fc6), UINT64_C(0x136fcdfbe8e887e8),
  UINT64_C(0x4ca113cb87872687), UINT64_C(0xa9626d11b8b8dab8),
  UINT64_C(0x0805020901010401), UINT64_C(0x426e9e0d4f4f214f),
  UINT64_C(0xadee6c9b3636d836), UINT64_C(0x590451ffa6a6a2a6),
  UINT64_C(0xdebdb90cd2d26fd2), UINT64_C(0xfb06f70ef5f5f3f5),
  UINT64_C(0xef80f2967979f979), UINT64_C(0x5fcede306f6fa16f),
  UINT64_C(0xfcef3f6d91917e91), UINT64_C(0xaa07a4f852525552),
  UINT64_C(0x27fdc04760609d60), UINT64_C(0x89766535bcbccabc),
  UINT64_C(0xaccd2b379b9b569b), UINT64_C(0x048c018a8e8e028e),
  UINT64_C(0x71155bd2a3a3b6a3), UINT64_C(0x603c186c0c0c300c),
  UINT64_C(0xff8af6847b7bf17b), UINT64_C(0xb5e16a803535d435),
  UINT64_C(0xe8693af51d1d741d), UINT64_C(0x5347ddb3e0e0a7e0),
  UINT64_C(0xf6acb321d7d77bd7), UINT64_C(0x5eed999cc2c22fc2),
  UINT64_C(0x6d965c432e2eb82e), UINT64_C(0x627a96294b4b314b),
  UINT64_C(0xa321e15dfefedffe), UINT64_C(0x8216aed557574157),
  UINT64_C(0xa8412abd15155415), UINT64_C(0x9fb6eee87777c177),
  UINT64_C(0xa5eb6e923737dc37), UINT64_C(0x7b56d79ee5e5b3e5),
  UINT64_C(0x8cd923139f9f469f), UINT64_C(0xd317fd23f0f0e7f0),
  UINT64_C(0x6a7f94204a4a354a), UINT64_C(0x9e95a944dada4fda),
  UINT64_C(0xfa25b0a258587d58), UINT64_C(0x06ca8fcfc9c903c9),
  UINT64_C(0x558d527c2929a429), UINT64_C(0x5022145a0a0a280a),
  UINT64_C(0xe14f7f50b1b1feb1), UINT64_C(0x691a5dc9a0a0baa0),
  UINT64_C(0x7fdad6146b6bb16b), UINT64_C(0x5cab17d985852e85),
  UINT64_C(0x8173673cbdbdcebd), UINT64_C(0xd234ba8f5d5d695d),
  UINT64_C(0x8050209010104010), UINT64_C(0xf303f507f4f4f7f4),
  UINT64_C(0x16c08bddcbcb0bcb), UINT64_C(0xedc67cd33e3ef83e),
  UINT64_C(0x28110a2d05051405), UINT64_C(0x1fe6ce7867678167),
  UINT64_C(0x7353d597e4e4b7e4), UINT64_C(0x25bb4e0227279c27),
  UINT64_C(0x3258827341411941), UINT64_C(0x2c9d0ba78b8b168b),
  UINT64_C(0x510153f6a7a7a6a7), UINT64_C(0xcf94fab27d7de97d),
  UINT64_C(0xdcfb374995956e95), UINT64_C(0x8e9fad56d8d847d8),
  UINT64_C(0x8b30eb70fbfbcbfb), UINT64_C(0x2371c1cdeeee9fee),
  UINT64_C(0xc791f8bb7c7ced7c), UINT64_C(0x17e3cc7166668566),
  UINT64_C(0xa68ea77bdddd53dd), UINT64_C(0xb84b2eaf17175c17),
  UINT64_C(0x02468e4547470147), UINT64_C(0x84dc211a9e9e429e),
  UINT64_C(0x1ec589d4caca0fca), UINT64_C(0x75995a582d2db42d),
  UINT64_C(0x9179632ebfbfc6bf), UINT64_C(0x381b0e3f07071c07),
  UINT64_C(0x012347acadad8ead), UINT64_C(0xea2fb4b05a5a755a),
  UINT64_C(0x6cb51bef83833683), UINT64_C(0x85ff66b63333cc33),
  UINT64_C(0x3ff2c65c63639163), UINT64_C(0x100a041202020802),
  UINT64_C(0x39384993aaaa92aa), UINT64_C(0xafa8e2de7171d971),
  UINT64_C(0x0ecf8dc6c8c807c8), UINT64_C(0xc87d32d119196419),
  UINT64_C(0x7270923b49493949), UINT64_C(0x869aaf5fd9d943d9),
  UINT64_C(0xc31df931f2f2eff2), UINT64_C(0x4b48dba8e3e3abe3),
  UINT64_C(0xe22ab6b95b5b715b), UINT64_C(0x34920dbc88881a88),
  UINT64_C(0xa4c8293e9a9a529a), UINT64_C(0x2dbe4c0b26269826),
  UINT64_C(0x8dfa64bf3232c832), UINT64_C(0xe94a7d59b0b0fab0),
  UINT64_C(0x1b6acff2e9e983e9), UINT64_C(0x78331e770f0f3c0f),
  UINT64_C(0xe6a6b733d5d573d5), UINT64_C(0x74ba1df480803a80),
  UINT64_C(0x997c6127bebec2be), UINT64_C(0x26de87ebcdcd13cd),
  UINT64_C(0xbde468893434d034), UINT64_C(0x7a75903248483d48),
  UINT64_C(0xab24e354ffffdbff), UINT64_C(0xf78ff48d7a7af57a),
  UINT64_C(0xf4ea3d6490907a90), UINT64_C(0xc23ebe9d5f5f615f),
  UINT64_C(0x1da0403d20208020), UINT64_C(0x67d5d00f6868bd68),
  UINT64_C(0xd07234ca1a1a681a), UINT64_C(0x192c41b7aeae82ae),
  UINT64_C(0xc95e757db4b4eab4), UINT64_C(0x9a19a8ce54544d54),
  UINT64_C(0xece53b7f93937693), UINT64_C(0x0daa442f22228822),
  UINT64_C(0x07e9c86364648d64), UINT64_C(0xdb12ff2af1f1e3f1),
  UINT64_C(0xbfa2e6cc7373d173), UINT64_C(0x905a248212124812),
  UINT64_C(0x3a5d807a40401d40), UINT64_C(0x4028104808082008),
  UINT64_C(0x56e89b95c3c32bc3), UINT64_C(0x337bc5dfecec97ec),
  UINT64_C(0x9690ab4ddbdb4bdb), UINT64_C(0x611f5fc0a1a1bea1),
  UINT64_C(0x1c8307918d8d0e8d), UINT64_C(0xf5c97ac83d3df43d),
  UINT64_C(0xccf1335b97976697), UINT64_C(0x0000000000000000),
  UINT64_C(0x36d483f9cfcf1bcf), UINT64_C(0x4587566e2b2bac2b),
  UINT64_C(0x97b3ece17676c576), UINT64_C(0x64b019e682823282),
  UINT64_C(0xfea9b128d6d67fd6), UINT64_C(0xd87736c31b1b6c1b),
  UINT64_C(0xc15b7774b5b5eeb5), UINT64_C(0x112943beafaf86af),
  UINT64_C(0x77dfd41d6a6ab56a), UINT64_C(0xba0da0ea50505d50),
  UINT64_C(0x124c8a5745450945), UINT64_C(0xcb18fb38f3f3ebf3),
  UINT64_C(0x9df060ad3030c030), UINT64_C(0x2b74c3c4efef9bef),
  UINT64_C(0xe5c37eda3f3ffc3f), UINT64_C(0x921caac755554955),
  UINT64_C(0x791059dba2a2b2a2), UINT64_C(0x0365c9e9eaea8fea),
  UINT64_C(0x0fecca6a65658965), UINT64_C(0xb9686903babad2ba),
  UINT64_C(0x65935e4a2f2fbc2f), UINT64_C(0x4ee79d8ec0c027c0),
  UINT64_C(0xbe81a160dede5fde), UINT64_C(0xe06c38fc1c1c701c),
  UINT64_C(0xbb2ee746fdfdd3fd), UINT64_C(0x52649a1f4d4d294d),
  UINT64_C(0xe4e0397692927292), UINT64_C(0x8fbceafa7575c975),
  UINT64_C(0x301e0c3606061806), UINT64_C(0x249809ae8a8a128a),
  UINT64_C(0xf940794bb2b2f2b2), UINT64_C(0x6359d185e6e6bfe6),
  UINT64_C(0x70361c7e0e0e380e), UINT64_C(0xf8633ee71f1f7c1f),
  UINT64_C(0x37f7c45562629562), UINT64_C(0xeea3b53ad4d477d4),
  UINT64_C(0x29324d81a8a89aa8), UINT64_C(0xc4f4315296966296),
  UINT64_C(0x9b3aef62f9f9c3f9), UINT64_C(0x66f697a3c5c533c5),
  UINT64_C(0x35b14a1025259425), UINT64_C(0xf220b2ab59597959),
  UINT64_C(0x54ae15d084842a84), UINT64_C(0xb7a7e4c57272d572),
  UINT64_C(0xd5dd72ec3939e439), UINT64_C(0x5a6198164c4c2d4c),
  UINT64_C(0xca3bbc945e5e655e), UINT64_C(0xe785f09f7878fd78),
  UINT64_C(0xddd870e53838e038), UINT64_C(0x148605988c8c0a8c),
  UINT64_C(0xc6b2bf17d1d163d1), UINT64_C(0x410b57e4a5a5aea5),
  UINT64_C(0x434dd9a1e2e2afe2), UINT64_C(0x2ff8c24e61619961),
  UINT64_C(0xf1457b42b3b3f6b3), UINT64_C(0x15a5423421218421),
  UINT64_C(0x94d625089c9c4a9c), UINT64_C(0xf0663cee1e1e781e),
  UINT64_C(0x2252866143431143), UINT64_C(0x76fc93b1c7c73bc7),
  UINT64_C(0xb32be54ffcfcd7fc), UINT64_C(0x2014082404041004),
  UINT64_C(0xb208a2e351515951), UINT64_C(0xbcc72f2599995e99),
  UINT64_C(0x4fc4da226d6da96d), UINT64_C(0x68391a650d0d340d),
  UINT64_C(0x8335e979fafacffa), UINT64_C(0xb684a369dfdf5bdf),
  UINT64_C(0xd79bfca97e7ee57e), UINT64_C(0x3db4481924249024),
  UINT64_C(0xc5d776fe3b3bec3b), UINT64_C(0x313d4b9aabab96ab),
  UINT64_C(0x3ed181f0cece1fce), UINT64_C(0x8855229911114411),
  UINT64_C(0x0c8903838f8f068f), UINT64_C(0x4a6b9c044e4e254e),
  UINT64_C(0xd1517366b7b7e6b7), UINT64_C(0x0b60cbe0ebeb8beb),
  UINT64_C(0xfdcc78c13c3cf03c), UINT64_C(0x7cbf1ffd81813e81),
  UINT64_C(0xd4fe354094946a94), UINT64_C(0xeb0cf31cf7f7fbf7),
  UINT64_C(0xa1676f18b9b9deb9), UINT64_C(0x985f268b13134c13),
  UINT64_C(0x7d9c58512c2cb02c), UINT64_C(0xd6b8bb05d3d36bd3),
  UINT64_C(0x6b5cd38ce7e7bbe7), UINT64_C(0x57cbdc396e6ea56e),
  UINT64_C(0x6ef395aac4c437c4), UINT64_C(0x180f061b03030c03),
  UINT64_C(0x8a13acdc56564556), UINT64_C(0x1a49885e44440d44),
  UINT64_C(0xdf9efea07f7fe17f), UINT64_C(0x21374f88a9a99ea9),
  UINT64_C(0x4d8254672a2aa82a), UINT64_C(0xb16d6b0abbbbd6bb),
  UINT64_C(0x46e29f87c1c123c1), UINT64_C(0xa202a6f153535153),
  UINT64_C(0xae8ba572dcdc57dc), UINT64_C(0x582716530b0b2c0b),
  UINT64_C(0x9cd327019d9d4e9d), UINT64_C(0x47c1d82b6c6cad6c),
  UINT64_C(0x95f562a43131c431), UINT64_C(0x87b9e8f37474cd74),
  UINT64_C(0xe309f115f6f6fff6), UINT64_C(0x0a438c4c46460546),
  UINT64_C(0x092645a5acac8aac), UINT64_C(0x3c970fb589891e89),
  UINT64_C(0xa04428b414145014), UINT64_C(0x5b42dfbae1e1a3e1),
  UINT64_C(0xb04e2ca616165816), UINT64_C(0xcdd274f73a3ae83a),
  UINT64_C(0x6fd0d2066969b969), UINT64_C(0x482d124109092409),
  UINT64_C(0xa7ade0d77070dd70), UINT64_C(0xd954716fb6b6e2b6),
  UINT64_C(0xceb7bd1ed0d067d0), UINT64_C(0x3b7ec7d6eded93ed),
  UINT64_C(0x2edb85e2cccc17cc), UINT64_C(0x2a57846842421542),
  UINT64_C(0xb4c22d2c98985a98), UINT64_C(0x490e55eda4a4aaa4),
  UINT64_C(0x5d8850752828a028), UINT64_C(0xda31b8865c5c6d5c),
  UINT64_C(0x933fed6bf8f8c7f8), UINT64_C(0x44a411c286862286)
};

static const uint64_t whirlpool_C5[256] = {
  UINT64_C(0x18c07830d8181860), UINT64_C(0x2305af462623238c),
  UINT64_C(0xc67ef991b8c6c63f), UINT64_C(0xe8136fcdfbe8e887),
  UINT64_C(0x874ca113cb878726), UINT64_C(0xb8a9626d11b8b8da),
  UINT64_C(0x0108050209010104), UINT64_C(0x4f426e9e0d4f4f21),
  UINT64_C(0x36adee6c9b3636d8), UINT64_C(0xa6590451ffa6a6a2),
  UINT64_C(0xd2debdb90cd2d26f), UINT64_C(0xf5fb06f70ef5f5f3),
  UINT64_C(0x79ef80f2967979f9), UINT64_C(0x6f5fcede306f6fa1),
  UINT64_C(0x91fcef3f6d91917e), UINT64_C(0x52aa07a4f8525255),
  UINT64_C(0x6027fdc04760609d), UINT64_C(0xbc89766535bcbcca),
  UINT64_C(0x9baccd2b379b9b56), UINT64_C(0x8e048c018a8e8e02),
  UINT64_C(0xa371155bd2a3a3b6), UINT64_C(0x0c603c186c0c0c30),
  UINT64_C(0x7bff8af6847b7bf1), UINT64_C(0x35b5e16a803535d4),
  UINT64_C(0x1de8693af51d1d74), UINT64_C(0xe05347ddb3e0e0a7),
  UINT64_C(0xd7f6acb321d7d77b), UINT64_C(0xc25eed999cc2c22f),
  UINT64_C(0x2e6d965c432e2eb8), UINT64_C(0x4b627a96294b4b31),
  UINT64_C(0xfea321e15dfefedf), UINT64_C(0x578216aed5575741),
  UINT64_C(0x15a8412abd151554), UINT64_C(0x779fb6eee87777c1),
  UINT64_C(0x37a5eb6e923737dc), UINT64_C(0xe57b56d79ee5e5b3),
  UINT64_C(0x9f8cd923139f9f46), UINT64_C(0xf0d317fd23f0f0e7),
  UINT64_C(0x4a6a7f94204a4a35), UINT64_C(0xda9e95a944dada4f),
  UINT64_C(0x58fa25b0a258587d), UINT64_C(0xc906ca8fcfc9c903),
  UINT64_C(0x29558d527c2929a4), UINT64_C(0x0a5022145a0a0a28),
  UINT64_C(0xb1e14f7f50b1b1fe), UINT64_C(0xa0691a5dc9a0a0ba),
  UINT64_C(0x6b7fdad6146b6bb1), UINT64_C(0x855cab17d985852e),
  UINT64_C(0xbd8173673cbdbdce), UINT64_C(0x5dd234ba8f5d5d69),
  UINT64_C(0x1080502090101040), UINT64_C(0xf4f303f507f4f4f7),
  UINT64_C(0xcb16c08bddcbcb0b), UINT64_C(0x3eedc67cd33e3ef8),
  UINT64_C(0x0528110a2d050514), UINT64_C(0x671fe6ce78676781),
  UINT64_C(0xe47353d597e4e4b7), UINT64_C(0x2725bb4e0227279c),
  UINT64_C(0x4132588273414119), UINT64_C(0x8b2c9d0ba78b8b16),
  UINT64_C(0xa7510153f6a7a7a6), UINT64_C(0x7dcf94fab27d7de9),
  UINT64_C(0x95dcfb374995956e), UINT64_C(0xd88e9fad56d8d847),
  UINT64_C(0xfb8b30eb70fbfbcb), UINT64_C(0xee2371c1cdeeee9f),
  UINT64_C(0x7cc791f8bb7c7ced), UINT64_C(0x6617e3cc71666685),
  UINT64_C(0xdda68ea77bdddd53), UINT64_C(0x17b84b2eaf17175c),
  UINT64_C(0x4702468e45474701), UINT64_C(0x9e84dc211a9e9e42),
  UINT64_C(0xca1ec589d4caca0f), UINT64_C(0x2d75995a582d2db4),
  UINT64_C(0xbf9179632ebfbfc6), UINT64_C(0x07381b0e3f07071c),
  UINT64_C(0xad012347acadad8e), UINT64_C(0x5aea2fb4b05a5a75),
  UINT64_C(0x836cb51bef838336), UINT64_C(0x3385ff66b63333cc),
  UINT64_C(0x633ff2c65c636391), UINT64_C(0x02100a0412020208),
  UINT64_C(0xaa39384993aaaa92), UINT64_C(0x71afa8e2de7171d9),
  UINT64_C(0xc80ecf8dc6c8c807), UINT64_C(0x19c87d32d1191964),
  UINT64_C(0x497270923b494939), UINT64_C(0xd9869aaf5fd9d943),
  UINT64_C(0xf2c31df931f2f2ef), UINT64_C(0xe34b48dba8e3e3ab),
  UINT64_C(0x5be22ab6b95b5b71), UINT64_C(0x8834920dbc88881a),
  UINT64_C(0x9aa4c8293e9a9a52), UINT64_C(0x262dbe4c0b262698),
  UINT64_C(0x328dfa64bf3232c8), UINT64_C(0xb0e94a7d59b0b0fa),
  UINT64_C(0xe91b6acff2e9e983), UINT64_C(0x0f78331e770f0f3c),
  UINT64_C(0xd5e6a6b733d5d573), UINT64_C(0x8074ba1df480803a),
  UINT64_C(0xbe997c6127bebec2), UINT64_C(0xcd26de87ebcdcd13),
  UINT64_C(0x34bde468893434d0), UINT64_C(0x487a75903248483d),
  UINT64_C(0xffab24e354ffffdb), UINT64_C(0x7af78ff48d7a7af5),
  UINT64_C(0x90f4ea3d6490907a), UINT64_C(0x5fc23ebe9d5f5f61),
  UINT64_C(0x201da0403d202080), UINT64_C(0x6867d5d00f6868bd),
  UINT64_C(0x1ad07234ca1a1a68), UINT64_C(0xae192c41b7aeae82),
  UINT64_C(0xb4c95e757db4b4ea), UINT64_C(0x549a19a8ce54544d),
  UINT64_C(0x93ece53b7f939376), UINT64_C(0x220daa442f222288),
  UINT64_C(0x6407e9c86364648d), UINT64_C(0xf1db12ff2af1f1e3),
  UINT64_C(0x73bfa2e6cc7373d1), UINT64_C(0x12905a2482121248),
  UINT64_C(0x403a5d807a40401d), UINT64_C(0x0840281048080820),
  UINT64_C(0xc356e89b95c3c32b), UINT64_C(0xec337bc5dfecec97),
  UINT64_C(0xdb9690ab4ddbdb4b), UINT64_C(0xa1611f5fc0a1a1be),
  UINT64_C(0x8d1c8307918d8d0e), UINT64_C(0x3df5c97ac83d3df4),
  UINT64_C(0x97ccf1335b979766), UINT64_C(0x0000000000000000),
  UINT64_C(0xcf36d483f9cfcf1b), UINT64_C(0x2b4587566e2b2bac),
  UINT64_C(0x7697b3ece17676c5), UINT64_C(0x8264b019e6828232),
  UINT64_C(0xd6fea9b128d6d67f), UINT64_C(0x1bd87736c31b1b6c),
  UINT64_C(0xb5c15b7774b5b5ee), UINT64_C(0xaf112943beafaf86),
  UINT64_C(0x6a77dfd41d6a6ab5), UINT64_C(0x50ba0da0ea50505d),
  UINT64_C(0x45124c8a57454509), UINT64_C(0xf3cb18fb38f3f3eb),
  UINT64_C(0x309df060ad3030c0), UINT64_C(0xef2b74c3c4efef9b),
  UINT64_C(0x3fe5c37eda3f3ffc), UINT64_C(0x55921caac7555549),
  UINT64_C(0xa2791059dba2a2b2), UINT64_C(0xea0365c9e9eaea8f),
  UINT64_C(0x650fecca6a656589), UINT64_C(0xbab9686903babad2),
  UINT64_C(0x2f65935e4a2f2fbc), UINT64_C(0xc04ee79d8ec0c027),
  UINT64_C(0xdebe81a160dede5f), UINT64_C(0x1ce06c38fc1c1c70),
  UINT64_C(0xfdbb2ee746fdfdd3), UINT64_C(0x4d52649a1f4d4d29),
  UINT64_C(0x92e4e03976929272), UINT64_C(0x758fbceafa7575c9),
  UINT64_C(0x06301e0c36060618), UINT64_C(0x8a249809ae8a8a12),
  UINT64_C(0xb2f940794bb2b2f2), UINT64_C(0xe66359d185e6e6bf),
  UINT64_C(0x0e70361c7e0e0e38), UINT64_C(0x1ff8633ee71f1f7c),
  UINT64_C(0x6237f7c455626295), UINT64_C(0xd4eea3b53ad4d477),
  UINT64_C(0xa829324d81a8a89a), UINT64_C(0x96c4f43152969662),
  UINT64_C(0xf99b3aef62f9f9c3), UINT64_C(0xc566f697a3c5c533),
  UINT64_C(0x2535b14a10252594), UINT64_C(0x59f220b2ab595979),
  UINT64_C(0x8454ae15d084842a), UINT64_C(0x72b7a7e4c57272d5),
  UINT64_C(0x39d5dd72ec3939e4), UINT64_C(0x4c5a6198164c4c2d),
  UINT64_C(0x5eca3bbc945e5e65), UINT64_C(0x78e785f09f7878fd),
  UINT64_C(0x38ddd870e53838e0), UINT64_C(0x8c148605988c8c0a),
  UINT64_C(0xd1c6b2bf17d1d163), UINT64_C(0xa5410b57e4a5a5ae),
  UINT64_C(0xe2434dd9a1e2e2af), UINT64_C(0x612ff8c24e616199),
  UINT64_C(0xb3f1457b42b3b3f6), UINT64_C(0x2115a54234212184),
  UINT64_C(0x9c94d625089c9c4a), UINT64_C(0x1ef0663cee1e1e78),
  UINT64_C(0x4322528661434311), UINT64_C(0xc776fc93b1c7c73b),
  UINT64_C(0xfcb32be54ffcfcd7), UINT64_C(0x0420140824040410),
  UINT64_C(0x51b208a2e3515159), UINT64_C(0x99bcc72f2599995e),
  UINT64_C(0x6d4fc4da226d6da9), UINT64_C(0x0d68391a650d0d34),
  UINT64_C(0xfa8335e979fafacf), UINT64_C(0xdfb684a369dfdf5b),
  UINT64_C(0x7ed79bfca97e7ee5), UINT64_C(0x243db44819242490),
  UINT64_C(0x3bc5d776fe3b3bec), UINT64_C(0xab313d4b9aabab96),
  UINT64_C(0xce3ed181f0cece1f), UINT64_C(0x1188552299111144),
  UINT64_C(0x8f0c8903838f8f06), UINT64_C(0x4e4a6b9c044e4e25),
  UINT64_C(0xb7d1517366b7b7e6), UINT64_C(0xeb0b60cbe0ebeb8b),
  UINT64_C(0x3cfdcc78c13c3cf0), UINT64_C(0x817cbf1ffd81813e),
  UINT64_C(0x94d4fe354094946a), UINT64_C(0xf7eb0cf31cf7f7fb),
  UINT64_C(0xb9a1676f18b9b9de), UINT64_C(0x13985f268b13134c),
  UINT64_C(0x2c7d9c58512c2cb0), UINT64_C(0xd3d6b8bb05d3d36b),
  UINT64_C(0xe76b5cd38ce7e7bb), UINT64_C(0x6e57cbdc396e6ea5),
  UINT64_C(0xc46ef395aac4c437), UINT64_C(0x03180f061b03030c),
  UINT64_C(0x568a13acdc565645), UINT64_C(0x441a49885e44440d),
  UINT64_C(0x7fdf9efea07f7fe1), UINT64_C(0xa921374f88a9a99e),
  UINT64_C(0x2a4d8254672a2aa8), UINT64_C(0xbbb16d6b0abbbbd6),
  UINT64_C(0xc146e29f87c1c123), UINT64_C(0x53a202a6f1535351),
  UINT64_C(0xdcae8ba572dcdc57), UINT64_C(0x0b582716530b0b2c),
  UINT64_C(0x9d9cd327019d9d4e), UINT64_C(0x6c47c1d82b6c6cad),
  UINT64_C(0x3195f562a43131c4), UINT64_C(0x7487b9e8f37474cd),
  UINT64_C(0xf6e309f115f6f6ff), UINT64_C(0x460a438c4c464605),
  UINT64_C(0xac092645a5acac8a), UINT64_C(0x893c970fb589891e),
  UINT64_C(0x14a04428b4141450), UINT64_C(0xe15b42dfbae1e1a3),
  UINT64_C(0x16b04e2ca6161658), UINT64_C(0x3acdd274f73a3ae8),
  UINT64_C(0x696fd0d2066969b9), UINT64_C(0x09482d1241090924),
  UINT64_C(0x70a7ade0d77070dd), UINT64_C(0xb6d954716fb6b6e2),
  UINT64_C(0xd0ceb7bd1ed0d067), UINT64_C(0xed3b7ec7d6eded93),
  UINT64_C(0xcc2edb85e2cccc17), UINT64_C(0x422a578468424215),
  UINT64_C(0x98b4c22d2c98985a), UINT64_C(0xa4490e55eda4a4aa),
  UINT64_C(0x285d8850752828a0), UINT64_C(0x5cda31b8865c5c6d),
  UINT64_C(0xf8933fed6bf8f8c7), UINT64_C(0x8644a411c2868622)
};

static const uint64_t whirlpool_C6[256] = {
  UINT64_C(0x6018c07830d81818), UINT64_C(0x8c2305af46262323),
  UINT64_C(0x3fc67ef991b8c6c6), UINT64_C(0x87e8136fcdfbe8e8),
  UINT64_C(0x26874ca113cb8787), UINT64_C(0xdab8a9626d11b8b8),
  UINT64_C(0x0401080502090101), UINT64_C(0x214f426e9e0d4f4f),
  UINT64_C(0xd836adee6c9b3636), UINT64_C(0xa2a6590451ffa6a6),
  UINT64_C(0x6fd2debdb90cd2d2), UINT64_C(0xf3f5fb06f70ef5f5),
  UINT64_C(0xf979ef80f2967979), UINT64_C(0xa16f5fcede306f6f),
  UINT64_C(0x7e91fcef3f6d9191), UINT64_C(0x5552aa07a4f85252),
  UINT64_C(0x9d6027fdc0476060), UINT64_C(0xcabc89766535bcbc),
  UINT64_C(0x569baccd2b379b9b), UINT64_C(0x028e048c018a8e8e),
  UINT64_C(0xb6a371155bd2a3a3), UINT64_C(0x300c603c186c0c0c),
  UINT64_C(0xf17bff8af6847b7b), UINT64_C(0xd435b5e16a803535),
  UINT64_C(0x741de8693af51d1d), UINT64_C(0xa7e05347ddb3e0e0),
  UINT64_C(0x7bd7f6acb321d7d7), UINT64_C(0x2fc25eed999cc2c2),
  UINT64_C(0xb82e6d965c432e2e), UINT64_C(0x314b627a96294b4b),
  UINT64_C(0xdffea321e15dfefe), UINT64_C(0x41578216aed55757),
  UINT64_C(0x5415a8412abd1515), UINT64_C(0xc1779fb6eee87777),
  UINT64_C(0xdc37a5eb6e923737), UINT64_C(0xb3e57b56d79ee5e5),
  UINT64_C(0x469f8cd923139f9f), UINT64_C(0xe7f0d317fd23f0f0),
  UINT64_C(0x354a6a7f94204a4a), UINT64_C(0x4fda9e95a944dada),
  UINT64_C(0x7d58fa25b0a25858), UINT64_C(0x03c906ca8fcfc9c9),
  UINT64_C(0xa429558d527c2929), UINT64_C(0x280a5022145a0a0a),
  UINT64_C(0xfeb1e14f7f50b1b1), UINT64_C(0xbaa0691a5dc9a0a0),
  UINT64_C(0xb16b7fdad6146b6b), UINT64_C(0x2e855cab17d98585),
  UINT64_C(0xcebd8173673cbdbd), UINT64_C(0x695dd234ba8f5d5d),
  UINT64_C(0x4010805020901010), UINT64_C(0xf7f4f303f507f4f4),
  UINT64_C(0x0bcb16c08bddcbcb), UINT64_C(0xf83eedc67cd33e3e),
  UINT64_C(0x140528110a2d0505), UINT64_C(0x81671fe6ce786767),
  UINT64_C(0xb7e47353d597e4e4), UINT64_C(0x9c2725bb4e022727),
  UINT64_C(0x1941325882734141), UINT64_C(0x168b2c9d0ba78b8b),
  UINT64_C(0xa6a7510153f6a7a7), UINT64_C(0xe97dcf94fab27d7d),
  UINT64_C(0x6e95dcfb37499595), UINT64_C(0x47d88e9fad56d8d8),
  UINT64_C(0xcbfb8b30eb70fbfb), UINT64_C(0x9fee2371c1cdeeee),
  UINT64_C(0xed7cc791f8bb7c7c), UINT64_C(0x856617e3cc716666),
  UINT64_C(0x53dda68ea77bdddd), UINT64_C(0x5c17b84b2eaf1717),
  UINT64_C(0x014702468e454747), UINT64_C(0x429e84dc211a9e9e),
  UINT64_C(0x0fca1ec589d4caca), UINT64_C(0xb42d75995a582d2d),
  UINT64_C(0xc6bf9179632ebfbf), UINT64_C(0x1c07381b0e3f0707),
  UINT64_C(0x8ead012347acadad), UINT64_C(0x755aea2fb4b05a5a),
  UINT64_C(0x36836cb51bef8383), UINT64_C(0xcc3385ff66b63333),
  UINT64_C(0x91633ff2c65c6363), UINT64_C(0x0802100a04120202),
  UINT64_C(0x92aa39384993aaaa), UINT64_C(0xd971afa8e2de7171),
  UINT64_C(0x07c80ecf8dc6c8c8), UINT64_C(0x6419c87d32d11919),
  UINT64_C(0x39497270923b4949), UINT64_C(0x43d9869aaf5fd9d9),
  UINT64_C(0xeff2c31df931f2f2), UINT64_C(0xabe34b48dba8e3e3),
  UINT64_C(0x715be22ab6b95b5b), UINT64_C(0x1a8834920dbc8888),
  UINT64_C(0x529aa4c8293e9a9a), UINT64_C(0x98262dbe4c0b2626),
  UINT64_C(0xc8328dfa64bf3232), UINT64_C(0xfab0e94a7d59b0b0),
  UINT64_C(0x83e91b6acff2e9e9), UINT64_C(0x3c0f78331e770f0f),
  UINT64_C(0x73d5e6a6b733d5d5), UINT64_C(0x3a8074ba1df48080),
  UINT64_C(0xc2be997c6127bebe), UINT64_C(0x13cd26de87ebcdcd),
  UINT64_C(0xd034bde468893434), UINT64_C(0x3d487a7590324848),
  UINT64_C(0xdbffab24e354ffff), UINT64_C(0xf57af78ff48d7a7a),
  UINT64_C(0x7a90f4ea3d649090), UINT64_C(0x615fc23ebe9d5f5f),
  UINT64_C(0x80201da0403d2020), UINT64_C(0xbd6867d5d00f6868),
  UINT64_C(0x681ad07234ca1a1a), UINT64_C(0x82ae192c41b7aeae),
  UINT64_C(0xeab4c95e757db4b4), UINT64_C(0x4d549a19a8ce5454),
  UINT64_C(0x7693ece53b7f9393), UINT64_C(0x88220daa442f2222),
  UINT64_C(0x8d6407e9c8636464), UINT64_C(0xe3f1db12ff2af1f1),
  UINT64_C(0xd173bfa2e6cc7373), UINT64_C(0x4812905a24821212),
  UINT64_C(0x1d403a5d807a4040), UINT64_C(0x2008402810480808),
  UINT64_C(0x2bc356e89b95c3c3), UINT64_C(0x97ec337bc5dfecec),
  UINT64_C(0x4bdb9690ab4ddbdb), UINT64_C(0xbea1611f5fc0a1a1),
  UINT64_C(0x0e8d1c8307918d8d), UINT64_C(0xf43df5c97ac83d3d),
  UINT64_C(0x6697ccf1335b9797), UINT64_C(0x0000000000000000),
  UINT64_C(0x1bcf36d483f9cfcf), UINT64_C(0xac2b4587566e2b2b),
  UINT64_C(0xc57697b3ece17676), UINT64_C(0x328264b019e68282),
  UINT64_C(0x7fd6fea9b128d6d6), UINT64_C(0x6c1bd87736c31b1b),
  UINT64_C(0xeeb5c15b7774b5b5), UINT64_C(0x86af112943beafaf),
  UINT64_C(0xb56a77dfd41d6a6a), UINT64_C(0x5d50ba0da0ea5050),
  UINT64_C(0x0945124c8a574545), UINT64_C(0xebf3cb18fb38f3f3),
  UINT64_C(0xc0309df060ad3030), UINT64_C(0x9bef2b74c3c4efef),
  UINT64_C(0xfc3fe5c37eda3f3f), UINT64_C(0x4955921caac75555),
  UINT64_C(0xb2a2791059dba2a2), UINT64_C(0x8fea0365c9e9eaea),
  UINT64_C(0x89650fecca6a6565), UINT64_C(0xd2bab9686903baba),
  UINT64_C(0xbc2f65935e4a2f2f), UINT64_C(0x27c04ee79d8ec0c0),
  UINT64_C(0x5fdebe81a160dede), UINT64_C(0x701ce06c38fc1c1c),
  UINT64_C(0xd3fdbb2ee746fdfd), UINT64_C(0x294d52649a1f4d4d),
  UINT64_C(0x7292e4e039769292), UINT64_C(0xc9758fbceafa7575),
  UINT64_C(0x1806301e0c360606), UINT64_C(0x128a249809ae8a8a),
  UINT64_C(0xf2b2f940794bb2b2), UINT64_C(0xbfe66359d185e6e6),
  UINT64_C(0x380e70361c7e0e0e), UINT64_C(0x7c1ff8633ee71f1f),
  UINT64_C(0x956237f7c4556262), UINT64_C(0x77d4eea3b53ad4d4),
  UINT64_C(0x9aa829324d81a8a8), UINT64_C(0x6296c4f431529696),
  UINT64_C(0xc3f99b3aef62f9f9), UINT64_C(0x33c566f697a3c5c5),
  UINT64_C(0x942535b14a102525), UINT64_C(0x7959f220b2ab5959),
  UINT64_C(0x2a8454ae15d08484), UINT64_C(0xd572b7a7e4c57272),
  UINT64_C(0xe439d5dd72ec3939), UINT64_C(0x2d4c5a6198164c4c),
  UINT64_C(0x655eca3bbc945e5e), UINT64_C(0xfd78e785f09f7878),
  UINT64_C(0xe038ddd870e53838), UINT64_C(0x0a8c148605988c8c),
  UINT64_C(0x63d1c6b2bf17d1d1), UINT64_C(0xaea5410b57e4a5a5),
  UINT64_C(0xafe2434dd9a1e2e2), UINT64_C(0x99612ff8c24e6161),
  UINT64_C(0xf6b3f1457b42b3b3), UINT64_C(0x842115a542342121),
  UINT64_C(0x4a9c94d625089c9c), UINT64_C(0x781ef0663cee1e1e),
  UINT64_C(0x1143225286614343), UINT64_C(0x3bc776fc93b1c7c7),
  UINT64_C(0xd7fcb32be54ffcfc), UINT64_C(0x1004201408240404),
  UINT64_C(0x5951b208a2e35151), UINT64_C(0x5e99bcc72f259999),
  UINT64_C(0xa96d4fc4da226d6d), UINT64_C(0x340d68391a650d0d),
  UINT64_C(0xcffa8335e979fafa), UINT64_C(0x5bdfb684a369dfdf),
  UINT64_C(0xe57ed79bfca97e7e), UINT64_C(0x90243db448192424),
  UINT64_C(0xec3bc5d776fe3b3b), UINT64_C(0x96ab313d4b9aabab),
  UINT64_C(0x1fce3ed181f0cece), UINT64_C(0x4411885522991111),
  UINT64_C(0x068f0c8903838f8f), UINT64_C(0x254e4a6b9c044e4e),
  UINT64_C(0xe6b7d1517366b7b7), UINT64_C(0x8beb0b60cbe0ebeb),
  UINT64_C(0xf03cfdcc78c13c3c), UINT64_C(0x3e817cbf1ffd8181),
  UINT64_C(0x6a94d4fe35409494), UINT64_C(0xfbf7eb0cf31cf7f7),
  UINT64_C(0xdeb9a1676f18b9b9), UINT64_C(0x4c13985f268b1313),
  UINT64_C(0xb02c7d9c58512c2c), UINT64_C(0x6bd3d6b8bb05d3d3),
  UINT64_C(0xbbe76b5cd38ce7e7), UINT64_C(0xa56e57cbdc396e6e),
  UINT64_C(0x37c46ef395aac4c4), UINT64_C(0x0c03180f061b0303),
  UINT64_C(0x45568a13acdc5656), UINT64_C(0x0d441a49885e4444),
  UINT64_C(0xe17fdf9efea07f7f), UINT64_C(0x9ea921374f88a9a9),
  UINT64_C(0xa82a4d8254672a2a), UINT64_C(0xd6bbb16d6b0abbbb),
  UINT64_C(0x23c146e29f87c1c1), UINT64_C(0x5153a202a6f15353),
  UINT64_C(0x57dcae8ba572dcdc), UINT64_C(0x2c0b582716530b0b),
  UINT64_C(0x4e9d9cd327019d9d), UINT64_C(0xad6c47c1d82b6c6c),
  UINT64_C(0xc43195f562a43131), UINT64_C(0xcd7487b9e8f37474),
  UINT64_C(0xfff6e309f115f6f6), UINT64_C(0x05460a438c4c4646),
  UINT64_C(0x8aac092645a5acac), UINT64_C(0x1e893c970fb58989),
  UINT64_C(0x5014a04428b41414), UINT64_C(0xa3e15b42dfbae1e1),
  UINT64_C(0x5816b04e2ca61616), UINT64_C(0xe83acdd274f73a3a),
  UINT64_C(0xb9696fd0d2066969), UINT64_C(0x2409482d12410909),
  UINT64_C(0xdd70a7ade0d77070), UINT64_C(0xe2b6d954716fb6b6),
  UINT64_C(0x67d0ceb7bd1ed0d0), UINT64_C(0x93ed3b7ec7d6eded),
  UINT64_C(0x17cc2edb85e2cccc), UINT64_C(0x15422a5784684242),
  UINT64_C(0x5a98b4c22d2c9898), UINT64_C(0xaaa4490e55eda4a4),
  UINT64_C(0xa0285d8850752828), UINT64_C(0x6d5cda31b8865c5c),
  UINT64_C(0xc7f8933fed6bf8f8), UINT64_C(0x228644a411c28686)
};

static const uint64_t whirlpool_C7[256] = {
  UINT64_C(0x186018c07830d818), UINT64_C(0x238c2305af462623),
  UINT64_C(0xc63fc67ef991b8c6), UINT64_C(0xe887e8136fcdfbe8),
  UINT64_C(0x8726874ca113cb87), UINT64_C(0xb8dab8a9626d11b8),
  UINT64_C(0x0104010805020901), UINT64_C(0x4f214f426e9e0d4f),
  UINT64_C(0x36d836adee6c9b36), UINT64_C(0xa6a2a6590451ffa6),
  UINT64_C(0xd26fd2debdb90cd2), UINT64_C(0xf5f3f5fb06f70ef5),
  UINT64_C(0x79f979ef80f29679), UINT64_C(0x6fa16f5fcede306f),
  UINT64_C(0x917e91fcef3f6d91), UINT64_C(0x525552aa07a4f852),
  UINT64_C(0x609d6027fdc04760), UINT64_C(0xbccabc89766535bc),
  UINT64_C(0x9b569baccd2b379b), UINT64_C(0x8e028e048c018a8e),
  UINT64_C(0xa3b6a371155bd2a3), UINT64_C(0x0c300c603c186c0c),
  UINT64_C(0x7bf17bff8af6847b), UINT64_C(0x35d435b5e16a8035),
  UINT64_C(0x1d741de8693af51d), UINT64_C(0xe0a7e05347ddb3e0),
  UINT64_C(0xd77bd7f6acb321d7), UINT64_C(0xc22fc25eed999cc2),
  UINT64_C(0x2eb82e6d965c432e), UINT64_C(0x4b314b627a96294b),
  UINT64_C(0xfedffea321e15dfe), UINT64_C(0x5741578216aed557),
  UINT64_C(0x155415a8412abd15), UINT64_C(0x77c1779fb6eee877),
  UINT64_C(0x37dc37a5eb6e9237), UINT64_C(0xe5b3e57b56d79ee5),
  UINT64_C(0x9f469f8cd923139f), UINT64_C(0xf0e7f0d317fd23f0),
  UINT64_C(0x4a354a6a7f94204a), UINT64_C(0xda4fda9e95a944da),
  UINT64_C(0x587d58fa25b0a258), UINT64_C(0xc903c906ca8fcfc9),
  UINT64_C(0x29a429558d527c29), UINT64_C(0x0a280a5022145a0a),
  UINT64_C(0xb1feb1e14f7f50b1), UINT64_C(0xa0baa0691a5dc9a0),
  UINT64_C(0x6bb16b7fdad6146b), UINT64_C(0x852e855cab17d985),
  UINT64_C(0xbdcebd8173673cbd), UINT64_C(0x5d695dd234ba8f5d),
  UINT64_C(0x1040108050209010), UINT64_C(0xf4f7f4f303f507f4),
  UINT64_C(0xcb0bcb16c08bddcb), UINT64_C(0x3ef83eedc67cd33e),
  UINT64_C(0x05140528110a2d05), UINT64_C(0x6781671fe6ce7867),
  UINT64_C(0xe4b7e47353d597e4), UINT64_C(0x279c2725bb4e0227),
  UINT64_C(0x4119413258827341), UINT64_C(0x8b168b2c9d0ba78b),
  UINT64_C(0xa7a6a7510153f6a7), UINT64_C(0x7de97dcf94fab27d),
  UINT64_C(0x956e95dcfb374995), UINT64_C(0xd847d88e9fad56d8),
  UINT64_C(0xfbcbfb8b30eb70fb), UINT64_C(0xee9fee2371c1cdee),
  UINT64_C(0x7ced7cc791f8bb7c), UINT64_C(0x66856617e3cc7166),
  UINT64_C(0xdd53dda68ea77bdd), UINT64_C(0x175c17b84b2eaf17),
  UINT64_C(0x47014702468e4547), UINT64_C(0x9e429e84dc211a9e),
  UINT64_C(0xca0fca1ec589d4ca), UINT64_C(0x2db42d75995a582d),
  UINT64_C(0xbfc6bf9179632ebf), UINT64_C(0x071c07381b0e3f07),
  UINT64_C(0xad8ead012347acad), UINT64_C(0x5a755aea2fb4b05a),
  UINT64_C(0x8336836cb51bef83), UINT64_C(0x33cc3385ff66b633),
  UINT64_C(0x6391633ff2c65c63), UINT64_C(0x020802100a041202),
  UINT64_C(0xaa92aa39384993aa), UINT64_C(0x71d971afa8e2de71),
  UINT64_C(0xc807c80ecf8dc6c8), UINT64_C(0x196419c87d32d119),
  UINT64_C(0x4939497270923b49), UINT64_C(0xd943d9869aaf5fd9),
  UINT64_C(0xf2eff2c31df931f2), UINT64_C(0xe3abe34b48dba8e3),
  UINT64_C(0x5b715be22ab6b95b), UINT64_C(0x881a8834920dbc88),
  UINT64_C(0x9a529aa4c8293e9a), UINT64_C(0x2698262dbe4c0b26),
  UINT64_C(0x32c8328dfa64bf32), UINT64_C(0xb0fab0e94a7d59b0),
  UINT64_C(0xe983e91b6acff2e9), UINT64_C(0x0f3c0f78331e770f),
  UINT64_C(0xd573d5e6a6b733d5), UINT64_C(0x803a8074ba1df480),
  UINT64_C(0xbec2be997c6127be), UINT64_C(0xcd13cd26de87ebcd),
  UINT64_C(0x34d034bde4688934), UINT64_C(0x483d487a75903248),
  UINT64_C(0xffdbffab24e354ff), UINT64_C(0x7af57af78ff48d7a),
  UINT64_C(0x907a90f4ea3d6490), UINT64_C(0x5f615fc23ebe9d5f),
  UINT64_C(0x2080201da0403d20), UINT64_C(0x68bd6867d5d00f68),
  UINT64_C(0x1a681ad07234ca1a), UINT64_C(0xae82ae192c41b7ae),
  UINT64_C(0xb4eab4c95e757db4), UINT64_C(0x544d549a19a8ce54),
  UINT64_C(0x937693ece53b7f93), UINT64_C(0x2288220daa442f22),
  UINT64_C(0x648d6407e9c86364), UINT64_C(0xf1e3f1db12ff2af1),
  UINT64_C(0x73d173bfa2e6cc73), UINT64_C(0x124812905a248212),
  UINT64_C(0x401d403a5d807a40), UINT64_C(0x0820084028104808),
  UINT64_C(0xc32bc356e89b95c3), UINT64_C(0xec97ec337bc5dfec),
  UINT64_C(0xdb4bdb9690ab4ddb), UINT64_C(0xa1bea1611f5fc0a1),
  UINT64_C(0x8d0e8d1c8307918d), UINT64_C(0x3df43df5c97ac83d),
  UINT64_C(0x976697ccf1335b97), UINT64_C(0x0000000000000000),
  UINT64_C(0xcf1bcf36d483f9cf), UINT64_C(0x2bac2b4587566e2b),
  UINT64_C(0x76c57697b3ece176), UINT64_C(0x82328264b019e682),
  UINT64_C(0xd67fd6fea9b128d6), UINT64_C(0x1b6c1bd87736c31b),
  UINT64_C(0xb5eeb5c15b7774b5), UINT64_C(0xaf86af112943beaf),
  UINT64_C(0x6ab56a77dfd41d6a), UINT64_C(0x505d50ba0da0ea50),
  UINT64_C(0x450945124c8a5745), UINT64_C(0xf3ebf3cb18fb38f3),
  UINT64_C(0x30c0309df060ad30), UINT64_C(0xef9bef2b74c3c4ef),
  UINT64_C(0x3ffc3fe5c37eda3f), UINT64_C(0x554955921caac755),
  UINT64_C(0xa2b2a2791059dba2), UINT64_C(0xea8fea0365c9e9ea),
  UINT64_C(0x6589650fecca6a65), UINT64_C(0xbad2bab9686903ba),
  UINT64_C(0x2fbc2f65935e4a2f), UINT64_C(0xc027c04ee79d8ec0),
  UINT64_C(0xde5fdebe81a160de), UINT64_C(0x1c701ce06c38fc1c),
  UINT64_C(0xfdd3fdbb2ee746fd), UINT64_C(0x4d294d52649a1f4d),
  UINT64_C(0x927292e4e0397692), UINT64_C(0x75c9758fbceafa75),
  UINT64_C(0x061806301e0c3606), UINT64_C(0x8a128a249809ae8a),
  UINT64_C(0xb2f2b2f940794bb2), UINT64_C(0xe6bfe66359d185e6),
  UINT64_C(0x0e380e70361c7e0e), UINT64_C(0x1f7c1ff8633ee71f),
  UINT64_C(0x62956237f7c45562), UINT64_C(0xd477d4eea3b53ad4),
  UINT64_C(0xa89aa829324d81a8), UINT64_C(0x966296c4f4315296),
  UINT64_C(0xf9c3f99b3aef62f9), UINT64_C(0xc533c566f697a3c5),
  UINT64_C(0x25942535b14a1025), UINT64_C(0x597959f220b2ab59),
  UINT64_C(0x842a8454ae15d084), UINT64_C(0x72d572b7a7e4c572),
  UINT64_C(0x39e439d5dd72ec39), UINT64_C(0x4c2d4c5a6198164c),
  UINT64_C(0x5e655eca3bbc945e), UINT64_C(0x78fd78e785f09f78),
  UINT64_C(0x38e038ddd870e538), UINT64_C(0x8c0a8c148605988c),
  UINT64_C(0xd163d1c6b2bf17d1), UINT64_C(0xa5aea5410b57e4a5),
  UINT64_C(0xe2afe2434dd9a1e2), UINT64_C(0x6199612ff8c24e61),
  UINT64_C(0xb3f6b3f1457b42b3), UINT64_C(0x21842115a5423421),
  UINT64_C(0x9c4a9c94d625089c), UINT64_C(0x1e781ef0663cee1e),
  UINT64_C(0x4311432252866143), UINT64_C(0xc73bc776fc93b1c7),
  UINT64_C(0xfcd7fcb32be54ffc), UINT64_C(0x0410042014082404),
  UINT64_C(0x515951b208a2e351), UINT64_C(0x995e99bcc72f2599),
  UINT64_C(0x6da96d4fc4da226d), UINT64_C(0x0d340d68391a650d),
  UINT64_C(0xfacffa8335e979fa), UINT64_C(0xdf5bdfb684a369df),
  UINT64_C(0x7ee57ed79bfca97e), UINT64_C(0x2490243db4481924),
  UINT64_C(0x3bec3bc5d776fe3b), UINT64_C(0xab96ab313d4b9aab),
  UINT64_C(0xce1fce3ed181f0ce), UINT64_C(0x1144118855229911),
  UINT64_C(0x8f068f0c8903838f), UINT64_C(0x4e254e4a6b9c044e),
  UINT64_C(0xb7e6b7d1517366b7), UINT64_C(0xeb8beb0b60cbe0eb),
  UINT64_C(0x3cf03cfdcc78c13c), UINT64_C(0x813e817cbf1ffd81),
  UINT64_C(0x946a94d4fe354094), UINT64_C(0xf7fbf7eb0cf31cf7),
  UINT64_C(0xb9deb9a1676f18b9), UINT64_C(0x134c13985f268b13),
  UINT64_C(0x2cb02c7d9c58512c), UINT64_C(0xd36bd3d6b8bb05d3),
  UINT64_C(0xe7bbe76b5cd38ce7), UINT64_C(0x6ea56e57cbdc396e),
  UINT64_C(0xc437c46ef395aac4), UINT64_C(0x030c03180f061b03),
  UINT64_C(0x5645568a13acdc56), UINT64_C(0x440d441a49885e44),
  UINT64_C(0x7fe17fdf9efea07f), UINT64_C(0xa99ea921374f88a9),
  UINT64_C(0x2aa82a4d8254672a), UINT64_C(0xbbd6bbb16d6b0abb),
  UINT64_C(0xc123c146e29f87c1), UINT64_C(0x535153a202a6f153),
  UINT64_C(0xdc57dcae8ba572dc), UINT64_C(0x0b2c0b582716530b),
  UINT64_C(0x9d4e9d9cd327019d), UINT64_C(0x6cad6c47c1d82b6c),
  UINT64_C(0x31c43195f562a431), UINT64_C(0x74cd7487b9e8f374),
  UINT64_C(0xf6fff6e309f115f6), UINT64_C(0x4605460a438c4c46),
  UINT64_C(0xac8aac092645a5ac), UINT64_C(0x891e893c970fb589),
  UINT64_C(0x145014a04428b414), UINT64_C(0xe1a3e15b42dfbae1),
  UINT64_C(0x165816b04e2ca616), UINT64_C(0x3ae83acdd274f73a),
  UINT64_C(0x69b9696fd0d20669), UINT64_C(0x092409482d124109),
  UINT64_C(0x70dd70a7ade0d770), UINT64_C(0xb6e2b6d954716fb6),
  UINT64_C(0xd067d0ceb7bd1ed0), UINT64_C(0xed93ed3b7ec7d6ed),
  UINT64_C(0xcc17cc2edb85e2cc), UINT64_C(0x4215422a57846842),
  UINT64_C(0x985a98b4c22d2c98), UINT64_C(0xa4aaa4490e55eda4),
  UINT64_C(0x28a0285d88507528), UINT64_C(0x5c6d5cda31b8865c),
  UINT64_C(0xf8c7f8933fed6bf8), UINT64_C(0x86228644a411c286)
};

void
whirlpool_init(whirlpool_t *ctx) {
  memset(ctx, 0, sizeof(*ctx));
}

static void
whirlpool_transform(whirlpool_t *ctx, const unsigned char *chunk) {
  uint64_t B[8], S[8], K[8], L[8];
  int i, r;

  for (i = 0; i < 8; i++)
    B[i] = read64be(chunk + i * 8);

  for (i = 0; i < 8; i++) {
    K[i] = ctx->state[i];
    S[i] = B[i] ^ K[i];
  }

  for (r = 0; r < 10; r++) {
    for (i = 0; i < 8; i++) {
      L[i] = whirlpool_C0[(K[(0 + i) & 7] >> 56) & 0xff]
           ^ whirlpool_C1[(K[(7 + i) & 7] >> 48) & 0xff]
           ^ whirlpool_C2[(K[(6 + i) & 7] >> 40) & 0xff]
           ^ whirlpool_C3[(K[(5 + i) & 7] >> 32) & 0xff]
           ^ whirlpool_C4[(K[(4 + i) & 7] >> 24) & 0xff]
           ^ whirlpool_C5[(K[(3 + i) & 7] >> 16) & 0xff]
           ^ whirlpool_C6[(K[(2 + i) & 7] >>  8) & 0xff]
           ^ whirlpool_C7[(K[(1 + i) & 7] >>  0) & 0xff];
    }

    L[0] ^= whirlpool_RC[r];

    for (i = 0; i < 8; i++)
      K[i] = L[i];

    for (i = 0; i < 8; i++) {
      L[i] = whirlpool_C0[(S[(0 + i) & 7] >> 56) & 0xff]
           ^ whirlpool_C1[(S[(7 + i) & 7] >> 48) & 0xff]
           ^ whirlpool_C2[(S[(6 + i) & 7] >> 40) & 0xff]
           ^ whirlpool_C3[(S[(5 + i) & 7] >> 32) & 0xff]
           ^ whirlpool_C4[(S[(4 + i) & 7] >> 24) & 0xff]
           ^ whirlpool_C5[(S[(3 + i) & 7] >> 16) & 0xff]
           ^ whirlpool_C6[(S[(2 + i) & 7] >>  8) & 0xff]
           ^ whirlpool_C7[(S[(1 + i) & 7] >>  0) & 0xff]
           ^ K[i];
    }

    for (i = 0; i < 8; i++)
      S[i] = L[i];
  }

  for (i = 0; i < 8; i++)
    ctx->state[i] ^= S[i] ^ B[i];
}

void
whirlpool_update(whirlpool_t *ctx, const void *data, size_t len) {
  const unsigned char *raw = (const unsigned char *)data;
  size_t pos = ctx->size & 63;

  if (len == 0)
    return;

  ctx->size += len;

  if (pos > 0) {
    size_t want = 64 - pos;

    if (want > len)
      want = len;

    memcpy(ctx->block + pos, raw, want);

    pos += want;
    len -= want;
    raw += want;

    if (pos < 64)
      return;

    whirlpool_transform(ctx, ctx->block);
  }

  while (len >= 64) {
    whirlpool_transform(ctx, raw);
    raw += 64;
    len -= 64;
  }

  if (len > 0)
    memcpy(ctx->block, raw, len);
}

void
whirlpool_final(whirlpool_t *ctx, unsigned char *out) {
  static const unsigned char P[64] = { 0x80, 0x00 };
  size_t pos = ctx->size & 63;
  unsigned char D[32];
  int i;

  memset(D, 0x00, 16);

  write64be(D + 16, ctx->size >> (64 - 3));
  write64be(D + 24, ctx->size << 3);

  whirlpool_update(ctx, P, 1 + ((95 - pos) & 63));
  whirlpool_update(ctx, D, 32);

  for (i = 0; i < 8; i++)
    write64be(out + i * 8, ctx->state[i]);
}

/*
 * Hash
 */

void
hash_init(hash_t *hash, int type) {
  hash->type = type;
  switch (hash->type) {
    case HASH_BLAKE2B_160:
      blake2b_init(&hash->ctx.blake2b, 20, NULL, 0);
      break;
    case HASH_BLAKE2B_256:
      blake2b_init(&hash->ctx.blake2b, 32, NULL, 0);
      break;
    case HASH_BLAKE2B_384:
      blake2b_init(&hash->ctx.blake2b, 48, NULL, 0);
      break;
    case HASH_BLAKE2B_512:
      blake2b_init(&hash->ctx.blake2b, 64, NULL, 0);
      break;
    case HASH_BLAKE2S_128:
      blake2s_init(&hash->ctx.blake2s, 16, NULL, 0);
      break;
    case HASH_BLAKE2S_160:
      blake2s_init(&hash->ctx.blake2s, 20, NULL, 0);
      break;
    case HASH_BLAKE2S_224:
      blake2s_init(&hash->ctx.blake2s, 28, NULL, 0);
      break;
    case HASH_BLAKE2S_256:
      blake2s_init(&hash->ctx.blake2s, 32, NULL, 0);
      break;
    case HASH_GOST94:
      gost94_init(&hash->ctx.gost94);
      break;
    case HASH_HASH160:
    case HASH_HASH256:
      sha256_init(&hash->ctx.sha256);
      break;
    case HASH_KECCAK224:
      keccak_init(&hash->ctx.keccak, 224);
      break;
    case HASH_KECCAK256:
      keccak_init(&hash->ctx.keccak, 256);
      break;
    case HASH_KECCAK384:
      keccak_init(&hash->ctx.keccak, 384);
      break;
    case HASH_KECCAK512:
      keccak_init(&hash->ctx.keccak, 512);
      break;
    case HASH_MD2:
      md2_init(&hash->ctx.md2);
      break;
    case HASH_MD4:
      md4_init(&hash->ctx.md5);
      break;
    case HASH_MD5:
      md5_init(&hash->ctx.md5);
      break;
    case HASH_MD5SHA1:
      md5sha1_init(&hash->ctx.md5sha1);
      break;
    case HASH_RIPEMD160:
      ripemd160_init(&hash->ctx.ripemd160);
      break;
    case HASH_SHA1:
      sha1_init(&hash->ctx.sha1);
      break;
    case HASH_SHA224:
      sha224_init(&hash->ctx.sha256);
      break;
    case HASH_SHA256:
      sha256_init(&hash->ctx.sha256);
      break;
    case HASH_SHA384:
      sha384_init(&hash->ctx.sha512);
      break;
    case HASH_SHA512:
      sha512_init(&hash->ctx.sha512);
      break;
    case HASH_SHA3_224:
      keccak_init(&hash->ctx.keccak, 224);
      break;
    case HASH_SHA3_256:
      keccak_init(&hash->ctx.keccak, 256);
      break;
    case HASH_SHA3_384:
      keccak_init(&hash->ctx.keccak, 384);
      break;
    case HASH_SHA3_512:
      keccak_init(&hash->ctx.keccak, 512);
      break;
    case HASH_SHAKE128:
      keccak_init(&hash->ctx.keccak, 128);
      break;
    case HASH_SHAKE256:
      keccak_init(&hash->ctx.keccak, 256);
      break;
    case HASH_WHIRLPOOL:
      whirlpool_init(&hash->ctx.whirlpool);
      break;
    default:
      torsion_abort(); /* LCOV_EXCL_LINE */
      break;
  }
}

void
hash_update(hash_t *hash, const void *data, size_t len) {
  switch (hash->type) {
    case HASH_BLAKE2B_160:
    case HASH_BLAKE2B_256:
    case HASH_BLAKE2B_384:
    case HASH_BLAKE2B_512:
      blake2b_update(&hash->ctx.blake2b, data, len);
      break;
    case HASH_BLAKE2S_128:
    case HASH_BLAKE2S_160:
    case HASH_BLAKE2S_224:
    case HASH_BLAKE2S_256:
      blake2s_update(&hash->ctx.blake2s, data, len);
      break;
    case HASH_GOST94:
      gost94_update(&hash->ctx.gost94, data, len);
      break;
    case HASH_HASH160:
    case HASH_HASH256:
      sha256_update(&hash->ctx.sha256, data, len);
      break;
    case HASH_KECCAK224:
    case HASH_KECCAK256:
    case HASH_KECCAK384:
    case HASH_KECCAK512:
      keccak_update(&hash->ctx.keccak, data, len);
      break;
    case HASH_MD2:
      md2_update(&hash->ctx.md2, data, len);
      break;
    case HASH_MD4:
      md4_update(&hash->ctx.md5, data, len);
      break;
    case HASH_MD5:
      md5_update(&hash->ctx.md5, data, len);
      break;
    case HASH_MD5SHA1:
      md5sha1_update(&hash->ctx.md5sha1, data, len);
      break;
    case HASH_RIPEMD160:
      ripemd160_update(&hash->ctx.ripemd160, data, len);
      break;
    case HASH_SHA1:
      sha1_update(&hash->ctx.sha1, data, len);
      break;
    case HASH_SHA224:
    case HASH_SHA256:
      sha256_update(&hash->ctx.sha256, data, len);
      break;
    case HASH_SHA384:
    case HASH_SHA512:
      sha512_update(&hash->ctx.sha512, data, len);
      break;
    case HASH_SHA3_224:
    case HASH_SHA3_256:
    case HASH_SHA3_384:
    case HASH_SHA3_512:
    case HASH_SHAKE128:
    case HASH_SHAKE256:
      keccak_update(&hash->ctx.keccak, data, len);
      break;
    case HASH_WHIRLPOOL:
      whirlpool_update(&hash->ctx.whirlpool, data, len);
      break;
    default:
      torsion_abort(); /* LCOV_EXCL_LINE */
      break;
  }
}

void
hash_final(hash_t *hash, unsigned char *out, size_t len) {
  switch (hash->type) {
    case HASH_BLAKE2B_160:
    case HASH_BLAKE2B_256:
    case HASH_BLAKE2B_384:
    case HASH_BLAKE2B_512:
      blake2b_final(&hash->ctx.blake2b, out);
      break;
    case HASH_BLAKE2S_128:
    case HASH_BLAKE2S_160:
    case HASH_BLAKE2S_224:
    case HASH_BLAKE2S_256:
      blake2s_final(&hash->ctx.blake2s, out);
      break;
    case HASH_GOST94:
      gost94_final(&hash->ctx.gost94, out);
      break;
    case HASH_HASH160:
      hash160_final(&hash->ctx.sha256, out);
      break;
    case HASH_HASH256:
      hash256_final(&hash->ctx.sha256, out);
      break;
    case HASH_KECCAK224:
    case HASH_KECCAK256:
    case HASH_KECCAK384:
    case HASH_KECCAK512:
      keccak_final(&hash->ctx.keccak, out, 0x01, 0);
      break;
    case HASH_MD2:
      md2_final(&hash->ctx.md2, out);
      break;
    case HASH_MD4:
      md4_final(&hash->ctx.md5, out);
      break;
    case HASH_MD5:
      md5_final(&hash->ctx.md5, out);
      break;
    case HASH_MD5SHA1:
      md5sha1_final(&hash->ctx.md5sha1, out);
      break;
    case HASH_RIPEMD160:
      ripemd160_final(&hash->ctx.ripemd160, out);
      break;
    case HASH_SHA1:
      sha1_final(&hash->ctx.sha1, out);
      break;
    case HASH_SHA224:
      sha224_final(&hash->ctx.sha256, out);
      break;
    case HASH_SHA256:
      sha256_final(&hash->ctx.sha256, out);
      break;
    case HASH_SHA384:
      sha384_final(&hash->ctx.sha512, out);
      break;
    case HASH_SHA512:
      sha512_final(&hash->ctx.sha512, out);
      break;
    case HASH_SHA3_224:
    case HASH_SHA3_256:
    case HASH_SHA3_384:
    case HASH_SHA3_512:
      keccak_final(&hash->ctx.keccak, out, 0x06, 0);
      break;
    case HASH_SHAKE128:
    case HASH_SHAKE256:
      keccak_final(&hash->ctx.keccak, out, 0x1f, len);
      break;
    case HASH_WHIRLPOOL:
      whirlpool_final(&hash->ctx.whirlpool, out);
      break;
    default:
      torsion_abort(); /* LCOV_EXCL_LINE */
      break;
  }
}

int
hash_has_backend(int type) {
  switch (type) {
    case HASH_BLAKE2B_160:
    case HASH_BLAKE2B_256:
    case HASH_BLAKE2B_384:
    case HASH_BLAKE2B_512:
    case HASH_BLAKE2S_128:
    case HASH_BLAKE2S_160:
    case HASH_BLAKE2S_224:
    case HASH_BLAKE2S_256:
    case HASH_GOST94:
    case HASH_HASH160:
    case HASH_HASH256:
    case HASH_KECCAK224:
    case HASH_KECCAK256:
    case HASH_KECCAK384:
    case HASH_KECCAK512:
    case HASH_MD2:
    case HASH_MD4:
    case HASH_MD5:
    case HASH_MD5SHA1:
    case HASH_RIPEMD160:
    case HASH_SHA1:
    case HASH_SHA224:
    case HASH_SHA256:
    case HASH_SHA384:
    case HASH_SHA512:
    case HASH_SHA3_224:
    case HASH_SHA3_256:
    case HASH_SHA3_384:
    case HASH_SHA3_512:
    case HASH_SHAKE128:
    case HASH_SHAKE256:
    case HASH_WHIRLPOOL:
      return 1;
  }
  return 0;
}

size_t
hash_output_size(int type) {
  switch (type) {
    case HASH_BLAKE2B_160:
      return 20;
    case HASH_BLAKE2B_256:
      return 32;
    case HASH_BLAKE2B_384:
      return 48;
    case HASH_BLAKE2B_512:
      return 64;
    case HASH_BLAKE2S_128:
      return 16;
    case HASH_BLAKE2S_160:
      return 20;
    case HASH_BLAKE2S_224:
      return 28;
    case HASH_BLAKE2S_256:
      return 32;
    case HASH_GOST94:
      return 32;
    case HASH_HASH160:
      return 20;
    case HASH_HASH256:
      return 32;
    case HASH_KECCAK224:
      return 28;
    case HASH_KECCAK256:
      return 32;
    case HASH_KECCAK384:
      return 48;
    case HASH_KECCAK512:
      return 64;
    case HASH_MD2:
      return 16;
    case HASH_MD4:
      return 16;
    case HASH_MD5:
      return 16;
    case HASH_MD5SHA1:
      return 36;
    case HASH_RIPEMD160:
      return 20;
    case HASH_SHA1:
      return 20;
    case HASH_SHA224:
      return 28;
    case HASH_SHA256:
      return 32;
    case HASH_SHA384:
      return 48;
    case HASH_SHA512:
      return 64;
    case HASH_SHA3_224:
      return 28;
    case HASH_SHA3_256:
      return 32;
    case HASH_SHA3_384:
      return 48;
    case HASH_SHA3_512:
      return 64;
    case HASH_SHAKE128:
      return 16;
    case HASH_SHAKE256:
      return 32;
    case HASH_WHIRLPOOL:
      return 64;
    default:
      return 0;
  }
}

size_t
hash_block_size(int type) {
  switch (type) {
    case HASH_BLAKE2B_160:
      return 128;
    case HASH_BLAKE2B_256:
      return 128;
    case HASH_BLAKE2B_384:
      return 128;
    case HASH_BLAKE2B_512:
      return 128;
    case HASH_BLAKE2S_128:
      return 64;
    case HASH_BLAKE2S_160:
      return 64;
    case HASH_BLAKE2S_224:
      return 64;
    case HASH_BLAKE2S_256:
      return 64;
    case HASH_GOST94:
      return 32;
    case HASH_HASH160:
      return 64;
    case HASH_HASH256:
      return 64;
    case HASH_KECCAK224:
      return 144;
    case HASH_KECCAK256:
      return 136;
    case HASH_KECCAK384:
      return 104;
    case HASH_KECCAK512:
      return 72;
    case HASH_MD2:
      return 16;
    case HASH_MD4:
      return 64;
    case HASH_MD5:
      return 64;
    case HASH_MD5SHA1:
      return 64;
    case HASH_RIPEMD160:
      return 64;
    case HASH_SHA1:
      return 64;
    case HASH_SHA224:
      return 64;
    case HASH_SHA256:
      return 64;
    case HASH_SHA384:
      return 128;
    case HASH_SHA512:
      return 128;
    case HASH_SHA3_224:
      return 144;
    case HASH_SHA3_256:
      return 136;
    case HASH_SHA3_384:
      return 104;
    case HASH_SHA3_512:
      return 72;
    case HASH_SHAKE128:
      return 168;
    case HASH_SHAKE256:
      return 136;
    case HASH_WHIRLPOOL:
      return 64;
    default:
      return 0;
  }
}

/*
 * HMAC
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/HMAC
 *   https://tools.ietf.org/html/rfc2104
 *   https://github.com/indutny/hash.js/blob/master/lib/hash/hmac.js
 */

void
hmac_init(hmac_t *hmac, int type, const unsigned char *key, size_t len) {
  size_t hash_size = hash_output_size(type);
  size_t block_size = hash_block_size(type);
  unsigned char tmp[HASH_MAX_OUTPUT_SIZE];
  unsigned char pad[HASH_MAX_BLOCK_SIZE];
  size_t i;

  hmac->type = type;

  if (len > block_size) {
    hash_init(&hmac->inner, type);
    hash_update(&hmac->inner, key, len);
    hash_final(&hmac->inner, tmp, hash_size);
    key = tmp;
    len = hash_size;
  }

  ASSERT(len <= block_size);

  for (i = 0; i < len; i++)
    pad[i] = key[i] ^ 0x36;

  for (i = len; i < block_size; i++)
    pad[i] = 0x36;

  hash_init(&hmac->inner, type);
  hash_update(&hmac->inner, pad, block_size);

  for (i = 0; i < len; i++)
    pad[i] = key[i] ^ 0x5c;

  for (i = len; i < block_size; i++)
    pad[i] = 0x5c;

  hash_init(&hmac->outer, type);
  hash_update(&hmac->outer, pad, block_size);

  torsion_cleanse(tmp, hash_size);
  torsion_cleanse(pad, block_size);
}

void
hmac_update(hmac_t *hmac, const void *data, size_t len) {
  hash_update(&hmac->inner, data, len);
}

void
hmac_final(hmac_t *hmac, unsigned char *out) {
  size_t hash_size = hash_output_size(hmac->type);

  hash_final(&hmac->inner, out, hash_size);
  hash_update(&hmac->outer, out, hash_size);
  hash_final(&hmac->outer, out, hash_size);
}
