/*!
 * mac.c - macs for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 *
 * Parts of this software are based on floodyberry/poly1305-donna:
 *   Placed into the public domain by Andrew Moon.
 *   https://github.com/floodyberry/poly1305-donna
 *
 * Parts of this software are based on bitcoin/bitcoin:
 *   Copyright (c) 2009-2019, The Bitcoin Core Developers (MIT License).
 *   Copyright (c) 2009-2019, The Bitcoin Developers (MIT License).
 *   https://github.com/bitcoin/bitcoin
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <torsion/mac.h>
#include "bio.h"
#include "internal.h"

#undef HAVE_UMUL128
#undef HAVE_UMULH

#if defined(_MSC_VER) && _MSC_VER >= 1400 /* VS 2005 */
#  include <intrin.h>
#  if defined(_M_AMD64) || defined(_M_X64)
#    pragma intrinsic(_umul128)
#    define HAVE_UMUL128
#  endif
#  if defined(_M_AMD64) || defined(_M_X64) || defined(_M_ARM64)
#    pragma intrinsic(__umulh)
#    define HAVE_UMULH
#  endif
#endif

/*
 * Poly1305
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/Poly1305
 *   https://cr.yp.to/mac.html
 *   https://tools.ietf.org/html/rfc7539#section-2.5
 *   https://github.com/floodyberry/poly1305-donna/blob/master/poly1305-donna-64.h
 */

#if defined(TORSION_HAVE_INT128)

#define POLY1305_HAVE_64BIT

typedef torsion_uint128_t poly1305_uint128_t;

#define poly1305_mul(z, x, y) ((z) = (poly1305_uint128_t)(x) * (y))
#define poly1305_add(z, x) ((z) += (x))
#define poly1305_add_1(z, x) ((z) += (x))
#define poly1305_shr(x, n) ((uint64_t)((x) >> (n)))
#define poly1305_lo(x) ((uint64_t)(x))

#elif defined(HAVE_UMUL128) || defined(HAVE_UMULH) /* !TORSION_HAVE_INT128 */

#define POLY1305_HAVE_64BIT

typedef struct poly1305_uint128_s {
  uint64_t lo;
  uint64_t hi;
} poly1305_uint128_t;

#if defined(HAVE_UMUL128)
#define poly1305_mul(z, x, y) do {      \
  (z).lo = _umul128((x), (y), &(z).hi); \
} while (0)
#else
#define poly1305_mul(z, x, y) do { \
  (z).hi = __umulh(x, y);          \
  (z).lo = (x) * (y);              \
} while (0)
#endif

#define poly1305_add(z, x) do {      \
  uint64_t _lo = (z).lo + (x).lo;    \
  (z).hi += (x).hi + (_lo < (x).lo); \
  (z).lo = _lo;                      \
} while (0)

#define poly1305_add_1(z, x) do { \
  uint64_t _lo = (z).lo + (x);    \
  (z).hi += (_lo < (x));          \
  (z).lo = _lo;                   \
} while (0)

#define poly1305_shr(x, n) \
  (((x).lo >> (n)) | ((x).hi << (64 - (n))))

#define poly1305_lo(x) ((x).lo)

#endif /* HAVE_UMUL128 */

void
poly1305_init(poly1305_t *ctx, const unsigned char *key) {
#if defined(POLY1305_HAVE_64BIT)
  struct poly1305_64_s *st = &ctx->state.u64;
  uint64_t t0 = read64le(key + 0);
  uint64_t t1 = read64le(key + 8);

  /* r &= 0xffffffc0ffffffc0ffffffc0fffffff */
  st->r[0] = t0 & UINT64_C(0xffc0fffffff);
  st->r[1] = ((t0 >> 44) | (t1 << 20)) & UINT64_C(0xfffffc0ffff);
  st->r[2] = (t1 >> 24) & UINT64_C(0x00ffffffc0f);

  /* h = 0 */
  st->h[0] = 0;
  st->h[1] = 0;
  st->h[2] = 0;

  /* Save pad for later. */
  st->pad[0] = read64le(key + 16);
  st->pad[1] = read64le(key + 24);

  ctx->pos = 0;
#else /* !POLY1305_HAVE_64BIT */
  struct poly1305_32_s *st = &ctx->state.u32;

  /* r &= 0xffffffc0ffffffc0ffffffc0fffffff */
  st->r[0] = (read32le(key +  0) >> 0) & 0x3ffffff;
  st->r[1] = (read32le(key +  3) >> 2) & 0x3ffff03;
  st->r[2] = (read32le(key +  6) >> 4) & 0x3ffc0ff;
  st->r[3] = (read32le(key +  9) >> 6) & 0x3f03fff;
  st->r[4] = (read32le(key + 12) >> 8) & 0x00fffff;

  /* h = 0 */
  st->h[0] = 0;
  st->h[1] = 0;
  st->h[2] = 0;
  st->h[3] = 0;
  st->h[4] = 0;

  /* Save pad for later. */
  st->pad[0] = read32le(key + 16);
  st->pad[1] = read32le(key + 20);
  st->pad[2] = read32le(key + 24);
  st->pad[3] = read32le(key + 28);

  ctx->pos = 0;
#endif /* !POLY1305_HAVE_64BIT */
}

static void
poly1305_blocks(poly1305_t *ctx,
                const unsigned char *data,
                size_t len, int final) {
#if defined(POLY1305_HAVE_64BIT)
  struct poly1305_64_s *st = &ctx->state.u64;
  uint64_t hibit = final ? 0 : (UINT64_C(1) << 40); /* 1 << 128 */
  uint64_t r0 = st->r[0];
  uint64_t r1 = st->r[1];
  uint64_t r2 = st->r[2];
  uint64_t h0 = st->h[0];
  uint64_t h1 = st->h[1];
  uint64_t h2 = st->h[2];
  uint64_t s1 = r1 * (5 << 2);
  uint64_t s2 = r2 * (5 << 2);
  uint64_t c, t0, t1;
  poly1305_uint128_t d0, d1, d2, d;

  while (len >= 16) {
    /* h += m[i] */
    t0 = read64le(data + 0);
    t1 = read64le(data + 8);

    h0 += t0 & UINT64_C(0xfffffffffff);
    h1 += ((t0 >> 44) | (t1 << 20)) & UINT64_C(0xfffffffffff);
    h2 += (((t1 >> 24)) & UINT64_C(0x3ffffffffff)) | hibit;

    /* h *= r */
    poly1305_mul(d0, h0, r0);
    poly1305_mul(d, h1, s2);
    poly1305_add(d0, d);
    poly1305_mul(d, h2, s1);
    poly1305_add(d0, d);

    poly1305_mul(d1, h0, r1);
    poly1305_mul(d, h1, r0);
    poly1305_add(d1, d);
    poly1305_mul(d, h2, s2);
    poly1305_add(d1, d);

    poly1305_mul(d2, h0, r2);
    poly1305_mul(d, h1, r1);
    poly1305_add(d2, d);
    poly1305_mul(d, h2, r0);
    poly1305_add(d2, d);

    /* (partial) h %= p */
    c = poly1305_shr(d0, 44);
    h0 = poly1305_lo(d0) & UINT64_C(0xfffffffffff);

    poly1305_add_1(d1, c);
    c = poly1305_shr(d1, 44);
    h1 = poly1305_lo(d1) & UINT64_C(0xfffffffffff);

    poly1305_add_1(d2, c);
    c = poly1305_shr(d2, 42);
    h2 = poly1305_lo(d2) & UINT64_C(0x3ffffffffff);

    h0 += c * 5;
    c = h0 >> 44;
    h0 &= UINT64_C(0xfffffffffff);

    h1 += c;

    data += 16;
    len -= 16;
  }

  st->h[0] = h0;
  st->h[1] = h1;
  st->h[2] = h2;
#else /* !POLY1305_HAVE_64BIT */
  struct poly1305_32_s *st = &ctx->state.u32;
  uint32_t hibit = final ? 0 : (UINT32_C(1) << 24); /* 1 << 128 */
  uint32_t r0 = st->r[0];
  uint32_t r1 = st->r[1];
  uint32_t r2 = st->r[2];
  uint32_t r3 = st->r[3];
  uint32_t r4 = st->r[4];
  uint32_t h0 = st->h[0];
  uint32_t h1 = st->h[1];
  uint32_t h2 = st->h[2];
  uint32_t h3 = st->h[3];
  uint32_t h4 = st->h[4];
  uint32_t s1 = r1 * 5;
  uint32_t s2 = r2 * 5;
  uint32_t s3 = r3 * 5;
  uint32_t s4 = r4 * 5;
  uint32_t c;
  uint64_t d0, d1, d2, d3, d4;

  while (len >= 16) {
    /* h += m[i] */
    h0 += (read32le(data +  0) >> 0) & 0x3ffffff;
    h1 += (read32le(data +  3) >> 2) & 0x3ffffff;
    h2 += (read32le(data +  6) >> 4) & 0x3ffffff;
    h3 += (read32le(data +  9) >> 6) & 0x3ffffff;
    h4 += (read32le(data + 12) >> 8) | hibit;

    /* h *= r */
    d0 = ((uint64_t)h0 * r0)
       + ((uint64_t)h1 * s4)
       + ((uint64_t)h2 * s3)
       + ((uint64_t)h3 * s2)
       + ((uint64_t)h4 * s1);

    d1 = ((uint64_t)h0 * r1)
       + ((uint64_t)h1 * r0)
       + ((uint64_t)h2 * s4)
       + ((uint64_t)h3 * s3)
       + ((uint64_t)h4 * s2);

    d2 = ((uint64_t)h0 * r2)
       + ((uint64_t)h1 * r1)
       + ((uint64_t)h2 * r0)
       + ((uint64_t)h3 * s4)
       + ((uint64_t)h4 * s3);

    d3 = ((uint64_t)h0 * r3)
       + ((uint64_t)h1 * r2)
       + ((uint64_t)h2 * r1)
       + ((uint64_t)h3 * r0)
       + ((uint64_t)h4 * s4);

    d4 = ((uint64_t)h0 * r4)
       + ((uint64_t)h1 * r3)
       + ((uint64_t)h2 * r2)
       + ((uint64_t)h3 * r1)
       + ((uint64_t)h4 * r0);

    /* (partial) h %= p */
    c = (uint32_t)(d0 >> 26);
    h0 = (uint32_t)d0 & 0x3ffffff;
    d1 += c;

    c = (uint32_t)(d1 >> 26);
    h1 = (uint32_t)d1 & 0x3ffffff;
    d2 += c;

    c = (uint32_t)(d2 >> 26);
    h2 = (uint32_t)d2 & 0x3ffffff;
    d3 += c;

    c = (uint32_t)(d3 >> 26);
    h3 = (uint32_t)d3 & 0x3ffffff;
    d4 += c;

    c = (uint32_t)(d4 >> 26);
    h4 = (uint32_t)d4 & 0x3ffffff;
    h0 += c * 5;

    c = h0 >> 26;
    h0 &= 0x3ffffff;
    h1 += c;

    data += 16;
    len -= 16;
  }

  st->h[0] = h0;
  st->h[1] = h1;
  st->h[2] = h2;
  st->h[3] = h3;
  st->h[4] = h4;
#endif /* !POLY1305_HAVE_64BIT */
}

void
poly1305_update(poly1305_t *ctx, const unsigned char *data, size_t len) {
  const unsigned char *raw = data;
  size_t pos = ctx->pos;
  size_t want = 16 - pos;

  if (len >= want) {
    if (pos > 0) {
      memcpy(ctx->block + pos, raw, want);

      raw += want;
      len -= want;
      pos = 0;

      poly1305_blocks(ctx, ctx->block, 16, 0);
    }

    if (len >= 16) {
      size_t aligned = len & -16;

      poly1305_blocks(ctx, raw, aligned, 0);

      raw += aligned;
      len -= aligned;
    }
  }

  if (len > 0) {
    memcpy(ctx->block + pos, raw, len);
    pos += len;
  }

  ctx->pos = pos;
}

void
poly1305_pad(poly1305_t *ctx) {
  if (ctx->pos > 0) {
    while (ctx->pos < 16)
      ctx->block[ctx->pos++] = 0;

    poly1305_blocks(ctx, ctx->block, 16, 0);

    ctx->pos = 0;
  }
}

void
poly1305_final(poly1305_t *ctx, unsigned char *mac) {
#if defined(POLY1305_HAVE_64BIT)
  struct poly1305_64_s *st = &ctx->state.u64;
  uint64_t h0, h1, h2, c;
  uint64_t g0, g1, g2;
  uint64_t t0, t1;

  /* Process the remaining block. */
  if (ctx->pos > 0) {
    ctx->block[ctx->pos++] = 1;

    while (ctx->pos < 16)
      ctx->block[ctx->pos++] = 0;

    poly1305_blocks(ctx, ctx->block, 16, 1);

    ctx->pos = 0;
  }

  /* Fully carry h. */
  h0 = st->h[0];
  h1 = st->h[1];
  h2 = st->h[2];

  c = h1 >> 44;
  h1 &= UINT64_C(0xfffffffffff);

  h2 += c;
  c = h2 >> 42;
  h2 &= UINT64_C(0x3ffffffffff);

  h0 += c * 5;
  c = h0 >> 44;
  h0 &= UINT64_C(0xfffffffffff);

  h1 += c;
  c = h1 >> 44;
  h1 &= UINT64_C(0xfffffffffff);

  h2 += c;
  c = h2 >> 42;
  h2 &= UINT64_C(0x3ffffffffff);

  h0 += c * 5;
  c = h0 >> 44;
  h0 &= UINT64_C(0xfffffffffff);
  h1 += c;

  /* Compute h + -p. */
  g0 = h0 + 5;
  c = g0 >> 44;
  g0 &= UINT64_C(0xfffffffffff);

  g1 = h1 + c;
  c = g1 >> 44;
  g1 &= UINT64_C(0xfffffffffff);
  g2 = h2 + c - (UINT64_C(1) << 42);

  /* Select h if h < p, or h + -p if h >= p. */
  c = (g2 >> 63) - 1;
  g0 &= c;
  g1 &= c;
  g2 &= c;
  c = ~c;
  h0 = (h0 & c) | g0;
  h1 = (h1 & c) | g1;
  h2 = (h2 & c) | g2;

  /* h = (h + pad) */
  t0 = st->pad[0];
  t1 = st->pad[1];

  h0 += (t0 & UINT64_C(0xfffffffffff));
  c = h0 >> 44;
  h0 &= UINT64_C(0xfffffffffff);

  h1 += (((t0 >> 44) | (t1 << 20)) & UINT64_C(0xfffffffffff)) + c;
  c = h1 >> 44;
  h1 &= UINT64_C(0xfffffffffff);

  h2 += (((t1 >> 24)) & UINT64_C(0x3ffffffffff)) + c;
  h2 &= UINT64_C(0x3ffffffffff);

  /* mac = h % (2^128) */
  h0 |= (h1 << 44);
  h1 = (h1 >> 20) | (h2 << 24);

  write64le(mac + 0, h0);
  write64le(mac + 8, h1);
#else /* !POLY1305_HAVE_64BIT */
  struct poly1305_32_s *st = &ctx->state.u32;
  uint32_t h0, h1, h2, h3, h4, c;
  uint32_t g0, g1, g2, g3, g4;
  uint32_t mask;
  uint64_t f;

  /* Process the remaining block. */
  if (ctx->pos > 0) {
    ctx->block[ctx->pos++] = 1;

    while (ctx->pos < 16)
      ctx->block[ctx->pos++] = 0;

    poly1305_blocks(ctx, ctx->block, 16, 1);

    ctx->pos = 0;
  }

  /* Fully carry h. */
  h0 = st->h[0];
  h1 = st->h[1];
  h2 = st->h[2];
  h3 = st->h[3];
  h4 = st->h[4];

  c = h1 >> 26;
  h1 &= 0x3ffffff;
  h2 += c;

  c = h2 >> 26;
  h2 &= 0x3ffffff;
  h3 += c;

  c = h3 >> 26;
  h3 &= 0x3ffffff;
  h4 += c;

  c = h4 >> 26;
  h4 &= 0x3ffffff;
  h0 += c * 5;

  c = h0 >> 26;
  h0 &= 0x3ffffff;

  h1 += c;

  /* Compute h + -p. */
  g0 = h0 + 5;
  c = g0 >> 26;
  g0 &= 0x3ffffff;

  g1 = h1 + c;
  c = g1 >> 26;
  g1 &= 0x3ffffff;

  g2 = h2 + c;
  c = g2 >> 26;
  g2 &= 0x3ffffff;

  g3 = h3 + c;
  c = g3 >> 26;
  g3 &= 0x3ffffff;
  g4 = h4 + c - (UINT32_C(1) << 26);

  /* Select h if h < p, or h + -p if h >= p. */
  mask = (g4 >> 31) - 1;
  g0 &= mask;
  g1 &= mask;
  g2 &= mask;
  g3 &= mask;
  g4 &= mask;
  mask = ~mask;
  h0 = (h0 & mask) | g0;
  h1 = (h1 & mask) | g1;
  h2 = (h2 & mask) | g2;
  h3 = (h3 & mask) | g3;
  h4 = (h4 & mask) | g4;

  /* h = h % (2^128) */
  h0 = (h0 | (h1 << 26)) & 0xffffffff;
  h1 = ((h1 >> 6) | (h2 << 20)) & 0xffffffff;
  h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
  h3 = ((h3 >> 18) | (h4 <<  8)) & 0xffffffff;

  /* mac = (h + pad) % (2^128) */
  f = (uint64_t)h0 + st->pad[0];
  h0 = (uint32_t)f;

  f = (uint64_t)h1 + st->pad[1] + (f >> 32);
  h1 = (uint32_t)f;

  f = (uint64_t)h2 + st->pad[2] + (f >> 32);
  h2 = (uint32_t)f;

  f = (uint64_t)h3 + st->pad[3] + (f >> 32);
  h3 = (uint32_t)f;

  write32le(mac +  0, h0);
  write32le(mac +  4, h1);
  write32le(mac +  8, h2);
  write32le(mac + 12, h3);
#endif /* !POLY1305_HAVE_64BIT */
}

/*
 * Siphash
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/SipHash
 *   https://131002.net/siphash/
 *   https://131002.net/siphash/siphash.pdf
 *   https://github.com/bitcoin/bitcoin/blob/master/src/crypto/siphash.cpp
 */

#define ROTL64(w, b) (((w) << (b)) | ((w) >> (64 - (b))))

#define SIPROUND do {                      \
  v0 += v1; v1 = ROTL64(v1, 13); v1 ^= v0; \
  v0 = ROTL64(v0, 32);                     \
  v2 += v3; v3 = ROTL64(v3, 16); v3 ^= v2; \
  v0 += v3; v3 = ROTL64(v3, 21); v3 ^= v0; \
  v2 += v1; v1 = ROTL64(v1, 17); v1 ^= v2; \
  v2 = ROTL64(v2, 32);                     \
} while (0)

uint64_t
siphash_sum(const unsigned char *data, size_t len, const unsigned char *key) {
  uint64_t k0 = read64le(key + 0);
  uint64_t k1 = read64le(key + 8);
  uint64_t v0 = k0 ^ UINT64_C(0x736f6d6570736575);
  uint64_t v1 = k1 ^ UINT64_C(0x646f72616e646f6d);
  uint64_t v2 = k0 ^ UINT64_C(0x6c7967656e657261);
  uint64_t v3 = k1 ^ UINT64_C(0x7465646279746573);
  uint64_t f0 = (uint64_t)len << 56;
  uint64_t f1 = 0xff;
  uint64_t w;

  while (len >= 8) {
    w = read64le(data);

    v3 ^= w;
    SIPROUND;
    SIPROUND;
    v0 ^= w;

    data += 8;
    len -= 8;
  }

  switch (len) {
    case 7:
      f0 |= (uint64_t)data[6] << 48;
    case 6:
      f0 |= (uint64_t)data[5] << 40;
    case 5:
      f0 |= (uint64_t)data[4] << 32;
    case 4:
      f0 |= (uint64_t)data[3] << 24;
    case 3:
      f0 |= (uint64_t)data[2] << 16;
    case 2:
      f0 |= (uint64_t)data[1] << 8;
    case 1:
      f0 |= (uint64_t)data[0];
  }

  v3 ^= f0;
  SIPROUND;
  SIPROUND;
  v0 ^= f0;
  v2 ^= f1;
  SIPROUND;
  SIPROUND;
  SIPROUND;
  SIPROUND;
  v0 ^= v1;
  v0 ^= v2;
  v0 ^= v3;

  return v0;
}

uint64_t
siphash_mod(const unsigned char *data,
            size_t len,
            const unsigned char *key,
            uint64_t mod) {
  uint64_t a = siphash_sum(data, len, key);
  uint64_t b = mod;

#if defined(TORSION_HAVE_INT128)
  return ((torsion_uint128_t)a * b) >> 64;
#elif defined(HAVE_UMULH)
  return __umulh(a, b);
#else
  /* https://stackoverflow.com/questions/28868367 */
  uint64_t ahi = a >> 32;
  uint64_t alo = a & 0xffffffff;
  uint64_t bhi = b >> 32;
  uint64_t blo = b & 0xffffffff;
  uint64_t axbhi = ahi * bhi;
  uint64_t axbmid = ahi * blo;
  uint64_t bxamid = bhi * alo;
  uint64_t axblo = alo * blo;
  uint64_t c = (axbmid & 0xffffffff) + (bxamid & 0xffffffff) + (axblo >> 32);

  return axbhi + (axbmid >> 32) + (bxamid >> 32) + (c >> 32);
#endif
}

uint64_t
siphash128_sum(uint64_t num, const unsigned char *key) {
  uint64_t k0 = read64le(key + 0);
  uint64_t k1 = read64le(key + 8);
  uint64_t v0 = k0 ^ UINT64_C(0x736f6d6570736575);
  uint64_t v1 = k1 ^ UINT64_C(0x646f72616e646f6d);
  uint64_t v2 = k0 ^ UINT64_C(0x6c7967656e657261);
  uint64_t v3 = k1 ^ UINT64_C(0x7465646279746573);
  uint64_t f0 = num;
  uint64_t f1 = 0xff;

  v3 ^= f0;
  SIPROUND;
  SIPROUND;
  v0 ^= f0;
  v2 ^= f1;
  SIPROUND;
  SIPROUND;
  SIPROUND;
  SIPROUND;
  v0 ^= v1;
  v0 ^= v2;
  v0 ^= v3;

  return v0;
}

uint64_t
siphash256_sum(uint64_t num, const unsigned char *key) {
  uint64_t v0 = read64le(key +  0);
  uint64_t v1 = read64le(key +  8);
  uint64_t v2 = read64le(key + 16);
  uint64_t v3 = read64le(key + 24);
  uint64_t f0 = num;
  uint64_t f1 = 0xff;

  v3 ^= f0;
  SIPROUND;
  SIPROUND;
  v0 ^= f0;
  v2 ^= f1;
  SIPROUND;
  SIPROUND;
  SIPROUND;
  SIPROUND;
  v0 ^= v1;
  v0 ^= v2;
  v0 ^= v3;

  return v0;
}

#undef ROTL64
#undef SIPROUND
