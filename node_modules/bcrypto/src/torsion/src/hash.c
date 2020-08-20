/*!
 * hash.c - hash functions for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 *
 * Parts of this software are based on gnutls/nettle:
 *   Copyright (c) 1998-2019, Niels Möller and Contributors
 *   https://github.com/gnutls/nettle
 *
 * Parts of this software are based on BLAKE2/BLAKE2:
 *   CC0 1.0 Universal
 *   https://github.com/BLAKE2/BLAKE2
 */

#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <torsion/hash.h>
#include <torsion/util.h>

#define ROTL32(n, x) (((x) << (n)) | ((x) >> ((-(n) & 31))))
#define ROTL64(n, x) (((x) << (n)) | ((x) >> ((-(n)) & 63)))

/*
 * Helpers
 */

static uint32_t
rotr32(const uint32_t w, const unsigned c) {
  return (w >> c) | (w << (32 - c));
}

static uint64_t
rotr64(const uint64_t w, const unsigned c) {
  return (w >> c) | (w << (64 - c));
}

static uint32_t
read32be(const void *src) {
#ifdef WORDS_BIGENDIAN
  uint32_t w;
  memcpy(&w, src, sizeof(w));
  return w;
#else
  const uint8_t *p = (const uint8_t *)src;
  return ((uint32_t)p[0] << 24)
       | ((uint32_t)p[1] << 16)
       | ((uint32_t)p[2] << 8)
       | ((uint32_t)p[3] << 0);
#endif
}

static void
write32be(void *dst, uint32_t w) {
#ifdef WORDS_BIGENDIAN
  memcpy(dst, &w, sizeof(w));
#else
  uint8_t *p = (uint8_t *)dst;
  p[0] = w >> 24;
  p[1] = w >> 16;
  p[2] = w >> 8;
  p[3] = w >> 0;
#endif
}

static uint64_t
read64be(const void *src) {
#ifdef WORDS_BIGENDIAN
  uint64_t w;
  memcpy(&w, src, sizeof(w));
  return w;
#else
  const uint8_t *p = (const uint8_t *)src;
  return ((uint64_t)p[0] << 56)
       | ((uint64_t)p[1] << 48)
       | ((uint64_t)p[2] << 40)
       | ((uint64_t)p[3] << 32)
       | ((uint64_t)p[4] << 24)
       | ((uint64_t)p[5] << 16)
       | ((uint64_t)p[6] << 8)
       | ((uint64_t)p[7] << 0);
#endif
}

static void
write64be(void *dst, uint64_t w) {
#ifdef WORDS_BIGENDIAN
  memcpy(dst, &w, sizeof(w));
#else
  uint8_t *p = (uint8_t *)dst;
  p[0] = w >> 56;
  p[1] = w >> 48;
  p[2] = w >> 40;
  p[3] = w >> 32;
  p[4] = w >> 24;
  p[5] = w >> 16;
  p[6] = w >> 8;
  p[7] = w >> 0;
#endif
}

static uint32_t
read32le(const void *src) {
#ifndef WORDS_BIGENDIAN
  uint32_t w;
  memcpy(&w, src, sizeof(w));
  return w;
#else
  const uint8_t *p = (const uint8_t *)src;
  return ((uint32_t)p[3] << 24)
       | ((uint32_t)p[2] << 16)
       | ((uint32_t)p[1] << 8)
       | ((uint32_t)p[0] << 0);
#endif
}

static void
write32le(void *dst, uint32_t w) {
#ifndef WORDS_BIGENDIAN
  memcpy(dst, &w, sizeof(w));
#else
  uint8_t *p = (uint8_t *)dst;
  p[3] = w >> 24;
  p[2] = w >> 16;
  p[1] = w >> 8;
  p[0] = w >> 0;
#endif
}

static uint64_t
read64le(const void *src) {
#ifndef WORDS_BIGENDIAN
  uint64_t w;
  memcpy(&w, src, sizeof(w));
  return w;
#else
  const uint8_t *p = (const uint8_t *)src;
  return ((uint64_t)p[7] << 56)
       | ((uint64_t)p[6] << 48)
       | ((uint64_t)p[5] << 40)
       | ((uint64_t)p[4] << 32)
       | ((uint64_t)p[3] << 24)
       | ((uint64_t)p[2] << 16)
       | ((uint64_t)p[1] << 8)
       | ((uint64_t)p[0] << 0);
#endif
}

static void
write64le(void *dst, uint64_t w) {
#ifndef WORDS_BIGENDIAN
  memcpy(dst, &w, sizeof(w));
#else
  uint8_t *p = (uint8_t *)dst;
  p[7] = w >> 56;
  p[6] = w >> 48;
  p[5] = w >> 40;
  p[4] = w >> 32;
  p[3] = w >> 24;
  p[2] = w >> 16;
  p[1] = w >> 8;
  p[0] = w >> 0;
#endif
}

/*
 * MD2
 */

static const uint8_t md2_S[256] = {
  41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6,
  19, 98, 167, 5, 243, 192, 199, 115, 140, 152, 147, 43, 217, 188,
  76, 130, 202, 30, 155, 87, 60, 253, 212, 224, 22, 103, 66, 111, 24,
  138, 23, 229, 18, 190, 78, 196, 214, 218, 158, 222, 73, 160, 251,
  245, 142, 187, 47, 238, 122, 169, 104, 121, 145, 21, 178, 7, 63,
  148, 194, 16, 137, 11, 34, 95, 33, 128, 127, 93, 154, 90, 144, 50,
  39, 53, 62, 204, 231, 191, 247, 151, 3, 255, 25, 48, 179, 72, 165,
  181, 209, 215, 94, 146, 42, 172, 86, 170, 198, 79, 184, 56, 210,
  150, 164, 125, 182, 118, 252, 107, 226, 156, 116, 4, 241, 69, 157,
  112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45, 168, 2, 27,
  96, 37, 173, 174, 176, 185, 246, 28, 70, 97, 105, 52, 64, 126, 15,
  85, 71, 163, 35, 221, 81, 175, 58, 195, 92, 249, 206, 186, 197,
  234, 38, 44, 83, 13, 110, 133, 40, 132, 9, 211, 223, 205, 244, 65,
  129, 77, 82, 106, 220, 55, 200, 108, 193, 171, 250, 36, 225, 123,
  8, 12, 189, 177, 74, 120, 136, 149, 139, 227, 99, 232, 109, 233,
  203, 213, 254, 59, 0, 29, 57, 242, 239, 183, 14, 102, 88, 208, 228,
  166, 119, 114, 248, 235, 117, 75, 10, 49, 68, 80, 180, 143, 237,
  31, 26, 219, 153, 141, 51, 159, 17, 131, 20
};

void
md2_init(md2_t *ctx) {
  memset(ctx, 0, sizeof(md2_t));
}

static void
md2_transform(md2_t *ctx, const unsigned char *chunk) {
  uint8_t t, l;
  size_t j, k;

  for (j = 0; j < 16; j++) {
    ctx->state[16 + j] = chunk[j];
    ctx->state[32 + j] = ctx->state[16 + j] ^ ctx->state[j];
  }

  t = 0;

  for (j = 0; j < 18; j++) {
    for (k = 0; k < 48; k++) {
      ctx->state[k] ^= md2_S[t];
      t = ctx->state[k];
    }
    t += (uint8_t)j;
  }

  l = ctx->checksum[15];

  for (j = 0; j < 16; j++) {
    ctx->checksum[j] ^= md2_S[chunk[j] ^ l];
    l = ctx->checksum[j];
  }
}

void
md2_update(md2_t *ctx, const void *data, size_t len) {
  const unsigned char *bytes = (const unsigned char *)data;
  size_t pos = ctx->size & 15;
  size_t off = 0;

  ctx->size += len;

  if (pos > 0) {
    size_t want = 16 - pos;

    if (want > len)
      want = len;

    memcpy(ctx->block + pos, bytes + off, want);

    pos += want;
    len -= want;
    off += want;

    if (pos < 16)
      return;

    md2_transform(ctx, ctx->block);
  }

  while (len >= 16) {
    md2_transform(ctx, bytes + off);
    off += 16;
    len -= 16;
  }

  if (len > 0)
    memcpy(ctx->block, bytes + off, len);
}

void
md2_final(md2_t *ctx, unsigned char *out) {
  size_t pos = ctx->size & 15;
  size_t left = 16 - pos;
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
 */

static const unsigned char md4_P[64] = {
  0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

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
  uint32_t data[16];
  uint32_t a, b, c, d;
  unsigned int i;

  for (i = 0; i < 16; i++, chunk += 4)
    data[i] = read32le(chunk);

  a = ctx->state[0];
  b = ctx->state[1];
  c = ctx->state[2];
  d = ctx->state[3];

#define F(x, y, z) (((y) & (x)) | ((z) & ~(x)))
#define G(x, y, z) (((y) & (x)) | ((z) & (x)) | ((y) & (z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define ROUND(f, w, x, y, z, data, s) \
  (w += f(x, y, z) + data,  w = w << s | w >> (32 - s))

  ROUND(F, a, b, c, d, data[ 0], 3);
  ROUND(F, d, a, b, c, data[ 1], 7);
  ROUND(F, c, d, a, b, data[ 2], 11);
  ROUND(F, b, c, d, a, data[ 3], 19);
  ROUND(F, a, b, c, d, data[ 4], 3);
  ROUND(F, d, a, b, c, data[ 5], 7);
  ROUND(F, c, d, a, b, data[ 6], 11);
  ROUND(F, b, c, d, a, data[ 7], 19);
  ROUND(F, a, b, c, d, data[ 8], 3);
  ROUND(F, d, a, b, c, data[ 9], 7);
  ROUND(F, c, d, a, b, data[10], 11);
  ROUND(F, b, c, d, a, data[11], 19);
  ROUND(F, a, b, c, d, data[12], 3);
  ROUND(F, d, a, b, c, data[13], 7);
  ROUND(F, c, d, a, b, data[14], 11);
  ROUND(F, b, c, d, a, data[15], 19);

  ROUND(G, a, b, c, d, data[ 0] + 0x5a827999, 3);
  ROUND(G, d, a, b, c, data[ 4] + 0x5a827999, 5);
  ROUND(G, c, d, a, b, data[ 8] + 0x5a827999, 9);
  ROUND(G, b, c, d, a, data[12] + 0x5a827999, 13);
  ROUND(G, a, b, c, d, data[ 1] + 0x5a827999, 3);
  ROUND(G, d, a, b, c, data[ 5] + 0x5a827999, 5);
  ROUND(G, c, d, a, b, data[ 9] + 0x5a827999, 9);
  ROUND(G, b, c, d, a, data[13] + 0x5a827999, 13);
  ROUND(G, a, b, c, d, data[ 2] + 0x5a827999, 3);
  ROUND(G, d, a, b, c, data[ 6] + 0x5a827999, 5);
  ROUND(G, c, d, a, b, data[10] + 0x5a827999, 9);
  ROUND(G, b, c, d, a, data[14] + 0x5a827999, 13);
  ROUND(G, a, b, c, d, data[ 3] + 0x5a827999, 3);
  ROUND(G, d, a, b, c, data[ 7] + 0x5a827999, 5);
  ROUND(G, c, d, a, b, data[11] + 0x5a827999, 9);
  ROUND(G, b, c, d, a, data[15] + 0x5a827999, 13);

  ROUND(H, a, b, c, d, data[ 0] + 0x6ed9eba1, 3);
  ROUND(H, d, a, b, c, data[ 8] + 0x6ed9eba1, 9);
  ROUND(H, c, d, a, b, data[ 4] + 0x6ed9eba1, 11);
  ROUND(H, b, c, d, a, data[12] + 0x6ed9eba1, 15);
  ROUND(H, a, b, c, d, data[ 2] + 0x6ed9eba1, 3);
  ROUND(H, d, a, b, c, data[10] + 0x6ed9eba1, 9);
  ROUND(H, c, d, a, b, data[ 6] + 0x6ed9eba1, 11);
  ROUND(H, b, c, d, a, data[14] + 0x6ed9eba1, 15);
  ROUND(H, a, b, c, d, data[ 1] + 0x6ed9eba1, 3);
  ROUND(H, d, a, b, c, data[ 9] + 0x6ed9eba1, 9);
  ROUND(H, c, d, a, b, data[ 5] + 0x6ed9eba1, 11);
  ROUND(H, b, c, d, a, data[13] + 0x6ed9eba1, 15);
  ROUND(H, a, b, c, d, data[ 3] + 0x6ed9eba1, 3);
  ROUND(H, d, a, b, c, data[11] + 0x6ed9eba1, 9);
  ROUND(H, c, d, a, b, data[ 7] + 0x6ed9eba1, 11);
  ROUND(H, b, c, d, a, data[15] + 0x6ed9eba1, 15);

#undef F
#undef G
#undef H
#undef ROUND

  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;
}

void
md4_update(md4_t *ctx, const void *data, size_t len) {
  const unsigned char *bytes = (const unsigned char *)data;
  size_t pos = ctx->size & 63;
  size_t off = 0;

  ctx->size += len;

  if (pos > 0) {
    size_t want = 64 - pos;

    if (want > len)
      want = len;

    memcpy(ctx->block + pos, bytes + off, want);

    pos += want;
    len -= want;
    off += want;

    if (pos < 64)
      return;

    md4_transform(ctx, ctx->block);
  }

  while (len >= 64) {
    md4_transform(ctx, bytes + off);
    off += 64;
    len -= 64;
  }

  if (len > 0)
    memcpy(ctx->block, bytes + off, len);
}

void
md4_final(md4_t *ctx, unsigned char *out) {
  size_t pos = ctx->size & 63;
  uint64_t len = ctx->size << 3;
  unsigned char D[8];
  size_t i;

  write64le(D, len);

  md4_update(ctx, md4_P, 1 + ((119 - pos) & 63));
  md4_update(ctx, D, 8);

  for (i = 0; i < 4; i++)
    write32le(out + i * 4, ctx->state[i]);
}

/*
 * MD5
 */

static const unsigned char md5_P[64] = {
  0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

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
  uint32_t data[16];
  uint32_t a, b, c, d;
  unsigned int i;

  for (i = 0; i < 16; i++, chunk += 4)
    data[i] = read32le(chunk);

  a = ctx->state[0];
  b = ctx->state[1];
  c = ctx->state[2];
  d = ctx->state[3];

#define F1(x, y, z) ((z) ^ ((x) & ((y) ^ (z))))
#define F2(x, y, z) F1((z), (x), (y))
#define F3(x, y, z) ((x) ^ (y) ^ (z))
#define F4(x, y, z) ((y) ^ ((x) | ~(z)))
#define ROUND(f, w, x, y, z, data, s) \
  (w += f(x, y, z) + data,  w = w << s | w >> (32 - s), w += x)

  ROUND(F1, a, b, c, d, data[ 0] + 0xd76aa478, 7);
  ROUND(F1, d, a, b, c, data[ 1] + 0xe8c7b756, 12);
  ROUND(F1, c, d, a, b, data[ 2] + 0x242070db, 17);
  ROUND(F1, b, c, d, a, data[ 3] + 0xc1bdceee, 22);
  ROUND(F1, a, b, c, d, data[ 4] + 0xf57c0faf, 7);
  ROUND(F1, d, a, b, c, data[ 5] + 0x4787c62a, 12);
  ROUND(F1, c, d, a, b, data[ 6] + 0xa8304613, 17);
  ROUND(F1, b, c, d, a, data[ 7] + 0xfd469501, 22);
  ROUND(F1, a, b, c, d, data[ 8] + 0x698098d8, 7);
  ROUND(F1, d, a, b, c, data[ 9] + 0x8b44f7af, 12);
  ROUND(F1, c, d, a, b, data[10] + 0xffff5bb1, 17);
  ROUND(F1, b, c, d, a, data[11] + 0x895cd7be, 22);
  ROUND(F1, a, b, c, d, data[12] + 0x6b901122, 7);
  ROUND(F1, d, a, b, c, data[13] + 0xfd987193, 12);
  ROUND(F1, c, d, a, b, data[14] + 0xa679438e, 17);
  ROUND(F1, b, c, d, a, data[15] + 0x49b40821, 22);

  ROUND(F2, a, b, c, d, data[ 1] + 0xf61e2562, 5);
  ROUND(F2, d, a, b, c, data[ 6] + 0xc040b340, 9);
  ROUND(F2, c, d, a, b, data[11] + 0x265e5a51, 14);
  ROUND(F2, b, c, d, a, data[ 0] + 0xe9b6c7aa, 20);
  ROUND(F2, a, b, c, d, data[ 5] + 0xd62f105d, 5);
  ROUND(F2, d, a, b, c, data[10] + 0x02441453, 9);
  ROUND(F2, c, d, a, b, data[15] + 0xd8a1e681, 14);
  ROUND(F2, b, c, d, a, data[ 4] + 0xe7d3fbc8, 20);
  ROUND(F2, a, b, c, d, data[ 9] + 0x21e1cde6, 5);
  ROUND(F2, d, a, b, c, data[14] + 0xc33707d6, 9);
  ROUND(F2, c, d, a, b, data[ 3] + 0xf4d50d87, 14);
  ROUND(F2, b, c, d, a, data[ 8] + 0x455a14ed, 20);
  ROUND(F2, a, b, c, d, data[13] + 0xa9e3e905, 5);
  ROUND(F2, d, a, b, c, data[ 2] + 0xfcefa3f8, 9);
  ROUND(F2, c, d, a, b, data[ 7] + 0x676f02d9, 14);
  ROUND(F2, b, c, d, a, data[12] + 0x8d2a4c8a, 20);

  ROUND(F3, a, b, c, d, data[ 5] + 0xfffa3942, 4);
  ROUND(F3, d, a, b, c, data[ 8] + 0x8771f681, 11);
  ROUND(F3, c, d, a, b, data[11] + 0x6d9d6122, 16);
  ROUND(F3, b, c, d, a, data[14] + 0xfde5380c, 23);
  ROUND(F3, a, b, c, d, data[ 1] + 0xa4beea44, 4);
  ROUND(F3, d, a, b, c, data[ 4] + 0x4bdecfa9, 11);
  ROUND(F3, c, d, a, b, data[ 7] + 0xf6bb4b60, 16);
  ROUND(F3, b, c, d, a, data[10] + 0xbebfbc70, 23);
  ROUND(F3, a, b, c, d, data[13] + 0x289b7ec6, 4);
  ROUND(F3, d, a, b, c, data[ 0] + 0xeaa127fa, 11);
  ROUND(F3, c, d, a, b, data[ 3] + 0xd4ef3085, 16);
  ROUND(F3, b, c, d, a, data[ 6] + 0x04881d05, 23);
  ROUND(F3, a, b, c, d, data[ 9] + 0xd9d4d039, 4);
  ROUND(F3, d, a, b, c, data[12] + 0xe6db99e5, 11);
  ROUND(F3, c, d, a, b, data[15] + 0x1fa27cf8, 16);
  ROUND(F3, b, c, d, a, data[ 2] + 0xc4ac5665, 23);

  ROUND(F4, a, b, c, d, data[ 0] + 0xf4292244, 6);
  ROUND(F4, d, a, b, c, data[ 7] + 0x432aff97, 10);
  ROUND(F4, c, d, a, b, data[14] + 0xab9423a7, 15);
  ROUND(F4, b, c, d, a, data[ 5] + 0xfc93a039, 21);
  ROUND(F4, a, b, c, d, data[12] + 0x655b59c3, 6);
  ROUND(F4, d, a, b, c, data[ 3] + 0x8f0ccc92, 10);
  ROUND(F4, c, d, a, b, data[10] + 0xffeff47d, 15);
  ROUND(F4, b, c, d, a, data[ 1] + 0x85845dd1, 21);
  ROUND(F4, a, b, c, d, data[ 8] + 0x6fa87e4f, 6);
  ROUND(F4, d, a, b, c, data[15] + 0xfe2ce6e0, 10);
  ROUND(F4, c, d, a, b, data[ 6] + 0xa3014314, 15);
  ROUND(F4, b, c, d, a, data[13] + 0x4e0811a1, 21);
  ROUND(F4, a, b, c, d, data[ 4] + 0xf7537e82, 6);
  ROUND(F4, d, a, b, c, data[11] + 0xbd3af235, 10);
  ROUND(F4, c, d, a, b, data[ 2] + 0x2ad7d2bb, 15);
  ROUND(F4, b, c, d, a, data[ 9] + 0xeb86d391, 21);

#undef F1
#undef F2
#undef F3
#undef F4
#undef ROUND

  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;
}

void
md5_update(md5_t *ctx, const void *data, size_t len) {
  const unsigned char *bytes = (const unsigned char *)data;
  size_t pos = ctx->size & 63;
  size_t off = 0;

  ctx->size += len;

  if (pos > 0) {
    size_t want = 64 - pos;

    if (want > len)
      want = len;

    memcpy(ctx->block + pos, bytes + off, want);

    pos += want;
    len -= want;
    off += want;

    if (pos < 64)
      return;

    md5_transform(ctx, ctx->block);
  }

  while (len >= 64) {
    md5_transform(ctx, bytes + off);
    off += 64;
    len -= 64;
  }

  if (len > 0)
    memcpy(ctx->block, bytes + off, len);
}

void
md5_final(md5_t *ctx, unsigned char *out) {
  size_t pos = ctx->size & 63;
  uint64_t len = ctx->size << 3;
  unsigned char D[8];
  size_t i;

  write64le(D, len);

  md5_update(ctx, md5_P, 1 + ((119 - pos) & 63));
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
 */

static const unsigned char ripemd160_P[64] = {
  0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

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
  register uint32_t a, b, c, d, e;
  uint32_t aa, bb, cc, dd, ee, t;
  uint32_t x[16];

#ifdef WORDS_BIGENDIAN
  {
    int i;
    for (i = 0; i < 16; i++, chunk += 4)
      x[i] = read32le(chunk);
  }
#else
  memcpy(x, chunk, sizeof(x));
#endif

#define K0 0x00000000
#define K1 0x5a827999
#define K2 0x6ed9eba1
#define K3 0x8f1bbcdc
#define K4 0xa953fd4e
#define KK0 0x50a28be6
#define KK1 0x5c4dd124
#define KK2 0x6d703ef3
#define KK3 0x7a6d76e9
#define KK4 0x00000000
#define F0(x, y, z) ((x) ^ (y) ^ (z))
#define F1(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define F2(x, y, z) (((x) | ~(y)) ^ (z))
#define F3(x, y, z) (((x) & (z)) | ((y) & ~(z)))
#define F4(x, y, z) ((x) ^ ((y) | ~(z)))
#define R(a, b, c, d, e, f, k, r, s) do { \
  t = a + f(b, c, d) + k + x[r];          \
  a = ROTL32(s, t) + e;                   \
  c = ROTL32(10, c);                      \
} while (0)

  a = ctx->state[0];
  b = ctx->state[1];
  c = ctx->state[2];
  d = ctx->state[3];
  e = ctx->state[4];

  R(a, b, c, d, e, F0, K0,  0, 11);
  R(e, a, b, c, d, F0, K0,  1, 14);
  R(d, e, a, b, c, F0, K0,  2, 15);
  R(c, d, e, a, b, F0, K0,  3, 12);
  R(b, c, d, e, a, F0, K0,  4,  5);
  R(a, b, c, d, e, F0, K0,  5,  8);
  R(e, a, b, c, d, F0, K0,  6,  7);
  R(d, e, a, b, c, F0, K0,  7,  9);
  R(c, d, e, a, b, F0, K0,  8, 11);
  R(b, c, d, e, a, F0, K0,  9, 13);
  R(a, b, c, d, e, F0, K0, 10, 14);
  R(e, a, b, c, d, F0, K0, 11, 15);
  R(d, e, a, b, c, F0, K0, 12,  6);
  R(c, d, e, a, b, F0, K0, 13,  7);
  R(b, c, d, e, a, F0, K0, 14,  9);
  R(a, b, c, d, e, F0, K0, 15,  8);
  R(e, a, b, c, d, F1, K1,  7,  7);
  R(d, e, a, b, c, F1, K1,  4,  6);
  R(c, d, e, a, b, F1, K1, 13,  8);
  R(b, c, d, e, a, F1, K1,  1, 13);
  R(a, b, c, d, e, F1, K1, 10, 11);
  R(e, a, b, c, d, F1, K1,  6,  9);
  R(d, e, a, b, c, F1, K1, 15,  7);
  R(c, d, e, a, b, F1, K1,  3, 15);
  R(b, c, d, e, a, F1, K1, 12,  7);
  R(a, b, c, d, e, F1, K1,  0, 12);
  R(e, a, b, c, d, F1, K1,  9, 15);
  R(d, e, a, b, c, F1, K1,  5,  9);
  R(c, d, e, a, b, F1, K1,  2, 11);
  R(b, c, d, e, a, F1, K1, 14,  7);
  R(a, b, c, d, e, F1, K1, 11, 13);
  R(e, a, b, c, d, F1, K1,  8, 12);
  R(d, e, a, b, c, F2, K2,  3, 11);
  R(c, d, e, a, b, F2, K2, 10, 13);
  R(b, c, d, e, a, F2, K2, 14,  6);
  R(a, b, c, d, e, F2, K2,  4,  7);
  R(e, a, b, c, d, F2, K2,  9, 14);
  R(d, e, a, b, c, F2, K2, 15,  9);
  R(c, d, e, a, b, F2, K2,  8, 13);
  R(b, c, d, e, a, F2, K2,  1, 15);
  R(a, b, c, d, e, F2, K2,  2, 14);
  R(e, a, b, c, d, F2, K2,  7,  8);
  R(d, e, a, b, c, F2, K2,  0, 13);
  R(c, d, e, a, b, F2, K2,  6,  6);
  R(b, c, d, e, a, F2, K2, 13,  5);
  R(a, b, c, d, e, F2, K2, 11, 12);
  R(e, a, b, c, d, F2, K2,  5,  7);
  R(d, e, a, b, c, F2, K2, 12,  5);
  R(c, d, e, a, b, F3, K3,  1, 11);
  R(b, c, d, e, a, F3, K3,  9, 12);
  R(a, b, c, d, e, F3, K3, 11, 14);
  R(e, a, b, c, d, F3, K3, 10, 15);
  R(d, e, a, b, c, F3, K3,  0, 14);
  R(c, d, e, a, b, F3, K3,  8, 15);
  R(b, c, d, e, a, F3, K3, 12,  9);
  R(a, b, c, d, e, F3, K3,  4,  8);
  R(e, a, b, c, d, F3, K3, 13,  9);
  R(d, e, a, b, c, F3, K3,  3, 14);
  R(c, d, e, a, b, F3, K3,  7,  5);
  R(b, c, d, e, a, F3, K3, 15,  6);
  R(a, b, c, d, e, F3, K3, 14,  8);
  R(e, a, b, c, d, F3, K3,  5,  6);
  R(d, e, a, b, c, F3, K3,  6,  5);
  R(c, d, e, a, b, F3, K3,  2, 12);
  R(b, c, d, e, a, F4, K4,  4,  9);
  R(a, b, c, d, e, F4, K4,  0, 15);
  R(e, a, b, c, d, F4, K4,  5,  5);
  R(d, e, a, b, c, F4, K4,  9, 11);
  R(c, d, e, a, b, F4, K4,  7,  6);
  R(b, c, d, e, a, F4, K4, 12,  8);
  R(a, b, c, d, e, F4, K4,  2, 13);
  R(e, a, b, c, d, F4, K4, 10, 12);
  R(d, e, a, b, c, F4, K4, 14,  5);
  R(c, d, e, a, b, F4, K4,  1, 12);
  R(b, c, d, e, a, F4, K4,  3, 13);
  R(a, b, c, d, e, F4, K4,  8, 14);
  R(e, a, b, c, d, F4, K4, 11, 11);
  R(d, e, a, b, c, F4, K4,  6,  8);
  R(c, d, e, a, b, F4, K4, 15,  5);
  R(b, c, d, e, a, F4, K4, 13,  6);

  aa = a;
  bb = b;
  cc = c;
  dd = d;
  ee = e;

  a = ctx->state[0];
  b = ctx->state[1];
  c = ctx->state[2];
  d = ctx->state[3];
  e = ctx->state[4];

  R(a, b, c, d, e, F4, KK0,  5,  8);
  R(e, a, b, c, d, F4, KK0, 14,  9);
  R(d, e, a, b, c, F4, KK0,  7,  9);
  R(c, d, e, a, b, F4, KK0,  0, 11);
  R(b, c, d, e, a, F4, KK0,  9, 13);
  R(a, b, c, d, e, F4, KK0,  2, 15);
  R(e, a, b, c, d, F4, KK0, 11, 15);
  R(d, e, a, b, c, F4, KK0,  4,  5);
  R(c, d, e, a, b, F4, KK0, 13,  7);
  R(b, c, d, e, a, F4, KK0,  6,  7);
  R(a, b, c, d, e, F4, KK0, 15,  8);
  R(e, a, b, c, d, F4, KK0,  8, 11);
  R(d, e, a, b, c, F4, KK0,  1, 14);
  R(c, d, e, a, b, F4, KK0, 10, 14);
  R(b, c, d, e, a, F4, KK0,  3, 12);
  R(a, b, c, d, e, F4, KK0, 12,  6);
  R(e, a, b, c, d, F3, KK1,  6,  9);
  R(d, e, a, b, c, F3, KK1, 11, 13);
  R(c, d, e, a, b, F3, KK1,  3, 15);
  R(b, c, d, e, a, F3, KK1,  7,  7);
  R(a, b, c, d, e, F3, KK1,  0, 12);
  R(e, a, b, c, d, F3, KK1, 13,  8);
  R(d, e, a, b, c, F3, KK1,  5,  9);
  R(c, d, e, a, b, F3, KK1, 10, 11);
  R(b, c, d, e, a, F3, KK1, 14,  7);
  R(a, b, c, d, e, F3, KK1, 15,  7);
  R(e, a, b, c, d, F3, KK1,  8, 12);
  R(d, e, a, b, c, F3, KK1, 12,  7);
  R(c, d, e, a, b, F3, KK1,  4,  6);
  R(b, c, d, e, a, F3, KK1,  9, 15);
  R(a, b, c, d, e, F3, KK1,  1, 13);
  R(e, a, b, c, d, F3, KK1,  2, 11);
  R(d, e, a, b, c, F2, KK2, 15,  9);
  R(c, d, e, a, b, F2, KK2,  5,  7);
  R(b, c, d, e, a, F2, KK2,  1, 15);
  R(a, b, c, d, e, F2, KK2,  3, 11);
  R(e, a, b, c, d, F2, KK2,  7,  8);
  R(d, e, a, b, c, F2, KK2, 14,  6);
  R(c, d, e, a, b, F2, KK2,  6,  6);
  R(b, c, d, e, a, F2, KK2,  9, 14);
  R(a, b, c, d, e, F2, KK2, 11, 12);
  R(e, a, b, c, d, F2, KK2,  8, 13);
  R(d, e, a, b, c, F2, KK2, 12,  5);
  R(c, d, e, a, b, F2, KK2,  2, 14);
  R(b, c, d, e, a, F2, KK2, 10, 13);
  R(a, b, c, d, e, F2, KK2,  0, 13);
  R(e, a, b, c, d, F2, KK2,  4,  7);
  R(d, e, a, b, c, F2, KK2, 13,  5);
  R(c, d, e, a, b, F1, KK3,  8, 15);
  R(b, c, d, e, a, F1, KK3,  6,  5);
  R(a, b, c, d, e, F1, KK3,  4,  8);
  R(e, a, b, c, d, F1, KK3,  1, 11);
  R(d, e, a, b, c, F1, KK3,  3, 14);
  R(c, d, e, a, b, F1, KK3, 11, 14);
  R(b, c, d, e, a, F1, KK3, 15,  6);
  R(a, b, c, d, e, F1, KK3,  0, 14);
  R(e, a, b, c, d, F1, KK3,  5,  6);
  R(d, e, a, b, c, F1, KK3, 12,  9);
  R(c, d, e, a, b, F1, KK3,  2, 12);
  R(b, c, d, e, a, F1, KK3, 13,  9);
  R(a, b, c, d, e, F1, KK3,  9, 12);
  R(e, a, b, c, d, F1, KK3,  7,  5);
  R(d, e, a, b, c, F1, KK3, 10, 15);
  R(c, d, e, a, b, F1, KK3, 14,  8);
  R(b, c, d, e, a, F0, KK4, 12,  8);
  R(a, b, c, d, e, F0, KK4, 15,  5);
  R(e, a, b, c, d, F0, KK4, 10, 12);
  R(d, e, a, b, c, F0, KK4,  4,  9);
  R(c, d, e, a, b, F0, KK4,  1, 12);
  R(b, c, d, e, a, F0, KK4,  5,  5);
  R(a, b, c, d, e, F0, KK4,  8, 14);
  R(e, a, b, c, d, F0, KK4,  7,  6);
  R(d, e, a, b, c, F0, KK4,  6,  8);
  R(c, d, e, a, b, F0, KK4,  2, 13);
  R(b, c, d, e, a, F0, KK4, 13,  6);
  R(a, b, c, d, e, F0, KK4, 14,  5);
  R(e, a, b, c, d, F0, KK4,  0, 15);
  R(d, e, a, b, c, F0, KK4,  3, 13);
  R(c, d, e, a, b, F0, KK4,  9, 11);
  R(b, c, d, e, a, F0, KK4, 11, 11);

#undef K0
#undef K1
#undef K2
#undef K3
#undef K4
#undef KK0
#undef KK1
#undef KK2
#undef KK3
#undef KK4
#undef F0
#undef F1
#undef F2
#undef F3
#undef F4
#undef R

  t = ctx->state[1] + d + cc;
  ctx->state[1] = ctx->state[2] + e + dd;
  ctx->state[2] = ctx->state[3] + a + ee;
  ctx->state[3] = ctx->state[4] + b + aa;
  ctx->state[4] = ctx->state[0] + c + bb;
  ctx->state[0] = t;
}

void
ripemd160_update(ripemd160_t *ctx, const void *data, size_t len) {
  const unsigned char *bytes = (const unsigned char *)data;
  size_t pos = ctx->size & 63;
  size_t off = 0;

  ctx->size += len;

  if (pos > 0) {
    size_t want = 64 - pos;

    if (want > len)
      want = len;

    memcpy(ctx->block + pos, bytes + off, want);

    pos += want;
    len -= want;
    off += want;

    if (pos < 64)
      return;

    ripemd160_transform(ctx, ctx->block);
  }

  while (len >= 64) {
    ripemd160_transform(ctx, bytes + off);
    off += 64;
    len -= 64;
  }

  if (len > 0)
    memcpy(ctx->block, bytes + off, len);
}

void
ripemd160_final(ripemd160_t *ctx, unsigned char *out) {
  size_t pos = ctx->size & 63;
  uint64_t len = ctx->size << 3;
  unsigned char D[8];
  size_t i;

  write64le(D, len);

  ripemd160_update(ctx, ripemd160_P, 1 + ((119 - pos) & 63));
  ripemd160_update(ctx, D, 8);

  for (i = 0; i < 5; i++)
    write32le(out + i * 4, ctx->state[i]);
}

/*
 * SHA1
 */

static const unsigned char sha1_P[64] = {
  0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

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
  uint32_t data[16];
  uint32_t A, B, C, D, E;
  int i;

  for (i = 0; i < 16; i++, chunk += 4)
    data[i] = read32be(chunk);

  A = ctx->state[0];
  B = ctx->state[1];
  C = ctx->state[2];
  D = ctx->state[3];
  E = ctx->state[4];

#define f1(x,y,z) (z ^ (x & (y ^ z)))
#define f2(x,y,z) (x ^ y ^ z )
#define f3(x,y,z) ((x & y) | (z & (x | y)))
#define f4 f2
#define K1 0x5a827999l
#define K2 0x6ed9eba1l
#define K3 0x8f1bbcdcl
#define K4 0xca62c1d6l
#define expand(W, i) (W[i & 15] =         \
  ROTL32(1, (W[i & 15] ^ W[(i - 14) & 15] \
  ^ W[(i - 8) & 15] ^ W[(i - 3) & 15])))
#define subround(a, b, c, d, e, f, k, data) \
  (e += ROTL32(5, a) + f(b, c, d) + k + data, b = ROTL32(30, b))

  subround(A, B, C, D, E, f1, K1, data[ 0]);
  subround(E, A, B, C, D, f1, K1, data[ 1]);
  subround(D, E, A, B, C, f1, K1, data[ 2]);
  subround(C, D, E, A, B, f1, K1, data[ 3]);
  subround(B, C, D, E, A, f1, K1, data[ 4]);
  subround(A, B, C, D, E, f1, K1, data[ 5]);
  subround(E, A, B, C, D, f1, K1, data[ 6]);
  subround(D, E, A, B, C, f1, K1, data[ 7]);
  subround(C, D, E, A, B, f1, K1, data[ 8]);
  subround(B, C, D, E, A, f1, K1, data[ 9]);
  subround(A, B, C, D, E, f1, K1, data[10]);
  subround(E, A, B, C, D, f1, K1, data[11]);
  subround(D, E, A, B, C, f1, K1, data[12]);
  subround(C, D, E, A, B, f1, K1, data[13]);
  subround(B, C, D, E, A, f1, K1, data[14]);
  subround(A, B, C, D, E, f1, K1, data[15]);
  subround(E, A, B, C, D, f1, K1, expand(data, 16));
  subround(D, E, A, B, C, f1, K1, expand(data, 17));
  subround(C, D, E, A, B, f1, K1, expand(data, 18));
  subround(B, C, D, E, A, f1, K1, expand(data, 19));

  subround(A, B, C, D, E, f2, K2, expand(data, 20));
  subround(E, A, B, C, D, f2, K2, expand(data, 21));
  subround(D, E, A, B, C, f2, K2, expand(data, 22));
  subround(C, D, E, A, B, f2, K2, expand(data, 23));
  subround(B, C, D, E, A, f2, K2, expand(data, 24));
  subround(A, B, C, D, E, f2, K2, expand(data, 25));
  subround(E, A, B, C, D, f2, K2, expand(data, 26));
  subround(D, E, A, B, C, f2, K2, expand(data, 27));
  subround(C, D, E, A, B, f2, K2, expand(data, 28));
  subround(B, C, D, E, A, f2, K2, expand(data, 29));
  subround(A, B, C, D, E, f2, K2, expand(data, 30));
  subround(E, A, B, C, D, f2, K2, expand(data, 31));
  subround(D, E, A, B, C, f2, K2, expand(data, 32));
  subround(C, D, E, A, B, f2, K2, expand(data, 33));
  subround(B, C, D, E, A, f2, K2, expand(data, 34));
  subround(A, B, C, D, E, f2, K2, expand(data, 35));
  subround(E, A, B, C, D, f2, K2, expand(data, 36));
  subround(D, E, A, B, C, f2, K2, expand(data, 37));
  subround(C, D, E, A, B, f2, K2, expand(data, 38));
  subround(B, C, D, E, A, f2, K2, expand(data, 39));

  subround(A, B, C, D, E, f3, K3, expand(data, 40));
  subround(E, A, B, C, D, f3, K3, expand(data, 41));
  subround(D, E, A, B, C, f3, K3, expand(data, 42));
  subround(C, D, E, A, B, f3, K3, expand(data, 43));
  subround(B, C, D, E, A, f3, K3, expand(data, 44));
  subround(A, B, C, D, E, f3, K3, expand(data, 45));
  subround(E, A, B, C, D, f3, K3, expand(data, 46));
  subround(D, E, A, B, C, f3, K3, expand(data, 47));
  subround(C, D, E, A, B, f3, K3, expand(data, 48));
  subround(B, C, D, E, A, f3, K3, expand(data, 49));
  subround(A, B, C, D, E, f3, K3, expand(data, 50));
  subround(E, A, B, C, D, f3, K3, expand(data, 51));
  subround(D, E, A, B, C, f3, K3, expand(data, 52));
  subround(C, D, E, A, B, f3, K3, expand(data, 53));
  subround(B, C, D, E, A, f3, K3, expand(data, 54));
  subround(A, B, C, D, E, f3, K3, expand(data, 55));
  subround(E, A, B, C, D, f3, K3, expand(data, 56));
  subround(D, E, A, B, C, f3, K3, expand(data, 57));
  subround(C, D, E, A, B, f3, K3, expand(data, 58));
  subround(B, C, D, E, A, f3, K3, expand(data, 59));

  subround(A, B, C, D, E, f4, K4, expand(data, 60));
  subround(E, A, B, C, D, f4, K4, expand(data, 61));
  subround(D, E, A, B, C, f4, K4, expand(data, 62));
  subround(C, D, E, A, B, f4, K4, expand(data, 63));
  subround(B, C, D, E, A, f4, K4, expand(data, 64));
  subround(A, B, C, D, E, f4, K4, expand(data, 65));
  subround(E, A, B, C, D, f4, K4, expand(data, 66));
  subround(D, E, A, B, C, f4, K4, expand(data, 67));
  subround(C, D, E, A, B, f4, K4, expand(data, 68));
  subround(B, C, D, E, A, f4, K4, expand(data, 69));
  subround(A, B, C, D, E, f4, K4, expand(data, 70));
  subround(E, A, B, C, D, f4, K4, expand(data, 71));
  subround(D, E, A, B, C, f4, K4, expand(data, 72));
  subround(C, D, E, A, B, f4, K4, expand(data, 73));
  subround(B, C, D, E, A, f4, K4, expand(data, 74));
  subround(A, B, C, D, E, f4, K4, expand(data, 75));
  subround(E, A, B, C, D, f4, K4, expand(data, 76));
  subround(D, E, A, B, C, f4, K4, expand(data, 77));
  subround(C, D, E, A, B, f4, K4, expand(data, 78));
  subround(B, C, D, E, A, f4, K4, expand(data, 79));

#undef f1
#undef f2
#undef f3
#undef f4
#undef K1
#undef K2
#undef K3
#undef K4
#undef expand
#undef subround

  ctx->state[0] += A;
  ctx->state[1] += B;
  ctx->state[2] += C;
  ctx->state[3] += D;
  ctx->state[4] += E;
}

void
sha1_update(sha1_t *ctx, const void *data, size_t len) {
  const unsigned char *bytes = (const unsigned char *)data;
  size_t pos = ctx->size & 63;
  size_t off = 0;

  ctx->size += len;

  if (pos > 0) {
    size_t want = 64 - pos;

    if (want > len)
      want = len;

    memcpy(ctx->block + pos, bytes + off, want);

    pos += want;
    len -= want;
    off += want;

    if (pos < 64)
      return;

    sha1_transform(ctx, ctx->block);
  }

  while (len >= 64) {
    sha1_transform(ctx, bytes + off);
    off += 64;
    len -= 64;
  }

  if (len > 0)
    memcpy(ctx->block, bytes + off, len);
}

void
sha1_final(sha1_t *ctx, unsigned char *out) {
  size_t pos = ctx->size & 63;
  uint64_t len = ctx->size << 3;
  unsigned char D[8];
  size_t i;

  write64be(D, len);

  sha1_update(ctx, sha1_P, 1 + ((119 - pos) & 63));
  sha1_update(ctx, D, 8);

  for (i = 0; i < 5; i++)
    write32be(out + i * 4, ctx->state[i]);
}

/*
 * SHA256
 */

#ifdef TORSION_USE_OPENSSL
/* Doubtful that this ABI will change. */
int SHA256_Init(sha256_t *c);
int SHA256_Update(sha256_t *c, const void *data, size_t len);
int SHA256_Final(unsigned char *md, sha256_t *c);

void
sha256_init(sha256_t *ctx) {
  SHA256_Init(ctx);
}

void
sha256_update(sha256_t *ctx, const void *data, size_t len) {
  SHA256_Update(ctx, data, len);
}

void
sha256_final(sha256_t *ctx, unsigned char *out) {
  SHA256_Final(out, ctx);
}
#else /* TORSION_USE_OPENSSL */
static const uint32_t sha256_K[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static const unsigned char sha256_P[64] = {
  0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

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
  const uint32_t *k = sha256_K;
  uint32_t data[16];
  uint32_t A, B, C, D, E, F, G, H;
  unsigned i;
  uint32_t *d;

  for (i = 0; i < 16; i++, chunk += 4)
    data[i] = read32be(chunk);

  A = ctx->state[0];
  B = ctx->state[1];
  C = ctx->state[2];
  D = ctx->state[3];
  E = ctx->state[4];
  F = ctx->state[5];
  G = ctx->state[6];
  H = ctx->state[7];

#define Ch(x, y, z) ((z) ^ ((x) & ((y) ^ (z))))
#define Maj(x, y, z) (((x) & (y)) ^ ((z) & ((x) ^ (y))))

#define S0(x) (ROTL32(30, (x)) ^ ROTL32(19, (x)) ^ ROTL32(10, (x)))
#define S1(x) (ROTL32(26, (x)) ^ ROTL32(21, (x)) ^ ROTL32(7, (x)))

#define s0(x) (ROTL32(25, (x)) ^ ROTL32(14, (x)) ^ ((x) >> 3))
#define s1(x) (ROTL32(15, (x)) ^ ROTL32(13, (x)) ^ ((x) >> 10))

#define EXPAND(W,i) \
  (W[(i) & 15] += (s1(W[((i)-2) & 15]) + W[((i)-7) & 15] + s0(W[((i)-15) & 15])))

#define ROUND(a, b, c, d, e, f, g, h, k, data) do { \
  h += S1(e) + Ch(e, f, g) + k + data;              \
  d += h;                                           \
  h += S0(a) + Maj(a, b, c);                        \
} while (0)

  for (i = 0, d = data; i < 16; i += 8, k += 8, d += 8) {
    ROUND(A, B, C, D, E, F, G, H, k[0], d[0]);
    ROUND(H, A, B, C, D, E, F, G, k[1], d[1]);
    ROUND(G, H, A, B, C, D, E, F, k[2], d[2]);
    ROUND(F, G, H, A, B, C, D, E, k[3], d[3]);
    ROUND(E, F, G, H, A, B, C, D, k[4], d[4]);
    ROUND(D, E, F, G, H, A, B, C, k[5], d[5]);
    ROUND(C, D, E, F, G, H, A, B, k[6], d[6]);
    ROUND(B, C, D, E, F, G, H, A, k[7], d[7]);
  }

  for (; i < 64; i += 16, k += 16) {
    ROUND(A, B, C, D, E, F, G, H, k[ 0], EXPAND(data,  0));
    ROUND(H, A, B, C, D, E, F, G, k[ 1], EXPAND(data,  1));
    ROUND(G, H, A, B, C, D, E, F, k[ 2], EXPAND(data,  2));
    ROUND(F, G, H, A, B, C, D, E, k[ 3], EXPAND(data,  3));
    ROUND(E, F, G, H, A, B, C, D, k[ 4], EXPAND(data,  4));
    ROUND(D, E, F, G, H, A, B, C, k[ 5], EXPAND(data,  5));
    ROUND(C, D, E, F, G, H, A, B, k[ 6], EXPAND(data,  6));
    ROUND(B, C, D, E, F, G, H, A, k[ 7], EXPAND(data,  7));
    ROUND(A, B, C, D, E, F, G, H, k[ 8], EXPAND(data,  8));
    ROUND(H, A, B, C, D, E, F, G, k[ 9], EXPAND(data,  9));
    ROUND(G, H, A, B, C, D, E, F, k[10], EXPAND(data, 10));
    ROUND(F, G, H, A, B, C, D, E, k[11], EXPAND(data, 11));
    ROUND(E, F, G, H, A, B, C, D, k[12], EXPAND(data, 12));
    ROUND(D, E, F, G, H, A, B, C, k[13], EXPAND(data, 13));
    ROUND(C, D, E, F, G, H, A, B, k[14], EXPAND(data, 14));
    ROUND(B, C, D, E, F, G, H, A, k[15], EXPAND(data, 15));
  }

#undef Ch
#undef Maj
#undef S0
#undef S1
#undef s0
#undef s1
#undef EXPAND
#undef ROUND

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
  const unsigned char *bytes = (const unsigned char *)data;
  size_t pos = ctx->size & 63;
  size_t off = 0;

  ctx->size += len;

  if (pos > 0) {
    size_t want = 64 - pos;

    if (want > len)
      want = len;

    memcpy(ctx->block + pos, bytes + off, want);

    pos += want;
    len -= want;
    off += want;

    if (pos < 64)
      return;

    sha256_transform(ctx, ctx->block);
  }

  while (len >= 64) {
    sha256_transform(ctx, bytes + off);
    off += 64;
    len -= 64;
  }

  if (len > 0)
    memcpy(ctx->block, bytes + off, len);
}

void
sha256_final(sha256_t *ctx, unsigned char *out) {
  size_t pos = ctx->size & 63;
  uint64_t len = ctx->size << 3;
  unsigned char D[8];
  size_t i;

  write64be(D, len);

  sha256_update(ctx, sha256_P, 1 + ((119 - pos) & 63));
  sha256_update(ctx, D, 8);

  for (i = 0; i < 8; i++)
    write32be(out + i * 4, ctx->state[i]);
}
#endif /* TORSION_USE_OPENSSL */

/*
 * SHA224
 */

#ifdef TORSION_USE_OPENSSL
/* Doubtful that this ABI will change. */
int SHA224_Init(sha224_t *c);

void
sha224_init(sha224_t *ctx) {
  SHA224_Init(ctx);
}
#else /* TORSION_USE_OPENSSL */
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
#endif /* TORSION_USE_OPENSSL */

void
sha224_update(sha224_t *ctx, const void *data, size_t len) {
  sha256_update(ctx, data, len);
}

void
sha224_final(sha224_t *ctx, unsigned char *out) {
  uint8_t tmp[32];

  sha256_final(ctx, tmp);

  memcpy(out, tmp, 28);
  cleanse(tmp, sizeof(tmp));
}

/*
 * SHA512
 */

#ifdef TORSION_USE_OPENSSL
/* Doubtful that this ABI will change. */
int SHA512_Init(sha512_t *c);
int SHA512_Update(sha512_t *c, const void *data, size_t len);
int SHA512_Final(unsigned char *md, sha512_t *c);

void
sha512_init(sha512_t *ctx) {
  SHA512_Init(ctx);
}

void
sha512_update(sha512_t *ctx, const void *data, size_t len) {
  SHA512_Update(ctx, data, len);
}

void
sha512_final(sha512_t *ctx, unsigned char *out) {
  SHA512_Final(out, ctx);
}
#else /* TORSION_USE_OPENSSL */
static const uint64_t sha512_K[80] = {
  0x428a2f98d728ae22ull, 0x7137449123ef65cdull,
  0xb5c0fbcfec4d3b2full, 0xe9b5dba58189dbbcull,
  0x3956c25bf348b538ull, 0x59f111f1b605d019ull,
  0x923f82a4af194f9bull, 0xab1c5ed5da6d8118ull,
  0xd807aa98a3030242ull, 0x12835b0145706fbeull,
  0x243185be4ee4b28cull, 0x550c7dc3d5ffb4e2ull,
  0x72be5d74f27b896full, 0x80deb1fe3b1696b1ull,
  0x9bdc06a725c71235ull, 0xc19bf174cf692694ull,
  0xe49b69c19ef14ad2ull, 0xefbe4786384f25e3ull,
  0x0fc19dc68b8cd5b5ull, 0x240ca1cc77ac9c65ull,
  0x2de92c6f592b0275ull, 0x4a7484aa6ea6e483ull,
  0x5cb0a9dcbd41fbd4ull, 0x76f988da831153b5ull,
  0x983e5152ee66dfabull, 0xa831c66d2db43210ull,
  0xb00327c898fb213full, 0xbf597fc7beef0ee4ull,
  0xc6e00bf33da88fc2ull, 0xd5a79147930aa725ull,
  0x06ca6351e003826full, 0x142929670a0e6e70ull,
  0x27b70a8546d22ffcull, 0x2e1b21385c26c926ull,
  0x4d2c6dfc5ac42aedull, 0x53380d139d95b3dfull,
  0x650a73548baf63deull, 0x766a0abb3c77b2a8ull,
  0x81c2c92e47edaee6ull, 0x92722c851482353bull,
  0xa2bfe8a14cf10364ull, 0xa81a664bbc423001ull,
  0xc24b8b70d0f89791ull, 0xc76c51a30654be30ull,
  0xd192e819d6ef5218ull, 0xd69906245565a910ull,
  0xf40e35855771202aull, 0x106aa07032bbd1b8ull,
  0x19a4c116b8d2d0c8ull, 0x1e376c085141ab53ull,
  0x2748774cdf8eeb99ull, 0x34b0bcb5e19b48a8ull,
  0x391c0cb3c5c95a63ull, 0x4ed8aa4ae3418acbull,
  0x5b9cca4f7763e373ull, 0x682e6ff3d6b2b8a3ull,
  0x748f82ee5defb2fcull, 0x78a5636f43172f60ull,
  0x84c87814a1f0ab72ull, 0x8cc702081a6439ecull,
  0x90befffa23631e28ull, 0xa4506cebde82bde9ull,
  0xbef9a3f7b2c67915ull, 0xc67178f2e372532bull,
  0xca273eceea26619cull, 0xd186b8c721c0c207ull,
  0xeada7dd6cde0eb1eull, 0xf57d4f7fee6ed178ull,
  0x06f067aa72176fbaull, 0x0a637dc5a2c898a6ull,
  0x113f9804bef90daeull, 0x1b710b35131c471bull,
  0x28db77f523047d84ull, 0x32caab7b40c72493ull,
  0x3c9ebe0a15c9bebcull, 0x431d67c49c100d4cull,
  0x4cc5d4becb3e42b6ull, 0x597f299cfc657e2aull,
  0x5fcb6fab3ad6faecull, 0x6c44198c4a475817ull
};

static const unsigned char sha512_P[128] = {
  0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

void
sha512_init(sha512_t *ctx) {
  ctx->state[0] = 0x6a09e667f3bcc908ull;
  ctx->state[1] = 0xbb67ae8584caa73bull;
  ctx->state[2] = 0x3c6ef372fe94f82bull;
  ctx->state[3] = 0xa54ff53a5f1d36f1ull;
  ctx->state[4] = 0x510e527fade682d1ull;
  ctx->state[5] = 0x9b05688c2b3e6c1full;
  ctx->state[6] = 0x1f83d9abfb41bd6bull;
  ctx->state[7] = 0x5be0cd19137e2179ull;
  ctx->size = 0;
}

static void
sha512_transform(sha512_t *ctx, const unsigned char *chunk) {
  const uint64_t *k = sha512_K;
  uint64_t data[16];
  uint64_t A, B, C, D, E, F, G, H;
  unsigned i;
  uint64_t *d;

  for (i = 0; i < 16; i++, chunk += 8)
    data[i] = read64be(chunk);

  A = ctx->state[0];
  B = ctx->state[1];
  C = ctx->state[2];
  D = ctx->state[3];
  E = ctx->state[4];
  F = ctx->state[5];
  G = ctx->state[6];
  H = ctx->state[7];

#define Ch(x, y, z) ((z) ^ ((x) & ((y) ^ (z))))
#define Maj(x, y, z) (((x) & (y)) ^ ((z) & ((x) ^ (y))))

#define S0(x) (ROTL64(36, (x)) ^ ROTL64(30, (x)) ^ ROTL64(25, (x)))
#define S1(x) (ROTL64(50, (x)) ^ ROTL64(46, (x)) ^ ROTL64(23, (x)))

#define s0(x) (ROTL64(63, (x)) ^ ROTL64(56, (x)) ^ ((x) >> 7))
#define s1(x) (ROTL64(45, (x)) ^ ROTL64(3, (x)) ^ ((x) >> 6))

#define EXPAND(W,i) \
  (W[(i) & 15] += (s1(W[((i)-2) & 15]) + W[((i)-7) & 15] + s0(W[((i)-15) & 15])))

#define ROUND(a, b, c, d, e, f, g, h, k, data) do { \
  h += S1(e) + Ch(e, f, g) + k + data;              \
  d += h;                                           \
  h += S0(a) + Maj(a, b, c);                        \
} while (0)

  for (i = 0, d = data; i < 16; i += 8, k += 8, d += 8) {
    ROUND(A, B, C, D, E, F, G, H, k[0], d[0]);
    ROUND(H, A, B, C, D, E, F, G, k[1], d[1]);
    ROUND(G, H, A, B, C, D, E, F, k[2], d[2]);
    ROUND(F, G, H, A, B, C, D, E, k[3], d[3]);
    ROUND(E, F, G, H, A, B, C, D, k[4], d[4]);
    ROUND(D, E, F, G, H, A, B, C, k[5], d[5]);
    ROUND(C, D, E, F, G, H, A, B, k[6], d[6]);
    ROUND(B, C, D, E, F, G, H, A, k[7], d[7]);
  }

  for (; i < 80; i += 16, k += 16) {
    ROUND(A, B, C, D, E, F, G, H, k[ 0], EXPAND(data,  0));
    ROUND(H, A, B, C, D, E, F, G, k[ 1], EXPAND(data,  1));
    ROUND(G, H, A, B, C, D, E, F, k[ 2], EXPAND(data,  2));
    ROUND(F, G, H, A, B, C, D, E, k[ 3], EXPAND(data,  3));
    ROUND(E, F, G, H, A, B, C, D, k[ 4], EXPAND(data,  4));
    ROUND(D, E, F, G, H, A, B, C, k[ 5], EXPAND(data,  5));
    ROUND(C, D, E, F, G, H, A, B, k[ 6], EXPAND(data,  6));
    ROUND(B, C, D, E, F, G, H, A, k[ 7], EXPAND(data,  7));
    ROUND(A, B, C, D, E, F, G, H, k[ 8], EXPAND(data,  8));
    ROUND(H, A, B, C, D, E, F, G, k[ 9], EXPAND(data,  9));
    ROUND(G, H, A, B, C, D, E, F, k[10], EXPAND(data, 10));
    ROUND(F, G, H, A, B, C, D, E, k[11], EXPAND(data, 11));
    ROUND(E, F, G, H, A, B, C, D, k[12], EXPAND(data, 12));
    ROUND(D, E, F, G, H, A, B, C, k[13], EXPAND(data, 13));
    ROUND(C, D, E, F, G, H, A, B, k[14], EXPAND(data, 14));
    ROUND(B, C, D, E, F, G, H, A, k[15], EXPAND(data, 15));
  }

#undef Ch
#undef Maj
#undef S0
#undef S1
#undef s0
#undef s1
#undef EXPAND
#undef ROUND

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
  const unsigned char *bytes = (const unsigned char *)data;
  size_t pos = ctx->size & 127;
  size_t off = 0;

  ctx->size += len;

  if (pos > 0) {
    size_t want = 128 - pos;

    if (want > len)
      want = len;

    memcpy(ctx->block + pos, bytes + off, want);

    pos += want;
    len -= want;
    off += want;

    if (pos < 128)
      return;

    sha512_transform(ctx, ctx->block);
  }

  while (len >= 128) {
    sha512_transform(ctx, bytes + off);
    off += 128;
    len -= 128;
  }

  if (len > 0)
    memcpy(ctx->block, bytes + off, len);
}

void
sha512_final(sha512_t *ctx, unsigned char *out) {
  size_t pos = ctx->size & 127;
  uint64_t len = ctx->size << 3;
  unsigned char D[16];
  size_t i;

  write64be(D + 0, 0);
  write64be(D + 8, len);

  sha512_update(ctx, sha512_P, 1 + ((239 - pos) & 127));
  sha512_update(ctx, D, 16);

  for (i = 0; i < 8; i++)
    write64be(out + i * 8, ctx->state[i]);
}
#endif /* TORSION_USE_OPENSSL */

/*
 * SHA384
 */

#ifdef TORSION_USE_OPENSSL
/* Doubtful that this ABI will change. */
int SHA384_Init(sha384_t *c);

void
sha384_init(sha384_t *ctx) {
  SHA384_Init(ctx);
}
#else /* TORSION_USE_OPENSSL */
void
sha384_init(sha384_t *ctx) {
  ctx->state[0] = 0xcbbb9d5dc1059ed8ull;
  ctx->state[1] = 0x629a292a367cd507ull;
  ctx->state[2] = 0x9159015a3070dd17ull;
  ctx->state[3] = 0x152fecd8f70e5939ull;
  ctx->state[4] = 0x67332667ffc00b31ull;
  ctx->state[5] = 0x8eb44a8768581511ull;
  ctx->state[6] = 0xdb0c2e0d64f98fa7ull;
  ctx->state[7] = 0x47b5481dbefa4fa4ull;
  ctx->size = 0;
}
#endif /* TORSION_USE_OPENSSL */

void
sha384_update(sha384_t *ctx, const void *data, size_t len) {
  sha512_update(ctx, data, len);
}

void
sha384_final(sha384_t *ctx, unsigned char *out) {
  uint8_t tmp[64];

  sha512_final(ctx, tmp);

  memcpy(out, tmp, 48);
  cleanse(tmp, sizeof(tmp));
}

/*
 * Hash160
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

  cleanse(tmp, sizeof(tmp));
}

/*
 * Hash256
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
 */

void
keccak_init(keccak_t *ctx, size_t bits) {
  size_t rate = 1600 - bits * 2;

  assert(bits >= 128);
  assert(bits <= 512);
  assert((rate & 63) == 0);

  ctx->bs = rate >> 3;
  ctx->pos = 0;

  memset(ctx->state, 0, sizeof(ctx->state));
}

static void
keccak_permute(keccak_t *ctx) {
#ifdef TORSION_USE_ASM
  /* Borrowed from:
   * https://github.com/gnutls/nettle/blob/master/x86_64/sha3-permute.asm
   *
   * Note: we stripped out the handmade clobber guards
   * and use %rbx instead of %rbp (GCC doesn't allow
   * clobber guards for %rbp).
   *
   * Layout:
   *   %rdi = state pointer (ctx->state)
   *   %r14 = constants pointer (rc, reversed)
   *   %r8 = round counter (starts at 24, decrements)
   *
   * For reference, our full range of clobbered registers:
   * rax, rbx, rcx, rdx, rdi, r8, r9, r10, r11, r12, r13, r14
   */
  static const uint64_t rc[25] = {
    0x0000000000000000ull,
    0x8000000080008008ull, 0x0000000080000001ull,
    0x8000000000008080ull, 0x8000000080008081ull,
    0x800000008000000aull, 0x000000000000800aull,
    0x8000000000000080ull, 0x8000000000008002ull,
    0x8000000000008003ull, 0x8000000000008089ull,
    0x800000000000008bull, 0x000000008000808bull,
    0x000000008000000aull, 0x0000000080008009ull,
    0x0000000000000088ull, 0x000000000000008aull,
    0x8000000000008009ull, 0x8000000080008081ull,
    0x0000000080000001ull, 0x000000000000808bull,
    0x8000000080008000ull, 0x800000000000808aull,
    0x0000000000008082ull, 0x0000000000000001ull
  };

  __asm__ __volatile__(
    "movq %[st], %%rdi\n"
    "movq %[rc], %%r14\n"
    "movl $24, %%r8d\n"

    "movq (%%rdi), %%rax\n"
    "movups 8(%%rdi), %%xmm0\n"
    "movups 24(%%rdi), %%xmm1\n"
    "movq %%rax, %%r10\n"

    "movq 40(%%rdi), %%rcx\n"
    "movdqa %%xmm0, %%xmm10\n"
    "movups 48(%%rdi), %%xmm2\n"
    "movdqa %%xmm1, %%xmm11\n"
    "movups 64(%%rdi), %%xmm3\n"
    "xorq %%rcx, %%r10\n"

    "movq 80(%%rdi), %%rdx\n"
    "pxor %%xmm2, %%xmm10\n"
    "movups 88(%%rdi), %%xmm4\n"
    "pxor %%xmm3, %%xmm11\n"
    "movups 104(%%rdi), %%xmm5\n"
    "xorq %%rdx, %%r10\n"

    "movq 120(%%rdi), %%rbx\n"
    "pxor %%xmm4, %%xmm10\n"
    "movups 128(%%rdi), %%xmm6\n"
    "pxor %%xmm5, %%xmm11\n"
    "movups 144(%%rdi), %%xmm7\n"
    "xorq %%rbx, %%r10\n"

    "movq 160(%%rdi), %%r9\n"
    "pxor %%xmm6, %%xmm10\n"
    "movups 168(%%rdi), %%xmm8\n"
    "pxor %%xmm7, %%xmm11\n"
    "movups 184(%%rdi), %%xmm9\n"
    "xorq %%r9, %%r10\n"
    "pxor %%xmm8, %%xmm10\n"
    "pxor %%xmm9, %%xmm11\n"

    "1:\n"

    "pshufd $0x4e, %%xmm11, %%xmm11\n"
    "movdqa %%xmm10, %%xmm13\n"

    "movq %%r10, (%%rdi)\n"
    "movq (%%rdi), %%xmm12\n"

    "punpcklqdq %%xmm10, %%xmm12\n"
    "punpckhqdq %%xmm11, %%xmm13\n"
    "punpcklqdq %%xmm12, %%xmm11\n"

    "movq %%xmm11, (%%rdi)\n"
    "movq (%%rdi), %%r11\n"

    "movq %%xmm10, (%%rdi)\n"
    "movq (%%rdi), %%r12\n"

    "rolq $1, %%r12\n"
    "xorq %%r12, %%r11\n"

    "movdqa %%xmm13, %%xmm14\n"
    "movdqa %%xmm13, %%xmm15\n"
    "psllq $1, %%xmm14\n"
    "psrlq $63, %%xmm15\n"
    "pxor %%xmm14, %%xmm12\n"
    "pxor %%xmm15, %%xmm12\n"

    "movdqa %%xmm11, %%xmm10\n"
    "psrlq $63, %%xmm11\n"
    "psllq $1, %%xmm10\n"
    "pxor %%xmm11, %%xmm13\n"
    "pxor %%xmm10, %%xmm13\n"

    "xorq %%r11, %%rax\n"
    "xorq %%r11, %%rcx\n"
    "xorq %%r11, %%rdx\n"
    "xorq %%r11, %%rbx\n"
    "xorq %%r11, %%r9\n"
    "pxor %%xmm12, %%xmm0\n"
    "pxor %%xmm12, %%xmm2\n"
    "pxor %%xmm12, %%xmm4\n"
    "pxor %%xmm12, %%xmm6\n"
    "pxor %%xmm12, %%xmm8\n"
    "pxor %%xmm13, %%xmm1\n"
    "pxor %%xmm13, %%xmm3\n"
    "pxor %%xmm13, %%xmm5\n"
    "pxor %%xmm13, %%xmm7\n"
    "pxor %%xmm13, %%xmm9\n"

    "movdqa %%xmm0, %%xmm14\n"
    "movdqa %%xmm0, %%xmm15\n"
    "movdqa %%xmm0, %%xmm12\n"
    "psllq $1, %%xmm0\n"
    "psrlq $63, %%xmm14\n"
    "psllq $62, %%xmm15\n"
    "por %%xmm0, %%xmm14\n"
    "psrlq $2, %%xmm12\n"
    "por %%xmm15, %%xmm12\n"

    "movdqa %%xmm1, %%xmm0\n"
    "movdqa %%xmm1, %%xmm15\n"
    "psllq $28, %%xmm0\n"
    "psrlq $36, %%xmm15\n"
    "por %%xmm15, %%xmm0\n"
    "movdqa %%xmm1, %%xmm15\n"
    "psllq $27, %%xmm1\n"
    "psrlq $37, %%xmm15\n"
    "por %%xmm15, %%xmm1\n"

    "punpcklqdq %%xmm14, %%xmm0\n"
    "punpckhqdq %%xmm12, %%xmm1\n"

    "rolq $36, %%rcx\n"

    "movq %%rcx, (%%rdi)\n"
    "movq (%%rdi), %%xmm14\n"

    "movq %%xmm2, (%%rdi)\n"
    "movq (%%rdi), %%rcx\n"

    "rolq $44, %%rcx\n"

    "movdqa %%xmm2, %%xmm15\n"
    "psllq $6, %%xmm2\n"
    "psrlq $58, %%xmm15\n"

    "por %%xmm2, %%xmm15\n"
    "movdqa %%xmm3, %%xmm2\n"

    "movdqa %%xmm2, %%xmm12\n"
    "psllq $20, %%xmm2\n"
    "psrlq $44, %%xmm12\n"

    "por %%xmm12, %%xmm2\n"
    "punpckhqdq %%xmm15, %%xmm2\n"

    "movdqa %%xmm3, %%xmm15\n"
    "psllq $55, %%xmm3\n"
    "psrlq $9, %%xmm15\n"

    "por %%xmm3, %%xmm15\n"
    "movdqa %%xmm14, %%xmm3\n"
    "punpcklqdq %%xmm15, %%xmm3\n"

    "rolq $42, %%rdx\n"
    "pshufd $0x4e, %%xmm4, %%xmm14\n"

    "movq %%rdx, (%%rdi)\n"
    "movq (%%rdi), %%xmm4\n"

    "movq %%xmm14, (%%rdi)\n"
    "movq (%%rdi), %%rdx\n"

    "rolq $43, %%rdx\n"

    "punpcklqdq %%xmm5, %%xmm4\n"

    "movdqa %%xmm4, %%xmm15\n"
    "psllq $25, %%xmm4\n"
    "psrlq $39, %%xmm15\n"

    "por %%xmm15, %%xmm4\n"

    "movdqa %%xmm5, %%xmm12\n"
    "psllq $39, %%xmm5\n"
    "psrlq $25, %%xmm12\n"

    "por %%xmm5, %%xmm12\n"

    "movdqa %%xmm14, %%xmm5\n"
    "psllq $10, %%xmm14\n"
    "psrlq $54, %%xmm5\n"

    "por %%xmm14, %%xmm5\n"
    "punpckhqdq %%xmm12, %%xmm5\n"

    "pshufd $0x4e, %%xmm7, %%xmm14\n"
    "rolq $41, %%rbx\n"

    "movq %%rbx, (%%rdi)\n"
    "movq (%%rdi), %%xmm15\n"

    "movq %%xmm7, (%%rdi)\n"
    "movq (%%rdi), %%rbx\n"

    "rolq $21, %%rbx\n"
    "pshufd $0x4e, %%xmm6, %%xmm7\n"

    "movdqa %%xmm6, %%xmm12\n"
    "psllq $45, %%xmm6\n"
    "psrlq $19, %%xmm12\n"

    "por %%xmm12, %%xmm6\n"

    "movdqa %%xmm14, %%xmm13\n"
    "psllq $8, %%xmm14\n"
    "psrlq $56, %%xmm13\n"

    "por %%xmm13, %%xmm14\n"
    "punpcklqdq %%xmm14, %%xmm6\n"

    "movdqa %%xmm7, %%xmm12\n"
    "psllq $15, %%xmm7\n"
    "psrlq $49, %%xmm12\n"

    "por %%xmm12, %%xmm7\n"
    "punpcklqdq %%xmm15, %%xmm7\n"

    "rolq $18, %%r9\n"

    "movq %%r9, (%%rdi)\n"
    "movq (%%rdi), %%xmm14\n"

    "pshufd $0x4e, %%xmm9, %%xmm15\n"
    "movd %%xmm15, %%r9\n"
    "rolq $14, %%r9\n"

    "movdqa %%xmm9, %%xmm15\n"
    "psllq $56, %%xmm9\n"
    "psrlq $8, %%xmm15\n"

    "por %%xmm15, %%xmm9\n"

    "movdqa %%xmm8, %%xmm12\n"

    "movdqa %%xmm12, %%xmm15\n"
    "psllq $2, %%xmm12\n"
    "psrlq $62, %%xmm15\n"

    "por %%xmm15, %%xmm12\n"
    "punpcklqdq %%xmm12, %%xmm9\n"

    "movdqa %%xmm8, %%xmm15\n"
    "psllq $61, %%xmm8\n"
    "psrlq $3, %%xmm15\n"

    "por %%xmm15, %%xmm8\n"
    "psrldq $8, %%xmm8\n"
    "punpcklqdq %%xmm14, %%xmm8\n"

    "movq %%rcx, %%r12\n"
    "notq %%r12\n"
    "andq %%rdx, %%r12\n"
    "movq %%rdx, %%r13\n"
    "notq %%r13\n"
    "andq %%rbx, %%r13\n"
    "movq %%rbx, %%r11\n"
    "notq %%r11\n"
    "andq %%r9, %%r11\n"
    "xorq %%r11, %%rdx\n"
    "movq %%r9, %%r10\n"
    "notq %%r10\n"
    "andq %%rax, %%r10\n"
    "xorq %%r10, %%rbx\n"
    "movq %%rax, %%r11\n"
    "notq %%r11\n"
    "andq %%rcx, %%r11\n"
    "xorq %%r11, %%r9\n"
    "xorq %%r12, %%rax\n"
    "xorq %%r13, %%rcx\n"

    "movdqa %%xmm2, %%xmm14\n"
    "pandn %%xmm4, %%xmm14\n"
    "movdqa %%xmm4, %%xmm15\n"
    "pandn %%xmm6, %%xmm15\n"
    "movdqa %%xmm6, %%xmm12\n"
    "pandn %%xmm8, %%xmm12\n"
    "pxor %%xmm12, %%xmm4\n"
    "movdqa %%xmm8, %%xmm13\n"
    "pandn %%xmm0, %%xmm13\n"
    "pxor %%xmm13, %%xmm6\n"
    "movdqa %%xmm0, %%xmm12\n"
    "pandn %%xmm2, %%xmm12\n"
    "pxor %%xmm12, %%xmm8\n"
    "pxor %%xmm14, %%xmm0\n"
    "pxor %%xmm15, %%xmm2\n"

    "movdqa %%xmm3, %%xmm14\n"
    "pandn %%xmm5, %%xmm14\n"
    "movdqa %%xmm5, %%xmm15\n"
    "pandn %%xmm7, %%xmm15\n"
    "movdqa %%xmm7, %%xmm12\n"
    "pandn %%xmm9, %%xmm12\n"
    "pxor %%xmm12, %%xmm5\n"
    "movdqa %%xmm9, %%xmm13\n"
    "pandn %%xmm1, %%xmm13\n"
    "pxor %%xmm13, %%xmm7\n"
    "movdqa %%xmm1, %%xmm12\n"
    "pandn %%xmm3, %%xmm12\n"
    "pxor %%xmm12, %%xmm9\n"
    "pxor %%xmm14, %%xmm1\n"
    "pxor %%xmm15, %%xmm3\n"

    "xorq (%%r14, %%r8, 8), %%rax\n"

    "movq %%rcx, (%%rdi)\n"
    "movq (%%rdi), %%xmm10\n"

    "movq %%rbx, (%%rdi)\n"
    "movq (%%rdi), %%xmm11\n"

    "movq %%rdx, (%%rdi)\n"
    "movq (%%rdi), %%xmm14\n"

    "movq %%r9, (%%rdi)\n"
    "movq (%%rdi), %%xmm15\n"

    "movq %%rax, %%r10\n"
    "punpcklqdq %%xmm14, %%xmm10\n"
    "punpcklqdq %%xmm15, %%xmm11\n"

    "movq %%xmm0, (%%rdi)\n"
    "movq (%%rdi), %%rcx\n"

    "movq %%xmm1, (%%rdi)\n"
    "movq (%%rdi), %%rbx\n"

    "psrldq $8, %%xmm0\n"
    "psrldq $8, %%xmm1\n"
    "xorq %%rcx, %%r10\n"
    "xorq %%rbx, %%r10\n"

    "movq %%xmm0, (%%rdi)\n"
    "movq (%%rdi), %%rdx\n"

    "movq %%xmm1, (%%rdi)\n"
    "movq (%%rdi), %%r9\n"

    "movdqa %%xmm10, %%xmm0\n"
    "movdqa %%xmm11, %%xmm1\n"

    "movdqa %%xmm2, %%xmm14\n"
    "punpcklqdq %%xmm4, %%xmm2\n"
    "xorq %%rdx, %%r10\n"
    "xorq %%r9, %%r10\n"
    "punpckhqdq %%xmm14, %%xmm4\n"
    "pshufd $0x4e, %%xmm4, %%xmm4\n"

    "movdqa %%xmm7, %%xmm14\n"
    "punpcklqdq %%xmm9, %%xmm7\n"
    "pxor %%xmm2, %%xmm10\n"
    "pxor %%xmm4, %%xmm10\n"
    "punpckhqdq %%xmm14, %%xmm9\n"
    "pshufd $0x4e, %%xmm9, %%xmm9\n"

    "movdqa %%xmm3, %%xmm14\n"
    "movdqa %%xmm5, %%xmm15\n"
    "movdqa %%xmm6, %%xmm3\n"
    "movdqa %%xmm8, %%xmm5\n"
    "pxor %%xmm7, %%xmm11\n"
    "pxor %%xmm9, %%xmm11\n"
    "punpcklqdq %%xmm8, %%xmm3\n"
    "punpckhqdq %%xmm6, %%xmm5\n"
    "pshufd $0x4e, %%xmm5, %%xmm5\n"
    "movdqa %%xmm14, %%xmm6\n"
    "movdqa %%xmm15, %%xmm8\n"
    "pxor %%xmm3, %%xmm11\n"
    "pxor %%xmm5, %%xmm11\n"
    "punpcklqdq %%xmm15, %%xmm6\n"
    "punpckhqdq %%xmm14, %%xmm8\n"
    "pshufd $0x4e, %%xmm8, %%xmm8\n"

    "decl %%r8d\n"
    "pxor %%xmm6, %%xmm10\n"
    "pxor %%xmm8, %%xmm10\n"
    "jnz 1b\n"

    "movq %%rax, (%%rdi)\n"
    "movups %%xmm0, 8(%%rdi)\n"
    "movups %%xmm1, 24(%%rdi)\n"

    "movq %%rcx, 40(%%rdi)\n"
    "movups %%xmm2, 48(%%rdi)\n"
    "movups %%xmm3, 64(%%rdi)\n"

    "movq %%rdx, 80(%%rdi)\n"
    "movups %%xmm4, 88(%%rdi)\n"
    "movups %%xmm5, 104(%%rdi)\n"

    "movq %%rbx, 120(%%rdi)\n"
    "movups %%xmm6, 128(%%rdi)\n"
    "movups %%xmm7, 144(%%rdi)\n"

    "movq %%r9, 160(%%rdi)\n"
    "movups %%xmm8, 168(%%rdi)\n"
    "movups %%xmm9, 184(%%rdi)\n"
    :
    : [st] "r" (ctx->state),
      [rc] "r" (rc)
    : "rbx", "r12", "r13", "r14", /* Necessary */
      "rax", "rcx", "rdx", "rdi", /* Not necessary (but better to be safe) */
      "r8",  "r9",  "r10", "r11",
      "cc", "memory"
  );
#else
  static const uint64_t rc[24] = {
    0x0000000000000001ull, 0x0000000000008082ull,
    0x800000000000808aull, 0x8000000080008000ull,
    0x000000000000808bull, 0x0000000080000001ull,
    0x8000000080008081ull, 0x8000000000008009ull,
    0x000000000000008aull, 0x0000000000000088ull,
    0x0000000080008009ull, 0x000000008000000aull,
    0x000000008000808bull, 0x800000000000008bull,
    0x8000000000008089ull, 0x8000000000008003ull,
    0x8000000000008002ull, 0x8000000000000080ull,
    0x000000000000800aull, 0x800000008000000aull,
    0x8000000080008081ull, 0x8000000000008080ull,
    0x0000000080000001ull, 0x8000000080008008ull
  };

  uint64_t C[5], D[5], T, X;
  unsigned i, y;

#define A ctx->state

  C[0] = A[0] ^ A[5 + 0] ^ A[10 + 0] ^ A[15 + 0] ^ A[20 + 0];
  C[1] = A[1] ^ A[5 + 1] ^ A[10 + 1] ^ A[15 + 1] ^ A[20 + 1];
  C[2] = A[2] ^ A[5 + 2] ^ A[10 + 2] ^ A[15 + 2] ^ A[20 + 2];
  C[3] = A[3] ^ A[5 + 3] ^ A[10 + 3] ^ A[15 + 3] ^ A[20 + 3];
  C[4] = A[4] ^ A[5 + 4] ^ A[10 + 4] ^ A[15 + 4] ^ A[20 + 4];

  for (i = 0; i < 24; i++) {
    D[0] = C[4] ^ ROTL64(1, C[1]);
    D[1] = C[0] ^ ROTL64(1, C[2]);
    D[2] = C[1] ^ ROTL64(1, C[3]);
    D[3] = C[2] ^ ROTL64(1, C[4]);
    D[4] = C[3] ^ ROTL64(1, C[0]);

    A[0] ^= D[0];
    X = A[ 1] ^ D[1];     T = ROTL64( 1, X);
    X = A[ 6] ^ D[1]; A[ 1] = ROTL64(44, X);
    X = A[ 9] ^ D[4]; A[ 6] = ROTL64(20, X);
    X = A[22] ^ D[2]; A[ 9] = ROTL64(61, X);
    X = A[14] ^ D[4]; A[22] = ROTL64(39, X);
    X = A[20] ^ D[0]; A[14] = ROTL64(18, X);
    X = A[ 2] ^ D[2]; A[20] = ROTL64(62, X);
    X = A[12] ^ D[2]; A[ 2] = ROTL64(43, X);
    X = A[13] ^ D[3]; A[12] = ROTL64(25, X);
    X = A[19] ^ D[4]; A[13] = ROTL64( 8, X);
    X = A[23] ^ D[3]; A[19] = ROTL64(56, X);
    X = A[15] ^ D[0]; A[23] = ROTL64(41, X);
    X = A[ 4] ^ D[4]; A[15] = ROTL64(27, X);
    X = A[24] ^ D[4]; A[ 4] = ROTL64(14, X);
    X = A[21] ^ D[1]; A[24] = ROTL64( 2, X);
    X = A[ 8] ^ D[3]; A[21] = ROTL64(55, X);
    X = A[16] ^ D[1]; A[ 8] = ROTL64(45, X);
    X = A[ 5] ^ D[0]; A[16] = ROTL64(36, X);
    X = A[ 3] ^ D[3]; A[ 5] = ROTL64(28, X);
    X = A[18] ^ D[3]; A[ 3] = ROTL64(21, X);
    X = A[17] ^ D[2]; A[18] = ROTL64(15, X);
    X = A[11] ^ D[1]; A[17] = ROTL64(10, X);
    X = A[ 7] ^ D[2]; A[11] = ROTL64( 6, X);
    X = A[10] ^ D[0]; A[ 7] = ROTL64( 3, X);
    A[10] = T;

    D[0] = ~A[1] & A[2];
    D[1] = ~A[2] & A[3];
    D[2] = ~A[3] & A[4];
    D[3] = ~A[4] & A[0];
    D[4] = ~A[0] & A[1];

    A[0] ^= D[0] ^ rc[i]; C[0] = A[0];
    A[1] ^= D[1]; C[1] = A[1];
    A[2] ^= D[2]; C[2] = A[2];
    A[3] ^= D[3]; C[3] = A[3];
    A[4] ^= D[4]; C[4] = A[4];

    for (y = 5; y < 25; y+= 5) {
      D[0] = ~A[y + 1] & A[y + 2];
      D[1] = ~A[y + 2] & A[y + 3];
      D[2] = ~A[y + 3] & A[y + 4];
      D[3] = ~A[y + 4] & A[y + 0];
      D[4] = ~A[y + 0] & A[y + 1];

      A[y + 0] ^= D[0]; C[0] ^= A[y + 0];
      A[y + 1] ^= D[1]; C[1] ^= A[y + 1];
      A[y + 2] ^= D[2]; C[2] ^= A[y + 2];
      A[y + 3] ^= D[3]; C[3] ^= A[y + 3];
      A[y + 4] ^= D[4]; C[4] ^= A[y + 4];
    }
  }
#undef A
#endif
}

static void
keccak_transform(keccak_t *ctx, const unsigned char *chunk) {
  size_t count = ctx->bs >> 3;
  size_t i;

  for (i = 0; i < count; i++)
    ctx->state[i] ^= read64le(chunk + i * 8);

  keccak_permute(ctx);
}

void
keccak_update(keccak_t *ctx, const void *data, size_t len) {
  const unsigned char *bytes = (const unsigned char *)data;
  size_t pos = ctx->pos;
  size_t off = 0;

  ctx->pos = (ctx->pos + len) % ctx->bs;

  if (pos > 0) {
    size_t want = ctx->bs - pos;

    if (want > len)
      want = len;

    memcpy(ctx->block + pos, bytes + off, want);

    pos += want;
    len -= want;
    off += want;

    if (pos < ctx->bs)
      return;

    keccak_transform(ctx, ctx->block);
  }

  while (len >= ctx->bs) {
    keccak_transform(ctx, bytes + off);
    off += ctx->bs;
    len -= ctx->bs;
  }

  if (len > 0)
    memcpy(ctx->block, bytes + off, len);
}

void
keccak_final(keccak_t *ctx, unsigned char *out, unsigned char pad, size_t len) {
  size_t i;

  if (pad == 0)
    pad = 0x01;

  if (len == 0)
    len = 100 - (ctx->bs >> 1);

  assert(len < ctx->bs);

  memset(ctx->block + ctx->pos, 0x00, ctx->bs - ctx->pos);

  ctx->block[ctx->pos] |= pad;
  ctx->block[ctx->bs - 1] |= 0x80;

  keccak_transform(ctx, ctx->block);

  for (i = 0; i < len; i++)
    out[i] = ctx->state[i >> 3] >> (8 * (i & 7));
}

/*
 * BLAKE2s
 */

static const uint32_t blake2s_iv[8] = {
  0x6a09e667ul, 0xbb67ae85ul, 0x3c6ef372ul, 0xa54ff53aul,
  0x510e527ful, 0x9b05688cul, 0x1f83d9abul, 0x5be0cd19ul
};

static const uint8_t blake2s_sigma[10][16] = {
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
};

void
blake2s_init(blake2s_t *ctx,
             size_t outlen,
             const unsigned char *key,
             size_t keylen) {
  size_t i;

  assert(outlen >= 1 && outlen <= 32);
  assert(keylen <= 32);

  memset(ctx, 0, sizeof(blake2s_t));

  ctx->outlen = outlen;

  for (i = 0; i < 8; i++)
    ctx->h[i] = blake2s_iv[i];

  ctx->h[0] ^= 0x01010000 ^ (keylen << 8) ^ outlen;

  if (keylen > 0) {
    uint8_t block[64];

    memset(block, 0x00, 64);
    memcpy(block, key, keylen);

    blake2s_update(ctx, block, 64);

    cleanse(block, 64);
  }
}

static void
blake2s_increment(blake2s_t *ctx, uint32_t inc) {
  ctx->t[0] += inc;
  ctx->t[1] += (ctx->t[0] < inc);
}

static void
blake2s_compress(blake2s_t *ctx, const uint8_t *chunk) {
  uint32_t m[16];
  uint32_t v[16];
  size_t i;

  for (i = 0; i < 16; i++)
    m[i] = read32le(chunk + i * 4);

  for (i = 0; i < 8; i++)
    v[i] = ctx->h[i];

  v[ 8] = blake2s_iv[0];
  v[ 9] = blake2s_iv[1];
  v[10] = blake2s_iv[2];
  v[11] = blake2s_iv[3];
  v[12] = ctx->t[0] ^ blake2s_iv[4];
  v[13] = ctx->t[1] ^ blake2s_iv[5];
  v[14] = ctx->f[0] ^ blake2s_iv[6];
  v[15] = ctx->f[1] ^ blake2s_iv[7];

#define G(r, i, a, b, c, d) do {              \
  a = a + b + m[blake2s_sigma[r][2 * i + 0]]; \
  d = rotr32(d ^ a, 16);                      \
  c = c + d;                                  \
  b = rotr32(b ^ c, 12);                      \
  a = a + b + m[blake2s_sigma[r][2 * i + 1]]; \
  d = rotr32(d ^ a, 8);                       \
  c = c + d;                                  \
  b = rotr32(b ^ c, 7);                       \
} while (0)

#define ROUND(r) do {                  \
  G(r, 0, v[ 0], v[ 4], v[ 8], v[12]); \
  G(r, 1, v[ 1], v[ 5], v[ 9], v[13]); \
  G(r, 2, v[ 2], v[ 6], v[10], v[14]); \
  G(r, 3, v[ 3], v[ 7], v[11], v[15]); \
  G(r, 4, v[ 0], v[ 5], v[10], v[15]); \
  G(r, 5, v[ 1], v[ 6], v[11], v[12]); \
  G(r, 6, v[ 2], v[ 7], v[ 8], v[13]); \
  G(r, 7, v[ 3], v[ 4], v[ 9], v[14]); \
} while (0)

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

  for (i = 0; i < 8; i++)
    ctx->h[i] = ctx->h[i] ^ v[i] ^ v[i + 8];
#undef G
#undef ROUND
}

void
blake2s_update(blake2s_t *ctx, const void *data, size_t len) {
  const unsigned char *in = (const unsigned char *)data;

  if (len > 0) {
    size_t left = ctx->buflen;
    size_t fill = 64 - left;

    if (len > fill) {
      ctx->buflen = 0;
      memcpy(ctx->buf + left, in, fill);

      blake2s_increment(ctx, 64);
      blake2s_compress(ctx, ctx->buf);

      in += fill;
      len -= fill;

      while (len > 64) {
        blake2s_increment(ctx, 64);
        blake2s_compress(ctx, in);

        in += 64;
        len -= 64;
      }
    }

    memcpy(ctx->buf + ctx->buflen, in, len);
    ctx->buflen += len;
  }
}

void
blake2s_final(blake2s_t *ctx, unsigned char *out) {
  uint8_t buffer[32];
  size_t i;

  blake2s_increment(ctx, (uint32_t)ctx->buflen);

  ctx->f[0] = (uint32_t)-1;

  memset(ctx->buf + ctx->buflen, 0, 64 - ctx->buflen);

  blake2s_compress(ctx, ctx->buf);

  for (i = 0; i < 8; i++)
    write32le(buffer + i * 4, ctx->h[i]);

  memcpy(out, buffer, ctx->outlen);

  cleanse(buffer, sizeof(buffer));
}

/*
 * BLAKE2b
 */

static const uint64_t blake2b_iv[8] = {
  0x6a09e667f3bcc908ull, 0xbb67ae8584caa73bull,
  0x3c6ef372fe94f82bull, 0xa54ff53a5f1d36f1ull,
  0x510e527fade682d1ull, 0x9b05688c2b3e6c1full,
  0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull
};

static const uint8_t blake2b_sigma[12][16] = {
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

void
blake2b_init(blake2b_t *ctx,
             size_t outlen,
             const unsigned char *key,
             size_t keylen) {
  size_t i;

  assert(outlen >= 1 && outlen <= 64);
  assert(keylen <= 64);

  memset(ctx, 0, sizeof(blake2b_t));

  ctx->outlen = outlen;

  for (i = 0; i < 8; i++)
    ctx->h[i] = blake2b_iv[i];

  ctx->h[0] ^= 0x01010000 ^ (keylen << 8) ^ outlen;

  if (keylen > 0) {
    uint8_t block[128];

    memset(block, 0x00, 128);
    memcpy(block, key, keylen);

    blake2b_update(ctx, block, 128);

    cleanse(block, 128);
  }
}

static void
blake2b_increment(blake2b_t *ctx, const uint64_t inc) {
  ctx->t[0] += inc;
  ctx->t[1] += (ctx->t[0] < inc);
}

static void
blake2b_compress(blake2b_t *ctx, const uint8_t *chunk) {
  uint64_t m[16];
  uint64_t v[16];
  size_t i;

  for (i = 0; i < 16; i++)
    m[i] = read64le(chunk + i * 8);

  for (i = 0; i < 8; i++)
    v[i] = ctx->h[i];

  v[ 8] = blake2b_iv[0];
  v[ 9] = blake2b_iv[1];
  v[10] = blake2b_iv[2];
  v[11] = blake2b_iv[3];
  v[12] = blake2b_iv[4] ^ ctx->t[0];
  v[13] = blake2b_iv[5] ^ ctx->t[1];
  v[14] = blake2b_iv[6] ^ ctx->f[0];
  v[15] = blake2b_iv[7] ^ ctx->f[1];

#define G(r, i, a, b, c, d) do {              \
  a = a + b + m[blake2b_sigma[r][2 * i + 0]]; \
  d = rotr64(d ^ a, 32);                      \
  c = c + d;                                  \
  b = rotr64(b ^ c, 24);                      \
  a = a + b + m[blake2b_sigma[r][2 * i + 1]]; \
  d = rotr64(d ^ a, 16);                      \
  c = c + d;                                  \
  b = rotr64(b ^ c, 63);                      \
} while (0)

#define ROUND(r) do {                  \
  G(r, 0, v[ 0], v[ 4], v[ 8], v[12]); \
  G(r, 1, v[ 1], v[ 5], v[ 9], v[13]); \
  G(r, 2, v[ 2], v[ 6], v[10], v[14]); \
  G(r, 3, v[ 3], v[ 7], v[11], v[15]); \
  G(r, 4, v[ 0], v[ 5], v[10], v[15]); \
  G(r, 5, v[ 1], v[ 6], v[11], v[12]); \
  G(r, 6, v[ 2], v[ 7], v[ 8], v[13]); \
  G(r, 7, v[ 3], v[ 4], v[ 9], v[14]); \
} while (0)

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
}

void
blake2b_update(blake2b_t *ctx, const void *data, size_t len) {
  const unsigned char *in = (const unsigned char *)data;

  if (len > 0) {
    size_t left = ctx->buflen;
    size_t fill = 128 - left;

    if (len > fill) {
      ctx->buflen = 0;

      memcpy(ctx->buf + left, in, fill);

      blake2b_increment(ctx, 128);
      blake2b_compress(ctx, ctx->buf);

      in += fill;
      len -= fill;

      while (len > 128) {
        blake2b_increment(ctx, 128);
        blake2b_compress(ctx, in);
        in += 128;
        len -= 128;
      }
    }

    memcpy(ctx->buf + ctx->buflen, in, len);
    ctx->buflen += len;
  }
}

void
blake2b_final(blake2b_t *ctx, unsigned char *out) {
  uint8_t buffer[64];
  size_t i;

  blake2b_increment(ctx, ctx->buflen);

  ctx->f[0] = (uint64_t)-1;

  memset(ctx->buf + ctx->buflen, 0x00, 128 - ctx->buflen);

  blake2b_compress(ctx, ctx->buf);

  for (i = 0; i < 8; i++)
    write64le(buffer + i * 8, ctx->h[i]);

  memcpy(out, buffer, ctx->outlen);

  cleanse(buffer, sizeof(buffer));
}

/*
 * GOST94
 * Logic from: https://github.com/RustCrypto/hashes
 */

static const uint8_t gost94_C[32] = {
  0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff,
  0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00,
  0x00, 0xff, 0xff, 0x00, 0xff, 0x00, 0x00, 0xff,
  0xff, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0xff
};

static const uint8_t gost94_S[8][16] = { /* CryptoPro */
  {10, 4, 5, 6, 8, 1, 3, 7, 13, 12, 14, 0, 9, 2, 11, 15},
  {5, 15, 4, 0, 2, 13, 11, 9, 1, 7, 6, 3, 12, 14, 10, 8},
  {7, 15, 12, 14, 9, 4, 1, 0, 3, 11, 5, 2, 6, 10, 8, 13},
  {4, 10, 7, 12, 0, 15, 2, 8, 14, 1, 6, 5, 13, 11, 9, 3},
  {7, 6, 4, 11, 9, 12, 2, 10, 1, 8, 0, 14, 15, 13, 3, 5},
  {7, 6, 2, 4, 13, 9, 15, 0, 10, 1, 5, 11, 8, 14, 12, 3},
  {13, 14, 4, 1, 7, 0, 5, 10, 3, 12, 8, 15, 6, 2, 9, 11},
  {1, 3, 10, 9, 5, 11, 4, 15, 8, 6, 7, 14, 13, 0, 2, 12}
};

static uint32_t
gost94_sbox(uint32_t a) {
  uint32_t v = 0;
  uint32_t k;
  size_t i, shift;

  for (i = 0; i < 8; i++) {
    shift = 4 * i;
    k = (a & (15 << shift)) >> shift;
    v += (uint32_t)gost94_S[i][k] << shift;
  }

  return v;
}

static uint32_t
gost94_g(uint32_t a, uint32_t k) {
  uint32_t w = gost94_sbox(a + k);
  return (w << 11) | (w >> (32 - 11));
}

static void
gost94_encrypt(uint8_t *msg, const uint8_t *key) {
  uint32_t k[8];
  uint32_t a = read32le(msg + 0);
  uint32_t b = read32le(msg + 4);
  uint32_t t;
  size_t i, x;

  for (i = 0; i < 8; i++)
    k[i] = read32le(key + i * 4);

  for (x = 0; x < 3; x++) {
    for (i = 0; i < 8; i++) {
      t = b ^ gost94_g(a, k[i]);
      b = a;
      a = t;
    }
  }

  for (i = 8; i-- > 0;) {
    t = b ^ gost94_g(a, k[i]);
    b = a;
    a = t;
  }

  write32le(msg + 0, b);
  write32le(msg + 4, a);
}

static void
gost94_x(uint8_t out[32], const uint8_t a[32], const uint8_t b[32]) {
  size_t i;

  for (i = 0; i < 32; i++)
    out[i] = a[i] ^ b[i];
}

static void
gost94_a(uint8_t out[32], const uint8_t x[32]) {
  size_t i;

  memcpy(out, x + 8, 24);

  for (i = 0; i < 8; i++)
    out[24 + i] = x[i] ^ x[i + 8];
}

static void
gost94_p(uint8_t out[32], const uint8_t y[32]) {
  size_t i, k;

  for (i = 0; i < 4; i++) {
    for (k = 0; k < 8; k++)
      out[i + 4 * k] = y[8 * i + k];
  }
}

static void
gost94_psi(uint8_t block[32]) {
  uint8_t out[32];

  memcpy(out, block + 2, 30);
  memcpy(out + 30, block, 2);

  out[30] ^= block[2];
  out[31] ^= block[3];

  out[30] ^= block[4];
  out[31] ^= block[5];

  out[30] ^= block[6];
  out[31] ^= block[7];

  out[30] ^= block[24];
  out[31] ^= block[25];

  out[30] ^= block[30];
  out[31] ^= block[31];

  memcpy(block, out, 32);
}

static void
gost94_compress(gost94_t *ctx, const uint8_t m[32]) {
  uint8_t s[32], k[32], u[32], v[32], t[32];
  size_t i;

  memcpy(s, ctx->state, 32);

  gost94_x(t, ctx->state, m);
  gost94_p(k, t);
  gost94_encrypt(s + 0, k);

  gost94_a(u, ctx->state);
  gost94_a(t, m);
  gost94_a(v, t);
  gost94_x(t, u, v);
  gost94_p(k, t);
  gost94_encrypt(s + 8, k);

  memcpy(t, u, 32);
  gost94_a(u, t);
  gost94_x(u, u, gost94_C);
  gost94_a(t, v);
  gost94_a(v, t);
  gost94_x(t, u, v);
  gost94_p(k, t);
  gost94_encrypt(s + 16, k);

  memcpy(t, u, 32);
  gost94_a(u, t);
  gost94_a(t, v);
  gost94_a(v, t);
  gost94_x(t, u, v);
  gost94_p(k, t);
  gost94_encrypt(s + 24, k);

  for (i = 0; i < 12; i++)
    gost94_psi(s);

  gost94_x(s, s, m);
  gost94_psi(s);
  gost94_x(ctx->state, ctx->state, s);

  for (i = 0; i < 61; i++)
    gost94_psi(ctx->state);
}

static void
gost94_sum(gost94_t *ctx, const uint8_t m[32]) {
  uint32_t c = 0;
  size_t i;

  for (i = 0; i < 32; i++) {
    c += ctx->sigma[i] + m[i];
    ctx->sigma[i] = c;
    c >>= 8;
  }
}

void
gost94_init(gost94_t *ctx) {
  memset(ctx, 0, sizeof(gost94_t));
}

static void
gost94_transform(gost94_t *ctx, const unsigned char *chunk) {
  gost94_compress(ctx, chunk);
  gost94_sum(ctx, chunk);
}

void
gost94_update(gost94_t *ctx, const void *data, size_t len) {
  const unsigned char *bytes = (const unsigned char *)data;
  size_t pos = ctx->size & 31;
  size_t off = 0;

  ctx->size += len;

  if (pos > 0) {
    size_t want = 32 - pos;

    if (want > len)
      want = len;

    memcpy(ctx->block + pos, bytes + off, want);

    pos += want;
    len -= want;
    off += want;

    if (pos < 32)
      return;

    gost94_transform(ctx, ctx->block);
  }

  while (len >= 32) {
    gost94_transform(ctx, bytes + off);
    off += 32;
    len -= 32;
  }

  if (len > 0)
    memcpy(ctx->block, bytes + off, len);
}

void
gost94_final(gost94_t *ctx, unsigned char *out) {
  size_t pos = ctx->size & 31;
  uint64_t bits = ctx->size << 3;
  uint8_t D[32];

  memset(D, 0x00, 32);

  if (pos != 0)
    gost94_update(ctx, D, 32 - pos);

  write64le(D, bits);

  gost94_compress(ctx, D);
  gost94_compress(ctx, ctx->sigma);

  memcpy(out, ctx->state, 32);
}

/*
 * Whirlpool
 * Logic from: https://github.com/RustCrypto/hashes
 */

static const uint64_t whirlpool_RC[10] = {
  0x1823c6e887b8014full,
  0x36a6d2f5796f9152ull,
  0x60bc9b8ea30c7b35ull,
  0x1de0d7c22e4bfe57ull,
  0x157737e59ff04adaull,
  0x58c9290ab1a06b85ull,
  0xbd5d10f4cb3e0567ull,
  0xe427418ba77d95d8ull,
  0xfbee7c66dd17479eull,
  0xca2dbf07ad5a8333ull
};

static const uint64_t whirlpool_C0[256] = {
  0x18186018c07830d8ull, 0x23238c2305af4626ull, 0xc6c63fc67ef991b8ull,
  0xe8e887e8136fcdfbull, 0x878726874ca113cbull, 0xb8b8dab8a9626d11ull,
  0x0101040108050209ull, 0x4f4f214f426e9e0dull, 0x3636d836adee6c9bull,
  0xa6a6a2a6590451ffull, 0xd2d26fd2debdb90cull, 0xf5f5f3f5fb06f70eull,
  0x7979f979ef80f296ull, 0x6f6fa16f5fcede30ull, 0x91917e91fcef3f6dull,
  0x52525552aa07a4f8ull, 0x60609d6027fdc047ull, 0xbcbccabc89766535ull,
  0x9b9b569baccd2b37ull, 0x8e8e028e048c018aull, 0xa3a3b6a371155bd2ull,
  0x0c0c300c603c186cull, 0x7b7bf17bff8af684ull, 0x3535d435b5e16a80ull,
  0x1d1d741de8693af5ull, 0xe0e0a7e05347ddb3ull, 0xd7d77bd7f6acb321ull,
  0xc2c22fc25eed999cull, 0x2e2eb82e6d965c43ull, 0x4b4b314b627a9629ull,
  0xfefedffea321e15dull, 0x575741578216aed5ull, 0x15155415a8412abdull,
  0x7777c1779fb6eee8ull, 0x3737dc37a5eb6e92ull, 0xe5e5b3e57b56d79eull,
  0x9f9f469f8cd92313ull, 0xf0f0e7f0d317fd23ull, 0x4a4a354a6a7f9420ull,
  0xdada4fda9e95a944ull, 0x58587d58fa25b0a2ull, 0xc9c903c906ca8fcfull,
  0x2929a429558d527cull, 0x0a0a280a5022145aull, 0xb1b1feb1e14f7f50ull,
  0xa0a0baa0691a5dc9ull, 0x6b6bb16b7fdad614ull, 0x85852e855cab17d9ull,
  0xbdbdcebd8173673cull, 0x5d5d695dd234ba8full, 0x1010401080502090ull,
  0xf4f4f7f4f303f507ull, 0xcbcb0bcb16c08bddull, 0x3e3ef83eedc67cd3ull,
  0x0505140528110a2dull, 0x676781671fe6ce78ull, 0xe4e4b7e47353d597ull,
  0x27279c2725bb4e02ull, 0x4141194132588273ull, 0x8b8b168b2c9d0ba7ull,
  0xa7a7a6a7510153f6ull, 0x7d7de97dcf94fab2ull, 0x95956e95dcfb3749ull,
  0xd8d847d88e9fad56ull, 0xfbfbcbfb8b30eb70ull, 0xeeee9fee2371c1cdull,
  0x7c7ced7cc791f8bbull, 0x6666856617e3cc71ull, 0xdddd53dda68ea77bull,
  0x17175c17b84b2eafull, 0x4747014702468e45ull, 0x9e9e429e84dc211aull,
  0xcaca0fca1ec589d4ull, 0x2d2db42d75995a58ull, 0xbfbfc6bf9179632eull,
  0x07071c07381b0e3full, 0xadad8ead012347acull, 0x5a5a755aea2fb4b0ull,
  0x838336836cb51befull, 0x3333cc3385ff66b6ull, 0x636391633ff2c65cull,
  0x02020802100a0412ull, 0xaaaa92aa39384993ull, 0x7171d971afa8e2deull,
  0xc8c807c80ecf8dc6ull, 0x19196419c87d32d1ull, 0x494939497270923bull,
  0xd9d943d9869aaf5full, 0xf2f2eff2c31df931ull, 0xe3e3abe34b48dba8ull,
  0x5b5b715be22ab6b9ull, 0x88881a8834920dbcull, 0x9a9a529aa4c8293eull,
  0x262698262dbe4c0bull, 0x3232c8328dfa64bfull, 0xb0b0fab0e94a7d59ull,
  0xe9e983e91b6acff2ull, 0x0f0f3c0f78331e77ull, 0xd5d573d5e6a6b733ull,
  0x80803a8074ba1df4ull, 0xbebec2be997c6127ull, 0xcdcd13cd26de87ebull,
  0x3434d034bde46889ull, 0x48483d487a759032ull, 0xffffdbffab24e354ull,
  0x7a7af57af78ff48dull, 0x90907a90f4ea3d64ull, 0x5f5f615fc23ebe9dull,
  0x202080201da0403dull, 0x6868bd6867d5d00full, 0x1a1a681ad07234caull,
  0xaeae82ae192c41b7ull, 0xb4b4eab4c95e757dull, 0x54544d549a19a8ceull,
  0x93937693ece53b7full, 0x222288220daa442full, 0x64648d6407e9c863ull,
  0xf1f1e3f1db12ff2aull, 0x7373d173bfa2e6ccull, 0x12124812905a2482ull,
  0x40401d403a5d807aull, 0x0808200840281048ull, 0xc3c32bc356e89b95ull,
  0xecec97ec337bc5dfull, 0xdbdb4bdb9690ab4dull, 0xa1a1bea1611f5fc0ull,
  0x8d8d0e8d1c830791ull, 0x3d3df43df5c97ac8ull, 0x97976697ccf1335bull,
  0x0000000000000000ull, 0xcfcf1bcf36d483f9ull, 0x2b2bac2b4587566eull,
  0x7676c57697b3ece1ull, 0x8282328264b019e6ull, 0xd6d67fd6fea9b128ull,
  0x1b1b6c1bd87736c3ull, 0xb5b5eeb5c15b7774ull, 0xafaf86af112943beull,
  0x6a6ab56a77dfd41dull, 0x50505d50ba0da0eaull, 0x45450945124c8a57ull,
  0xf3f3ebf3cb18fb38ull, 0x3030c0309df060adull, 0xefef9bef2b74c3c4ull,
  0x3f3ffc3fe5c37edaull, 0x55554955921caac7ull, 0xa2a2b2a2791059dbull,
  0xeaea8fea0365c9e9ull, 0x656589650fecca6aull, 0xbabad2bab9686903ull,
  0x2f2fbc2f65935e4aull, 0xc0c027c04ee79d8eull, 0xdede5fdebe81a160ull,
  0x1c1c701ce06c38fcull, 0xfdfdd3fdbb2ee746ull, 0x4d4d294d52649a1full,
  0x92927292e4e03976ull, 0x7575c9758fbceafaull, 0x06061806301e0c36ull,
  0x8a8a128a249809aeull, 0xb2b2f2b2f940794bull, 0xe6e6bfe66359d185ull,
  0x0e0e380e70361c7eull, 0x1f1f7c1ff8633ee7ull, 0x6262956237f7c455ull,
  0xd4d477d4eea3b53aull, 0xa8a89aa829324d81ull, 0x96966296c4f43152ull,
  0xf9f9c3f99b3aef62ull, 0xc5c533c566f697a3ull, 0x2525942535b14a10ull,
  0x59597959f220b2abull, 0x84842a8454ae15d0ull, 0x7272d572b7a7e4c5ull,
  0x3939e439d5dd72ecull, 0x4c4c2d4c5a619816ull, 0x5e5e655eca3bbc94ull,
  0x7878fd78e785f09full, 0x3838e038ddd870e5ull, 0x8c8c0a8c14860598ull,
  0xd1d163d1c6b2bf17ull, 0xa5a5aea5410b57e4ull, 0xe2e2afe2434dd9a1ull,
  0x616199612ff8c24eull, 0xb3b3f6b3f1457b42ull, 0x2121842115a54234ull,
  0x9c9c4a9c94d62508ull, 0x1e1e781ef0663ceeull, 0x4343114322528661ull,
  0xc7c73bc776fc93b1ull, 0xfcfcd7fcb32be54full, 0x0404100420140824ull,
  0x51515951b208a2e3ull, 0x99995e99bcc72f25ull, 0x6d6da96d4fc4da22ull,
  0x0d0d340d68391a65ull, 0xfafacffa8335e979ull, 0xdfdf5bdfb684a369ull,
  0x7e7ee57ed79bfca9ull, 0x242490243db44819ull, 0x3b3bec3bc5d776feull,
  0xabab96ab313d4b9aull, 0xcece1fce3ed181f0ull, 0x1111441188552299ull,
  0x8f8f068f0c890383ull, 0x4e4e254e4a6b9c04ull, 0xb7b7e6b7d1517366ull,
  0xebeb8beb0b60cbe0ull, 0x3c3cf03cfdcc78c1ull, 0x81813e817cbf1ffdull,
  0x94946a94d4fe3540ull, 0xf7f7fbf7eb0cf31cull, 0xb9b9deb9a1676f18ull,
  0x13134c13985f268bull, 0x2c2cb02c7d9c5851ull, 0xd3d36bd3d6b8bb05ull,
  0xe7e7bbe76b5cd38cull, 0x6e6ea56e57cbdc39ull, 0xc4c437c46ef395aaull,
  0x03030c03180f061bull, 0x565645568a13acdcull, 0x44440d441a49885eull,
  0x7f7fe17fdf9efea0ull, 0xa9a99ea921374f88ull, 0x2a2aa82a4d825467ull,
  0xbbbbd6bbb16d6b0aull, 0xc1c123c146e29f87ull, 0x53535153a202a6f1ull,
  0xdcdc57dcae8ba572ull, 0x0b0b2c0b58271653ull, 0x9d9d4e9d9cd32701ull,
  0x6c6cad6c47c1d82bull, 0x3131c43195f562a4ull, 0x7474cd7487b9e8f3ull,
  0xf6f6fff6e309f115ull, 0x464605460a438c4cull, 0xacac8aac092645a5ull,
  0x89891e893c970fb5ull, 0x14145014a04428b4ull, 0xe1e1a3e15b42dfbaull,
  0x16165816b04e2ca6ull, 0x3a3ae83acdd274f7ull, 0x6969b9696fd0d206ull,
  0x09092409482d1241ull, 0x7070dd70a7ade0d7ull, 0xb6b6e2b6d954716full,
  0xd0d067d0ceb7bd1eull, 0xeded93ed3b7ec7d6ull, 0xcccc17cc2edb85e2ull,
  0x424215422a578468ull, 0x98985a98b4c22d2cull, 0xa4a4aaa4490e55edull,
  0x2828a0285d885075ull, 0x5c5c6d5cda31b886ull, 0xf8f8c7f8933fed6bull,
  0x8686228644a411c2ull
};

static const uint64_t whirlpool_C1[256] = {
  0xd818186018c07830ull, 0x2623238c2305af46ull, 0xb8c6c63fc67ef991ull,
  0xfbe8e887e8136fcdull, 0xcb878726874ca113ull, 0x11b8b8dab8a9626dull,
  0x0901010401080502ull, 0x0d4f4f214f426e9eull, 0x9b3636d836adee6cull,
  0xffa6a6a2a6590451ull, 0x0cd2d26fd2debdb9ull, 0x0ef5f5f3f5fb06f7ull,
  0x967979f979ef80f2ull, 0x306f6fa16f5fcedeull, 0x6d91917e91fcef3full,
  0xf852525552aa07a4ull, 0x4760609d6027fdc0ull, 0x35bcbccabc897665ull,
  0x379b9b569baccd2bull, 0x8a8e8e028e048c01ull, 0xd2a3a3b6a371155bull,
  0x6c0c0c300c603c18ull, 0x847b7bf17bff8af6ull, 0x803535d435b5e16aull,
  0xf51d1d741de8693aull, 0xb3e0e0a7e05347ddull, 0x21d7d77bd7f6acb3ull,
  0x9cc2c22fc25eed99ull, 0x432e2eb82e6d965cull, 0x294b4b314b627a96ull,
  0x5dfefedffea321e1ull, 0xd5575741578216aeull, 0xbd15155415a8412aull,
  0xe87777c1779fb6eeull, 0x923737dc37a5eb6eull, 0x9ee5e5b3e57b56d7ull,
  0x139f9f469f8cd923ull, 0x23f0f0e7f0d317fdull, 0x204a4a354a6a7f94ull,
  0x44dada4fda9e95a9ull, 0xa258587d58fa25b0ull, 0xcfc9c903c906ca8full,
  0x7c2929a429558d52ull, 0x5a0a0a280a502214ull, 0x50b1b1feb1e14f7full,
  0xc9a0a0baa0691a5dull, 0x146b6bb16b7fdad6ull, 0xd985852e855cab17ull,
  0x3cbdbdcebd817367ull, 0x8f5d5d695dd234baull, 0x9010104010805020ull,
  0x07f4f4f7f4f303f5ull, 0xddcbcb0bcb16c08bull, 0xd33e3ef83eedc67cull,
  0x2d0505140528110aull, 0x78676781671fe6ceull, 0x97e4e4b7e47353d5ull,
  0x0227279c2725bb4eull, 0x7341411941325882ull, 0xa78b8b168b2c9d0bull,
  0xf6a7a7a6a7510153ull, 0xb27d7de97dcf94faull, 0x4995956e95dcfb37ull,
  0x56d8d847d88e9fadull, 0x70fbfbcbfb8b30ebull, 0xcdeeee9fee2371c1ull,
  0xbb7c7ced7cc791f8ull, 0x716666856617e3ccull, 0x7bdddd53dda68ea7ull,
  0xaf17175c17b84b2eull, 0x454747014702468eull, 0x1a9e9e429e84dc21ull,
  0xd4caca0fca1ec589ull, 0x582d2db42d75995aull, 0x2ebfbfc6bf917963ull,
  0x3f07071c07381b0eull, 0xacadad8ead012347ull, 0xb05a5a755aea2fb4ull,
  0xef838336836cb51bull, 0xb63333cc3385ff66ull, 0x5c636391633ff2c6ull,
  0x1202020802100a04ull, 0x93aaaa92aa393849ull, 0xde7171d971afa8e2ull,
  0xc6c8c807c80ecf8dull, 0xd119196419c87d32ull, 0x3b49493949727092ull,
  0x5fd9d943d9869aafull, 0x31f2f2eff2c31df9ull, 0xa8e3e3abe34b48dbull,
  0xb95b5b715be22ab6ull, 0xbc88881a8834920dull, 0x3e9a9a529aa4c829ull,
  0x0b262698262dbe4cull, 0xbf3232c8328dfa64ull, 0x59b0b0fab0e94a7dull,
  0xf2e9e983e91b6acfull, 0x770f0f3c0f78331eull, 0x33d5d573d5e6a6b7ull,
  0xf480803a8074ba1dull, 0x27bebec2be997c61ull, 0xebcdcd13cd26de87ull,
  0x893434d034bde468ull, 0x3248483d487a7590ull, 0x54ffffdbffab24e3ull,
  0x8d7a7af57af78ff4ull, 0x6490907a90f4ea3dull, 0x9d5f5f615fc23ebeull,
  0x3d202080201da040ull, 0x0f6868bd6867d5d0ull, 0xca1a1a681ad07234ull,
  0xb7aeae82ae192c41ull, 0x7db4b4eab4c95e75ull, 0xce54544d549a19a8ull,
  0x7f93937693ece53bull, 0x2f222288220daa44ull, 0x6364648d6407e9c8ull,
  0x2af1f1e3f1db12ffull, 0xcc7373d173bfa2e6ull, 0x8212124812905a24ull,
  0x7a40401d403a5d80ull, 0x4808082008402810ull, 0x95c3c32bc356e89bull,
  0xdfecec97ec337bc5ull, 0x4ddbdb4bdb9690abull, 0xc0a1a1bea1611f5full,
  0x918d8d0e8d1c8307ull, 0xc83d3df43df5c97aull, 0x5b97976697ccf133ull,
  0x0000000000000000ull, 0xf9cfcf1bcf36d483ull, 0x6e2b2bac2b458756ull,
  0xe17676c57697b3ecull, 0xe68282328264b019ull, 0x28d6d67fd6fea9b1ull,
  0xc31b1b6c1bd87736ull, 0x74b5b5eeb5c15b77ull, 0xbeafaf86af112943ull,
  0x1d6a6ab56a77dfd4ull, 0xea50505d50ba0da0ull, 0x5745450945124c8aull,
  0x38f3f3ebf3cb18fbull, 0xad3030c0309df060ull, 0xc4efef9bef2b74c3ull,
  0xda3f3ffc3fe5c37eull, 0xc755554955921caaull, 0xdba2a2b2a2791059ull,
  0xe9eaea8fea0365c9ull, 0x6a656589650feccaull, 0x03babad2bab96869ull,
  0x4a2f2fbc2f65935eull, 0x8ec0c027c04ee79dull, 0x60dede5fdebe81a1ull,
  0xfc1c1c701ce06c38ull, 0x46fdfdd3fdbb2ee7ull, 0x1f4d4d294d52649aull,
  0x7692927292e4e039ull, 0xfa7575c9758fbceaull, 0x3606061806301e0cull,
  0xae8a8a128a249809ull, 0x4bb2b2f2b2f94079ull, 0x85e6e6bfe66359d1ull,
  0x7e0e0e380e70361cull, 0xe71f1f7c1ff8633eull, 0x556262956237f7c4ull,
  0x3ad4d477d4eea3b5ull, 0x81a8a89aa829324dull, 0x5296966296c4f431ull,
  0x62f9f9c3f99b3aefull, 0xa3c5c533c566f697ull, 0x102525942535b14aull,
  0xab59597959f220b2ull, 0xd084842a8454ae15ull, 0xc57272d572b7a7e4ull,
  0xec3939e439d5dd72ull, 0x164c4c2d4c5a6198ull, 0x945e5e655eca3bbcull,
  0x9f7878fd78e785f0ull, 0xe53838e038ddd870ull, 0x988c8c0a8c148605ull,
  0x17d1d163d1c6b2bfull, 0xe4a5a5aea5410b57ull, 0xa1e2e2afe2434dd9ull,
  0x4e616199612ff8c2ull, 0x42b3b3f6b3f1457bull, 0x342121842115a542ull,
  0x089c9c4a9c94d625ull, 0xee1e1e781ef0663cull, 0x6143431143225286ull,
  0xb1c7c73bc776fc93ull, 0x4ffcfcd7fcb32be5ull, 0x2404041004201408ull,
  0xe351515951b208a2ull, 0x2599995e99bcc72full, 0x226d6da96d4fc4daull,
  0x650d0d340d68391aull, 0x79fafacffa8335e9ull, 0x69dfdf5bdfb684a3ull,
  0xa97e7ee57ed79bfcull, 0x19242490243db448ull, 0xfe3b3bec3bc5d776ull,
  0x9aabab96ab313d4bull, 0xf0cece1fce3ed181ull, 0x9911114411885522ull,
  0x838f8f068f0c8903ull, 0x044e4e254e4a6b9cull, 0x66b7b7e6b7d15173ull,
  0xe0ebeb8beb0b60cbull, 0xc13c3cf03cfdcc78ull, 0xfd81813e817cbf1full,
  0x4094946a94d4fe35ull, 0x1cf7f7fbf7eb0cf3ull, 0x18b9b9deb9a1676full,
  0x8b13134c13985f26ull, 0x512c2cb02c7d9c58ull, 0x05d3d36bd3d6b8bbull,
  0x8ce7e7bbe76b5cd3ull, 0x396e6ea56e57cbdcull, 0xaac4c437c46ef395ull,
  0x1b03030c03180f06ull, 0xdc565645568a13acull, 0x5e44440d441a4988ull,
  0xa07f7fe17fdf9efeull, 0x88a9a99ea921374full, 0x672a2aa82a4d8254ull,
  0x0abbbbd6bbb16d6bull, 0x87c1c123c146e29full, 0xf153535153a202a6ull,
  0x72dcdc57dcae8ba5ull, 0x530b0b2c0b582716ull, 0x019d9d4e9d9cd327ull,
  0x2b6c6cad6c47c1d8ull, 0xa43131c43195f562ull, 0xf37474cd7487b9e8ull,
  0x15f6f6fff6e309f1ull, 0x4c464605460a438cull, 0xa5acac8aac092645ull,
  0xb589891e893c970full, 0xb414145014a04428ull, 0xbae1e1a3e15b42dfull,
  0xa616165816b04e2cull, 0xf73a3ae83acdd274ull, 0x066969b9696fd0d2ull,
  0x4109092409482d12ull, 0xd77070dd70a7ade0ull, 0x6fb6b6e2b6d95471ull,
  0x1ed0d067d0ceb7bdull, 0xd6eded93ed3b7ec7ull, 0xe2cccc17cc2edb85ull,
  0x68424215422a5784ull, 0x2c98985a98b4c22dull, 0xeda4a4aaa4490e55ull,
  0x752828a0285d8850ull, 0x865c5c6d5cda31b8ull, 0x6bf8f8c7f8933fedull,
  0xc28686228644a411ull
};

static const uint64_t whirlpool_C2[256] = {
  0x30d818186018c078ull, 0x462623238c2305afull, 0x91b8c6c63fc67ef9ull,
  0xcdfbe8e887e8136full, 0x13cb878726874ca1ull, 0x6d11b8b8dab8a962ull,
  0x0209010104010805ull, 0x9e0d4f4f214f426eull, 0x6c9b3636d836adeeull,
  0x51ffa6a6a2a65904ull, 0xb90cd2d26fd2debdull, 0xf70ef5f5f3f5fb06ull,
  0xf2967979f979ef80ull, 0xde306f6fa16f5fceull, 0x3f6d91917e91fcefull,
  0xa4f852525552aa07ull, 0xc04760609d6027fdull, 0x6535bcbccabc8976ull,
  0x2b379b9b569baccdull, 0x018a8e8e028e048cull, 0x5bd2a3a3b6a37115ull,
  0x186c0c0c300c603cull, 0xf6847b7bf17bff8aull, 0x6a803535d435b5e1ull,
  0x3af51d1d741de869ull, 0xddb3e0e0a7e05347ull, 0xb321d7d77bd7f6acull,
  0x999cc2c22fc25eedull, 0x5c432e2eb82e6d96ull, 0x96294b4b314b627aull,
  0xe15dfefedffea321ull, 0xaed5575741578216ull, 0x2abd15155415a841ull,
  0xeee87777c1779fb6ull, 0x6e923737dc37a5ebull, 0xd79ee5e5b3e57b56ull,
  0x23139f9f469f8cd9ull, 0xfd23f0f0e7f0d317ull, 0x94204a4a354a6a7full,
  0xa944dada4fda9e95ull, 0xb0a258587d58fa25ull, 0x8fcfc9c903c906caull,
  0x527c2929a429558dull, 0x145a0a0a280a5022ull, 0x7f50b1b1feb1e14full,
  0x5dc9a0a0baa0691aull, 0xd6146b6bb16b7fdaull, 0x17d985852e855cabull,
  0x673cbdbdcebd8173ull, 0xba8f5d5d695dd234ull, 0x2090101040108050ull,
  0xf507f4f4f7f4f303ull, 0x8bddcbcb0bcb16c0ull, 0x7cd33e3ef83eedc6ull,
  0x0a2d050514052811ull, 0xce78676781671fe6ull, 0xd597e4e4b7e47353ull,
  0x4e0227279c2725bbull, 0x8273414119413258ull, 0x0ba78b8b168b2c9dull,
  0x53f6a7a7a6a75101ull, 0xfab27d7de97dcf94ull, 0x374995956e95dcfbull,
  0xad56d8d847d88e9full, 0xeb70fbfbcbfb8b30ull, 0xc1cdeeee9fee2371ull,
  0xf8bb7c7ced7cc791ull, 0xcc716666856617e3ull, 0xa77bdddd53dda68eull,
  0x2eaf17175c17b84bull, 0x8e45474701470246ull, 0x211a9e9e429e84dcull,
  0x89d4caca0fca1ec5ull, 0x5a582d2db42d7599ull, 0x632ebfbfc6bf9179ull,
  0x0e3f07071c07381bull, 0x47acadad8ead0123ull, 0xb4b05a5a755aea2full,
  0x1bef838336836cb5ull, 0x66b63333cc3385ffull, 0xc65c636391633ff2ull,
  0x041202020802100aull, 0x4993aaaa92aa3938ull, 0xe2de7171d971afa8ull,
  0x8dc6c8c807c80ecfull, 0x32d119196419c87dull, 0x923b494939497270ull,
  0xaf5fd9d943d9869aull, 0xf931f2f2eff2c31dull, 0xdba8e3e3abe34b48ull,
  0xb6b95b5b715be22aull, 0x0dbc88881a883492ull, 0x293e9a9a529aa4c8ull,
  0x4c0b262698262dbeull, 0x64bf3232c8328dfaull, 0x7d59b0b0fab0e94aull,
  0xcff2e9e983e91b6aull, 0x1e770f0f3c0f7833ull, 0xb733d5d573d5e6a6ull,
  0x1df480803a8074baull, 0x6127bebec2be997cull, 0x87ebcdcd13cd26deull,
  0x68893434d034bde4ull, 0x903248483d487a75ull, 0xe354ffffdbffab24ull,
  0xf48d7a7af57af78full, 0x3d6490907a90f4eaull, 0xbe9d5f5f615fc23eull,
  0x403d202080201da0ull, 0xd00f6868bd6867d5ull, 0x34ca1a1a681ad072ull,
  0x41b7aeae82ae192cull, 0x757db4b4eab4c95eull, 0xa8ce54544d549a19ull,
  0x3b7f93937693ece5ull, 0x442f222288220daaull, 0xc86364648d6407e9ull,
  0xff2af1f1e3f1db12ull, 0xe6cc7373d173bfa2ull, 0x248212124812905aull,
  0x807a40401d403a5dull, 0x1048080820084028ull, 0x9b95c3c32bc356e8ull,
  0xc5dfecec97ec337bull, 0xab4ddbdb4bdb9690ull, 0x5fc0a1a1bea1611full,
  0x07918d8d0e8d1c83ull, 0x7ac83d3df43df5c9ull, 0x335b97976697ccf1ull,
  0x0000000000000000ull, 0x83f9cfcf1bcf36d4ull, 0x566e2b2bac2b4587ull,
  0xece17676c57697b3ull, 0x19e68282328264b0ull, 0xb128d6d67fd6fea9ull,
  0x36c31b1b6c1bd877ull, 0x7774b5b5eeb5c15bull, 0x43beafaf86af1129ull,
  0xd41d6a6ab56a77dfull, 0xa0ea50505d50ba0dull, 0x8a5745450945124cull,
  0xfb38f3f3ebf3cb18ull, 0x60ad3030c0309df0ull, 0xc3c4efef9bef2b74ull,
  0x7eda3f3ffc3fe5c3ull, 0xaac755554955921cull, 0x59dba2a2b2a27910ull,
  0xc9e9eaea8fea0365ull, 0xca6a656589650fecull, 0x6903babad2bab968ull,
  0x5e4a2f2fbc2f6593ull, 0x9d8ec0c027c04ee7ull, 0xa160dede5fdebe81ull,
  0x38fc1c1c701ce06cull, 0xe746fdfdd3fdbb2eull, 0x9a1f4d4d294d5264ull,
  0x397692927292e4e0ull, 0xeafa7575c9758fbcull, 0x0c3606061806301eull,
  0x09ae8a8a128a2498ull, 0x794bb2b2f2b2f940ull, 0xd185e6e6bfe66359ull,
  0x1c7e0e0e380e7036ull, 0x3ee71f1f7c1ff863ull, 0xc4556262956237f7ull,
  0xb53ad4d477d4eea3ull, 0x4d81a8a89aa82932ull, 0x315296966296c4f4ull,
  0xef62f9f9c3f99b3aull, 0x97a3c5c533c566f6ull, 0x4a102525942535b1ull,
  0xb2ab59597959f220ull, 0x15d084842a8454aeull, 0xe4c57272d572b7a7ull,
  0x72ec3939e439d5ddull, 0x98164c4c2d4c5a61ull, 0xbc945e5e655eca3bull,
  0xf09f7878fd78e785ull, 0x70e53838e038ddd8ull, 0x05988c8c0a8c1486ull,
  0xbf17d1d163d1c6b2ull, 0x57e4a5a5aea5410bull, 0xd9a1e2e2afe2434dull,
  0xc24e616199612ff8ull, 0x7b42b3b3f6b3f145ull, 0x42342121842115a5ull,
  0x25089c9c4a9c94d6ull, 0x3cee1e1e781ef066ull, 0x8661434311432252ull,
  0x93b1c7c73bc776fcull, 0xe54ffcfcd7fcb32bull, 0x0824040410042014ull,
  0xa2e351515951b208ull, 0x2f2599995e99bcc7ull, 0xda226d6da96d4fc4ull,
  0x1a650d0d340d6839ull, 0xe979fafacffa8335ull, 0xa369dfdf5bdfb684ull,
  0xfca97e7ee57ed79bull, 0x4819242490243db4ull, 0x76fe3b3bec3bc5d7ull,
  0x4b9aabab96ab313dull, 0x81f0cece1fce3ed1ull, 0x2299111144118855ull,
  0x03838f8f068f0c89ull, 0x9c044e4e254e4a6bull, 0x7366b7b7e6b7d151ull,
  0xcbe0ebeb8beb0b60ull, 0x78c13c3cf03cfdccull, 0x1ffd81813e817cbfull,
  0x354094946a94d4feull, 0xf31cf7f7fbf7eb0cull, 0x6f18b9b9deb9a167ull,
  0x268b13134c13985full, 0x58512c2cb02c7d9cull, 0xbb05d3d36bd3d6b8ull,
  0xd38ce7e7bbe76b5cull, 0xdc396e6ea56e57cbull, 0x95aac4c437c46ef3ull,
  0x061b03030c03180full, 0xacdc565645568a13ull, 0x885e44440d441a49ull,
  0xfea07f7fe17fdf9eull, 0x4f88a9a99ea92137ull, 0x54672a2aa82a4d82ull,
  0x6b0abbbbd6bbb16dull, 0x9f87c1c123c146e2ull, 0xa6f153535153a202ull,
  0xa572dcdc57dcae8bull, 0x16530b0b2c0b5827ull, 0x27019d9d4e9d9cd3ull,
  0xd82b6c6cad6c47c1ull, 0x62a43131c43195f5ull, 0xe8f37474cd7487b9ull,
  0xf115f6f6fff6e309ull, 0x8c4c464605460a43ull, 0x45a5acac8aac0926ull,
  0x0fb589891e893c97ull, 0x28b414145014a044ull, 0xdfbae1e1a3e15b42ull,
  0x2ca616165816b04eull, 0x74f73a3ae83acdd2ull, 0xd2066969b9696fd0ull,
  0x124109092409482dull, 0xe0d77070dd70a7adull, 0x716fb6b6e2b6d954ull,
  0xbd1ed0d067d0ceb7ull, 0xc7d6eded93ed3b7eull, 0x85e2cccc17cc2edbull,
  0x8468424215422a57ull, 0x2d2c98985a98b4c2ull, 0x55eda4a4aaa4490eull,
  0x50752828a0285d88ull, 0xb8865c5c6d5cda31ull, 0xed6bf8f8c7f8933full,
  0x11c28686228644a4ull
};

static const uint64_t whirlpool_C3[256] = {
  0x7830d818186018c0ull, 0xaf462623238c2305ull, 0xf991b8c6c63fc67eull,
  0x6fcdfbe8e887e813ull, 0xa113cb878726874cull, 0x626d11b8b8dab8a9ull,
  0x0502090101040108ull, 0x6e9e0d4f4f214f42ull, 0xee6c9b3636d836adull,
  0x0451ffa6a6a2a659ull, 0xbdb90cd2d26fd2deull, 0x06f70ef5f5f3f5fbull,
  0x80f2967979f979efull, 0xcede306f6fa16f5full, 0xef3f6d91917e91fcull,
  0x07a4f852525552aaull, 0xfdc04760609d6027ull, 0x766535bcbccabc89ull,
  0xcd2b379b9b569bacull, 0x8c018a8e8e028e04ull, 0x155bd2a3a3b6a371ull,
  0x3c186c0c0c300c60ull, 0x8af6847b7bf17bffull, 0xe16a803535d435b5ull,
  0x693af51d1d741de8ull, 0x47ddb3e0e0a7e053ull, 0xacb321d7d77bd7f6ull,
  0xed999cc2c22fc25eull, 0x965c432e2eb82e6dull, 0x7a96294b4b314b62ull,
  0x21e15dfefedffea3ull, 0x16aed55757415782ull, 0x412abd15155415a8ull,
  0xb6eee87777c1779full, 0xeb6e923737dc37a5ull, 0x56d79ee5e5b3e57bull,
  0xd923139f9f469f8cull, 0x17fd23f0f0e7f0d3ull, 0x7f94204a4a354a6aull,
  0x95a944dada4fda9eull, 0x25b0a258587d58faull, 0xca8fcfc9c903c906ull,
  0x8d527c2929a42955ull, 0x22145a0a0a280a50ull, 0x4f7f50b1b1feb1e1ull,
  0x1a5dc9a0a0baa069ull, 0xdad6146b6bb16b7full, 0xab17d985852e855cull,
  0x73673cbdbdcebd81ull, 0x34ba8f5d5d695dd2ull, 0x5020901010401080ull,
  0x03f507f4f4f7f4f3ull, 0xc08bddcbcb0bcb16ull, 0xc67cd33e3ef83eedull,
  0x110a2d0505140528ull, 0xe6ce78676781671full, 0x53d597e4e4b7e473ull,
  0xbb4e0227279c2725ull, 0x5882734141194132ull, 0x9d0ba78b8b168b2cull,
  0x0153f6a7a7a6a751ull, 0x94fab27d7de97dcfull, 0xfb374995956e95dcull,
  0x9fad56d8d847d88eull, 0x30eb70fbfbcbfb8bull, 0x71c1cdeeee9fee23ull,
  0x91f8bb7c7ced7cc7ull, 0xe3cc716666856617ull, 0x8ea77bdddd53dda6ull,
  0x4b2eaf17175c17b8ull, 0x468e454747014702ull, 0xdc211a9e9e429e84ull,
  0xc589d4caca0fca1eull, 0x995a582d2db42d75ull, 0x79632ebfbfc6bf91ull,
  0x1b0e3f07071c0738ull, 0x2347acadad8ead01ull, 0x2fb4b05a5a755aeaull,
  0xb51bef838336836cull, 0xff66b63333cc3385ull, 0xf2c65c636391633full,
  0x0a04120202080210ull, 0x384993aaaa92aa39ull, 0xa8e2de7171d971afull,
  0xcf8dc6c8c807c80eull, 0x7d32d119196419c8ull, 0x70923b4949394972ull,
  0x9aaf5fd9d943d986ull, 0x1df931f2f2eff2c3ull, 0x48dba8e3e3abe34bull,
  0x2ab6b95b5b715be2ull, 0x920dbc88881a8834ull, 0xc8293e9a9a529aa4ull,
  0xbe4c0b262698262dull, 0xfa64bf3232c8328dull, 0x4a7d59b0b0fab0e9ull,
  0x6acff2e9e983e91bull, 0x331e770f0f3c0f78ull, 0xa6b733d5d573d5e6ull,
  0xba1df480803a8074ull, 0x7c6127bebec2be99ull, 0xde87ebcdcd13cd26ull,
  0xe468893434d034bdull, 0x75903248483d487aull, 0x24e354ffffdbffabull,
  0x8ff48d7a7af57af7ull, 0xea3d6490907a90f4ull, 0x3ebe9d5f5f615fc2ull,
  0xa0403d202080201dull, 0xd5d00f6868bd6867ull, 0x7234ca1a1a681ad0ull,
  0x2c41b7aeae82ae19ull, 0x5e757db4b4eab4c9ull, 0x19a8ce54544d549aull,
  0xe53b7f93937693ecull, 0xaa442f222288220dull, 0xe9c86364648d6407ull,
  0x12ff2af1f1e3f1dbull, 0xa2e6cc7373d173bfull, 0x5a24821212481290ull,
  0x5d807a40401d403aull, 0x2810480808200840ull, 0xe89b95c3c32bc356ull,
  0x7bc5dfecec97ec33ull, 0x90ab4ddbdb4bdb96ull, 0x1f5fc0a1a1bea161ull,
  0x8307918d8d0e8d1cull, 0xc97ac83d3df43df5ull, 0xf1335b97976697ccull,
  0x0000000000000000ull, 0xd483f9cfcf1bcf36ull, 0x87566e2b2bac2b45ull,
  0xb3ece17676c57697ull, 0xb019e68282328264ull, 0xa9b128d6d67fd6feull,
  0x7736c31b1b6c1bd8ull, 0x5b7774b5b5eeb5c1ull, 0x2943beafaf86af11ull,
  0xdfd41d6a6ab56a77ull, 0x0da0ea50505d50baull, 0x4c8a574545094512ull,
  0x18fb38f3f3ebf3cbull, 0xf060ad3030c0309dull, 0x74c3c4efef9bef2bull,
  0xc37eda3f3ffc3fe5ull, 0x1caac75555495592ull, 0x1059dba2a2b2a279ull,
  0x65c9e9eaea8fea03ull, 0xecca6a656589650full, 0x686903babad2bab9ull,
  0x935e4a2f2fbc2f65ull, 0xe79d8ec0c027c04eull, 0x81a160dede5fdebeull,
  0x6c38fc1c1c701ce0ull, 0x2ee746fdfdd3fdbbull, 0x649a1f4d4d294d52ull,
  0xe0397692927292e4ull, 0xbceafa7575c9758full, 0x1e0c360606180630ull,
  0x9809ae8a8a128a24ull, 0x40794bb2b2f2b2f9ull, 0x59d185e6e6bfe663ull,
  0x361c7e0e0e380e70ull, 0x633ee71f1f7c1ff8ull, 0xf7c4556262956237ull,
  0xa3b53ad4d477d4eeull, 0x324d81a8a89aa829ull, 0xf4315296966296c4ull,
  0x3aef62f9f9c3f99bull, 0xf697a3c5c533c566ull, 0xb14a102525942535ull,
  0x20b2ab59597959f2ull, 0xae15d084842a8454ull, 0xa7e4c57272d572b7ull,
  0xdd72ec3939e439d5ull, 0x6198164c4c2d4c5aull, 0x3bbc945e5e655ecaull,
  0x85f09f7878fd78e7ull, 0xd870e53838e038ddull, 0x8605988c8c0a8c14ull,
  0xb2bf17d1d163d1c6ull, 0x0b57e4a5a5aea541ull, 0x4dd9a1e2e2afe243ull,
  0xf8c24e616199612full, 0x457b42b3b3f6b3f1ull, 0xa542342121842115ull,
  0xd625089c9c4a9c94ull, 0x663cee1e1e781ef0ull, 0x5286614343114322ull,
  0xfc93b1c7c73bc776ull, 0x2be54ffcfcd7fcb3ull, 0x1408240404100420ull,
  0x08a2e351515951b2ull, 0xc72f2599995e99bcull, 0xc4da226d6da96d4full,
  0x391a650d0d340d68ull, 0x35e979fafacffa83ull, 0x84a369dfdf5bdfb6ull,
  0x9bfca97e7ee57ed7ull, 0xb44819242490243dull, 0xd776fe3b3bec3bc5ull,
  0x3d4b9aabab96ab31ull, 0xd181f0cece1fce3eull, 0x5522991111441188ull,
  0x8903838f8f068f0cull, 0x6b9c044e4e254e4aull, 0x517366b7b7e6b7d1ull,
  0x60cbe0ebeb8beb0bull, 0xcc78c13c3cf03cfdull, 0xbf1ffd81813e817cull,
  0xfe354094946a94d4ull, 0x0cf31cf7f7fbf7ebull, 0x676f18b9b9deb9a1ull,
  0x5f268b13134c1398ull, 0x9c58512c2cb02c7dull, 0xb8bb05d3d36bd3d6ull,
  0x5cd38ce7e7bbe76bull, 0xcbdc396e6ea56e57ull, 0xf395aac4c437c46eull,
  0x0f061b03030c0318ull, 0x13acdc565645568aull, 0x49885e44440d441aull,
  0x9efea07f7fe17fdfull, 0x374f88a9a99ea921ull, 0x8254672a2aa82a4dull,
  0x6d6b0abbbbd6bbb1ull, 0xe29f87c1c123c146ull, 0x02a6f153535153a2ull,
  0x8ba572dcdc57dcaeull, 0x2716530b0b2c0b58ull, 0xd327019d9d4e9d9cull,
  0xc1d82b6c6cad6c47ull, 0xf562a43131c43195ull, 0xb9e8f37474cd7487ull,
  0x09f115f6f6fff6e3ull, 0x438c4c464605460aull, 0x2645a5acac8aac09ull,
  0x970fb589891e893cull, 0x4428b414145014a0ull, 0x42dfbae1e1a3e15bull,
  0x4e2ca616165816b0ull, 0xd274f73a3ae83acdull, 0xd0d2066969b9696full,
  0x2d12410909240948ull, 0xade0d77070dd70a7ull, 0x54716fb6b6e2b6d9ull,
  0xb7bd1ed0d067d0ceull, 0x7ec7d6eded93ed3bull, 0xdb85e2cccc17cc2eull,
  0x578468424215422aull, 0xc22d2c98985a98b4ull, 0x0e55eda4a4aaa449ull,
  0x8850752828a0285dull, 0x31b8865c5c6d5cdaull, 0x3fed6bf8f8c7f893ull,
  0xa411c28686228644ull
};

static const uint64_t whirlpool_C4[256] = {
  0xc07830d818186018ull, 0x05af462623238c23ull, 0x7ef991b8c6c63fc6ull,
  0x136fcdfbe8e887e8ull, 0x4ca113cb87872687ull, 0xa9626d11b8b8dab8ull,
  0x0805020901010401ull, 0x426e9e0d4f4f214full, 0xadee6c9b3636d836ull,
  0x590451ffa6a6a2a6ull, 0xdebdb90cd2d26fd2ull, 0xfb06f70ef5f5f3f5ull,
  0xef80f2967979f979ull, 0x5fcede306f6fa16full, 0xfcef3f6d91917e91ull,
  0xaa07a4f852525552ull, 0x27fdc04760609d60ull, 0x89766535bcbccabcull,
  0xaccd2b379b9b569bull, 0x048c018a8e8e028eull, 0x71155bd2a3a3b6a3ull,
  0x603c186c0c0c300cull, 0xff8af6847b7bf17bull, 0xb5e16a803535d435ull,
  0xe8693af51d1d741dull, 0x5347ddb3e0e0a7e0ull, 0xf6acb321d7d77bd7ull,
  0x5eed999cc2c22fc2ull, 0x6d965c432e2eb82eull, 0x627a96294b4b314bull,
  0xa321e15dfefedffeull, 0x8216aed557574157ull, 0xa8412abd15155415ull,
  0x9fb6eee87777c177ull, 0xa5eb6e923737dc37ull, 0x7b56d79ee5e5b3e5ull,
  0x8cd923139f9f469full, 0xd317fd23f0f0e7f0ull, 0x6a7f94204a4a354aull,
  0x9e95a944dada4fdaull, 0xfa25b0a258587d58ull, 0x06ca8fcfc9c903c9ull,
  0x558d527c2929a429ull, 0x5022145a0a0a280aull, 0xe14f7f50b1b1feb1ull,
  0x691a5dc9a0a0baa0ull, 0x7fdad6146b6bb16bull, 0x5cab17d985852e85ull,
  0x8173673cbdbdcebdull, 0xd234ba8f5d5d695dull, 0x8050209010104010ull,
  0xf303f507f4f4f7f4ull, 0x16c08bddcbcb0bcbull, 0xedc67cd33e3ef83eull,
  0x28110a2d05051405ull, 0x1fe6ce7867678167ull, 0x7353d597e4e4b7e4ull,
  0x25bb4e0227279c27ull, 0x3258827341411941ull, 0x2c9d0ba78b8b168bull,
  0x510153f6a7a7a6a7ull, 0xcf94fab27d7de97dull, 0xdcfb374995956e95ull,
  0x8e9fad56d8d847d8ull, 0x8b30eb70fbfbcbfbull, 0x2371c1cdeeee9feeull,
  0xc791f8bb7c7ced7cull, 0x17e3cc7166668566ull, 0xa68ea77bdddd53ddull,
  0xb84b2eaf17175c17ull, 0x02468e4547470147ull, 0x84dc211a9e9e429eull,
  0x1ec589d4caca0fcaull, 0x75995a582d2db42dull, 0x9179632ebfbfc6bfull,
  0x381b0e3f07071c07ull, 0x012347acadad8eadull, 0xea2fb4b05a5a755aull,
  0x6cb51bef83833683ull, 0x85ff66b63333cc33ull, 0x3ff2c65c63639163ull,
  0x100a041202020802ull, 0x39384993aaaa92aaull, 0xafa8e2de7171d971ull,
  0x0ecf8dc6c8c807c8ull, 0xc87d32d119196419ull, 0x7270923b49493949ull,
  0x869aaf5fd9d943d9ull, 0xc31df931f2f2eff2ull, 0x4b48dba8e3e3abe3ull,
  0xe22ab6b95b5b715bull, 0x34920dbc88881a88ull, 0xa4c8293e9a9a529aull,
  0x2dbe4c0b26269826ull, 0x8dfa64bf3232c832ull, 0xe94a7d59b0b0fab0ull,
  0x1b6acff2e9e983e9ull, 0x78331e770f0f3c0full, 0xe6a6b733d5d573d5ull,
  0x74ba1df480803a80ull, 0x997c6127bebec2beull, 0x26de87ebcdcd13cdull,
  0xbde468893434d034ull, 0x7a75903248483d48ull, 0xab24e354ffffdbffull,
  0xf78ff48d7a7af57aull, 0xf4ea3d6490907a90ull, 0xc23ebe9d5f5f615full,
  0x1da0403d20208020ull, 0x67d5d00f6868bd68ull, 0xd07234ca1a1a681aull,
  0x192c41b7aeae82aeull, 0xc95e757db4b4eab4ull, 0x9a19a8ce54544d54ull,
  0xece53b7f93937693ull, 0x0daa442f22228822ull, 0x07e9c86364648d64ull,
  0xdb12ff2af1f1e3f1ull, 0xbfa2e6cc7373d173ull, 0x905a248212124812ull,
  0x3a5d807a40401d40ull, 0x4028104808082008ull, 0x56e89b95c3c32bc3ull,
  0x337bc5dfecec97ecull, 0x9690ab4ddbdb4bdbull, 0x611f5fc0a1a1bea1ull,
  0x1c8307918d8d0e8dull, 0xf5c97ac83d3df43dull, 0xccf1335b97976697ull,
  0x0000000000000000ull, 0x36d483f9cfcf1bcfull, 0x4587566e2b2bac2bull,
  0x97b3ece17676c576ull, 0x64b019e682823282ull, 0xfea9b128d6d67fd6ull,
  0xd87736c31b1b6c1bull, 0xc15b7774b5b5eeb5ull, 0x112943beafaf86afull,
  0x77dfd41d6a6ab56aull, 0xba0da0ea50505d50ull, 0x124c8a5745450945ull,
  0xcb18fb38f3f3ebf3ull, 0x9df060ad3030c030ull, 0x2b74c3c4efef9befull,
  0xe5c37eda3f3ffc3full, 0x921caac755554955ull, 0x791059dba2a2b2a2ull,
  0x0365c9e9eaea8feaull, 0x0fecca6a65658965ull, 0xb9686903babad2baull,
  0x65935e4a2f2fbc2full, 0x4ee79d8ec0c027c0ull, 0xbe81a160dede5fdeull,
  0xe06c38fc1c1c701cull, 0xbb2ee746fdfdd3fdull, 0x52649a1f4d4d294dull,
  0xe4e0397692927292ull, 0x8fbceafa7575c975ull, 0x301e0c3606061806ull,
  0x249809ae8a8a128aull, 0xf940794bb2b2f2b2ull, 0x6359d185e6e6bfe6ull,
  0x70361c7e0e0e380eull, 0xf8633ee71f1f7c1full, 0x37f7c45562629562ull,
  0xeea3b53ad4d477d4ull, 0x29324d81a8a89aa8ull, 0xc4f4315296966296ull,
  0x9b3aef62f9f9c3f9ull, 0x66f697a3c5c533c5ull, 0x35b14a1025259425ull,
  0xf220b2ab59597959ull, 0x54ae15d084842a84ull, 0xb7a7e4c57272d572ull,
  0xd5dd72ec3939e439ull, 0x5a6198164c4c2d4cull, 0xca3bbc945e5e655eull,
  0xe785f09f7878fd78ull, 0xddd870e53838e038ull, 0x148605988c8c0a8cull,
  0xc6b2bf17d1d163d1ull, 0x410b57e4a5a5aea5ull, 0x434dd9a1e2e2afe2ull,
  0x2ff8c24e61619961ull, 0xf1457b42b3b3f6b3ull, 0x15a5423421218421ull,
  0x94d625089c9c4a9cull, 0xf0663cee1e1e781eull, 0x2252866143431143ull,
  0x76fc93b1c7c73bc7ull, 0xb32be54ffcfcd7fcull, 0x2014082404041004ull,
  0xb208a2e351515951ull, 0xbcc72f2599995e99ull, 0x4fc4da226d6da96dull,
  0x68391a650d0d340dull, 0x8335e979fafacffaull, 0xb684a369dfdf5bdfull,
  0xd79bfca97e7ee57eull, 0x3db4481924249024ull, 0xc5d776fe3b3bec3bull,
  0x313d4b9aabab96abull, 0x3ed181f0cece1fceull, 0x8855229911114411ull,
  0x0c8903838f8f068full, 0x4a6b9c044e4e254eull, 0xd1517366b7b7e6b7ull,
  0x0b60cbe0ebeb8bebull, 0xfdcc78c13c3cf03cull, 0x7cbf1ffd81813e81ull,
  0xd4fe354094946a94ull, 0xeb0cf31cf7f7fbf7ull, 0xa1676f18b9b9deb9ull,
  0x985f268b13134c13ull, 0x7d9c58512c2cb02cull, 0xd6b8bb05d3d36bd3ull,
  0x6b5cd38ce7e7bbe7ull, 0x57cbdc396e6ea56eull, 0x6ef395aac4c437c4ull,
  0x180f061b03030c03ull, 0x8a13acdc56564556ull, 0x1a49885e44440d44ull,
  0xdf9efea07f7fe17full, 0x21374f88a9a99ea9ull, 0x4d8254672a2aa82aull,
  0xb16d6b0abbbbd6bbull, 0x46e29f87c1c123c1ull, 0xa202a6f153535153ull,
  0xae8ba572dcdc57dcull, 0x582716530b0b2c0bull, 0x9cd327019d9d4e9dull,
  0x47c1d82b6c6cad6cull, 0x95f562a43131c431ull, 0x87b9e8f37474cd74ull,
  0xe309f115f6f6fff6ull, 0x0a438c4c46460546ull, 0x092645a5acac8aacull,
  0x3c970fb589891e89ull, 0xa04428b414145014ull, 0x5b42dfbae1e1a3e1ull,
  0xb04e2ca616165816ull, 0xcdd274f73a3ae83aull, 0x6fd0d2066969b969ull,
  0x482d124109092409ull, 0xa7ade0d77070dd70ull, 0xd954716fb6b6e2b6ull,
  0xceb7bd1ed0d067d0ull, 0x3b7ec7d6eded93edull, 0x2edb85e2cccc17ccull,
  0x2a57846842421542ull, 0xb4c22d2c98985a98ull, 0x490e55eda4a4aaa4ull,
  0x5d8850752828a028ull, 0xda31b8865c5c6d5cull, 0x933fed6bf8f8c7f8ull,
  0x44a411c286862286ull
};

static const uint64_t whirlpool_C5[256] = {
  0x18c07830d8181860ull, 0x2305af462623238cull, 0xc67ef991b8c6c63full,
  0xe8136fcdfbe8e887ull, 0x874ca113cb878726ull, 0xb8a9626d11b8b8daull,
  0x0108050209010104ull, 0x4f426e9e0d4f4f21ull, 0x36adee6c9b3636d8ull,
  0xa6590451ffa6a6a2ull, 0xd2debdb90cd2d26full, 0xf5fb06f70ef5f5f3ull,
  0x79ef80f2967979f9ull, 0x6f5fcede306f6fa1ull, 0x91fcef3f6d91917eull,
  0x52aa07a4f8525255ull, 0x6027fdc04760609dull, 0xbc89766535bcbccaull,
  0x9baccd2b379b9b56ull, 0x8e048c018a8e8e02ull, 0xa371155bd2a3a3b6ull,
  0x0c603c186c0c0c30ull, 0x7bff8af6847b7bf1ull, 0x35b5e16a803535d4ull,
  0x1de8693af51d1d74ull, 0xe05347ddb3e0e0a7ull, 0xd7f6acb321d7d77bull,
  0xc25eed999cc2c22full, 0x2e6d965c432e2eb8ull, 0x4b627a96294b4b31ull,
  0xfea321e15dfefedfull, 0x578216aed5575741ull, 0x15a8412abd151554ull,
  0x779fb6eee87777c1ull, 0x37a5eb6e923737dcull, 0xe57b56d79ee5e5b3ull,
  0x9f8cd923139f9f46ull, 0xf0d317fd23f0f0e7ull, 0x4a6a7f94204a4a35ull,
  0xda9e95a944dada4full, 0x58fa25b0a258587dull, 0xc906ca8fcfc9c903ull,
  0x29558d527c2929a4ull, 0x0a5022145a0a0a28ull, 0xb1e14f7f50b1b1feull,
  0xa0691a5dc9a0a0baull, 0x6b7fdad6146b6bb1ull, 0x855cab17d985852eull,
  0xbd8173673cbdbdceull, 0x5dd234ba8f5d5d69ull, 0x1080502090101040ull,
  0xf4f303f507f4f4f7ull, 0xcb16c08bddcbcb0bull, 0x3eedc67cd33e3ef8ull,
  0x0528110a2d050514ull, 0x671fe6ce78676781ull, 0xe47353d597e4e4b7ull,
  0x2725bb4e0227279cull, 0x4132588273414119ull, 0x8b2c9d0ba78b8b16ull,
  0xa7510153f6a7a7a6ull, 0x7dcf94fab27d7de9ull, 0x95dcfb374995956eull,
  0xd88e9fad56d8d847ull, 0xfb8b30eb70fbfbcbull, 0xee2371c1cdeeee9full,
  0x7cc791f8bb7c7cedull, 0x6617e3cc71666685ull, 0xdda68ea77bdddd53ull,
  0x17b84b2eaf17175cull, 0x4702468e45474701ull, 0x9e84dc211a9e9e42ull,
  0xca1ec589d4caca0full, 0x2d75995a582d2db4ull, 0xbf9179632ebfbfc6ull,
  0x07381b0e3f07071cull, 0xad012347acadad8eull, 0x5aea2fb4b05a5a75ull,
  0x836cb51bef838336ull, 0x3385ff66b63333ccull, 0x633ff2c65c636391ull,
  0x02100a0412020208ull, 0xaa39384993aaaa92ull, 0x71afa8e2de7171d9ull,
  0xc80ecf8dc6c8c807ull, 0x19c87d32d1191964ull, 0x497270923b494939ull,
  0xd9869aaf5fd9d943ull, 0xf2c31df931f2f2efull, 0xe34b48dba8e3e3abull,
  0x5be22ab6b95b5b71ull, 0x8834920dbc88881aull, 0x9aa4c8293e9a9a52ull,
  0x262dbe4c0b262698ull, 0x328dfa64bf3232c8ull, 0xb0e94a7d59b0b0faull,
  0xe91b6acff2e9e983ull, 0x0f78331e770f0f3cull, 0xd5e6a6b733d5d573ull,
  0x8074ba1df480803aull, 0xbe997c6127bebec2ull, 0xcd26de87ebcdcd13ull,
  0x34bde468893434d0ull, 0x487a75903248483dull, 0xffab24e354ffffdbull,
  0x7af78ff48d7a7af5ull, 0x90f4ea3d6490907aull, 0x5fc23ebe9d5f5f61ull,
  0x201da0403d202080ull, 0x6867d5d00f6868bdull, 0x1ad07234ca1a1a68ull,
  0xae192c41b7aeae82ull, 0xb4c95e757db4b4eaull, 0x549a19a8ce54544dull,
  0x93ece53b7f939376ull, 0x220daa442f222288ull, 0x6407e9c86364648dull,
  0xf1db12ff2af1f1e3ull, 0x73bfa2e6cc7373d1ull, 0x12905a2482121248ull,
  0x403a5d807a40401dull, 0x0840281048080820ull, 0xc356e89b95c3c32bull,
  0xec337bc5dfecec97ull, 0xdb9690ab4ddbdb4bull, 0xa1611f5fc0a1a1beull,
  0x8d1c8307918d8d0eull, 0x3df5c97ac83d3df4ull, 0x97ccf1335b979766ull,
  0x0000000000000000ull, 0xcf36d483f9cfcf1bull, 0x2b4587566e2b2bacull,
  0x7697b3ece17676c5ull, 0x8264b019e6828232ull, 0xd6fea9b128d6d67full,
  0x1bd87736c31b1b6cull, 0xb5c15b7774b5b5eeull, 0xaf112943beafaf86ull,
  0x6a77dfd41d6a6ab5ull, 0x50ba0da0ea50505dull, 0x45124c8a57454509ull,
  0xf3cb18fb38f3f3ebull, 0x309df060ad3030c0ull, 0xef2b74c3c4efef9bull,
  0x3fe5c37eda3f3ffcull, 0x55921caac7555549ull, 0xa2791059dba2a2b2ull,
  0xea0365c9e9eaea8full, 0x650fecca6a656589ull, 0xbab9686903babad2ull,
  0x2f65935e4a2f2fbcull, 0xc04ee79d8ec0c027ull, 0xdebe81a160dede5full,
  0x1ce06c38fc1c1c70ull, 0xfdbb2ee746fdfdd3ull, 0x4d52649a1f4d4d29ull,
  0x92e4e03976929272ull, 0x758fbceafa7575c9ull, 0x06301e0c36060618ull,
  0x8a249809ae8a8a12ull, 0xb2f940794bb2b2f2ull, 0xe66359d185e6e6bfull,
  0x0e70361c7e0e0e38ull, 0x1ff8633ee71f1f7cull, 0x6237f7c455626295ull,
  0xd4eea3b53ad4d477ull, 0xa829324d81a8a89aull, 0x96c4f43152969662ull,
  0xf99b3aef62f9f9c3ull, 0xc566f697a3c5c533ull, 0x2535b14a10252594ull,
  0x59f220b2ab595979ull, 0x8454ae15d084842aull, 0x72b7a7e4c57272d5ull,
  0x39d5dd72ec3939e4ull, 0x4c5a6198164c4c2dull, 0x5eca3bbc945e5e65ull,
  0x78e785f09f7878fdull, 0x38ddd870e53838e0ull, 0x8c148605988c8c0aull,
  0xd1c6b2bf17d1d163ull, 0xa5410b57e4a5a5aeull, 0xe2434dd9a1e2e2afull,
  0x612ff8c24e616199ull, 0xb3f1457b42b3b3f6ull, 0x2115a54234212184ull,
  0x9c94d625089c9c4aull, 0x1ef0663cee1e1e78ull, 0x4322528661434311ull,
  0xc776fc93b1c7c73bull, 0xfcb32be54ffcfcd7ull, 0x0420140824040410ull,
  0x51b208a2e3515159ull, 0x99bcc72f2599995eull, 0x6d4fc4da226d6da9ull,
  0x0d68391a650d0d34ull, 0xfa8335e979fafacfull, 0xdfb684a369dfdf5bull,
  0x7ed79bfca97e7ee5ull, 0x243db44819242490ull, 0x3bc5d776fe3b3becull,
  0xab313d4b9aabab96ull, 0xce3ed181f0cece1full, 0x1188552299111144ull,
  0x8f0c8903838f8f06ull, 0x4e4a6b9c044e4e25ull, 0xb7d1517366b7b7e6ull,
  0xeb0b60cbe0ebeb8bull, 0x3cfdcc78c13c3cf0ull, 0x817cbf1ffd81813eull,
  0x94d4fe354094946aull, 0xf7eb0cf31cf7f7fbull, 0xb9a1676f18b9b9deull,
  0x13985f268b13134cull, 0x2c7d9c58512c2cb0ull, 0xd3d6b8bb05d3d36bull,
  0xe76b5cd38ce7e7bbull, 0x6e57cbdc396e6ea5ull, 0xc46ef395aac4c437ull,
  0x03180f061b03030cull, 0x568a13acdc565645ull, 0x441a49885e44440dull,
  0x7fdf9efea07f7fe1ull, 0xa921374f88a9a99eull, 0x2a4d8254672a2aa8ull,
  0xbbb16d6b0abbbbd6ull, 0xc146e29f87c1c123ull, 0x53a202a6f1535351ull,
  0xdcae8ba572dcdc57ull, 0x0b582716530b0b2cull, 0x9d9cd327019d9d4eull,
  0x6c47c1d82b6c6cadull, 0x3195f562a43131c4ull, 0x7487b9e8f37474cdull,
  0xf6e309f115f6f6ffull, 0x460a438c4c464605ull, 0xac092645a5acac8aull,
  0x893c970fb589891eull, 0x14a04428b4141450ull, 0xe15b42dfbae1e1a3ull,
  0x16b04e2ca6161658ull, 0x3acdd274f73a3ae8ull, 0x696fd0d2066969b9ull,
  0x09482d1241090924ull, 0x70a7ade0d77070ddull, 0xb6d954716fb6b6e2ull,
  0xd0ceb7bd1ed0d067ull, 0xed3b7ec7d6eded93ull, 0xcc2edb85e2cccc17ull,
  0x422a578468424215ull, 0x98b4c22d2c98985aull, 0xa4490e55eda4a4aaull,
  0x285d8850752828a0ull, 0x5cda31b8865c5c6dull, 0xf8933fed6bf8f8c7ull,
  0x8644a411c2868622ull
};

static const uint64_t whirlpool_C6[256] = {
  0x6018c07830d81818ull, 0x8c2305af46262323ull, 0x3fc67ef991b8c6c6ull,
  0x87e8136fcdfbe8e8ull, 0x26874ca113cb8787ull, 0xdab8a9626d11b8b8ull,
  0x0401080502090101ull, 0x214f426e9e0d4f4full, 0xd836adee6c9b3636ull,
  0xa2a6590451ffa6a6ull, 0x6fd2debdb90cd2d2ull, 0xf3f5fb06f70ef5f5ull,
  0xf979ef80f2967979ull, 0xa16f5fcede306f6full, 0x7e91fcef3f6d9191ull,
  0x5552aa07a4f85252ull, 0x9d6027fdc0476060ull, 0xcabc89766535bcbcull,
  0x569baccd2b379b9bull, 0x028e048c018a8e8eull, 0xb6a371155bd2a3a3ull,
  0x300c603c186c0c0cull, 0xf17bff8af6847b7bull, 0xd435b5e16a803535ull,
  0x741de8693af51d1dull, 0xa7e05347ddb3e0e0ull, 0x7bd7f6acb321d7d7ull,
  0x2fc25eed999cc2c2ull, 0xb82e6d965c432e2eull, 0x314b627a96294b4bull,
  0xdffea321e15dfefeull, 0x41578216aed55757ull, 0x5415a8412abd1515ull,
  0xc1779fb6eee87777ull, 0xdc37a5eb6e923737ull, 0xb3e57b56d79ee5e5ull,
  0x469f8cd923139f9full, 0xe7f0d317fd23f0f0ull, 0x354a6a7f94204a4aull,
  0x4fda9e95a944dadaull, 0x7d58fa25b0a25858ull, 0x03c906ca8fcfc9c9ull,
  0xa429558d527c2929ull, 0x280a5022145a0a0aull, 0xfeb1e14f7f50b1b1ull,
  0xbaa0691a5dc9a0a0ull, 0xb16b7fdad6146b6bull, 0x2e855cab17d98585ull,
  0xcebd8173673cbdbdull, 0x695dd234ba8f5d5dull, 0x4010805020901010ull,
  0xf7f4f303f507f4f4ull, 0x0bcb16c08bddcbcbull, 0xf83eedc67cd33e3eull,
  0x140528110a2d0505ull, 0x81671fe6ce786767ull, 0xb7e47353d597e4e4ull,
  0x9c2725bb4e022727ull, 0x1941325882734141ull, 0x168b2c9d0ba78b8bull,
  0xa6a7510153f6a7a7ull, 0xe97dcf94fab27d7dull, 0x6e95dcfb37499595ull,
  0x47d88e9fad56d8d8ull, 0xcbfb8b30eb70fbfbull, 0x9fee2371c1cdeeeeull,
  0xed7cc791f8bb7c7cull, 0x856617e3cc716666ull, 0x53dda68ea77bddddull,
  0x5c17b84b2eaf1717ull, 0x014702468e454747ull, 0x429e84dc211a9e9eull,
  0x0fca1ec589d4cacaull, 0xb42d75995a582d2dull, 0xc6bf9179632ebfbfull,
  0x1c07381b0e3f0707ull, 0x8ead012347acadadull, 0x755aea2fb4b05a5aull,
  0x36836cb51bef8383ull, 0xcc3385ff66b63333ull, 0x91633ff2c65c6363ull,
  0x0802100a04120202ull, 0x92aa39384993aaaaull, 0xd971afa8e2de7171ull,
  0x07c80ecf8dc6c8c8ull, 0x6419c87d32d11919ull, 0x39497270923b4949ull,
  0x43d9869aaf5fd9d9ull, 0xeff2c31df931f2f2ull, 0xabe34b48dba8e3e3ull,
  0x715be22ab6b95b5bull, 0x1a8834920dbc8888ull, 0x529aa4c8293e9a9aull,
  0x98262dbe4c0b2626ull, 0xc8328dfa64bf3232ull, 0xfab0e94a7d59b0b0ull,
  0x83e91b6acff2e9e9ull, 0x3c0f78331e770f0full, 0x73d5e6a6b733d5d5ull,
  0x3a8074ba1df48080ull, 0xc2be997c6127bebeull, 0x13cd26de87ebcdcdull,
  0xd034bde468893434ull, 0x3d487a7590324848ull, 0xdbffab24e354ffffull,
  0xf57af78ff48d7a7aull, 0x7a90f4ea3d649090ull, 0x615fc23ebe9d5f5full,
  0x80201da0403d2020ull, 0xbd6867d5d00f6868ull, 0x681ad07234ca1a1aull,
  0x82ae192c41b7aeaeull, 0xeab4c95e757db4b4ull, 0x4d549a19a8ce5454ull,
  0x7693ece53b7f9393ull, 0x88220daa442f2222ull, 0x8d6407e9c8636464ull,
  0xe3f1db12ff2af1f1ull, 0xd173bfa2e6cc7373ull, 0x4812905a24821212ull,
  0x1d403a5d807a4040ull, 0x2008402810480808ull, 0x2bc356e89b95c3c3ull,
  0x97ec337bc5dfececull, 0x4bdb9690ab4ddbdbull, 0xbea1611f5fc0a1a1ull,
  0x0e8d1c8307918d8dull, 0xf43df5c97ac83d3dull, 0x6697ccf1335b9797ull,
  0x0000000000000000ull, 0x1bcf36d483f9cfcfull, 0xac2b4587566e2b2bull,
  0xc57697b3ece17676ull, 0x328264b019e68282ull, 0x7fd6fea9b128d6d6ull,
  0x6c1bd87736c31b1bull, 0xeeb5c15b7774b5b5ull, 0x86af112943beafafull,
  0xb56a77dfd41d6a6aull, 0x5d50ba0da0ea5050ull, 0x0945124c8a574545ull,
  0xebf3cb18fb38f3f3ull, 0xc0309df060ad3030ull, 0x9bef2b74c3c4efefull,
  0xfc3fe5c37eda3f3full, 0x4955921caac75555ull, 0xb2a2791059dba2a2ull,
  0x8fea0365c9e9eaeaull, 0x89650fecca6a6565ull, 0xd2bab9686903babaull,
  0xbc2f65935e4a2f2full, 0x27c04ee79d8ec0c0ull, 0x5fdebe81a160dedeull,
  0x701ce06c38fc1c1cull, 0xd3fdbb2ee746fdfdull, 0x294d52649a1f4d4dull,
  0x7292e4e039769292ull, 0xc9758fbceafa7575ull, 0x1806301e0c360606ull,
  0x128a249809ae8a8aull, 0xf2b2f940794bb2b2ull, 0xbfe66359d185e6e6ull,
  0x380e70361c7e0e0eull, 0x7c1ff8633ee71f1full, 0x956237f7c4556262ull,
  0x77d4eea3b53ad4d4ull, 0x9aa829324d81a8a8ull, 0x6296c4f431529696ull,
  0xc3f99b3aef62f9f9ull, 0x33c566f697a3c5c5ull, 0x942535b14a102525ull,
  0x7959f220b2ab5959ull, 0x2a8454ae15d08484ull, 0xd572b7a7e4c57272ull,
  0xe439d5dd72ec3939ull, 0x2d4c5a6198164c4cull, 0x655eca3bbc945e5eull,
  0xfd78e785f09f7878ull, 0xe038ddd870e53838ull, 0x0a8c148605988c8cull,
  0x63d1c6b2bf17d1d1ull, 0xaea5410b57e4a5a5ull, 0xafe2434dd9a1e2e2ull,
  0x99612ff8c24e6161ull, 0xf6b3f1457b42b3b3ull, 0x842115a542342121ull,
  0x4a9c94d625089c9cull, 0x781ef0663cee1e1eull, 0x1143225286614343ull,
  0x3bc776fc93b1c7c7ull, 0xd7fcb32be54ffcfcull, 0x1004201408240404ull,
  0x5951b208a2e35151ull, 0x5e99bcc72f259999ull, 0xa96d4fc4da226d6dull,
  0x340d68391a650d0dull, 0xcffa8335e979fafaull, 0x5bdfb684a369dfdfull,
  0xe57ed79bfca97e7eull, 0x90243db448192424ull, 0xec3bc5d776fe3b3bull,
  0x96ab313d4b9aababull, 0x1fce3ed181f0ceceull, 0x4411885522991111ull,
  0x068f0c8903838f8full, 0x254e4a6b9c044e4eull, 0xe6b7d1517366b7b7ull,
  0x8beb0b60cbe0ebebull, 0xf03cfdcc78c13c3cull, 0x3e817cbf1ffd8181ull,
  0x6a94d4fe35409494ull, 0xfbf7eb0cf31cf7f7ull, 0xdeb9a1676f18b9b9ull,
  0x4c13985f268b1313ull, 0xb02c7d9c58512c2cull, 0x6bd3d6b8bb05d3d3ull,
  0xbbe76b5cd38ce7e7ull, 0xa56e57cbdc396e6eull, 0x37c46ef395aac4c4ull,
  0x0c03180f061b0303ull, 0x45568a13acdc5656ull, 0x0d441a49885e4444ull,
  0xe17fdf9efea07f7full, 0x9ea921374f88a9a9ull, 0xa82a4d8254672a2aull,
  0xd6bbb16d6b0abbbbull, 0x23c146e29f87c1c1ull, 0x5153a202a6f15353ull,
  0x57dcae8ba572dcdcull, 0x2c0b582716530b0bull, 0x4e9d9cd327019d9dull,
  0xad6c47c1d82b6c6cull, 0xc43195f562a43131ull, 0xcd7487b9e8f37474ull,
  0xfff6e309f115f6f6ull, 0x05460a438c4c4646ull, 0x8aac092645a5acacull,
  0x1e893c970fb58989ull, 0x5014a04428b41414ull, 0xa3e15b42dfbae1e1ull,
  0x5816b04e2ca61616ull, 0xe83acdd274f73a3aull, 0xb9696fd0d2066969ull,
  0x2409482d12410909ull, 0xdd70a7ade0d77070ull, 0xe2b6d954716fb6b6ull,
  0x67d0ceb7bd1ed0d0ull, 0x93ed3b7ec7d6ededull, 0x17cc2edb85e2ccccull,
  0x15422a5784684242ull, 0x5a98b4c22d2c9898ull, 0xaaa4490e55eda4a4ull,
  0xa0285d8850752828ull, 0x6d5cda31b8865c5cull, 0xc7f8933fed6bf8f8ull,
  0x228644a411c28686ull
};

static const uint64_t whirlpool_C7[256] = {
  0x186018c07830d818ull, 0x238c2305af462623ull, 0xc63fc67ef991b8c6ull,
  0xe887e8136fcdfbe8ull, 0x8726874ca113cb87ull, 0xb8dab8a9626d11b8ull,
  0x0104010805020901ull, 0x4f214f426e9e0d4full, 0x36d836adee6c9b36ull,
  0xa6a2a6590451ffa6ull, 0xd26fd2debdb90cd2ull, 0xf5f3f5fb06f70ef5ull,
  0x79f979ef80f29679ull, 0x6fa16f5fcede306full, 0x917e91fcef3f6d91ull,
  0x525552aa07a4f852ull, 0x609d6027fdc04760ull, 0xbccabc89766535bcull,
  0x9b569baccd2b379bull, 0x8e028e048c018a8eull, 0xa3b6a371155bd2a3ull,
  0x0c300c603c186c0cull, 0x7bf17bff8af6847bull, 0x35d435b5e16a8035ull,
  0x1d741de8693af51dull, 0xe0a7e05347ddb3e0ull, 0xd77bd7f6acb321d7ull,
  0xc22fc25eed999cc2ull, 0x2eb82e6d965c432eull, 0x4b314b627a96294bull,
  0xfedffea321e15dfeull, 0x5741578216aed557ull, 0x155415a8412abd15ull,
  0x77c1779fb6eee877ull, 0x37dc37a5eb6e9237ull, 0xe5b3e57b56d79ee5ull,
  0x9f469f8cd923139full, 0xf0e7f0d317fd23f0ull, 0x4a354a6a7f94204aull,
  0xda4fda9e95a944daull, 0x587d58fa25b0a258ull, 0xc903c906ca8fcfc9ull,
  0x29a429558d527c29ull, 0x0a280a5022145a0aull, 0xb1feb1e14f7f50b1ull,
  0xa0baa0691a5dc9a0ull, 0x6bb16b7fdad6146bull, 0x852e855cab17d985ull,
  0xbdcebd8173673cbdull, 0x5d695dd234ba8f5dull, 0x1040108050209010ull,
  0xf4f7f4f303f507f4ull, 0xcb0bcb16c08bddcbull, 0x3ef83eedc67cd33eull,
  0x05140528110a2d05ull, 0x6781671fe6ce7867ull, 0xe4b7e47353d597e4ull,
  0x279c2725bb4e0227ull, 0x4119413258827341ull, 0x8b168b2c9d0ba78bull,
  0xa7a6a7510153f6a7ull, 0x7de97dcf94fab27dull, 0x956e95dcfb374995ull,
  0xd847d88e9fad56d8ull, 0xfbcbfb8b30eb70fbull, 0xee9fee2371c1cdeeull,
  0x7ced7cc791f8bb7cull, 0x66856617e3cc7166ull, 0xdd53dda68ea77bddull,
  0x175c17b84b2eaf17ull, 0x47014702468e4547ull, 0x9e429e84dc211a9eull,
  0xca0fca1ec589d4caull, 0x2db42d75995a582dull, 0xbfc6bf9179632ebfull,
  0x071c07381b0e3f07ull, 0xad8ead012347acadull, 0x5a755aea2fb4b05aull,
  0x8336836cb51bef83ull, 0x33cc3385ff66b633ull, 0x6391633ff2c65c63ull,
  0x020802100a041202ull, 0xaa92aa39384993aaull, 0x71d971afa8e2de71ull,
  0xc807c80ecf8dc6c8ull, 0x196419c87d32d119ull, 0x4939497270923b49ull,
  0xd943d9869aaf5fd9ull, 0xf2eff2c31df931f2ull, 0xe3abe34b48dba8e3ull,
  0x5b715be22ab6b95bull, 0x881a8834920dbc88ull, 0x9a529aa4c8293e9aull,
  0x2698262dbe4c0b26ull, 0x32c8328dfa64bf32ull, 0xb0fab0e94a7d59b0ull,
  0xe983e91b6acff2e9ull, 0x0f3c0f78331e770full, 0xd573d5e6a6b733d5ull,
  0x803a8074ba1df480ull, 0xbec2be997c6127beull, 0xcd13cd26de87ebcdull,
  0x34d034bde4688934ull, 0x483d487a75903248ull, 0xffdbffab24e354ffull,
  0x7af57af78ff48d7aull, 0x907a90f4ea3d6490ull, 0x5f615fc23ebe9d5full,
  0x2080201da0403d20ull, 0x68bd6867d5d00f68ull, 0x1a681ad07234ca1aull,
  0xae82ae192c41b7aeull, 0xb4eab4c95e757db4ull, 0x544d549a19a8ce54ull,
  0x937693ece53b7f93ull, 0x2288220daa442f22ull, 0x648d6407e9c86364ull,
  0xf1e3f1db12ff2af1ull, 0x73d173bfa2e6cc73ull, 0x124812905a248212ull,
  0x401d403a5d807a40ull, 0x0820084028104808ull, 0xc32bc356e89b95c3ull,
  0xec97ec337bc5dfecull, 0xdb4bdb9690ab4ddbull, 0xa1bea1611f5fc0a1ull,
  0x8d0e8d1c8307918dull, 0x3df43df5c97ac83dull, 0x976697ccf1335b97ull,
  0x0000000000000000ull, 0xcf1bcf36d483f9cfull, 0x2bac2b4587566e2bull,
  0x76c57697b3ece176ull, 0x82328264b019e682ull, 0xd67fd6fea9b128d6ull,
  0x1b6c1bd87736c31bull, 0xb5eeb5c15b7774b5ull, 0xaf86af112943beafull,
  0x6ab56a77dfd41d6aull, 0x505d50ba0da0ea50ull, 0x450945124c8a5745ull,
  0xf3ebf3cb18fb38f3ull, 0x30c0309df060ad30ull, 0xef9bef2b74c3c4efull,
  0x3ffc3fe5c37eda3full, 0x554955921caac755ull, 0xa2b2a2791059dba2ull,
  0xea8fea0365c9e9eaull, 0x6589650fecca6a65ull, 0xbad2bab9686903baull,
  0x2fbc2f65935e4a2full, 0xc027c04ee79d8ec0ull, 0xde5fdebe81a160deull,
  0x1c701ce06c38fc1cull, 0xfdd3fdbb2ee746fdull, 0x4d294d52649a1f4dull,
  0x927292e4e0397692ull, 0x75c9758fbceafa75ull, 0x061806301e0c3606ull,
  0x8a128a249809ae8aull, 0xb2f2b2f940794bb2ull, 0xe6bfe66359d185e6ull,
  0x0e380e70361c7e0eull, 0x1f7c1ff8633ee71full, 0x62956237f7c45562ull,
  0xd477d4eea3b53ad4ull, 0xa89aa829324d81a8ull, 0x966296c4f4315296ull,
  0xf9c3f99b3aef62f9ull, 0xc533c566f697a3c5ull, 0x25942535b14a1025ull,
  0x597959f220b2ab59ull, 0x842a8454ae15d084ull, 0x72d572b7a7e4c572ull,
  0x39e439d5dd72ec39ull, 0x4c2d4c5a6198164cull, 0x5e655eca3bbc945eull,
  0x78fd78e785f09f78ull, 0x38e038ddd870e538ull, 0x8c0a8c148605988cull,
  0xd163d1c6b2bf17d1ull, 0xa5aea5410b57e4a5ull, 0xe2afe2434dd9a1e2ull,
  0x6199612ff8c24e61ull, 0xb3f6b3f1457b42b3ull, 0x21842115a5423421ull,
  0x9c4a9c94d625089cull, 0x1e781ef0663cee1eull, 0x4311432252866143ull,
  0xc73bc776fc93b1c7ull, 0xfcd7fcb32be54ffcull, 0x0410042014082404ull,
  0x515951b208a2e351ull, 0x995e99bcc72f2599ull, 0x6da96d4fc4da226dull,
  0x0d340d68391a650dull, 0xfacffa8335e979faull, 0xdf5bdfb684a369dfull,
  0x7ee57ed79bfca97eull, 0x2490243db4481924ull, 0x3bec3bc5d776fe3bull,
  0xab96ab313d4b9aabull, 0xce1fce3ed181f0ceull, 0x1144118855229911ull,
  0x8f068f0c8903838full, 0x4e254e4a6b9c044eull, 0xb7e6b7d1517366b7ull,
  0xeb8beb0b60cbe0ebull, 0x3cf03cfdcc78c13cull, 0x813e817cbf1ffd81ull,
  0x946a94d4fe354094ull, 0xf7fbf7eb0cf31cf7ull, 0xb9deb9a1676f18b9ull,
  0x134c13985f268b13ull, 0x2cb02c7d9c58512cull, 0xd36bd3d6b8bb05d3ull,
  0xe7bbe76b5cd38ce7ull, 0x6ea56e57cbdc396eull, 0xc437c46ef395aac4ull,
  0x030c03180f061b03ull, 0x5645568a13acdc56ull, 0x440d441a49885e44ull,
  0x7fe17fdf9efea07full, 0xa99ea921374f88a9ull, 0x2aa82a4d8254672aull,
  0xbbd6bbb16d6b0abbull, 0xc123c146e29f87c1ull, 0x535153a202a6f153ull,
  0xdc57dcae8ba572dcull, 0x0b2c0b582716530bull, 0x9d4e9d9cd327019dull,
  0x6cad6c47c1d82b6cull, 0x31c43195f562a431ull, 0x74cd7487b9e8f374ull,
  0xf6fff6e309f115f6ull, 0x4605460a438c4c46ull, 0xac8aac092645a5acull,
  0x891e893c970fb589ull, 0x145014a04428b414ull, 0xe1a3e15b42dfbae1ull,
  0x165816b04e2ca616ull, 0x3ae83acdd274f73aull, 0x69b9696fd0d20669ull,
  0x092409482d124109ull, 0x70dd70a7ade0d770ull, 0xb6e2b6d954716fb6ull,
  0xd067d0ceb7bd1ed0ull, 0xed93ed3b7ec7d6edull, 0xcc17cc2edb85e2ccull,
  0x4215422a57846842ull, 0x985a98b4c22d2c98ull, 0xa4aaa4490e55eda4ull,
  0x28a0285d88507528ull, 0x5c6d5cda31b8865cull, 0xf8c7f8933fed6bf8ull,
  0x86228644a411c286ull
};

static const unsigned char whirlpool_P[64] = {
  0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

void
whirlpool_init(whirlpool_t *ctx) {
  memset(ctx, 0, sizeof(whirlpool_t));
}

static void
whirlpool_transform(whirlpool_t *ctx, const unsigned char *chunk) {
  uint64_t B[8], S[8], K[8], L[8];
  size_t i, r;

  for (i = 0; i < 8; i++) {
    B[i] = read64be(chunk + i * 8);
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
           ^ whirlpool_C7[(K[(1 + i) & 7] >>  0) & 0xff]
           ^ (i == 0 ? whirlpool_RC[r] : 0);
    }

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
  const unsigned char *bytes = (const unsigned char *)data;
  size_t pos = ctx->size & 63;
  size_t off = 0;

  ctx->size += len;

  if (pos > 0) {
    size_t want = 64 - pos;

    if (want > len)
      want = len;

    memcpy(ctx->block + pos, bytes + off, want);

    pos += want;
    len -= want;
    off += want;

    if (pos < 64)
      return;

    whirlpool_transform(ctx, ctx->block);
  }

  while (len >= 64) {
    whirlpool_transform(ctx, bytes + off);
    off += 64;
    len -= 64;
  }

  if (len > 0)
    memcpy(ctx->block, bytes + off, len);
}

void
whirlpool_final(whirlpool_t *ctx, unsigned char *out) {
  size_t pos = ctx->size & 63;
  uint64_t len = ctx->size << 3;
  unsigned char D[32];
  size_t i;

  memset(D, 0x00, 32);

  write64be(D + 24, len);

  whirlpool_update(ctx, whirlpool_P, 1 + ((95 - pos) & 63));
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
    case HASH_HASH160:
    case HASH_HASH256:
      sha256_init(&hash->ctx.sha256);
      break;
    case HASH_SHA384:
      sha384_init(&hash->ctx.sha512);
      break;
    case HASH_SHA512:
      sha512_init(&hash->ctx.sha512);
      break;
    case HASH_SHAKE128:
      keccak_init(&hash->ctx.keccak, 128);
      break;
    case HASH_KECCAK224:
    case HASH_SHA3_224:
      keccak_init(&hash->ctx.keccak, 224);
      break;
    case HASH_KECCAK256:
    case HASH_SHA3_256:
    case HASH_SHAKE256:
      keccak_init(&hash->ctx.keccak, 256);
      break;
    case HASH_KECCAK384:
    case HASH_SHA3_384:
      keccak_init(&hash->ctx.keccak, 384);
      break;
    case HASH_KECCAK512:
    case HASH_SHA3_512:
      keccak_init(&hash->ctx.keccak, 512);
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
    case HASH_GOST94:
      gost94_init(&hash->ctx.gost94);
      break;
    case HASH_WHIRLPOOL:
      whirlpool_init(&hash->ctx.whirlpool);
      break;
    default:
      assert(0);
      break;
  }
}

void
hash_update(hash_t *hash, const void *data, size_t len) {
  switch (hash->type) {
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
    case HASH_HASH160:
    case HASH_HASH256:
      sha256_update(&hash->ctx.sha256, data, len);
      break;
    case HASH_SHA384:
    case HASH_SHA512:
      sha512_update(&hash->ctx.sha512, data, len);
      break;
    case HASH_KECCAK224:
    case HASH_KECCAK256:
    case HASH_KECCAK384:
    case HASH_KECCAK512:
    case HASH_SHA3_224:
    case HASH_SHA3_256:
    case HASH_SHA3_384:
    case HASH_SHA3_512:
    case HASH_SHAKE128:
    case HASH_SHAKE256:
      keccak_update(&hash->ctx.keccak, data, len);
      break;
    case HASH_BLAKE2S_128:
    case HASH_BLAKE2S_160:
    case HASH_BLAKE2S_224:
    case HASH_BLAKE2S_256:
      blake2s_update(&hash->ctx.blake2s, data, len);
      break;
    case HASH_BLAKE2B_160:
    case HASH_BLAKE2B_256:
    case HASH_BLAKE2B_384:
    case HASH_BLAKE2B_512:
      blake2b_update(&hash->ctx.blake2b, data, len);
      break;
    case HASH_GOST94:
      gost94_update(&hash->ctx.gost94, data, len);
      break;
    case HASH_WHIRLPOOL:
      whirlpool_update(&hash->ctx.whirlpool, data, len);
      break;
    default:
      assert(0);
      break;
  }
}

void
hash_final(hash_t *hash, unsigned char *out, size_t len) {
  switch (hash->type) {
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
    case HASH_BLAKE2S_128:
    case HASH_BLAKE2S_160:
    case HASH_BLAKE2S_224:
    case HASH_BLAKE2S_256:
      blake2s_final(&hash->ctx.blake2s, out);
      break;
    case HASH_BLAKE2B_160:
    case HASH_BLAKE2B_256:
    case HASH_BLAKE2B_384:
    case HASH_BLAKE2B_512:
      blake2b_final(&hash->ctx.blake2b, out);
      break;
    case HASH_GOST94:
      gost94_final(&hash->ctx.gost94, out);
      break;
    case HASH_WHIRLPOOL:
      whirlpool_final(&hash->ctx.whirlpool, out);
      break;
    default:
      assert(0);
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
    case HASH_KECCAK256 :
    case HASH_KECCAK384 :
    case HASH_KECCAK512 :
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

  assert(len <= block_size);

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

  cleanse(tmp, hash_size);
  cleanse(pad, block_size);
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
