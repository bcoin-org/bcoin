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
    /*case HASH_GOST94:*/
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
    /*case HASH_WHIRLPOOL:*/
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
