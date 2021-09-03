/*!
 * stream.c - stream ciphers for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <torsion/stream.h>
#include <torsion/util.h>
#include "bio.h"
#include "internal.h"

/*
 * ARC4
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/RC4
 *   http://cypherpunks.venona.com/archive/1994/09/msg00304.html
 *   https://web.archive.org/web/20080207125928/http://cypherpunks.venona.com/archive/1994/09/msg00304.html
 *   https://tools.ietf.org/html/rfc4345
 *   https://tools.ietf.org/html/rfc6229
 *   https://github.com/golang/go/blob/master/src/crypto/rc4/rc4.go
 */

#define swap(x, y) do { \
  uint8_t _x = (x);     \
  (x) = (y);            \
  (y) = _x;             \
} while (0)

void
arc4_init(arc4_t *ctx, const unsigned char *key, size_t key_len) {
  uint8_t *s = ctx->s;
  size_t k = key_len;
  uint8_t j = 0;
  size_t i;

  CHECK(k >= 1 && k <= 256);

  for (i = 0; i < 256; i++)
    s[i] = i;

  for (i = 0; i < 256; i++) {
    j = (j + s[i] + key[i % k]) & 0xff;

    swap(s[i], s[j]);
  }

  ctx->i = 0;
  ctx->j = 0;
}

void
arc4_crypt(arc4_t *ctx,
           unsigned char *dst,
           const unsigned char *src,
           size_t len) {
  uint8_t *s = ctx->s;
  uint8_t i = ctx->i;
  uint8_t j = ctx->j;
  size_t k;

  for (k = 0; k < len; k++) {
    i = (i + 1) & 0xff;
    j = (j + s[i]) & 0xff;

    swap(s[i], s[j]);

    dst[k] = src[k] ^ s[(s[i] + s[j]) & 0xff];
  }

  ctx->i = i;
  ctx->j = j;
}

#undef swap

/*
 * ChaCha20
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/Chacha20
 *   https://tools.ietf.org/html/rfc7539#section-2
 *   https://cr.yp.to/chacha.html
 */

#define ROTL32(x, y) ((x) << (y)) | ((x) >> (32 - (y)))

#define QROUND(x, a, b, c, d)                   \
  x[a] += x[b]; x[d] = ROTL32(x[d] ^ x[a], 16); \
  x[c] += x[d]; x[b] = ROTL32(x[b] ^ x[c], 12); \
  x[a] += x[b]; x[d] = ROTL32(x[d] ^ x[a], 8);  \
  x[c] += x[d]; x[b] = ROTL32(x[b] ^ x[c], 7)

void
chacha20_init(chacha20_t *ctx,
              const unsigned char *key,
              size_t key_len,
              const unsigned char *nonce,
              size_t nonce_len,
              uint64_t counter) {
  uint8_t tmp[32];

  CHECK(key_len == 16 || key_len == 32);

  if (nonce_len >= 24) {
    chacha20_derive(tmp, key, key_len, nonce);
    key = tmp;
    key_len = 32;
    nonce += 16;
    nonce_len -= 16;
  }

  ctx->state[0] = 0x61707865;
  ctx->state[1] = key_len < 32 ? 0x3120646e : 0x3320646e;
  ctx->state[2] = key_len < 32 ? 0x79622d36 : 0x79622d32;
  ctx->state[3] = 0x6b206574;
  ctx->state[4] = read32le(key + 0);
  ctx->state[5] = read32le(key + 4);
  ctx->state[6] = read32le(key + 8);
  ctx->state[7] = read32le(key + 12);
  ctx->state[8] = read32le(key + 16 % key_len);
  ctx->state[9] = read32le(key + 20 % key_len);
  ctx->state[10] = read32le(key + 24 % key_len);
  ctx->state[11] = read32le(key + 28 % key_len);
  ctx->state[12] = counter;

  if (nonce_len == 8) {
    ctx->state[13] = counter >> 32;
    ctx->state[14] = read32le(nonce + 0);
    ctx->state[15] = read32le(nonce + 4);
  } else if (nonce_len == 12) {
    ctx->state[13] = read32le(nonce + 0);
    ctx->state[14] = read32le(nonce + 4);
    ctx->state[15] = read32le(nonce + 8);
  } else if (nonce_len == 16) {
    ctx->state[12] = read32le(nonce + 0);
    ctx->state[13] = read32le(nonce + 4);
    ctx->state[14] = read32le(nonce + 8);
    ctx->state[15] = read32le(nonce + 12);
  } else {
    torsion_abort(); /* LCOV_EXCL_LINE */
  }

  ctx->pos = 0;

  torsion_memzero(tmp, sizeof(tmp));
}

static void
chacha20_block(chacha20_t *ctx, uint32_t *stream) {
  int i;

  for (i = 0; i < 16; i++)
    stream[i] = ctx->state[i];

  for (i = 0; i < 10; i++) {
    QROUND(stream, 0, 4,  8, 12);
    QROUND(stream, 1, 5,  9, 13);
    QROUND(stream, 2, 6, 10, 14);
    QROUND(stream, 3, 7, 11, 15);
    QROUND(stream, 0, 5, 10, 15);
    QROUND(stream, 1, 6, 11, 12);
    QROUND(stream, 2, 7,  8, 13);
    QROUND(stream, 3, 4,  9, 14);
  }

  for (i = 0; i < 16; i++)
    stream[i] += ctx->state[i];

  if (TORSION_BIGENDIAN) {
    for (i = 0; i < 16; i++)
      stream[i] = torsion_bswap32(stream[i]);
  }

  ctx->state[12] += 1;
  ctx->state[13] += (ctx->state[12] < 1);
}

void
chacha20_crypt(chacha20_t *ctx,
               unsigned char *dst,
               const unsigned char *src,
               size_t len) {
  unsigned char *bytes = (unsigned char *)ctx->stream;
  size_t pos = ctx->pos;
  size_t want = 64 - pos;

  if (len >= want) {
    if (pos > 0) {
      torsion_memxor3(dst, src, bytes + pos, want);

      dst += want;
      src += want;
      len -= want;
      pos = 0;
    }

    while (len >= 64) {
      chacha20_block(ctx, ctx->stream);

      torsion_memxor3(dst, src, bytes, 64);

      dst += 64;
      src += 64;
      len -= 64;
    }
  }

  if (len > 0) {
    if (pos == 0)
      chacha20_block(ctx, ctx->stream);

    torsion_memxor3(dst, src, bytes + pos, len);

    pos += len;
  }

  ctx->pos = pos;
}

void
chacha20_derive(unsigned char *out,
                const unsigned char *key,
                size_t key_len,
                const unsigned char *nonce16) {
  uint32_t state[16];
  int i;

  CHECK(key_len == 16 || key_len == 32);

  state[0] = 0x61707865;
  state[1] = key_len < 32 ? 0x3120646e : 0x3320646e;
  state[2] = key_len < 32 ? 0x79622d36 : 0x79622d32;
  state[3] = 0x6b206574;
  state[4] = read32le(key + 0);
  state[5] = read32le(key + 4);
  state[6] = read32le(key + 8);
  state[7] = read32le(key + 12);
  state[8] = read32le(key + 16 % key_len);
  state[9] = read32le(key + 20 % key_len);
  state[10] = read32le(key + 24 % key_len);
  state[11] = read32le(key + 28 % key_len);
  state[12] = read32le(nonce16 + 0);
  state[13] = read32le(nonce16 + 4);
  state[14] = read32le(nonce16 + 8);
  state[15] = read32le(nonce16 + 12);

  for (i = 0; i < 10; i++) {
    QROUND(state, 0, 4,  8, 12);
    QROUND(state, 1, 5,  9, 13);
    QROUND(state, 2, 6, 10, 14);
    QROUND(state, 3, 7, 11, 15);
    QROUND(state, 0, 5, 10, 15);
    QROUND(state, 1, 6, 11, 12);
    QROUND(state, 2, 7,  8, 13);
    QROUND(state, 3, 4,  9, 14);
  }

  write32le(out +  0, state[0]);
  write32le(out +  4, state[1]);
  write32le(out +  8, state[2]);
  write32le(out + 12, state[3]);
  write32le(out + 16, state[12]);
  write32le(out + 20, state[13]);
  write32le(out + 24, state[14]);
  write32le(out + 28, state[15]);

  torsion_memzero(state, sizeof(state));
}

#undef ROTL32
#undef QROUND

/*
 * Salsa20
 *
 * Resources
 *   https://en.wikipedia.org/wiki/Salsa20
 *   https://cr.yp.to/snuffle.html
 *   https://cr.yp.to/snuffle/spec.pdf
 *   https://cr.yp.to/snuffle/812.pdf
 *   http://www.ecrypt.eu.org/stream/salsa20pf.html
 */

#define ROTL32(x, y) ((x) << (y)) | ((x) >> (32 - (y)))

#define QROUND(x, a, b, c, d)      \
  x[b] ^= ROTL32(x[a] + x[d], 7);  \
  x[c] ^= ROTL32(x[b] + x[a], 9);  \
  x[d] ^= ROTL32(x[c] + x[b], 13); \
  x[a] ^= ROTL32(x[d] + x[c], 18)

void
salsa20_init(salsa20_t *ctx,
             const unsigned char *key,
             size_t key_len,
             const unsigned char *nonce,
             size_t nonce_len,
             uint64_t counter) {
  uint8_t tmp[32];

  CHECK(key_len == 16 || key_len == 32);

  if (nonce_len >= 24) {
    salsa20_derive(tmp, key, key_len, nonce);
    key = tmp;
    key_len = 32;
    nonce += 16;
    nonce_len -= 16;
  }

  ctx->state[0] = 0x61707865;
  ctx->state[1] = read32le(key + 0);
  ctx->state[2] = read32le(key + 4);
  ctx->state[3] = read32le(key + 8);
  ctx->state[4] = read32le(key + 12);
  ctx->state[5] = key_len < 32 ? 0x3120646e : 0x3320646e;

  if (nonce_len == 8) {
    ctx->state[6] = read32le(nonce + 0);
    ctx->state[7] = read32le(nonce + 4);
    ctx->state[8] = counter;
    ctx->state[9] = counter >> 32;
  } else if (nonce_len == 12) {
    ctx->state[6] = read32le(nonce + 0);
    ctx->state[7] = read32le(nonce + 4);
    ctx->state[8] = read32le(nonce + 8);
    ctx->state[9] = counter;
  } else if (nonce_len == 16) {
    ctx->state[6] = read32le(nonce + 0);
    ctx->state[7] = read32le(nonce + 4);
    ctx->state[8] = read32le(nonce + 8);
    ctx->state[9] = read32le(nonce + 12);
  } else {
    torsion_abort(); /* LCOV_EXCL_LINE */
  }

  ctx->state[10] = key_len < 32 ? 0x79622d36 : 0x79622d32;
  ctx->state[11] = read32le(key + 16 % key_len);
  ctx->state[12] = read32le(key + 20 % key_len);
  ctx->state[13] = read32le(key + 24 % key_len);
  ctx->state[14] = read32le(key + 28 % key_len);
  ctx->state[15] = 0x6b206574;

  ctx->pos = 0;

  torsion_memzero(tmp, sizeof(tmp));
}

static void
salsa20_block(salsa20_t *ctx, uint32_t *stream) {
  int i;

  for (i = 0; i < 16; i++)
    stream[i] = ctx->state[i];

  for (i = 0; i < 10; i++) {
    QROUND(stream,  0,  4,  8, 12);
    QROUND(stream,  5,  9, 13,  1);
    QROUND(stream, 10, 14,  2,  6);
    QROUND(stream, 15,  3,  7, 11);
    QROUND(stream,  0,  1,  2,  3);
    QROUND(stream,  5,  6,  7,  4);
    QROUND(stream, 10, 11,  8,  9);
    QROUND(stream, 15, 12, 13, 14);
  }

  for (i = 0; i < 16; i++)
    stream[i] += ctx->state[i];

  if (TORSION_BIGENDIAN) {
    for (i = 0; i < 16; i++)
      stream[i] = torsion_bswap32(stream[i]);
  }

  ctx->state[8] += 1;
  ctx->state[9] += (ctx->state[8] < 1);
}

void
salsa20_crypt(salsa20_t *ctx,
              unsigned char *dst,
              const unsigned char *src,
              size_t len) {
  unsigned char *bytes = (unsigned char *)ctx->stream;
  size_t pos = ctx->pos;
  size_t want = 64 - pos;

  if (len >= want) {
    if (pos > 0) {
      torsion_memxor3(dst, src, bytes + pos, want);

      dst += want;
      src += want;
      len -= want;
      pos = 0;
    }

    while (len >= 64) {
      salsa20_block(ctx, ctx->stream);

      torsion_memxor3(dst, src, bytes, 64);

      dst += 64;
      src += 64;
      len -= 64;
    }
  }

  if (len > 0) {
    if (pos == 0)
      salsa20_block(ctx, ctx->stream);

    torsion_memxor3(dst, src, bytes + pos, len);

    pos += len;
  }

  ctx->pos = pos;
}

void
salsa20_derive(unsigned char *out,
               const unsigned char *key,
               size_t key_len,
               const unsigned char *nonce16) {
  uint32_t state[16];
  int i;

  CHECK(key_len == 16 || key_len == 32);

  state[0] = 0x61707865;
  state[1] = read32le(key + 0);
  state[2] = read32le(key + 4);
  state[3] = read32le(key + 8);
  state[4] = read32le(key + 12);
  state[5] = key_len < 32 ? 0x3120646e : 0x3320646e;
  state[6] = read32le(nonce16 + 0);
  state[7] = read32le(nonce16 + 4);
  state[8] = read32le(nonce16 + 8);
  state[9] = read32le(nonce16 + 12);
  state[10] = key_len < 32 ? 0x79622d36 : 0x79622d32;
  state[11] = read32le(key + 16 % key_len);
  state[12] = read32le(key + 20 % key_len);
  state[13] = read32le(key + 24 % key_len);
  state[14] = read32le(key + 28 % key_len);
  state[15] = 0x6b206574;

  for (i = 0; i < 10; i++) {
    QROUND(state,  0,  4,  8, 12);
    QROUND(state,  5,  9, 13,  1);
    QROUND(state, 10, 14,  2,  6);
    QROUND(state, 15,  3,  7, 11);
    QROUND(state,  0,  1,  2,  3);
    QROUND(state,  5,  6,  7,  4);
    QROUND(state, 10, 11,  8,  9);
    QROUND(state, 15, 12, 13, 14);
  }

  write32le(out +  0, state[0]);
  write32le(out +  4, state[5]);
  write32le(out +  8, state[10]);
  write32le(out + 12, state[15]);
  write32le(out + 16, state[6]);
  write32le(out + 20, state[7]);
  write32le(out + 24, state[8]);
  write32le(out + 28, state[9]);

  torsion_memzero(state, sizeof(state));
}

#undef ROTL32
#undef QROUND
