/*!
 * salsa20.c - salsa20 for C89
 * Copyright (c) 2019-2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 *
 * Resources
 *   https://en.wikipedia.org/wiki/Salsa20
 *   https://cr.yp.to/snuffle.html
 *   https://cr.yp.to/snuffle/spec.pdf
 *   https://cr.yp.to/snuffle/812.pdf
 *   http://www.ecrypt.eu.org/stream/salsa20pf.html
 */

#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <torsion/salsa20.h>
#include <torsion/util.h>

/*
 * Helpers
 */

#define ROTL32(v, n) ((v) << (n)) | ((v) >> (32 - (n)))

#define QROUND(x, a, b, c, d)      \
  x[b] ^= ROTL32(x[a] + x[d], 7);  \
  x[c] ^= ROTL32(x[b] + x[a], 9);  \
  x[d] ^= ROTL32(x[c] + x[b], 13); \
  x[a] ^= ROTL32(x[d] + x[c], 18)

static uint32_t
read32le(const void *src) {
#ifndef WORDS_BIGENDIAN
  uint32_t w;
  memcpy(&w, src, sizeof(w));
  return w;
#else
  const uint8_t *p = (const uint8_t *)src;
  return ((uint32_t)(p[0]) << 0)
       | ((uint32_t)(p[1]) << 8)
       | ((uint32_t)(p[2]) << 16)
       | ((uint32_t)(p[3]) << 24);
#endif
}

static void
write32le(void *dst, uint32_t w) {
#ifndef WORDS_BIGENDIAN
  memcpy(dst, (void *)&w, sizeof(w));
#else
  uint8_t *p = (uint8_t *)dst;
  p[0] = w >> 0;
  p[1] = w >> 8;
  p[2] = w >> 16;
  p[3] = w >> 24;
#endif
}

/*
 * salsa20
 */

void
salsa20_init(salsa20_t *ctx,
             const unsigned char *key,
             size_t key_len,
             const unsigned char *nonce,
             size_t nonce_len,
             uint64_t counter) {
  uint8_t tmp[32];

  assert(key_len == 16 || key_len == 32);

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
    assert(0 && "invalid nonce size");
  }

  ctx->state[10] = key_len < 32 ? 0x79622d36 : 0x79622d32;
  ctx->state[11] = read32le(key + 16 % key_len);
  ctx->state[12] = read32le(key + 20 % key_len);
  ctx->state[13] = read32le(key + 24 % key_len);
  ctx->state[14] = read32le(key + 28 % key_len);
  ctx->state[15] = 0x6b206574;

  ctx->pos = 0;

  cleanse(tmp, sizeof(tmp));
}

static void
salsa20_block(salsa20_t *ctx) {
  uint32_t *stream = ctx->stream.ints;
#ifdef TORSION_USE_ASM
  /* Borrowed from:
   * https://github.com/gnutls/nettle/blob/master/x86_64/salsa20-core-internal.asm
   *
   * Layout:
   *   %rsi = src pointer (&ctx->state[0])
   *   %rdi = dst pointer (&output[0])
   *   %edx = rounds integer (nettle does `20 >> 1`)
   *
   * For reference, our full range of clobbered registers:
   * rsi, rdi, edx
   */
  __asm__ __volatile__(
    "movq %[src], %%rsi\n"
    "movq %[dst], %%rdi\n"

    "mov $-1, %%edx\n"
    "movd %%edx, %%xmm6\n"

    "movl $20, %%edx\n"

    "pshufd $0x09, %%xmm6, %%xmm8\n"
    "pshufd $0x41, %%xmm6, %%xmm7\n"
    "pshufd $0x22, %%xmm6, %%xmm6\n"

    "movups (%%rsi), %%xmm0\n"
    "movups 16(%%rsi), %%xmm1\n"
    "movups 32(%%rsi), %%xmm2\n"
    "movups 48(%%rsi), %%xmm3\n"

    "movaps %%xmm0, %%xmm4\n"
    "pxor %%xmm1, %%xmm0\n"
    "pand %%xmm6, %%xmm0\n"
    "pxor %%xmm0, %%xmm1\n"
    "pxor %%xmm4, %%xmm0\n"

    "movaps %%xmm2, %%xmm4\n"
    "pxor %%xmm3, %%xmm2\n"
    "pand %%xmm6, %%xmm2\n"
    "pxor %%xmm2, %%xmm3\n"
    "pxor %%xmm4, %%xmm2\n"

    "movaps %%xmm1, %%xmm4\n"
    "pxor %%xmm3, %%xmm1\n"
    "pand %%xmm7, %%xmm1\n"
    "pxor %%xmm1, %%xmm3\n"
    "pxor %%xmm4, %%xmm1\n"

    "movaps %%xmm0, %%xmm4\n"
    "pxor %%xmm2, %%xmm0\n"
    "pand %%xmm8, %%xmm0\n"
    "pxor %%xmm0, %%xmm2\n"
    "pxor %%xmm4, %%xmm0\n"

    "shrl $1, %%edx\n"

    "1:\n"

    "movaps %%xmm3, %%xmm4\n"
    "paddd %%xmm0, %%xmm4\n"
    "movaps %%xmm4, %%xmm5\n"
    "pslld $7, %%xmm4\n"
    "psrld $25, %%xmm5\n"
    "pxor %%xmm4, %%xmm1\n"
    "pxor %%xmm5, %%xmm1\n"

    "movaps %%xmm0, %%xmm4\n"
    "paddd %%xmm1, %%xmm4\n"
    "movaps %%xmm4, %%xmm5\n"
    "pslld $9, %%xmm4\n"
    "psrld $23, %%xmm5\n"
    "pxor %%xmm4, %%xmm2\n"
    "pxor %%xmm5, %%xmm2\n"

    "movaps %%xmm1, %%xmm4\n"
    "paddd %%xmm2, %%xmm4\n"
    "movaps %%xmm4, %%xmm5\n"
    "pslld $13, %%xmm4\n"
    "psrld $19, %%xmm5\n"
    "pxor %%xmm4, %%xmm3\n"
    "pxor %%xmm5, %%xmm3\n"

    "movaps %%xmm2, %%xmm4\n"
    "paddd %%xmm3, %%xmm4\n"
    "movaps %%xmm4, %%xmm5\n"
    "pslld $18, %%xmm4\n"
    "psrld $14, %%xmm5\n"
    "pxor %%xmm4, %%xmm0\n"
    "pxor %%xmm5, %%xmm0\n"

    "pshufd $0x93, %%xmm1, %%xmm1\n"
    "pshufd $0x4e, %%xmm2, %%xmm2\n"
    "pshufd $0x39, %%xmm3, %%xmm3\n"

    "movaps %%xmm1, %%xmm4\n"
    "paddd %%xmm0, %%xmm4\n"
    "movaps %%xmm4, %%xmm5\n"
    "pslld $7, %%xmm4\n"
    "psrld $25, %%xmm5\n"
    "pxor %%xmm4, %%xmm3\n"
    "pxor %%xmm5, %%xmm3\n"

    "movaps %%xmm0, %%xmm4\n"
    "paddd %%xmm3, %%xmm4\n"
    "movaps %%xmm4, %%xmm5\n"
    "pslld $9, %%xmm4\n"
    "psrld $23, %%xmm5\n"
    "pxor %%xmm4, %%xmm2\n"
    "pxor %%xmm5, %%xmm2\n"

    "movaps %%xmm3, %%xmm4\n"
    "paddd %%xmm2, %%xmm4\n"
    "movaps %%xmm4, %%xmm5\n"
    "pslld $13, %%xmm4\n"
    "psrld $19, %%xmm5\n"
    "pxor %%xmm4, %%xmm1\n"
    "pxor %%xmm5, %%xmm1\n"

    "movaps %%xmm2, %%xmm4\n"
    "paddd %%xmm1, %%xmm4\n"
    "movaps %%xmm4, %%xmm5\n"
    "pslld $18, %%xmm4\n"
    "psrld $14, %%xmm5\n"
    "pxor %%xmm4, %%xmm0\n"
    "pxor %%xmm5, %%xmm0\n"

    "pshufd $0x39, %%xmm1, %%xmm1\n"
    "pshufd $0x4e, %%xmm2, %%xmm2\n"
    "pshufd $0x93, %%xmm3, %%xmm3\n"

    "decl %%edx\n"
    "jnz 1b\n"

    "movaps %%xmm0, %%xmm4\n"
    "pxor %%xmm2, %%xmm0\n"
    "pand %%xmm8, %%xmm0\n"
    "pxor %%xmm0, %%xmm2\n"
    "pxor %%xmm4, %%xmm0\n"

    "movaps %%xmm1, %%xmm4\n"
    "pxor %%xmm3, %%xmm1\n"
    "pand %%xmm7, %%xmm1\n"
    "pxor %%xmm1, %%xmm3\n"
    "pxor %%xmm4, %%xmm1\n"

    "movaps %%xmm0, %%xmm4\n"
    "pxor %%xmm1, %%xmm0\n"
    "pand %%xmm6, %%xmm0\n"
    "pxor %%xmm0, %%xmm1\n"
    "pxor %%xmm4, %%xmm0\n"

    "movaps %%xmm2, %%xmm4\n"
    "pxor %%xmm3, %%xmm2\n"
    "pand %%xmm6, %%xmm2\n"
    "pxor %%xmm2, %%xmm3\n"
    "pxor %%xmm4, %%xmm2\n"

    "movups (%%rsi), %%xmm4\n"
    "movups 16(%%rsi), %%xmm5\n"
    "paddd %%xmm4, %%xmm0\n"
    "paddd %%xmm5, %%xmm1\n"
    "movups %%xmm0,(%%rdi)\n"
    "movups %%xmm1,16(%%rdi)\n"
    "movups 32(%%rsi), %%xmm4\n"
    "movups 48(%%rsi), %%xmm5\n"
    "paddd %%xmm4, %%xmm2\n"
    "paddd %%xmm5, %%xmm3\n"
    "movups %%xmm2,32(%%rdi)\n"
    "movups %%xmm3,48(%%rdi)\n"

    "incq 32(%%rsi)\n"
    :
    : [src] "r" (ctx->state),
      [dst] "r" (stream)
    : "rsi", "rdi", "edx", "cc", "memory"
  );
#else
  size_t i;

  memcpy(stream, ctx->state, sizeof(ctx->state));

  for (i = 0; i < 10; i++) {
    QROUND(stream, 0, 4, 8, 12);
    QROUND(stream, 5, 9, 13, 1);
    QROUND(stream, 10, 14, 2, 6);
    QROUND(stream, 15, 3, 7, 11);
    QROUND(stream, 0, 1, 2, 3);
    QROUND(stream, 5, 6, 7, 4);
    QROUND(stream, 10, 11, 8, 9);
    QROUND(stream, 15, 12, 13, 14);
  }

  for (i = 0; i < 16; i++)
    stream[i] += ctx->state[i];

#ifdef WORDS_BIGENDIAN
  uint8_t *bytes = ctx->stream.bytes;

  for (i = 0; i < 16; i++)
    write32le(bytes + i * 4, stream[i]);
#endif

  ctx->state[8] += 1;

  if (ctx->state[8] == 0)
    ctx->state[9] += 1;
#endif
}

void
salsa20_encrypt(salsa20_t *ctx,
                unsigned char *out,
                const unsigned char *data,
                size_t len) {
  uint8_t *stream = ctx->stream.bytes;
  size_t i;

  for (i = 0; i < len; i++) {
    if ((ctx->pos & 63) == 0) {
      salsa20_block(ctx);
      ctx->pos = 0;
    }

    out[i] = data[i] ^ stream[ctx->pos++];
  }
}

void
salsa20_derive(unsigned char *out,
               const unsigned char *key,
               size_t key_len,
               const unsigned char *nonce16) {
  uint32_t state[16];
  size_t i;

  assert(key_len == 16 || key_len == 32);

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
    QROUND(state, 0, 4, 8, 12);
    QROUND(state, 5, 9, 13, 1);
    QROUND(state, 10, 14, 2, 6);
    QROUND(state, 15, 3, 7, 11);
    QROUND(state, 0, 1, 2, 3);
    QROUND(state, 5, 6, 7, 4);
    QROUND(state, 10, 11, 8, 9);
    QROUND(state, 15, 12, 13, 14);
  }

  write32le(out + 0, state[0]);
  write32le(out + 4, state[5]);
  write32le(out + 8, state[10]);
  write32le(out + 12, state[15]);
  write32le(out + 16, state[6]);
  write32le(out + 20, state[7]);
  write32le(out + 24, state[8]);
  write32le(out + 28, state[9]);

  cleanse(state, sizeof(state));
}
