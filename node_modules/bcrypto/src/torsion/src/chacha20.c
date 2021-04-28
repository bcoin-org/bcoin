/*!
 * chacha20.c - chacha20 for C89
 * Copyright (c) 2019-2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/Chacha20
 *   https://tools.ietf.org/html/rfc7539#section-2
 *   https://cr.yp.to/chacha.html
 */

#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <torsion/chacha20.h>
#include <torsion/util.h>

/*
 * Helpers
 */

#define ROTL32(x, y) ((x) << (y)) | ((x) >> (32 - (y)))

#define QROUND(x, a, b, c, d)                   \
  x[a] += x[b]; x[d] = ROTL32(x[d] ^ x[a], 16); \
  x[c] += x[d]; x[b] = ROTL32(x[b] ^ x[c], 12); \
  x[a] += x[b]; x[d] = ROTL32(x[d] ^ x[a], 8);  \
  x[c] += x[d]; x[b] = ROTL32(x[b] ^ x[c], 7)

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
 * ChaCha20
 */

void
chacha20_init(chacha20_t *ctx,
              const unsigned char *key,
              size_t key_len,
              const unsigned char *nonce,
              size_t nonce_len,
              uint64_t counter) {
  uint8_t tmp[32];

  assert(key_len == 16 || key_len == 32);

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
    assert(0 && "invalid nonce size");
  }

  ctx->pos = 0;

  cleanse(tmp, sizeof(tmp));
}

static void
chacha20_block(chacha20_t *ctx) {
  uint32_t *stream = ctx->stream.ints;
#ifdef TORSION_USE_ASM
  /* Borrowed from:
   * https://github.com/gnutls/nettle/blob/master/x86_64/chacha-core-internal.asm
   *
   * Layout:
   *   %rsi = src pointer (&ctx->state[0])
   *   %rdi = dst pointer (&stream[0])
   *   %edx = rounds integer (nettle does `20 >> 1`)
   *
   * For reference, our full range of clobbered registers:
   * rsi, rdi, edx
   */
  __asm__ __volatile__(
    "movq %[src], %%rsi\n"
    "movq %[dst], %%rdi\n"
    "movl $20, %%edx\n"

    "movups (%%rsi), %%xmm0\n"
    "movups 16(%%rsi), %%xmm1\n"
    "movups 32(%%rsi), %%xmm2\n"
    "movups 48(%%rsi), %%xmm3\n"

    "shrl $1, %%edx\n"

    "1:\n"

    "paddd %%xmm1, %%xmm0\n"
    "pxor %%xmm0, %%xmm3\n"
    "movaps %%xmm3, %%xmm4\n"

    "pshufhw $0xb1, %%xmm3, %%xmm3\n"
    "pshuflw $0xb1, %%xmm3, %%xmm3\n"

    "paddd %%xmm3, %%xmm2\n"
    "pxor %%xmm2, %%xmm1\n"
    "movaps %%xmm1, %%xmm4\n"
    "pslld $12, %%xmm1\n"
    "psrld $20, %%xmm4\n"
    "por %%xmm4, %%xmm1\n"

    "paddd %%xmm1, %%xmm0\n"
    "pxor %%xmm0, %%xmm3\n"
    "movaps %%xmm3, %%xmm4\n"
    "pslld $8, %%xmm3\n"
    "psrld $24, %%xmm4\n"
    "por %%xmm4, %%xmm3\n"

    "paddd %%xmm3, %%xmm2\n"
    "pxor %%xmm2, %%xmm1\n"
    "movaps %%xmm1, %%xmm4\n"
    "pslld $7, %%xmm1\n"
    "psrld $25, %%xmm4\n"
    "por %%xmm4, %%xmm1\n"

    "pshufd $0x39, %%xmm1, %%xmm1\n"
    "pshufd $0x4e, %%xmm2, %%xmm2\n"
    "pshufd $0x93, %%xmm3, %%xmm3\n"

    "paddd %%xmm1, %%xmm0\n"
    "pxor %%xmm0, %%xmm3\n"
    "movaps %%xmm3, %%xmm4\n"

    "pshufhw $0xb1, %%xmm3, %%xmm3\n"
    "pshuflw $0xb1, %%xmm3, %%xmm3\n"

    "paddd %%xmm3, %%xmm2\n"
    "pxor %%xmm2, %%xmm1\n"
    "movaps %%xmm1, %%xmm4\n"
    "pslld $12, %%xmm1\n"
    "psrld $20, %%xmm4\n"
    "por %%xmm4, %%xmm1\n"

    "paddd %%xmm1, %%xmm0\n"
    "pxor %%xmm0, %%xmm3\n"
    "movaps %%xmm3, %%xmm4\n"
    "pslld $8, %%xmm3\n"
    "psrld $24, %%xmm4\n"
    "por %%xmm4, %%xmm3\n"

    "paddd %%xmm3, %%xmm2\n"
    "pxor %%xmm2, %%xmm1\n"
    "movaps %%xmm1, %%xmm4\n"
    "pslld $7, %%xmm1\n"
    "psrld $25, %%xmm4\n"
    "por %%xmm4, %%xmm1\n"

    "pshufd $0x93, %%xmm1, %%xmm1\n"
    "pshufd $0x4e, %%xmm2, %%xmm2\n"
    "pshufd $0x39, %%xmm3, %%xmm3\n"

    "decl %%edx\n"
    "jnz 1b\n"

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

    "incq 48(%%rsi)\n"
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
    QROUND(stream, 1, 5, 9, 13);
    QROUND(stream, 2, 6, 10, 14);
    QROUND(stream, 3, 7, 11, 15);
    QROUND(stream, 0, 5, 10, 15);
    QROUND(stream, 1, 6, 11, 12);
    QROUND(stream, 2, 7, 8, 13);
    QROUND(stream, 3, 4, 9, 14);
  }

  for (i = 0; i < 16; i++)
    stream[i] += ctx->state[i];

#ifdef WORDS_BIGENDIAN
  uint8_t *bytes = ctx->stream.bytes;

  for (i = 0; i < 16; i++)
    write32le(bytes + i * 4, stream[i]);
#endif

  ctx->state[12] += 1;

  if (ctx->state[12] == 0)
    ctx->state[13] += 1;
#endif
}

void
chacha20_encrypt(chacha20_t *ctx,
                 unsigned char *out,
                 const unsigned char *data,
                 size_t len) {
  uint8_t *stream = ctx->stream.bytes;
  size_t i;

  for (i = 0; i < len; i++) {
    if ((ctx->pos & 63) == 0) {
      chacha20_block(ctx);
      ctx->pos = 0;
    }

    out[i] = data[i] ^ stream[ctx->pos++];
  }
}

void
chacha20_derive(unsigned char *out,
                const unsigned char *key,
                size_t key_len,
                const unsigned char *nonce16) {
  uint32_t state[16];
  size_t i;

  assert(key_len == 16 || key_len == 32);

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
    QROUND(state, 0, 4, 8, 12);
    QROUND(state, 1, 5, 9, 13);
    QROUND(state, 2, 6, 10, 14);
    QROUND(state, 3, 7, 11, 15);
    QROUND(state, 0, 5, 10, 15);
    QROUND(state, 1, 6, 11, 12);
    QROUND(state, 2, 7, 8, 13);
    QROUND(state, 3, 4, 9, 14);
  }

  write32le(out + 0, state[0]);
  write32le(out + 4, state[1]);
  write32le(out + 8, state[2]);
  write32le(out + 12, state[3]);
  write32le(out + 16, state[12]);
  write32le(out + 20, state[13]);
  write32le(out + 24, state[14]);
  write32le(out + 28, state[15]);

  cleanse(state, sizeof(state));
}
