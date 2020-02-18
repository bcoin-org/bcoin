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

#include "blake2s.h"
#include "blake2s-impl.h"

static const uint32_t bcrypto_blake2s_IV[8] = {
  0x6a09e667UL, 0xbb67ae85UL, 0x3c6ef372UL, 0xa54ff53aUL,
  0x510e527fUL, 0x9b05688cUL, 0x1f83d9abUL, 0x5be0cd19UL
};

static const uint8_t bcrypto_blake2s_sigma[10][16] = {
  {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
  { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
  { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
  {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
  {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
  {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
  { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
  { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
  {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
  { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 }
};

static void
bcrypto_blake2s_set_lastnode(bcrypto_blake2s_ctx *S) {
  S->f[1] = (uint32_t)-1;
}

static int
bcrypto_blake2s_is_lastblock(const bcrypto_blake2s_ctx *S) {
  return S->f[0] != 0;
}

static void
bcrypto_blake2s_set_lastblock(bcrypto_blake2s_ctx *S) {
  if (S->last_node)
    bcrypto_blake2s_set_lastnode(S);

  S->f[0] = (uint32_t)-1;
}

static void
bcrypto_blake2s_increment_counter(
  bcrypto_blake2s_ctx *S,
  const uint32_t inc
) {
  S->t[0] += inc;
  S->t[1] += (S->t[0] < inc);
}

static void
bcrypto_blake2s_init0(bcrypto_blake2s_ctx *S) {
  size_t i;
  memset(S, 0, sizeof(bcrypto_blake2s_ctx));

  for (i = 0; i < 8; ++i)
    S->h[i] = bcrypto_blake2s_IV[i];
}

int
bcrypto_blake2s_init_param(
  bcrypto_blake2s_ctx *S,
  const bcrypto_blake2s_param *P
) {
  const unsigned char *p = (const unsigned char *)(P);
  size_t i;

  bcrypto_blake2s_init0(S);

  for (i = 0; i < 8; ++i)
    S->h[i] ^= load32(&p[i * 4]);

  S->outlen = P->digest_length;

  return 0;
}

int
bcrypto_blake2s_init(bcrypto_blake2s_ctx *S, size_t outlen) {
  bcrypto_blake2s_param P[1];

  if ((!outlen) || (outlen > BCRYPTO_BLAKE2S_OUTBYTES))
    return -1;

  P->digest_length = (uint8_t)outlen;
  P->key_length = 0;
  P->fanout = 1;
  P->depth = 1;
  store32(&P->leaf_length, 0);
  store32(&P->node_offset, 0);
  store16(&P->xof_length, 0);
  P->node_depth = 0;
  P->inner_length = 0;
  memset(P->salt, 0, sizeof(P->salt));
  memset(P->personal, 0, sizeof(P->personal));

  return bcrypto_blake2s_init_param(S, P);
}

int
bcrypto_blake2s_init_key(
  bcrypto_blake2s_ctx *S,
  size_t outlen,
  const void *key,
  size_t keylen
) {
  bcrypto_blake2s_param P[1];

  if ((!outlen) || (outlen > BCRYPTO_BLAKE2S_OUTBYTES))
    return -1;

  if (!key || !keylen || keylen > BCRYPTO_BLAKE2S_KEYBYTES)
    return -1;

  P->digest_length = (uint8_t)outlen;
  P->key_length = (uint8_t)keylen;
  P->fanout = 1;
  P->depth = 1;
  store32(&P->leaf_length, 0);
  store32(&P->node_offset, 0);
  store16(&P->xof_length, 0);
  P->node_depth = 0;
  P->inner_length = 0;
  memset(P->salt, 0, sizeof(P->salt));
  memset(P->personal, 0, sizeof(P->personal));

  if (bcrypto_blake2s_init_param(S, P) < 0)
    return -1;

  {
    uint8_t block[BCRYPTO_BLAKE2S_BLOCKBYTES];
    memset(block, 0, BCRYPTO_BLAKE2S_BLOCKBYTES);
    memcpy(block, key, keylen);
    bcrypto_blake2s_update(S, block, BCRYPTO_BLAKE2S_BLOCKBYTES);
    secure_zero_memory(block, BCRYPTO_BLAKE2S_BLOCKBYTES);
  }

  return 0;
}

#define G(r, i, a, b, c, d)                             \
  do {                                                  \
    a = a + b + m[bcrypto_blake2s_sigma[r][2 * i + 0]]; \
    d = rotr32(d ^ a, 16);                              \
    c = c + d;                                          \
    b = rotr32(b ^ c, 12);                              \
    a = a + b + m[bcrypto_blake2s_sigma[r][2 * i + 1]]; \
    d = rotr32(d ^ a, 8);                               \
    c = c + d;                                          \
    b = rotr32(b ^ c, 7);                               \
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

static void
bcrypto_blake2s_compress(
  bcrypto_blake2s_ctx *S,
  const uint8_t in[BCRYPTO_BLAKE2S_BLOCKBYTES]
) {
  uint32_t m[16];
  uint32_t v[16];
  size_t i;

  for (i = 0; i < 16; ++i)
    m[i] = load32(in + i * sizeof(m[i]));

  for (i = 0; i < 8; ++i)
    v[i] = S->h[i];

  v[8] = bcrypto_blake2s_IV[0];
  v[9] = bcrypto_blake2s_IV[1];
  v[10] = bcrypto_blake2s_IV[2];
  v[11] = bcrypto_blake2s_IV[3];
  v[12] = S->t[0] ^ bcrypto_blake2s_IV[4];
  v[13] = S->t[1] ^ bcrypto_blake2s_IV[5];
  v[14] = S->f[0] ^ bcrypto_blake2s_IV[6];
  v[15] = S->f[1] ^ bcrypto_blake2s_IV[7];

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

  for (i = 0; i < 8; ++i)
    S->h[i] = S->h[i] ^ v[i] ^ v[i + 8];
}

#undef G
#undef ROUND

int
bcrypto_blake2s_update(
  bcrypto_blake2s_ctx *S,
  const void *pin,
  size_t inlen
) {
  const unsigned char *in = (const unsigned char *)pin;

  if (inlen > 0) {
    size_t left = S->buflen;
    size_t fill = BCRYPTO_BLAKE2S_BLOCKBYTES - left;

    if (inlen > fill) {
      S->buflen = 0;
      memcpy(S->buf + left, in, fill);
      bcrypto_blake2s_increment_counter(S, BCRYPTO_BLAKE2S_BLOCKBYTES);
      bcrypto_blake2s_compress(S, S->buf);

      in += fill;
      inlen -= fill;

      while (inlen > BCRYPTO_BLAKE2S_BLOCKBYTES) {
        bcrypto_blake2s_increment_counter(S, BCRYPTO_BLAKE2S_BLOCKBYTES);
        bcrypto_blake2s_compress(S, in);

        in += BCRYPTO_BLAKE2S_BLOCKBYTES;
        inlen -= BCRYPTO_BLAKE2S_BLOCKBYTES;
      }
    }

    memcpy(S->buf + S->buflen, in, inlen);

    S->buflen += inlen;
  }

  return 0;
}

int
bcrypto_blake2s_final(bcrypto_blake2s_ctx *S, void *out, size_t outlen) {
  uint8_t buffer[BCRYPTO_BLAKE2S_OUTBYTES] = {0};
  size_t i;

  if (out == NULL || outlen < S->outlen)
    return -1;

  if (bcrypto_blake2s_is_lastblock(S))
    return -1;

  bcrypto_blake2s_increment_counter(S, (uint32_t)S->buflen);
  bcrypto_blake2s_set_lastblock(S);
  memset(S->buf + S->buflen, 0, BCRYPTO_BLAKE2S_BLOCKBYTES - S->buflen);
  bcrypto_blake2s_compress(S, S->buf);

  for (i = 0; i < 8; ++i)
    store32(buffer + sizeof(S->h[i]) * i, S->h[i]);

  memcpy(out, buffer, outlen);
  secure_zero_memory(buffer, sizeof(buffer));

  return 0;
}

int
bcrypto_blake2s(
  void *out,
  size_t outlen,
  const void *in,
  size_t inlen,
  const void *key,
  size_t keylen
) {
  bcrypto_blake2s_ctx S[1];

  if (NULL == in && inlen > 0)
    return -1;

  if (NULL == out)
    return -1;

  if (NULL == key && keylen > 0)
    return -1;

  if (!outlen || outlen > BCRYPTO_BLAKE2S_OUTBYTES)
    return -1;

  if (keylen > BCRYPTO_BLAKE2S_KEYBYTES)
    return -1;

  if (keylen > 0) {
    if (bcrypto_blake2s_init_key(S, outlen, key, keylen) < 0)
      return -1;
  } else {
    if (bcrypto_blake2s_init(S, outlen) < 0)
      return -1;
  }

  bcrypto_blake2s_update(S, (const uint8_t *)in, inlen);
  bcrypto_blake2s_final(S, out, outlen);

  return 0;
}
