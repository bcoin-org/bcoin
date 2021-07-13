/*!
 * aead.c - aead for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <torsion/aead.h>
#include <torsion/mac.h>
#include <torsion/stream.h>
#include <torsion/util.h>
#include "bio.h"
#include "internal.h"

/*
 * Constants
 */

static const unsigned char zero64[64] = {0};

/*
 * ChaCha20-Poly1305
 *
 * Resources:
 *   https://tools.ietf.org/html/rfc7539#section-2.8
 *   https://github.com/openssh/openssh-portable
 */

void
chachapoly_init(chachapoly_t *aead,
                const unsigned char *key,
                const unsigned char *iv,
                size_t iv_len) {
  unsigned char polykey[64];

  chacha20_init(&aead->chacha, key, 32, iv, iv_len, 0);
  chacha20_crypt(&aead->chacha, polykey, zero64, 64);

  poly1305_init(&aead->poly, polykey);

  aead->mode = 0;
  aead->adlen = 0;
  aead->ctlen = 0;

  torsion_cleanse(polykey, sizeof(polykey));
}

void
chachapoly_aad(chachapoly_t *aead, const unsigned char *aad, size_t len) {
  CHECK(aead->mode == 0);

  poly1305_update(&aead->poly, aad, len);

  aead->adlen += len;
}

static void
chachapoly_pad16(chachapoly_t *aead, uint64_t size) {
  uint64_t pos = size & 15;

  if (pos > 0)
    poly1305_update(&aead->poly, zero64, 16 - pos);
}

void
chachapoly_encrypt(chachapoly_t *aead,
                   unsigned char *dst,
                   const unsigned char *src,
                   size_t len) {
  if (aead->mode == 0) {
    chachapoly_pad16(aead, aead->adlen);
    aead->mode = 1;
  }

  CHECK(aead->mode == 1);

  chacha20_crypt(&aead->chacha, dst, src, len);
  poly1305_update(&aead->poly, dst, len);

  aead->ctlen += len;
}

void
chachapoly_decrypt(chachapoly_t *aead,
                   unsigned char *dst,
                   const unsigned char *src,
                   size_t len) {
  if (aead->mode == 0) {
    chachapoly_pad16(aead, aead->adlen);
    aead->mode = 2;
  }

  CHECK(aead->mode == 2);

  aead->ctlen += len;

  poly1305_update(&aead->poly, src, len);
  chacha20_crypt(&aead->chacha, dst, src, len);
}

void
chachapoly_auth(chachapoly_t *aead, const unsigned char *data, size_t len) {
  if (aead->mode == 0) {
    chachapoly_pad16(aead, aead->adlen);
    aead->mode = 3;
  }

  CHECK(aead->mode == 3);

  aead->ctlen += len;

  poly1305_update(&aead->poly, data, len);
}

void
chachapoly_final(chachapoly_t *aead, unsigned char *tag) {
  unsigned char len[16];

  write64le(len + 0, aead->adlen);
  write64le(len + 8, aead->ctlen);

  if (aead->mode == 0)
    chachapoly_pad16(aead, aead->adlen);

  chachapoly_pad16(aead, aead->ctlen);

  poly1305_update(&aead->poly, len, 16);
  poly1305_final(&aead->poly, tag);

  aead->mode = -1;
}
