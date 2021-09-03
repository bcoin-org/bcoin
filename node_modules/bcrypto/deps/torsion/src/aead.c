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
  static const unsigned char zero64[64] = {0};
  unsigned char polykey[64];

  chacha20_init(&aead->chacha, key, 32, iv, iv_len, 0);
  chacha20_crypt(&aead->chacha, polykey, zero64, 64);

  poly1305_init(&aead->poly, polykey);

  aead->adlen = 0;
  aead->ctlen = 0;

  torsion_memzero(polykey, sizeof(polykey));
}

void
chachapoly_aad(chachapoly_t *aead, const unsigned char *aad, size_t len) {
  aead->adlen += len;
  poly1305_update(&aead->poly, aad, len);
}

void
chachapoly_encrypt(chachapoly_t *aead,
                   unsigned char *dst,
                   const unsigned char *src,
                   size_t len) {
  if (aead->ctlen == 0)
    poly1305_pad(&aead->poly);

  aead->ctlen += len;

  chacha20_crypt(&aead->chacha, dst, src, len);
  poly1305_update(&aead->poly, dst, len);
}

void
chachapoly_decrypt(chachapoly_t *aead,
                   unsigned char *dst,
                   const unsigned char *src,
                   size_t len) {
  if (aead->ctlen == 0)
    poly1305_pad(&aead->poly);

  aead->ctlen += len;

  poly1305_update(&aead->poly, src, len);
  chacha20_crypt(&aead->chacha, dst, src, len);
}

void
chachapoly_auth(chachapoly_t *aead, const unsigned char *data, size_t len) {
  if (aead->ctlen == 0)
    poly1305_pad(&aead->poly);

  aead->ctlen += len;

  poly1305_update(&aead->poly, data, len);
}

void
chachapoly_final(chachapoly_t *aead, unsigned char *tag) {
  unsigned char len[16];

  write64le(len + 0, aead->adlen);
  write64le(len + 8, aead->ctlen);

  poly1305_pad(&aead->poly);
  poly1305_update(&aead->poly, len, 16);
  poly1305_final(&aead->poly, tag);
}
