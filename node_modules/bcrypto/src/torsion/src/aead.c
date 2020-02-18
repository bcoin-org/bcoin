/*!
 * aead.c - aead for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 *
 * Resources:
 *   https://tools.ietf.org/html/rfc7539#section-2.8
 *   https://github.com/openssh/openssh-portable
 */

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <torsion/chacha20.h>
#include <torsion/poly1305.h>
#include <torsion/aead.h>

/*
 * Constants
 */

static const unsigned char aead_padding[16] = {0};

/*
 * AEAD
 */

void
aead_init(aead_t *aead) {
  memset(&aead->chacha, 0, sizeof(aead->chacha));
  memset(&aead->poly, 0, sizeof(aead->poly));
  memset(aead->key, 0x00, sizeof(aead->key));

  aead->mode = -1;
  aead->aad_len = 0;
  aead->cipher_len = 0;
}

void
aead_setup(aead_t *aead,
           const unsigned char *key,
           const unsigned char *iv,
           size_t iv_len) {
  memset(aead->key, 0x00, sizeof(aead->key));

  chacha20_init(&aead->chacha, key, 32, iv, iv_len, 0);
  chacha20_encrypt(&aead->chacha, aead->key, aead->key, sizeof(aead->key));
  poly1305_init(&aead->poly, aead->key);

  aead->mode = 0;
  aead->aad_len = 0;
  aead->cipher_len = 0;
}

void
aead_aad(aead_t *aead, const unsigned char *aad, size_t len) {
  assert(aead->mode == 0);

  poly1305_update(&aead->poly, aad, len);

  aead->aad_len += len;
}

static void
aead_pad16(aead_t *aead, uint64_t size) {
  uint64_t pos = size & 15;

  if (pos > 0)
    poly1305_update(&aead->poly, aead_padding, 16 - pos);
}

void
aead_encrypt(aead_t *aead,
             unsigned char *out,
             const unsigned char *in,
             size_t len) {
  if (aead->mode == 0) {
    aead_pad16(aead, aead->aad_len);
    aead->mode = 1;
  }

  assert(aead->mode == 1);

  chacha20_encrypt(&aead->chacha, out, in, len);
  poly1305_update(&aead->poly, out, len);

  aead->cipher_len += len;
}

void
aead_decrypt(aead_t *aead,
             unsigned char *out,
             const unsigned char *in,
             size_t len) {
  if (aead->mode == 0) {
    aead_pad16(aead, aead->aad_len);
    aead->mode = 2;
  }

  assert(aead->mode == 2);

  aead->cipher_len += len;

  poly1305_update(&aead->poly, in, len);
  chacha20_encrypt(&aead->chacha, out, in, len);
}

void
aead_auth(aead_t *aead, const unsigned char *in, size_t len) {
  if (aead->mode == 0) {
    aead_pad16(aead, aead->aad_len);
    aead->mode = 3;
  }

  assert(aead->mode == 3);

  aead->cipher_len += len;

  poly1305_update(&aead->poly, in, len);
}

void
aead_final(aead_t *aead, unsigned char *tag) {
  uint8_t len[16];

#ifdef WORDS_BIGENDIAN
  len[0] = aead->aad_len & 0xff;
  len[1] = (aead->aad_len >> 8) & 0xff;
  len[2] = (aead->aad_len >> 16) & 0xff;
  len[3] = (aead->aad_len >> 24) & 0xff;
  len[4] = (aead->aad_len >> 32) & 0xff;
  len[5] = (aead->aad_len >> 40) & 0xff;
  len[6] = (aead->aad_len >> 48) & 0xff;
  len[7] = (aead->aad_len >> 56) & 0xff;
  len[8] = aead->cipher_len & 0xff;
  len[9] = (aead->cipher_len >> 8) & 0xff;
  len[10] = (aead->cipher_len >> 16) & 0xff;
  len[11] = (aead->cipher_len >> 24) & 0xff;
  len[12] = (aead->cipher_len >> 32) & 0xff;
  len[13] = (aead->cipher_len >> 40) & 0xff;
  len[14] = (aead->cipher_len >> 48) & 0xff;
  len[15] = (aead->cipher_len >> 56) & 0xff;
#else
  memcpy(&len[0], &aead->aad_len, sizeof(aead->aad_len));
  memcpy(&len[8], &aead->cipher_len, sizeof(aead->cipher_len));
#endif

  if (aead->mode == 0)
    aead_pad16(aead, aead->aad_len);

  aead_pad16(aead, aead->cipher_len);

  poly1305_update(&aead->poly, len, sizeof(len));
  poly1305_final(&aead->poly, tag);

  aead->mode = -1;
}

int
aead_verify(const unsigned char *mac1, const unsigned char *mac2) {
  return poly1305_verify(mac1, mac2) != 0;
}
