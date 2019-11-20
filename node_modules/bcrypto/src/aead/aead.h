#ifndef _HSK_AEAD_H
#define _HSK_AEAD_H

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "../chacha20/chacha20.h"
#include "../poly1305/poly1305.h"

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct bcrypto_aead_s {
  bcrypto_chacha20_ctx chacha;
  bcrypto_poly1305_ctx poly;
  uint64_t aad_len;
  uint64_t cipher_len;
  bool has_cipher;
  uint8_t poly_key[32];
} bcrypto_aead_ctx;

void
bcrypto_aead_init(bcrypto_aead_ctx *aead);

void
bcrypto_aead_setup(
  bcrypto_aead_ctx *aead,
  const uint8_t *key,
  const uint8_t *iv,
  size_t iv_len
);

void
bcrypto_aead_aad(bcrypto_aead_ctx *aead, const uint8_t *aad, size_t len);

void
bcrypto_aead_encrypt(
  bcrypto_aead_ctx *aead,
  const uint8_t *in,
  uint8_t *out,
  size_t len
);

void
bcrypto_aead_decrypt(
  bcrypto_aead_ctx *aead,
  const uint8_t *in,
  uint8_t *out,
  size_t len
);

void
bcrypto_aead_auth(bcrypto_aead_ctx *aead, const uint8_t *in, size_t len);

void
bcrypto_aead_final(bcrypto_aead_ctx *aead, uint8_t *tag);

bool
bcrypto_aead_verify(const uint8_t *mac1, const uint8_t *mac2);

#if defined(__cplusplus)
}
#endif
#endif
