/*!
 * aead.h - aead for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 */

#ifndef TORSION_AEAD_H
#define TORSION_AEAD_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#include "common.h"
#include "mac.h"
#include "stream.h"

/*
 * Symbol Aliases
 */

#define chachapoly_init torsion_chachapoly_init
#define chachapoly_aad torsion_chachapoly_aad
#define chachapoly_encrypt torsion_chachapoly_encrypt
#define chachapoly_decrypt torsion_chachapoly_decrypt
#define chachapoly_auth torsion_chachapoly_auth
#define chachapoly_final torsion_chachapoly_final

/*
 * Types
 */

typedef struct chachapoly_s {
  chacha20_t chacha;
  poly1305_t poly;
  uint64_t adlen;
  uint64_t ctlen;
} chachapoly_t;

/*
 * AEAD
 */

typedef chachapoly_t aead_t;

#define aead_init chachapoly_init
#define aead_aad chachapoly_aad
#define aead_encrypt chachapoly_encrypt
#define aead_decrypt chachapoly_decrypt
#define aead_auth chachapoly_auth
#define aead_final chachapoly_final

/*
 * ChaCha20-Poly1305
 */

TORSION_EXTERN void
chachapoly_init(chachapoly_t *aead,
                const unsigned char *key,
                const unsigned char *iv,
                size_t iv_len);

TORSION_EXTERN void
chachapoly_aad(chachapoly_t *aead, const unsigned char *aad, size_t len);

TORSION_EXTERN void
chachapoly_encrypt(chachapoly_t *aead,
                   unsigned char *dst,
                   const unsigned char *src,
                   size_t len);

TORSION_EXTERN void
chachapoly_decrypt(chachapoly_t *aead,
                   unsigned char *dst,
                   const unsigned char *src,
                   size_t len);

TORSION_EXTERN void
chachapoly_auth(chachapoly_t *aead, const unsigned char *data, size_t len);

TORSION_EXTERN void
chachapoly_final(chachapoly_t *aead, unsigned char *tag);

#ifdef __cplusplus
}
#endif

#endif /* TORSION_AEAD_H */
