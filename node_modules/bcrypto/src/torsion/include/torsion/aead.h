#ifndef _TORSION_AEAD_H
#define _TORSION_AEAD_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

#include "chacha20.h"
#include "poly1305.h"

/*
 * Symbol Aliases
 */

#define aead_init torsion_aead_init
#define aead_setup torsion_aead_setup
#define aead_aad torsion_aead_aad
#define aead_encrypt torsion_aead_encrypt
#define aead_decrypt torsion_aead_decrypt
#define aead_auth torsion_aead_auth
#define aead_final torsion_aead_final
#define aead_verify torsion_aead_verify

/*
 * Structs
 */

typedef struct _aead_s {
  chacha20_t chacha;
  poly1305_t poly;
  unsigned char key[64];
  int mode;
  uint64_t aad_len;
  uint64_t cipher_len;
} aead_t;

/*
 * AEAD
 */

void
aead_init(aead_t *aead);

void
aead_setup(aead_t *aead,
           const unsigned char *key,
           const unsigned char *iv,
           size_t iv_len);

void
aead_aad(aead_t *aead, const unsigned char *aad, size_t len);

void
aead_encrypt(aead_t *aead,
             unsigned char *out,
             const unsigned char *in,
             size_t len);

void
aead_decrypt(aead_t *aead,
             unsigned char *out,
             const unsigned char *in,
             size_t len);

void
aead_auth(aead_t *aead, const unsigned char *in, size_t len);

void
aead_final(aead_t *aead, unsigned char *tag);

int
aead_verify(const unsigned char *mac1, const unsigned char *mac2);

#ifdef __cplusplus
}
#endif

#endif /* _TORSION_AEAD_H */
