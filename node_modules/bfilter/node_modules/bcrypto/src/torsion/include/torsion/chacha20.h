/*!
 * chacha20.h - chacha20 for C89
 * Copyright (c) 2019-2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 */

#ifndef _TORSION_CHACHA20_H
#define _TORSION_CHACHA20_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

/*
 * Symbol Aliases
 */

#define chacha20_init torsion_chacha20_init
#define chacha20_encrypt torsion_chacha20_encrypt
#define chacha20_derive torsion_chacha20_derive

/*
 * Structs
 */

typedef struct _chacha20_s {
  uint32_t state[16];
  union {
    uint32_t ints[16];
    unsigned char bytes[64];
  } stream;
  size_t pos;
} chacha20_t;

/*
 * ChaCha20
 */

void
chacha20_init(chacha20_t *ctx,
              const unsigned char *key,
              size_t key_len,
              const unsigned char *nonce,
              size_t nonce_len,
              uint64_t counter);

void
chacha20_encrypt(chacha20_t *ctx,
                 unsigned char *out,
                 const unsigned char *data,
                 size_t len);

void
chacha20_derive(unsigned char *out,
                const unsigned char *key,
                size_t key_len,
                const unsigned char *nonce16);

#ifdef __cplusplus
}
#endif

#endif /* _TORSION_CHACHA20_H */
