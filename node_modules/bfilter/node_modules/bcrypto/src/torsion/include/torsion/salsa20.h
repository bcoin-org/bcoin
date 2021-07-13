/*!
 * salsa20.h - salsa20 for C89
 * Copyright (c) 2019-2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 */

#ifndef _TORSION_SALSA20_H
#define _TORSION_SALSA20_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

/*
 * Symbol Aliases
 */

#define salsa20_init torsion_salsa20_init
#define salsa20_encrypt torsion_salsa20_encrypt
#define salsa20_derive torsion_salsa20_derive

/*
 * Structs
 */

typedef struct _salsa20_s {
  uint32_t state[16];
  union {
    uint32_t ints[16];
    unsigned char bytes[64];
  } stream;
  size_t pos;
} salsa20_t;

/*
 * Salsa20
 */

void
salsa20_init(salsa20_t *ctx,
             const unsigned char *key,
             size_t key_len,
             const unsigned char *nonce,
             size_t nonce_len,
             uint64_t counter);

void
salsa20_encrypt(salsa20_t *ctx,
                unsigned char *out,
                const unsigned char *data,
                size_t len);

void
salsa20_derive(unsigned char *out,
               const unsigned char *key,
               size_t key_len,
               const unsigned char *nonce16);

#ifdef __cplusplus
}
#endif

#endif /* _TORSION_SALSA20_H */
