/*!
 * stream.h - stream ciphers for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 */

#ifndef TORSION_STREAM_H
#define TORSION_STREAM_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "common.h"

/*
 * Symbol Aliases
 */

#define arc4_init torsion_arc4_init
#define arc4_crypt torsion_arc4_crypt
#define chacha20_init torsion_chacha20_init
#define chacha20_crypt torsion_chacha20_crypt
#define chacha20_derive torsion_chacha20_derive
#define salsa20_init torsion_salsa20_init
#define salsa20_crypt torsion_salsa20_crypt
#define salsa20_derive torsion_salsa20_derive

/*
 * Types
 */

typedef struct arc4_s {
  uint8_t s[256];
  uint8_t i;
  uint8_t j;
} arc4_t;

typedef struct chacha20_s {
  uint32_t state[16];
  uint32_t stream[16];
  size_t pos;
} chacha20_t;

typedef struct salsa20_s {
  uint32_t state[16];
  uint32_t stream[16];
  size_t pos;
} salsa20_t;

/*
 * ARC4
 */

TORSION_EXTERN void
arc4_init(arc4_t *ctx, const unsigned char *key, size_t key_len);

TORSION_EXTERN void
arc4_crypt(arc4_t *ctx,
           unsigned char *dst,
           const unsigned char *src,
           size_t len);

/*
 * ChaCha20
 */

TORSION_EXTERN void
chacha20_init(chacha20_t *ctx,
              const unsigned char *key,
              size_t key_len,
              const unsigned char *nonce,
              size_t nonce_len,
              uint64_t counter);

TORSION_EXTERN void
chacha20_crypt(chacha20_t *ctx,
               unsigned char *dst,
               const unsigned char *src,
               size_t len);

TORSION_EXTERN void
chacha20_derive(unsigned char *out,
                const unsigned char *key,
                size_t key_len,
                const unsigned char *nonce16);

/*
 * Salsa20
 */

TORSION_EXTERN void
salsa20_init(salsa20_t *ctx,
             const unsigned char *key,
             size_t key_len,
             const unsigned char *nonce,
             size_t nonce_len,
             uint64_t counter);

TORSION_EXTERN void
salsa20_crypt(salsa20_t *ctx,
              unsigned char *dst,
              const unsigned char *src,
              size_t len);

TORSION_EXTERN void
salsa20_derive(unsigned char *out,
               const unsigned char *key,
               size_t key_len,
               const unsigned char *nonce16);

#ifdef __cplusplus
}
#endif

#endif /* TORSION_STREAM_H */
