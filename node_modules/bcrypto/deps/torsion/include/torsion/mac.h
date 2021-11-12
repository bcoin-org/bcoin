/*!
 * mac.h - macs for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 */

#ifndef TORSION_MAC_H
#define TORSION_MAC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "common.h"

/*
 * Symbol Aliases
 */

#define poly1305_init torsion_poly1305_init
#define poly1305_update torsion_poly1305_update
#define poly1305_pad torsion_poly1305_pad
#define poly1305_final torsion_poly1305_final
#define siphash_sum torsion_siphash_sum
#define siphash_mod torsion_siphash_mod
#define siphash128_sum torsion_siphash128_sum
#define siphash256_sum torsion_siphash256_sum

/*
 * Types
 */

struct poly1305_32_s {
  uint32_t r[5];
  uint32_t h[5];
  uint32_t pad[4];
};

struct poly1305_64_s {
  uint64_t r[3];
  uint64_t h[3];
  uint64_t pad[2];
};

typedef struct poly1305_s {
  union {
    struct poly1305_32_s u32;
    struct poly1305_64_s u64;
  } state;
  unsigned char block[16];
  size_t pos;
} poly1305_t;

/*
 * Poly1305
 */

TORSION_EXTERN void
poly1305_init(poly1305_t *ctx, const unsigned char *key);

TORSION_EXTERN void
poly1305_update(poly1305_t *ctx, const unsigned char *data, size_t len);

TORSION_EXTERN void
poly1305_pad(poly1305_t *ctx);

TORSION_EXTERN void
poly1305_final(poly1305_t *ctx, unsigned char *mac);

/*
 * Siphash
 */

TORSION_EXTERN uint64_t
siphash_sum(const unsigned char *data, size_t len, const unsigned char *key);

TORSION_EXTERN uint64_t
siphash_mod(const unsigned char *data,
            size_t len,
            const unsigned char *key,
            uint64_t mod);

TORSION_EXTERN uint64_t
siphash128_sum(uint64_t num, const unsigned char *key);

TORSION_EXTERN uint64_t
siphash256_sum(uint64_t num, const unsigned char *key);

#ifdef __cplusplus
}
#endif

#endif /* TORSION_MAC_H */
