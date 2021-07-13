/*!
 * drbg.h - drbg implementations for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 */

#ifndef _TORSION_DRBG_H
#define _TORSION_DRBG_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include "common.h"
#include "cipher.h"
#include "hash.h"

/*
 * Symbol Aliases
 */

#define hmac_drbg_init torsion_hmac_drbg_init
#define hmac_drbg_reseed torsion_hmac_drbg_reseed
#define hmac_drbg_generate torsion_hmac_drbg_generate
#define hmac_drbg_rng __torsion_hmac_drbg_rng

#define hash_drbg_init torsion_hash_drbg_init
#define hash_drbg_reseed torsion_hash_drbg_reseed
#define hash_drbg_generate torsion_hash_drbg_generate
#define hash_drbg_rng __torsion_hash_drbg_rng

#define ctr_drbg_init torsion_ctr_drbg_init
#define ctr_drbg_reseed torsion_ctr_drbg_reseed
#define ctr_drbg_generate torsion_ctr_drbg_generate
#define ctr_drbg_rng __torsion_ctr_drbg_rng

/*
 * Structs
 */

typedef struct hmac_drbg_s {
  int type;
  size_t size;
  hmac_t kmac;
  unsigned char K[HASH_MAX_OUTPUT_SIZE];
  unsigned char V[HASH_MAX_OUTPUT_SIZE];
} hmac_drbg_t;

typedef struct hash_drbg_s {
  int type;
  hash_t hash;
  size_t size;
  size_t length;
  unsigned char V[111];
  unsigned char C[111];
  uint64_t rounds;
} hash_drbg_t;

typedef struct ctr_drbg_s {
  aes_t aes;
  size_t key_size;
  size_t blk_size;
  size_t ent_size;
  int derivation;
  unsigned char KV[48];
  unsigned char *K;
  unsigned char *V;
  uint8_t state[16];
} ctr_drbg_t;

/*
 * DRBG
 */

typedef hmac_drbg_t drbg_t;

#define drbg_init hmac_drbg_init
#define drbg_reseed hmac_drbg_reseed
#define drbg_generate(drbg, out, len) \
  hmac_drbg_generate(drbg, out, len, NULL, 0)
#define drbg_rng hmac_drbg_rng

/*
 * HMAC-DRBG
 */

TORSION_EXTERN void
hmac_drbg_init(hmac_drbg_t *drbg,
               int type,
               const unsigned char *seed,
               size_t seed_len);

TORSION_EXTERN void
hmac_drbg_reseed(hmac_drbg_t *drbg, const unsigned char *seed, size_t seed_len);

TORSION_EXTERN void
hmac_drbg_generate(hmac_drbg_t *drbg, void *out, size_t len,
                   const unsigned char *add, size_t add_len);

TORSION_EXTERN void
hmac_drbg_rng(void *out, size_t size, void *arg);

/*
 * Hash-DRBG
 */

TORSION_EXTERN void
hash_drbg_init(hash_drbg_t *drbg,
               int type,
               const unsigned char *seed,
               size_t seed_len);

TORSION_EXTERN void
hash_drbg_reseed(hash_drbg_t *drbg,
                 const unsigned char *seed,
                 size_t seed_len);

TORSION_EXTERN void
hash_drbg_generate(hash_drbg_t *drbg,
                   void *out,
                   size_t len,
                   const unsigned char *add,
                   size_t add_len);

TORSION_EXTERN void
hash_drbg_rng(void *out, size_t size, void *arg);

/*
 * CTR-DRBG
 */

TORSION_EXTERN void
ctr_drbg_init(ctr_drbg_t *drbg,
              unsigned int bits,
              int derivation,
              const unsigned char *nonce,
              size_t nonce_len,
              const unsigned char *pers,
              size_t pers_len);

TORSION_EXTERN void
ctr_drbg_reseed(ctr_drbg_t *drbg,
                const unsigned char *nonce,
                size_t nonce_len,
                const unsigned char *add,
                size_t add_len);

TORSION_EXTERN void
ctr_drbg_generate(ctr_drbg_t *drbg,
                  void *out,
                  size_t len,
                  const unsigned char *add,
                  size_t add_len);

TORSION_EXTERN void
ctr_drbg_rng(void *out, size_t size, void *arg);

#ifdef __cplusplus
}
#endif

#endif /* _TORSION_DRBG_H */
