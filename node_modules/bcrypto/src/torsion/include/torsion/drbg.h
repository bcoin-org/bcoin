#ifndef _TORSION_DRBG_H
#define _TORSION_DRBG_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include "hash.h"

/*
 * Symbol Aliases
 */

#define drbg_init torsion_drbg_init
#define drbg_reseed torsion_drbg_reseed
#define drbg_generate torsion_drbg_generate

/*
 * Structs
 */

typedef struct _drbg_s {
  int type;
  hmac_t kmac;
  unsigned char K[HASH_MAX_OUTPUT_SIZE];
  unsigned char V[HASH_MAX_OUTPUT_SIZE];
} drbg_t;

/*
 * DRBG
 */

void
drbg_init(drbg_t *drbg, int type, const unsigned char *seed, size_t seed_len);

void
drbg_reseed(drbg_t *drbg, const unsigned char *seed, size_t seed_len);

void
drbg_generate(drbg_t *drbg, void *out, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* _TORSION_DRBG_H */
