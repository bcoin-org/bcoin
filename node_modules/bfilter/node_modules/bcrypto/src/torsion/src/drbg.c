/*!
 * drbg.c - hmac-drbg implementation for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 *
 * Parts of this software are based on indutny/hmac-drbg:
 *   Copyright Fedor Indutny, 2017.
 *   https://github.com/indutny/hmac-drbg
 *
 * Resources:
 *   https://tools.ietf.org/html/rfc6979
 *   https://csrc.nist.gov/publications/detail/sp/800-90a/archive/2012-01-23
 *   https://github.com/indutny/hmac-drbg/blob/master/lib/hmac-drbg.js
 */

#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <torsion/hash.h>
#include <torsion/drbg.h>

/*
 * Constants
 */

static const unsigned char ZERO[1] = {0x00};
static const unsigned char ONE[1] = {0x01};

/*
 * DRBG
 */

static void
drbg_update(drbg_t *drbg, const unsigned char *seed, size_t seed_len) {
  size_t hash_size = hash_output_size(drbg->type);

  hmac_init(&drbg->kmac, drbg->type, drbg->K, hash_size);
  hmac_update(&drbg->kmac, drbg->V, hash_size);
  hmac_update(&drbg->kmac, ZERO, 1);

  if (seed_len != 0)
    hmac_update(&drbg->kmac, seed, seed_len);

  hmac_final(&drbg->kmac, drbg->K);

  hmac_init(&drbg->kmac, drbg->type, drbg->K, hash_size);
  hmac_update(&drbg->kmac, drbg->V, hash_size);
  hmac_final(&drbg->kmac, drbg->V);

  if (seed_len != 0) {
    hmac_init(&drbg->kmac, drbg->type, drbg->K, hash_size);
    hmac_update(&drbg->kmac, drbg->V, hash_size);
    hmac_update(&drbg->kmac, ONE, 1);
    hmac_update(&drbg->kmac, seed, seed_len);
    hmac_final(&drbg->kmac, drbg->K);

    hmac_init(&drbg->kmac, drbg->type, drbg->K, hash_size);
    hmac_update(&drbg->kmac, drbg->V, hash_size);
    hmac_final(&drbg->kmac, drbg->V);
  }
}

void
drbg_init(drbg_t *drbg, int type, const unsigned char *seed, size_t seed_len) {
  size_t hash_size = hash_output_size(type);

  assert(seed != NULL);
  assert(seed_len >= 24);

  drbg->type = type;

  memset(drbg->K, 0x00, hash_size);
  memset(drbg->V, 0x01, hash_size);

  drbg_update(drbg, seed, seed_len);
}

void
drbg_reseed(drbg_t *drbg, const unsigned char *seed, size_t seed_len) {
  assert(seed != NULL);
  assert(seed_len >= 24);

  drbg_update(drbg, seed, seed_len);
}

void
drbg_generate(drbg_t *drbg, void *out, size_t len) {
  size_t hash_size = hash_output_size(drbg->type);
  unsigned char *bytes = (unsigned char *)out;
  size_t pos = 0;
  size_t left = len;
  size_t outlen = hash_size;

  while (pos < len) {
    hmac_init(&drbg->kmac, drbg->type, drbg->K, hash_size);
    hmac_update(&drbg->kmac, drbg->V, hash_size);
    hmac_final(&drbg->kmac, drbg->V);

    if (outlen > left)
      outlen = left;

    memcpy(bytes + pos, drbg->V, outlen);

    pos += outlen;
    left -= outlen;
  }

  assert(pos == len);
  assert(left == 0);

  drbg_update(drbg, NULL, 0);
}
