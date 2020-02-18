/* sha3.c - an implementation of Secure Hash Algorithm 3 (Keccak).
 * based on the
 * The Keccak SHA-3 submission. Submission to NIST (Round 3), 2011
 * by Guido Bertoni, Joan Daemen, Michaël Peeters and Gilles Van Assche
 *
 * Copyright: 2013 Aleksey Kravchenko <rhash.admin@gmail.com>
 *
 * Permission is hereby granted,  free of charge,  to any person  obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction,  including without limitation
 * the rights to  use, copy, modify,  merge, publish, distribute, sublicense,
 * and/or sell copies  of  the Software,  and to permit  persons  to whom the
 * Software is furnished to do so.
 *
 * This program  is  distributed  in  the  hope  that it will be useful,  but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  Use this program  at  your own risk!
 */

#ifndef _BCRYPTO_KECCAK_H
#define _BCRYPTO_KECCAK_H

#ifdef __cplusplus
extern "C" {
#endif

#define bcrypto_keccak_224_hash_size 28
#define bcrypto_keccak_256_hash_size 32
#define bcrypto_keccak_384_hash_size 48
#define bcrypto_keccak_512_hash_size 64
#define bcrypto_keccak_max_permutation_size 25
#define bcrypto_keccak_max_rate_in_qwords 24

typedef struct bcrypto_keccak_ctx {
  uint64_t hash[bcrypto_keccak_max_permutation_size];
  uint64_t message[bcrypto_keccak_max_rate_in_qwords];
  unsigned rest;
  unsigned block_size;
} bcrypto_keccak_ctx;

int
bcrypto_keccak_init(bcrypto_keccak_ctx *ctx, unsigned bits);

void
bcrypto_keccak_224_init(bcrypto_keccak_ctx *ctx);

void
bcrypto_keccak_256_init(bcrypto_keccak_ctx *ctx);

void
bcrypto_keccak_384_init(bcrypto_keccak_ctx *ctx);

void
bcrypto_keccak_512_init(bcrypto_keccak_ctx *ctx);

void
bcrypto_keccak_update(
  bcrypto_keccak_ctx *ctx,
  const unsigned char *msg,
  size_t size
);

int
bcrypto_keccak_final(
  bcrypto_keccak_ctx *ctx,
  int pad,
  unsigned char *result,
  size_t digest_length,
  size_t *result_length
);

#ifdef __cplusplus
}
#endif

#endif
