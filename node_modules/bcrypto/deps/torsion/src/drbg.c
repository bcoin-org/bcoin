/*!
 * drbg.c - drbg implementations for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 *
 * Resources:
 *   https://tools.ietf.org/html/rfc6979
 *   https://csrc.nist.gov/publications/detail/sp/800-90a/archive/2012-01-23
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <torsion/cipher.h>
#include <torsion/drbg.h>
#include <torsion/hash.h>
#include "bio.h"
#include "internal.h"

/*
 * HMAC-DRBG
 */

static void
hmac_drbg_update(hmac_drbg_t *drbg,
                 const unsigned char *seed,
                 size_t seed_len) {
  static const unsigned char zero[1] = {0x00};
  static const unsigned char one[1] = {0x01};

  hmac_init(&drbg->kmac, drbg->type, drbg->K, drbg->size);
  hmac_update(&drbg->kmac, drbg->V, drbg->size);
  hmac_update(&drbg->kmac, zero, 1);
  hmac_update(&drbg->kmac, seed, seed_len);
  hmac_final(&drbg->kmac, drbg->K);

  hmac_init(&drbg->kmac, drbg->type, drbg->K, drbg->size);
  hmac_update(&drbg->kmac, drbg->V, drbg->size);
  hmac_final(&drbg->kmac, drbg->V);

  if (seed_len > 0) {
    hmac_init(&drbg->kmac, drbg->type, drbg->K, drbg->size);
    hmac_update(&drbg->kmac, drbg->V, drbg->size);
    hmac_update(&drbg->kmac, one, 1);
    hmac_update(&drbg->kmac, seed, seed_len);
    hmac_final(&drbg->kmac, drbg->K);

    hmac_init(&drbg->kmac, drbg->type, drbg->K, drbg->size);
    hmac_update(&drbg->kmac, drbg->V, drbg->size);
    hmac_final(&drbg->kmac, drbg->V);
  }

  hmac_init(&drbg->kmac, drbg->type, drbg->K, drbg->size);
}

void
hmac_drbg_init(hmac_drbg_t *drbg,
               hash_id_t type,
               const unsigned char *seed,
               size_t seed_len) {
  size_t size = hash_output_size(type);

  CHECK(size != 0);

  drbg->type = type;
  drbg->size = size;

  memset(drbg->K, 0x00, drbg->size);
  memset(drbg->V, 0x01, drbg->size);

  /* Zero for struct assignment. */
  memset(&drbg->kmac, 0, sizeof(drbg->kmac));

  hmac_drbg_update(drbg, seed, seed_len);
}

void
hmac_drbg_reseed(hmac_drbg_t *drbg,
                 const unsigned char *seed,
                 size_t seed_len) {
  hmac_drbg_update(drbg, seed, seed_len);
}

void
hmac_drbg_generate(hmac_drbg_t *drbg, void *out, size_t len,
                   const unsigned char *add, size_t add_len) {
  unsigned char *raw = (unsigned char *)out;
  size_t size = drbg->size;
  hmac_t kmac;

  if (add_len > 0)
    hmac_drbg_update(drbg, add, add_len);

  while (len > 0) {
    kmac = drbg->kmac;
    hmac_update(&kmac, drbg->V, size);
    hmac_final(&kmac, drbg->V);

    if (size > len)
      size = len;

    memcpy(raw, drbg->V, size);

    raw += size;
    len -= size;
  }

  hmac_drbg_update(drbg, add, add_len);
}

void
hmac_drbg_rng(void *out, size_t size, void *arg) {
  hmac_drbg_generate((hmac_drbg_t *)arg, out, size, NULL, 0);
}

/*
 * Hash-DRBG
 */

void
hash_drbg_init(hash_drbg_t *drbg,
               hash_id_t type,
               const unsigned char *seed,
               size_t seed_len) {
  size_t size = hash_output_size(type);
  size_t length = size <= 32 ? 55 : 111;
  unsigned char output[165]; /* ceil(111 / 55) * 55 */
  unsigned char state[6];
  size_t i, blocks;

  CHECK(size != 0);

  drbg->type = type;
  drbg->size = size;
  drbg->length = length;

  state[0] = 0x01;
  state[1] = (length >> 21) & 0xff;
  state[2] = (length >> 13) & 0xff;
  state[3] = (length >> 5) & 0xff;
  state[4] = (length & 0x1f) << 3;
  state[5] = 0x00;

  blocks = (length + size - 1) / size;

  ASSERT(sizeof(output) >= blocks * size);

  for (i = 0; i < blocks; i++) {
    hash_init(&drbg->hash, drbg->type);
    hash_update(&drbg->hash, state, 5);
    hash_update(&drbg->hash, seed, seed_len);
    hash_final(&drbg->hash, output + i * size, size);

    state[0] += 1;
  }

  memcpy(drbg->V, output, length);

  state[0] = 0x01;
  state[5] = 0x00;

  for (i = 0; i < blocks; i++) {
    hash_init(&drbg->hash, drbg->type);
    hash_update(&drbg->hash, state, 6);
    hash_update(&drbg->hash, drbg->V, length);
    hash_final(&drbg->hash, output + i * size, size);

    state[0] += 1;
  }

  memcpy(drbg->C, output, length);

  drbg->rounds = 1;
}

void
hash_drbg_reseed(hash_drbg_t *drbg,
                 const unsigned char *seed,
                 size_t seed_len) {
  size_t size = drbg->size;
  size_t length = drbg->length;
  unsigned char output[165]; /* ceil(111 / 55) * 55 */
  unsigned char state[6];
  size_t i, blocks;

  state[0] = 0x01;
  state[1] = (length >> 21) & 0xff;
  state[2] = (length >> 13) & 0xff;
  state[3] = (length >> 5) & 0xff;
  state[4] = (length & 0x1f) << 3;
  state[5] = 0x01;

  blocks = (length + size - 1) / size;

  ASSERT(sizeof(output) >= blocks * size);

  for (i = 0; i < blocks; i++) {
    hash_init(&drbg->hash, drbg->type);
    hash_update(&drbg->hash, state, 6);
    hash_update(&drbg->hash, drbg->V, length);
    hash_update(&drbg->hash, seed, seed_len);
    hash_final(&drbg->hash, output + i * size, size);

    state[0] += 1;
  }

  memcpy(drbg->V, output, length);

  state[0] = 0x01;
  state[5] = 0x00;

  for (i = 0; i < blocks; i++) {
    hash_init(&drbg->hash, drbg->type);
    hash_update(&drbg->hash, state, 6);
    hash_update(&drbg->hash, drbg->V, length);
    hash_final(&drbg->hash, output + i * size, size);

    state[0] += 1;
  }

  memcpy(drbg->C, output, length);

  drbg->rounds = 1;
}

static void
accumulate(unsigned char *dst, size_t dlen,
           const unsigned char *src, size_t slen) {
  unsigned int c = 0;

  ASSERT(dlen >= slen);

  while (slen > 0) {
    c += (unsigned int)src[--slen] + dst[--dlen];
    dst[dlen] = c & 0xff;
    c >>= 8;
  }

  while (dlen > 0) {
    c += (unsigned int)dst[--dlen];
    dst[dlen] = c & 0xff;
    c >>= 8;
  }
}

static void
hash_drbg_update(hash_drbg_t *drbg) {
  static const unsigned char three[1] = {0x03};
  unsigned char H[HASH_MAX_OUTPUT_SIZE];
  unsigned char L[8];

  hash_init(&drbg->hash, drbg->type);
  hash_update(&drbg->hash, three, 1);
  hash_update(&drbg->hash, drbg->V, drbg->length);
  hash_final(&drbg->hash, H, drbg->size);

  write64be(L, drbg->rounds);

  /* V = V + H + C + L */
  accumulate(drbg->V, drbg->length, H, drbg->size);
  accumulate(drbg->V, drbg->length, drbg->C, drbg->length);
  accumulate(drbg->V, drbg->length, L, 8);
}

void
hash_drbg_generate(hash_drbg_t *drbg,
                   void *out,
                   size_t len,
                   const unsigned char *add,
                   size_t add_len) {
  static const unsigned char one[1] = {0x01};
  static const unsigned char two[1] = {0x02};
  unsigned char *raw = (unsigned char *)out;
  unsigned char H[HASH_MAX_OUTPUT_SIZE];
  unsigned char V[111];

  if (add_len > 0) {
    hash_init(&drbg->hash, drbg->type);
    hash_update(&drbg->hash, two, 1);
    hash_update(&drbg->hash, drbg->V, drbg->length);
    hash_update(&drbg->hash, add, add_len);
    hash_final(&drbg->hash, H, drbg->size);

    accumulate(drbg->V, drbg->length, H, drbg->size);
  }

  memcpy(V, drbg->V, drbg->length);

  while (len > 0) {
    hash_init(&drbg->hash, drbg->type);
    hash_update(&drbg->hash, V, drbg->length);

    if (len < drbg->size) {
      hash_final(&drbg->hash, H, drbg->size);

      memcpy(raw, H, len);

      break;
    }

    hash_final(&drbg->hash, raw, drbg->size);

    accumulate(V, drbg->length, one, 1);

    raw += drbg->size;
    len -= drbg->size;
  }

  hash_drbg_update(drbg);

  drbg->rounds += 1;
}

void
hash_drbg_rng(void *out, size_t size, void *arg) {
  hash_drbg_generate((hash_drbg_t *)arg, out, size, NULL, 0);
}

/*
 * CTR-DRBG
 */

#define MAX_KEY_SIZE 32
#define MAX_BLK_SIZE 16
#define MAX_ENT_SIZE (MAX_KEY_SIZE + MAX_BLK_SIZE)
#define MAX_NONCE_SIZE 512
#define MAX_SER_SIZE (MAX_NONCE_SIZE * 2 + MAX_BLK_SIZE * 2)

static void
ctr_drbg_rekey(ctr_drbg_t *drbg,
               const unsigned char *key,
               const unsigned char *iv) {
  aes_init_encrypt(&drbg->aes, drbg->key_size * 8, key);

  memcpy(drbg->state, iv, drbg->blk_size);
}

static void
ctr_drbg_encrypt(ctr_drbg_t *drbg, unsigned char *out) {
  increment_be(drbg->state, drbg->blk_size);
  aes_encrypt(&drbg->aes, out, drbg->state);
}

static void
ctr_drbg_update(ctr_drbg_t *drbg, const unsigned char *seed, size_t seed_len) {
  size_t i;

  if (seed_len > drbg->ent_size)
    seed_len = drbg->ent_size;

  for (i = 0; i < drbg->ent_size; i += drbg->blk_size)
    ctr_drbg_encrypt(drbg, drbg->KV + i);

  for (i = 0; i < seed_len; i++)
    drbg->KV[i] ^= seed[i];

  ctr_drbg_rekey(drbg, drbg->K, drbg->V);
}

static void
ctr_drbg_serialize(ctr_drbg_t *drbg,
                   unsigned char *out, size_t *blocks,
                   const unsigned char *nonce, size_t nonce_len,
                   const unsigned char *pers, size_t pers_len) {
  size_t N = drbg->ent_size;
  size_t L, size;

  if (nonce_len > MAX_NONCE_SIZE)
    nonce_len = MAX_NONCE_SIZE;

  if (pers_len > MAX_NONCE_SIZE)
    pers_len = MAX_NONCE_SIZE;

  L = nonce_len + pers_len;
  size = drbg->blk_size + 4 + 4 + L + 1;

  if (size % drbg->blk_size)
    size += drbg->blk_size - (size % drbg->blk_size);

  ASSERT(size <= MAX_SER_SIZE);
  ASSERT((size % drbg->blk_size) == 0);

  /* S = IV || (L || N || input || 0x80 || 0x00...) */
  memset(out, 0, size);
  out += drbg->blk_size;

  write32be(out, L);
  out += 4;

  write32be(out, N);
  out += 4;

  if (nonce_len > 0) {
    memcpy(out, nonce, nonce_len);
    out += nonce_len;
  }

  if (pers_len > 0) {
    memcpy(out, pers, pers_len);
    out += pers_len;
  }

  *out = 0x80;
  *blocks = size / drbg->blk_size;
}

static void
ctr_drbg_derive(ctr_drbg_t *drbg,
                unsigned char *out,
                const unsigned char *nonce,
                size_t nonce_len,
                const unsigned char *pers,
                size_t pers_len) {
  unsigned char tmp[MAX_ENT_SIZE + MAX_BLK_SIZE];
  unsigned char slab[MAX_ENT_SIZE + MAX_BLK_SIZE];
  unsigned char chain[MAX_BLK_SIZE];
  unsigned char K[MAX_KEY_SIZE];
  unsigned char S[MAX_SER_SIZE];
  unsigned char *x = slab + drbg->key_size;
  size_t bits = drbg->key_size * 8;
  size_t i, j, k, blocks, N;
  aes_t aes;

  ctr_drbg_serialize(drbg, S, &N, nonce, nonce_len, pers, pers_len);

  for (i = 0; i < drbg->key_size; i++)
    K[i] = i;

  aes_init_encrypt(&aes, bits, K);

  blocks = (drbg->ent_size + drbg->blk_size - 1) / drbg->blk_size;

  for (i = 0; i < blocks; i++) {
    memset(chain, 0, drbg->blk_size);

    write32be(S, i);

    /* chain = BCC(K, IV || S) */
    for (j = 0; j < N; j++) {
      for (k = 0; k < drbg->blk_size; k++)
        chain[k] ^= S[j * drbg->blk_size + k];

      aes_encrypt(&aes, chain, chain);
    }

    memcpy(slab + i * drbg->blk_size, chain, drbg->blk_size);
  }

  aes_init_encrypt(&aes, bits, slab);

  for (i = 0; i < blocks; i++) {
    aes_encrypt(&aes, x, x);

    memcpy(tmp + i * drbg->blk_size, x, drbg->blk_size);
  }

  memcpy(out, tmp, drbg->ent_size);
}

void
ctr_drbg_init(ctr_drbg_t *drbg,
              unsigned int bits,
              int derivation,
              const unsigned char *nonce,
              size_t nonce_len,
              const unsigned char *pers,
              size_t pers_len) {
  unsigned char entropy[MAX_ENT_SIZE];
  size_t i;

  CHECK(bits == 128 || bits == 192 || bits == 256);

  drbg->key_size = bits / 8;
  drbg->blk_size = 16;
  drbg->ent_size = drbg->key_size + drbg->blk_size;
  drbg->derivation = derivation;
  drbg->K = &drbg->KV[0];
  drbg->V = &drbg->KV[drbg->key_size];

  if (drbg->derivation) {
    ctr_drbg_derive(drbg, entropy, nonce, nonce_len, pers, pers_len);
  } else {
    memset(entropy, 0, drbg->ent_size);

    if (nonce_len > drbg->ent_size)
      nonce_len = drbg->ent_size;

    if (pers_len > drbg->ent_size)
      pers_len = drbg->ent_size;

    if (nonce_len > 0)
      memcpy(entropy, nonce, nonce_len);

    for (i = 0; i < pers_len; i++)
      entropy[i] ^= pers[i];
  }

  memset(drbg->KV, 0, drbg->ent_size);

  ctr_drbg_rekey(drbg, drbg->K, drbg->V);
  ctr_drbg_update(drbg, entropy, drbg->ent_size);
}

void
ctr_drbg_reseed(ctr_drbg_t *drbg,
                const unsigned char *nonce,
                size_t nonce_len,
                const unsigned char *add,
                size_t add_len) {
  unsigned char entropy[MAX_ENT_SIZE];
  size_t i;

  if (drbg->derivation) {
    ctr_drbg_derive(drbg, entropy, nonce, nonce_len, add, add_len);
  } else {
    memset(entropy, 0, drbg->ent_size);

    if (nonce_len > drbg->ent_size)
      nonce_len = drbg->ent_size;

    if (add_len > drbg->ent_size)
      add_len = drbg->ent_size;

    if (nonce_len > 0)
      memcpy(entropy, nonce, nonce_len);

    for (i = 0; i < add_len; i++)
      entropy[i] ^= add[i];
  }

  ctr_drbg_update(drbg, entropy, drbg->ent_size);
}

void
ctr_drbg_generate(ctr_drbg_t *drbg,
                  void *out,
                  size_t len,
                  const unsigned char *add,
                  size_t add_len) {
  unsigned char *raw = (unsigned char *)out;
  unsigned char tmp[MAX_ENT_SIZE];

  if (add_len > 0) {
    if (drbg->derivation) {
      ctr_drbg_derive(drbg, tmp, add, add_len, NULL, 0);
      ctr_drbg_update(drbg, tmp, drbg->ent_size);

      add_len = drbg->ent_size;
      add = tmp;
    } else {
      ctr_drbg_update(drbg, add, add_len);
    }
  }

  while (len > 0) {
    if (len < drbg->blk_size) {
      unsigned char block[MAX_BLK_SIZE];

      ctr_drbg_encrypt(drbg, block);

      memcpy(raw, block, len);

      break;
    }

    ctr_drbg_encrypt(drbg, raw);

    raw += drbg->blk_size;
    len -= drbg->blk_size;
  }

  ctr_drbg_update(drbg, add, add_len);
}

void
ctr_drbg_rng(void *out, size_t size, void *arg) {
  ctr_drbg_generate((ctr_drbg_t *)arg, out, size, NULL, 0);
}
