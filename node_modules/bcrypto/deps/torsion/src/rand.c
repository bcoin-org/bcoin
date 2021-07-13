/*!
 * rand.c - RNG for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 */

/**
 * Random Number Generation
 *
 * We use a ChaCha20 RNG with a design inspired by
 * libsodium[1]. Our primary difference is a much
 * more complicated seeding procedure which ensures
 * strong randomness (similar to Bitcoin Core[2]).
 *
 * The seeding procedure uses a combination of OS
 * entropy, hardware entropy, and entropy manually
 * gathered from the environment. See entropy/ for
 * more information.
 *
 * We expose a global fork-aware and thread-safe
 * RNG. We use thread local storage for the global
 * context. This avoids us having to link to
 * pthread and deal with other OS compat issues.
 *
 * If TLS is not supported, we try to fall back
 * to pthread.
 *
 * The RNG below is not used anywhere internally,
 * and as such, libtorsion can build without it (in
 * the case that more portability is desired).
 *
 * [1] https://github.com/jedisct1/libsodium/blob/master/src/libsodium
 *     /randombytes/internal/randombytes_internal_random.c
 * [2] https://github.com/bitcoin/bitcoin/blob/master/src/random.cpp
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <torsion/hash.h>
#include <torsion/rand.h>
#include <torsion/stream.h>
#include <torsion/util.h>
#include "entropy/entropy.h"
#include "internal.h"
#include "tls.h"

/*
 * Helpers
 */

static void
sha512_update_ptr(sha512_t *hash, const void *ptr) {
#if defined(UINTPTR_MAX)
  uintptr_t uptr = (uintptr_t)ptr;
#else
  size_t uptr = (size_t)ptr;
#endif

  sha512_update(hash, &uptr, sizeof(uptr));
}

static void
sha512_update_tsc(sha512_t *hash) {
  uint64_t tsc = torsion_rdtsc();

  sha512_update(hash, &tsc, sizeof(tsc));
}

/*
 * RNG
 */

typedef struct rng_s {
  uint64_t key[4];
  uint64_t zero;
  uint64_t nonce;
  uint32_t pool[16];
  size_t pos;
  int rdrand;
} rng_t;

static int
rng_init(rng_t *rng) {
  unsigned char seed[64];
  sha512_t hash;

  memset(rng, 0, sizeof(*rng));

  sha512_init(&hash);
  sha512_update_ptr(&hash, rng);
  sha512_update_ptr(&hash, seed);
  sha512_update_tsc(&hash);

  /* OS entropy (64 bytes). */
  if (!torsion_sysrand(seed, 64))
    return 0;

  sha512_update(&hash, seed, 64);
  sha512_update_tsc(&hash);

  /* Hardware entropy (32 bytes). */
  if (torsion_hwrand(seed, 32)) {
    sha512_update(&hash, seed, 32);
    sha512_update_tsc(&hash);
  }

  /* Manual entropy (64 bytes). */
  if (torsion_envrand(seed)) {
    sha512_update(&hash, seed, 64);
    sha512_update_tsc(&hash);
  }

  /* At this point, only one of the above
     entropy sources needs to be strong in
     order for our RNG to work. It's extremely
     unlikely that all three would somehow
     be compromised. */
  sha512_final(&hash, seed);

  /* We use XChaCha20 to reduce the first
     48 bytes down to 32. This allows us to
     use the entire 64 byte hash as entropy. */
  chacha20_derive(seed, seed, 32, seed + 32);

  /* Read our initial ChaCha20 state. `zero`
     becomes our random "zero value" for the
     initial counter. */
  memcpy(rng->key, seed, 32);
  memcpy(&rng->zero, seed + 48, 8);
  memcpy(&rng->nonce, seed + 56, 8);

  /* Cache the rdrand check. */
  rng->rdrand = torsion_has_rdrand();

  torsion_cleanse(seed, sizeof(seed));
  torsion_cleanse(&hash, sizeof(hash));

  return 1;
}

static void
rng_generate(rng_t *rng, void *dst, size_t size) {
  unsigned char *key = (unsigned char *)rng->key;
  unsigned char *nonce = (unsigned char *)&rng->nonce;
  chacha20_t ctx;

  if (size > 0)
    memset(dst, 0, size);

  /* Read the keystream. */
  chacha20_init(&ctx, key, 32, nonce, 8, rng->zero);
  chacha20_crypt(&ctx, dst, dst, size);

  /* Mix in some user entropy. */
  rng->key[0] ^= size;

  /* Mix in some hardware entropy. We sacrifice
     only 32 bits here, lest RDRAND is backdoored.
     See: https://pastebin.com/A07q3nL3 */
  if (rng->rdrand)
    rng->key[3] ^= (uint32_t)torsion_rdrand();

  /* Re-key immediately. */
  rng->nonce++;

  /* At this point, the CTR-DRBG simply reads the
     keystream again in order to rekey. We mimic
     libsodium instead by XOR'ing the partially
     modified key with its own keystream. In truth,
     there's probably not really a difference in
     terms of security, as the outputs in both
     scenarios are dependent on the key. */
  chacha20_init(&ctx, key, 32, nonce, 8, rng->zero);
  chacha20_crypt(&ctx, key, key, 32);

  /* Cleanse the chacha state. */
  torsion_cleanse(&ctx, sizeof(ctx));
}

static uint32_t
rng_random(rng_t *rng) {
  if ((rng->pos & 15) == 0) {
    rng_generate(rng, rng->pool, 64);
    rng->pos = 0;
  }

  return rng->pool[rng->pos++];
}

static uint32_t
rng_uniform(rng_t *rng, uint32_t max) {
  /* See: http://www.pcg-random.org/posts/bounded-rands.html */
  uint32_t x, r;

  if (max <= 1)
    return 0;

  do {
    x = rng_random(rng);
    r = x % max;
  } while (x - r > (-max));

  return r;
}

/*
 * Global Lock
 */

#if !defined(TORSION_HAVE_TLS) && defined(TORSION_HAVE_PTHREAD)
#  define TORSION_USE_LOCK
#endif

#ifdef TORSION_USE_LOCK
#  include <pthread.h>
static pthread_mutex_t rng_lock = PTHREAD_MUTEX_INITIALIZER;
#endif

static void
rng_global_lock(void) {
#ifdef TORSION_USE_LOCK
  if (pthread_mutex_lock(&rng_lock) != 0)
    torsion_abort();
#endif
}

static void
rng_global_unlock(void) {
#ifdef TORSION_USE_LOCK
  if (pthread_mutex_unlock(&rng_lock) != 0)
    torsion_abort();
#endif
}

/*
 * Global Context
 */

static TORSION_TLS struct {
  rng_t rng;
  int started;
  uint64_t pid;
} rng_state;

static int
rng_global_init(void) {
  uint64_t pid = torsion_getpid();

  if (!rng_state.started || rng_state.pid != pid) {
    if (!rng_init(&rng_state.rng))
      return 0;

    rng_state.started = 1;
    rng_state.pid = pid;
  }

  return 1;
}

/*
 * Random
 */

int
torsion_getentropy(void *dst, size_t size) {
  return torsion_sysrand(dst, size);
}

int
torsion_getrandom(void *dst, size_t size) {
  rng_global_lock();

  if (!rng_global_init()) {
    rng_global_unlock();
    return 0;
  }

  rng_generate(&rng_state.rng, dst, size);
  rng_global_unlock();

  return 1;
}

int
torsion_random(uint32_t *num) {
  rng_global_lock();

  if (!rng_global_init()) {
    rng_global_unlock();
    return 0;
  }

  *num = rng_random(&rng_state.rng);

  rng_global_unlock();

  return 1;
}

int
torsion_uniform(uint32_t *num, uint32_t max) {
  rng_global_lock();

  if (!rng_global_init()) {
    rng_global_unlock();
    return 0;
  }

  *num = rng_uniform(&rng_state.rng, max);

  rng_global_unlock();

  return 1;
}

/*
 * Testing
 */

int
torsion_threadsafety(void) {
#if defined(TORSION_HAVE_TLS)
  return TORSION_THREAD_SAFETY_TLS;
#elif defined(TORSION_HAVE_PTHREAD)
  return TORSION_THREAD_SAFETY_MUTEX;
#else
  return TORSION_THREAD_SAFETY_NONE;
#endif
}

uint64_t
torsion_randomaddr(void) {
  void *ptr = (void *)&rng_state;
#if defined(UINTPTR_MAX)
  return (uintptr_t)ptr;
#else
  return (size_t)ptr;
#endif
}
