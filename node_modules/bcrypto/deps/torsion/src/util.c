/*!
 * util.c - utils for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#ifdef _WIN32
#  include <windows.h> /* SecureZeroMemory */
#endif
#include <torsion/util.h>
#include "bio.h"
#include "internal.h"

/*
 * Memzero
 *
 * Resources:
 *   https://github.com/jedisct1/libsodium/blob/3b26a5c/src/libsodium/sodium/utils.c#L112
 *   https://github.com/torvalds/linux/blob/37d4e84/include/linux/string.h#L233
 *   https://github.com/torvalds/linux/blob/37d4e84/include/linux/compiler-gcc.h#L21
 *   https://github.com/bminor/glibc/blob/master/string/explicit_bzero.c
 *   http://www.daemonology.net/blog/2014-09-04-how-to-zero-a-buffer.html
 */

void
torsion_cleanse(void *ptr, size_t len) {
#if defined(_WIN32) && defined(SecureZeroMemory)
  if (len > 0)
    SecureZeroMemory(ptr, len);
#elif defined(TORSION_HAVE_ASM)
  if (len > 0) {
    memset(ptr, 0, len);
    __asm__ __volatile__ ("" :: "r" (ptr) : "memory");
  }
#else
  static void *(*const volatile memset_ptr)(void *, int, size_t) = memset;
  if (len > 0)
    memset_ptr(ptr, 0, len);
#endif
}

/*
 * Memequal
 */

int
torsion_memequal(const void *s1, const void *s2, size_t n) {
  const unsigned char *x = s1;
  const unsigned char *y = s2;
  uint32_t z = 0;

  while (n--)
    z |= (uint32_t)x[n] ^ (uint32_t)y[n];

  return (z - 1) >> 31;
}

/*
 * Murmur3
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/MurmurHash
 *   https://github.com/aappleby/smhasher
 */

uint32_t
murmur3_sum(const unsigned char *data, size_t len, uint32_t seed) {
  uint32_t h1 = seed;
  uint32_t c1 = UINT32_C(0xcc9e2d51);
  uint32_t c2 = UINT32_C(0x1b873593);
  uint32_t k1 = 0;
  size_t left = len;

#define ROTL32(x, y) ((x) << (y)) | ((x) >> (32 - (y)))

  while (left >= 4) {
    k1 = read32le(data);

    k1 *= c1;
    k1 = ROTL32(k1, 15);
    k1 *= c2;

    h1 ^= k1;
    h1 = ROTL32(h1, 13);
    h1 = h1 * 5 + UINT32_C(0xe6546b64);

    data += 4;
    left -= 4;
  }

  k1 = 0;

  switch (left) {
    case 3:
      k1 ^= (uint32_t)data[2] << 16;
    case 2:
      k1 ^= (uint32_t)data[1] << 8;
    case 1:
      k1 ^= (uint32_t)data[0] << 0;
      k1 *= c1;
      k1 = ROTL32(k1, 15);
      k1 *= c2;
      h1 ^= k1;
  }

#undef ROTL32

  h1 ^= len;
  h1 ^= h1 >> 16;
  h1 *= UINT32_C(0x85ebca6b);
  h1 ^= h1 >> 13;
  h1 *= UINT32_C(0xc2b2ae35);
  h1 ^= h1 >> 16;

  return h1;
}

uint32_t
murmur3_tweak(const unsigned char *data,
              size_t len, uint32_t n, uint32_t tweak) {
  uint32_t seed = (n * UINT32_C(0xfba4c795)) + tweak;
  return murmur3_sum(data, len, seed);
}
