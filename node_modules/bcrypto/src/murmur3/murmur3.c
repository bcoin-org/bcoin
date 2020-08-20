#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "murmur3.h"

static uint32_t
read32(const void *src) {
#ifndef WORDS_BIGENDIAN
  uint32_t w;
  memcpy(&w, src, sizeof(w));
  return w;
#else
  const uint8_t *p = (const uint8_t *)src;
  return ((uint32_t)p[0] << 0)
       | ((uint32_t)p[1] << 8)
       | ((uint32_t)p[2] << 16)
       | ((uint32_t)p[3] << 24);
#endif
}

static uint32_t
rotl32(uint32_t x, int8_t r) {
  return (x << r) | (x >> (32 - r));
}

uint32_t
murmur3_sum(const uint8_t *data, size_t len, uint32_t seed) {
  uint32_t h1 = seed;
  uint32_t c1 = 0xcc9e2d51;
  uint32_t c2 = 0x1b873593;
  size_t blocks = len / 4;
  const uint8_t *tail = data + blocks * 4;
  uint32_t k1 = 0;
  size_t i;

  for (i = 0; i < blocks; i++) {
    k1 = read32(data + i * 4);

    k1 *= c1;
    k1 = rotl32(k1, 15);
    k1 *= c2;

    h1 ^= k1;
    h1 = rotl32(h1, 13);
    h1 = h1 * 5 + 0xe6546b64;
  }

  k1 = 0;

  switch (len & 3) {
    case 3:
      k1 ^= tail[2] << 16;
    case 2:
      k1 ^= tail[1] << 8;
    case 1:
      k1 ^= tail[0];
      k1 *= c1;
      k1 = rotl32(k1, 15);
      k1 *= c2;
      h1 ^= k1;
  }

  h1 ^= len;
  h1 ^= h1 >> 16;
  h1 *= 0x85ebca6b;
  h1 ^= h1 >> 13;
  h1 *= 0xc2b2ae35;
  h1 ^= h1 >> 16;

  return h1;
}

uint32_t
murmur3_tweak(const uint8_t *data, size_t len, uint32_t n, uint32_t tweak) {
  uint32_t seed = (n * 0xfba4c795ul) + tweak;
  return murmur3_sum(data, len, seed);
}
