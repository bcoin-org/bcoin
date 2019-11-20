#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "murmur3.h"

static inline uint32_t
read32(const void *src) {
#if defined(MRMR_LITTLE_ENDIAN)
  uint32_t w;
  memcpy(&w, src, sizeof w);
  return w;
#else
  const uint8_t *p = (const uint8_t *)src;
  return ((uint32_t)(p[0]) << 0)
    | ((uint32_t)(p[1]) << 8)
    | ((uint32_t)(p[2]) << 16)
    | ((uint32_t)(p[3]) << 24);
#endif
}

static inline uint32_t
rotl32(uint32_t x, int8_t r) {
  return (x << r) | (x >> (32 - r));
}

uint32_t
mrmr_murmur3_sum(const uint8_t *data, size_t len, uint32_t seed) {
  uint32_t h1 = seed;

  if (len > 0) {
    const uint32_t c1 = 0xcc9e2d51;
    const uint32_t c2 = 0x1b873593;

    const int32_t nblocks = len / 4;

    const uint8_t *blocks = &data[0] + nblocks * 4;

    for (int32_t i = -nblocks; i; i++) {
      uint32_t k1 = read32(blocks + i * 4);

      k1 *= c1;
      k1 = rotl32(k1, 15);
      k1 *= c2;

      h1 ^= k1;
      h1 = rotl32(h1, 13);
      h1 = h1 * 5 + 0xe6546b64;
    }

    const uint8_t *tail = (const uint8_t *)(&data[0] + nblocks * 4);

    uint32_t k1 = 0;

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
mrmr_murmur3_tweak(
  const uint8_t *data,
  size_t len,
  uint32_t n,
  uint32_t tweak
) {
  uint32_t seed = (n * 0xfba4c795ul) + tweak;
  return mrmr_murmur3_sum(data, len, seed);
}
