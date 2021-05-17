/*!
 * siphash.c - siphash for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 *
 * Parts of this software are based on bitcoin/bitcoin:
 *   Copyright (c) 2009-2019, The Bitcoin Core Developers (MIT License).
 *   Copyright (c) 2009-2019, The Bitcoin Developers (MIT License).
 *   https://github.com/bitcoin/bitcoin
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/SipHash
 *   https://131002.net/siphash/
 *   https://131002.net/siphash/siphash.pdf
 *   https://github.com/bitcoin/bitcoin/blob/master/src/crypto/siphash.cpp
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <torsion/siphash.h>

#ifdef TORSION_USE_64BIT
#ifdef _MSC_VER
#include <intrin.h>
#else
#ifdef __SIZEOF_INT128___
#ifdef __GNUC__
__extension__ typedef unsigned __int128 uint128_t;
#else
typedef unsigned __int128 uint128_t;
#endif
#else /* __SIZEOF_INT128__ */
typedef unsigned uint128_t __attribute__((mode(TI)));
#endif
#endif
#endif

#define ROTL64(x, b) (uint64_t)(((x) << (b)) | ((x) >> (64 - (b))))

#define SIPROUND do {                      \
  v0 += v1; v1 = ROTL64(v1, 13); v1 ^= v0; \
  v0 = ROTL64(v0, 32);                     \
  v2 += v3; v3 = ROTL64(v3, 16); v3 ^= v2; \
  v0 += v3; v3 = ROTL64(v3, 21); v3 ^= v0; \
  v2 += v1; v1 = ROTL64(v1, 17); v1 ^= v2; \
  v2 = ROTL64(v2, 32);                     \
} while (0)

static uint64_t
read64le(const void *src) {
#ifndef WORDS_BIGENDIAN
  uint64_t w;
  memcpy(&w, src, sizeof w);
  return w;
#else
  const uint8_t *p = (const uint8_t *)src;
  return ((uint64_t)p[0] << 0)
       | ((uint64_t)p[1] << 8)
       | ((uint64_t)p[2] << 16)
       | ((uint64_t)p[3] << 24)
       | ((uint64_t)p[4] << 32)
       | ((uint64_t)p[5] << 40)
       | ((uint64_t)p[6] << 48)
       | ((uint64_t)p[7] << 56);
#endif
}

static uint64_t
reduce64(uint64_t a, uint64_t b) {
#ifdef TORSION_USE_64BIT
#ifdef _MSC_VER
  return __umulh(a, b);
#else
  return ((uint128_t)a * b) >> 64;
#endif
#else /* TORSION_USE_64BIT */
  /* https://stackoverflow.com/questions/28868367 */
  uint64_t ahi = a >> 32;
  uint64_t alo = a & 0xffffffff;
  uint64_t bhi = b >> 32;
  uint64_t blo = b & 0xffffffff;
  uint64_t axbhi = ahi * bhi;
  uint64_t axbmid = ahi * blo;
  uint64_t bxamid = bhi * alo;
  uint64_t axblo = alo * blo;
  uint64_t c = (axbmid & 0xffffffff) + (bxamid & 0xffffffff) + (axblo >> 32);

  return axbhi + (axbmid >> 32) + (bxamid >> 32) + (c >> 32);
#endif
}

static uint64_t
_siphash(const unsigned char *data, size_t len, const unsigned char *key) {
  uint64_t c0 = 0x736f6d6570736575ull;
  uint64_t c1 = 0x646f72616e646f6dull;
  uint64_t c2 = 0x6c7967656e657261ull;
  uint64_t c3 = 0x7465646279746573ull;
  uint64_t f0 = (uint64_t)len << 56;
  uint64_t f1 = 0xff;
  uint64_t k0 = read64le(key);
  uint64_t k1 = read64le(key + 8);
  uint64_t v0 = k0 ^ c0;
  uint64_t v1 = k1 ^ c1;
  uint64_t v2 = k0 ^ c2;
  uint64_t v3 = k1 ^ c3;
  size_t blocks = len >> 3;
  size_t i;

  for (i = 0; i < blocks; i++, data += 8) {
    uint64_t word = read64le(data);

    v3 ^= word;
    SIPROUND;
    SIPROUND;
    v0 ^= word;
  }

  switch (len & 7) {
    case 7:
      f0 |= (uint64_t)data[6] << 48;
    case 6:
      f0 |= (uint64_t)data[5] << 40;
    case 5:
      f0 |= (uint64_t)data[4] << 32;
    case 4:
      f0 |= (uint64_t)data[3] << 24;
    case 3:
      f0 |= (uint64_t)data[2] << 16;
    case 2:
      f0 |= (uint64_t)data[1] << 8;
    case 1:
      f0 |= (uint64_t)data[0];
  }

  v3 ^= f0;
  SIPROUND;
  SIPROUND;
  v0 ^= f0;
  v2 ^= f1;
  SIPROUND;
  SIPROUND;
  SIPROUND;
  SIPROUND;
  v0 ^= v1;
  v0 ^= v2;
  v0 ^= v3;

  return v0;
}

static uint64_t
_siphash64(uint64_t num, const unsigned char *key) {
  uint64_t c0 = 0x736f6d6570736575ull;
  uint64_t c1 = 0x646f72616e646f6dull;
  uint64_t c2 = 0x6c7967656e657261ull;
  uint64_t c3 = 0x7465646279746573ull;
  uint64_t f0 = num;
  uint64_t f1 = 0xff;
  uint64_t k0 = read64le(key);
  uint64_t k1 = read64le(key + 8);
  uint64_t v0 = k0 ^ c0;
  uint64_t v1 = k1 ^ c1;
  uint64_t v2 = k0 ^ c2;
  uint64_t v3 = k1 ^ c3;

  v3 ^= f0;
  SIPROUND;
  SIPROUND;
  v0 ^= f0;
  v2 ^= f1;
  SIPROUND;
  SIPROUND;
  SIPROUND;
  SIPROUND;
  v0 ^= v1;
  v0 ^= v2;
  v0 ^= v3;

  return v0;
}

static uint64_t
_siphash64k256(uint64_t num, const unsigned char *key) {
  uint64_t f0 = num;
  uint64_t f1 = 0xff;
  uint64_t k0 = read64le(key);
  uint64_t k1 = read64le(key + 8);
  uint64_t k2 = read64le(key + 16);
  uint64_t k3 = read64le(key + 24);
  uint64_t v0 = k0;
  uint64_t v1 = k1;
  uint64_t v2 = k2;
  uint64_t v3 = k3;

  v3 ^= f0;
  SIPROUND;
  SIPROUND;
  v0 ^= f0;
  v2 ^= f1;
  SIPROUND;
  SIPROUND;
  SIPROUND;
  SIPROUND;
  v0 ^= v1;
  v0 ^= v2;
  v0 ^= v3;

  return v0;
}

uint64_t
siphash(const unsigned char *data, size_t len, const unsigned char *key) {
  return _siphash(data, len, key);
}

uint32_t
siphash32(uint32_t num, const unsigned char *key) {
  return _siphash64(num, key);
}

uint64_t
siphash64(uint64_t num, const unsigned char *key) {
  return _siphash64(num, key);
}

uint32_t
siphash32k256(uint32_t num, const unsigned char *key) {
  return _siphash64k256(num, key);
}

uint64_t
siphash64k256(uint64_t num, const unsigned char *key) {
  return _siphash64k256(num, key);
}

uint64_t
sipmod(const unsigned char *data,
       size_t len,
       const unsigned char *key,
       uint64_t m) {
  uint64_t h = _siphash(data, len, key);
  return reduce64(h, m);
}
