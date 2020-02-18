#ifndef _BCRYPTO_SIPHASH_H
#define _BCRYPTO_SIPHASH_H

#include <stdint.h>
#include <stdlib.h>

#if defined(__cplusplus)
extern "C" {
#endif

uint64_t
bcrypto_siphash(const uint8_t *data, size_t len, const uint8_t *key);

uint32_t
bcrypto_siphash32(uint32_t num, const uint8_t *key);

uint64_t
bcrypto_siphash64(uint64_t num, const uint8_t *key);

uint32_t
bcrypto_siphash32k256(uint32_t num, const uint8_t *key);

uint64_t
bcrypto_siphash64k256(uint64_t num, const uint8_t *key);

uint64_t
bcrypto_sipmod(
  const uint8_t *data,
  size_t len,
  const uint8_t *key,
  uint64_t m
);

#if defined(__cplusplus)
}
#endif

#endif
