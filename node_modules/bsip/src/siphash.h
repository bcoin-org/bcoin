#ifndef _BSIP_SIPHASH_H
#define _BSIP_SIPHASH_H

#include <stdint.h>
#include <stdlib.h>

uint64_t
bsip_siphash(const uint8_t *data, size_t len, const uint8_t *key);

uint32_t
bsip_siphash32(uint32_t num, const uint8_t *key);

uint64_t
bsip_siphash64(uint64_t num, const uint8_t *key);

uint32_t
bsip_siphash32k256(uint32_t num, const uint8_t *key);

uint64_t
bsip_siphash64k256(uint64_t num, const uint8_t *key);

uint64_t
bsip_sipmod(
  const uint8_t *data,
  size_t len,
  const uint8_t *key,
  uint64_t m
);

#endif
