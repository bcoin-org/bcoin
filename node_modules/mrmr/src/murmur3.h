#ifndef _MRMR_MURMUR_H
#define _MRMR_MURMUR_H

#include <stdint.h>
#include <stdlib.h>

uint32_t
mrmr_murmur3_sum(const uint8_t *data, size_t len, uint32_t seed);

uint32_t
mrmr_murmur3_tweak(
  const uint8_t *data,
  size_t len,
  uint32_t n,
  uint32_t tweak
);

#endif
