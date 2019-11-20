#ifndef _BSTRING_BASE58_H
#define _BSTRING_BASE58_H

#include <stdlib.h>

bool
bstring_base58_encode(
  const uint8_t *data,
  size_t datalen,
  uint8_t **str,
  size_t *strlen
);

bool
bstring_base58_decode(
  const uint8_t *str,
  size_t strlen,
  uint8_t **data,
  size_t *datalen
);

bool
bstring_base58_test(const uint8_t *str, size_t strlen);

#endif
