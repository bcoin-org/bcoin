#ifndef _BCRYPTO_PBKDF2_H
#define _BCRYPTO_PBKDF2_H

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#if defined(__cplusplus)
extern "C" {
#endif

bool
bcrypto_pbkdf2(
  const char *name,
  const uint8_t *data,
  size_t datalen,
  const uint8_t *salt,
  size_t saltlen,
  uint32_t iter,
  uint8_t *key,
  size_t keylen
);

bool
bcrypto_pbkdf2_has_hash(const char *name);

#if defined(__cplusplus)
}
#endif

#endif
