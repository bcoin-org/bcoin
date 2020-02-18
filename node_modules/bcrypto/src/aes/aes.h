#ifndef _BCRYPTO_CIPHER_H
#define _BCRYPTO_CIPHER_H

#define BCRYPTO_AES_ENCIPHER_SIZE(len) ((len) + (16 - ((len) % 16)));
#define BCRYPTO_AES_DECIPHER_SIZE(len) (len)

#include <stdbool.h>
#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif

bool
bcrypto_aes_encipher(
  const uint8_t *data,
  const uint32_t datalen,
  const uint8_t *key,
  const uint8_t *iv,
  uint8_t *out,
  uint32_t *outlen
);

bool
bcrypto_aes_decipher(
  const uint8_t *data,
  const uint32_t datalen,
  const uint8_t *key,
  const uint8_t *iv,
  uint8_t *out,
  uint32_t *outlen
);

#if defined(__cplusplus)
}
#endif

#endif
