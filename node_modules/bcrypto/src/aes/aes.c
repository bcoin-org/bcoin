#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "aes.h"
#include "openssl/aes.h"

static inline void
XOR(uint8_t *out, uint8_t *a, uint8_t *b) {
  uint32_t i;
  for (i = 0; i < 16; i++)
    out[i] = a[i] ^ b[i];
}

bool
bcrypto_aes_encipher(
  const uint8_t *data,
  const uint32_t datalen,
  const uint8_t *key,
  const uint8_t *iv,
  uint8_t *out,
  uint32_t *outlen
) {
  uint8_t *pblock = (uint8_t *)data;
  uint8_t *cblock = out;
  uint8_t *pprev = pblock;
  uint8_t *cprev = (uint8_t *)iv;
  uint32_t blocks = datalen / 16;
  uint32_t trailing = datalen % 16;
  uint32_t i;

  AES_KEY enckey;
  AES_set_encrypt_key(key, 256, &enckey);

  if (*outlen != datalen + (16 - trailing))
    return false;

  // Encrypt all blocks except for the last.
  for (i = 0; i < blocks; i++) {
    XOR(cblock, pblock, cprev);
    AES_encrypt(cblock, cblock, &enckey);
    cprev = cblock;
    cblock += 16;
    pblock += 16;
    pprev = pblock;
  }

  // Handle padding on the last block.
  uint8_t *last = cblock;
  uint32_t left = 16 - trailing;

  memcpy(last, pprev, trailing);

  for (i = trailing; i < 16; i++)
    last[i] = left;

  // Encrypt the last block,
  // as well as the padding.
  XOR(cblock, last, cprev);
  AES_encrypt(cblock, cblock, &enckey);

  return true;
}

bool
bcrypto_aes_decipher(
  const uint8_t *data,
  const uint32_t datalen,
  const uint8_t *key,
  const uint8_t *iv,
  uint8_t *out,
  uint32_t *outlen
) {
  uint8_t *pblock = out;
  uint8_t *cblock = (uint8_t *)data;
  uint8_t *pprev = pblock;
  uint8_t *cprev = (uint8_t *)iv;
  uint32_t blocks = datalen / 16;
  uint32_t trailing = datalen % 16;
  uint32_t i;

  if (*outlen != datalen)
    return false;

  if (trailing != 0)
    return false;

  AES_KEY deckey;
  AES_set_decrypt_key(key, 256, &deckey);

  // Decrypt all blocks.
  for (i = 0; i < blocks; i++) {
    AES_decrypt(cblock, pblock, &deckey);
    XOR(pblock, pblock, cprev);
    cprev = cblock;
    pprev = pblock;
    cblock += 16;
    pblock += 16;
  }

  // Check padding on the last block.
  uint8_t *last = pprev;
  uint32_t b = 16;
  uint32_t n = last[b - 1];

  if (n == 0 || n > b)
    return false;

  for (i = 0; i < n; i++) {
    if (last[--b] != n)
      return false;
  }

  *outlen = datalen - n;

  return true;
}
