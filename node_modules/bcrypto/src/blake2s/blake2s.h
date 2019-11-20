/**
 * Parts of this software are based on BLAKE2:
 * https://github.com/BLAKE2/BLAKE2
 *
 * BLAKE2 reference source code package - reference C implementations
 *
 * Copyright 2012, Samuel Neves <sneves@dei.uc.pt>.  You may use this under
 * the terms of the CC0, the OpenSSL Licence, or the Apache Public License
 * 2.0, at your option.  The terms of these licenses can be found at:
 *
 * - CC0 1.0 Universal : http://creativecommons.org/publicdomain/zero/1.0
 * - OpenSSL license   : https://www.openssl.org/source/license.html
 * - Apache 2.0        : http://www.apache.org/licenses/LICENSE-2.0
 *
 * More information about the BLAKE2 hash function can be found at
 * https://blake2.net.
 */

#ifndef BCRYPTO_BLAKE2S_H
#define BCRYPTO_BLAKE2S_H

#include <stddef.h>
#include <stdint.h>

#if defined(_MSC_VER)
#define BCRYPTO_BLAKE2S_PACKED(x) __pragma(pack(push, 1)) x __pragma(pack(pop))
#else
#define BCRYPTO_BLAKE2S_PACKED(x) x __attribute__((packed))
#endif

#if defined(__cplusplus)
extern "C" {
#endif

enum bcrypto_blake2s_constant {
  BCRYPTO_BLAKE2S_BLOCKBYTES = 64,
  BCRYPTO_BLAKE2S_OUTBYTES = 32,
  BCRYPTO_BLAKE2S_KEYBYTES = 32,
  BCRYPTO_BLAKE2S_SALTBYTES = 8,
  BCRYPTO_BLAKE2S_PERSONALBYTES = 8
};

typedef struct bcrypto_blake2s_ctx__ {
  uint32_t h[8];
  uint32_t t[2];
  uint32_t f[2];
  uint8_t buf[BCRYPTO_BLAKE2S_BLOCKBYTES];
  size_t buflen;
  size_t outlen;
  uint8_t last_node;
} bcrypto_blake2s_ctx;

BCRYPTO_BLAKE2S_PACKED(struct bcrypto_blake2s_param__ {
  uint8_t digest_length;
  uint8_t key_length;
  uint8_t fanout;
  uint8_t depth;
  uint32_t leaf_length;
  uint32_t node_offset;
  uint16_t xof_length;
  uint8_t node_depth;
  uint8_t inner_length;
  uint8_t salt[BCRYPTO_BLAKE2S_SALTBYTES];
  uint8_t personal[BCRYPTO_BLAKE2S_PERSONALBYTES];
});

typedef struct bcrypto_blake2s_param__ bcrypto_blake2s_param;

enum {
  BCRYPTO_BLAKE2S_DUMMY =
    1 / (sizeof(bcrypto_blake2s_param) == BCRYPTO_BLAKE2S_OUTBYTES)
};

int bcrypto_blake2s_init(bcrypto_blake2s_ctx *S, size_t outlen);

int bcrypto_blake2s_init_key(
  bcrypto_blake2s_ctx *S,
  size_t outlen,
  const void *key,
  size_t keylen
);

int bcrypto_blake2s_init_param(
  bcrypto_blake2s_ctx *S,
  const bcrypto_blake2s_param *P
);

int bcrypto_blake2s_update(
  bcrypto_blake2s_ctx *S,
  const void *in,
  size_t inlen
);

int bcrypto_blake2s_final(bcrypto_blake2s_ctx *S, void *out, size_t outlen);

int bcrypto_blake2s(
  void *out,
  size_t outlen,
  const void *in,
  size_t inlen,
  const void *key,
  size_t keylen
);

#if defined(__cplusplus)
}
#endif

#endif
