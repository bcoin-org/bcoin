/**
 * Parts of this software are based on poly1305-donna:
 * https://github.com/floodyberry/poly1305-donna
 *
 * MIT License
 * http://www.opensource.org/licenses/mit-license.php
 */

#ifndef _BCRYPTO_POLY1305_H
#define _BCRYPTO_POLY1305_H

#include <stddef.h>

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct bcrypto_poly1305_ctx_s {
  size_t aligner;
  unsigned char opaque[136];
} bcrypto_poly1305_ctx;

void
bcrypto_poly1305_init(bcrypto_poly1305_ctx *ctx, const unsigned char key[32]);

void
bcrypto_poly1305_update(
  bcrypto_poly1305_ctx *ctx,
  const unsigned char *m,
  size_t bytes
);

void
bcrypto_poly1305_finish(bcrypto_poly1305_ctx *ctx, unsigned char mac[16]);

void
bcrypto_poly1305_auth(
  unsigned char mac[16],
  const unsigned char *m,
  size_t bytes,
  const unsigned char key[32]
);

int
bcrypto_poly1305_verify(
  const unsigned char mac1[16],
  const unsigned char mac2[16]
);

int
bcrypto_poly1305_power_on_self_test(void);

#if defined(__cplusplus)
}
#endif

#endif
