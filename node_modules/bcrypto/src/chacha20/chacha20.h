/**
 * Parts of this software are based on chacha20-simple:
 * http://chacha20.insanecoding.org/
 *
 *   Copyright (C) 2014 insane coder
 *
 *   Permission to use, copy, modify, and distribute this software for any
 *   purpose with or without fee is hereby granted, provided that the above
 *   copyright notice and this permission notice appear in all copies.
 *
 *   THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 *   WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 *   MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 *   SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 *   WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 *   ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR
 *   IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *   This implementation is intended to be simple, many optimizations can be
 *   performed.
 */

#ifndef _BCRYPTO_CHACHA20_H
#define _BCRYPTO_CHACHA20_H

#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct {
  uint32_t state[16];
  uint32_t stream[16];
  size_t available;
  size_t nonce_size;
} bcrypto_chacha20_ctx;

void
bcrypto_chacha20_setup(
  bcrypto_chacha20_ctx *ctx,
  const uint8_t *key,
  size_t length,
  const uint8_t *nonce,
  size_t nonce_size
);

void
bcrypto_chacha20_keysetup(
  bcrypto_chacha20_ctx *ctx,
  const uint8_t *key,
  size_t length
);

void
bcrypto_chacha20_ivsetup(
  bcrypto_chacha20_ctx *ctx,
  const uint8_t *nonce,
  size_t nonce_size
);

void
bcrypto_chacha20_counter_set(bcrypto_chacha20_ctx *ctx, uint64_t counter);

uint64_t bcrypto_chacha20_counter_get(bcrypto_chacha20_ctx *ctx);

void
bcrypto_chacha20_block(bcrypto_chacha20_ctx *ctx, uint32_t output[16]);

void
bcrypto_chacha20_encrypt(
  bcrypto_chacha20_ctx *ctx,
  const uint8_t *in,
  uint8_t *out,
  size_t length
);

#if defined(__cplusplus)
}
#endif

#endif
