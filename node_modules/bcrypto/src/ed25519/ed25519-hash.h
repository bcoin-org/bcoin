#include "openssl/sha.h"

typedef SHA512_CTX bcrypto_ed25519_hash_context;

static void
bcrypto_ed25519_hash_init(bcrypto_ed25519_hash_context *ctx) {
  SHA512_Init(ctx);
}

static void
bcrypto_ed25519_hash_update(
  bcrypto_ed25519_hash_context *ctx,
  const uint8_t *in,
  size_t inlen
) {
  SHA512_Update(ctx, in, inlen);
}

static void
bcrypto_ed25519_hash_final(bcrypto_ed25519_hash_context *ctx, uint8_t *hash) {
  SHA512_Final(hash, ctx);
}

static void
bcrypto_ed25519_hash(uint8_t *hash, const uint8_t *in, size_t inlen) {
  SHA512(in, inlen, hash);
}
