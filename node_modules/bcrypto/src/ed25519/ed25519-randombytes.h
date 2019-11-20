#include "openssl/rand.h"

void
bcrypto_ed25519_randombytes_unsafe(void *p, size_t len) {
  RAND_bytes(p, (int)len);
}
