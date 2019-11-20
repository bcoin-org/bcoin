#include <assert.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include "openssl/rand.h"
#include "random.h"

void
bcrypto_poll(void) {
  for (;;) {
    // https://github.com/openssl/openssl/blob/bc420eb/crypto/rand/rand_lib.c#L792
    // https://github.com/openssl/openssl/blob/bc420eb/crypto/rand/drbg_lib.c#L988
    int status = RAND_status();

    assert(status >= 0);

    if (status != 0)
      break;

    // https://github.com/openssl/openssl/blob/bc420eb/crypto/rand/rand_lib.c#L376
    // https://github.com/openssl/openssl/blob/32f803d/crypto/rand/drbg_lib.c#L471
    if (RAND_poll() == 0)
      break;
  }
}

bool
bcrypto_random(uint8_t *dst, size_t len) {
  bcrypto_poll();

  int r = RAND_bytes(dst, len);

  if (r != 1)
    return false;

  return true;
}
