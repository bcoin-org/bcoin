/*!
 * ies.c - ies for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

#include <stddef.h>
#include <torsion/ies.h>
#include <torsion/mac.h>
#include <torsion/stream.h>
#include <torsion/util.h>

/*
 * Constants
 */

static const unsigned char zero32[32] = {0};

/*
 * Secret Box
 *
 * Resources:
 *   https://nacl.cr.yp.to/secretbox.html
 */

void
secretbox_seal(unsigned char *sealed,
               const unsigned char *msg,
               size_t msg_len,
               const unsigned char *key,
               const unsigned char *nonce) {
  unsigned char *tag = sealed;
  unsigned char *ct = sealed + 16;
  unsigned char polykey[32];
  poly1305_t poly;
  salsa20_t salsa;

  salsa20_init(&salsa, key, 32, nonce, 24, 0);
  salsa20_crypt(&salsa, polykey, zero32, 32);
  salsa20_crypt(&salsa, ct, msg, msg_len);

  poly1305_init(&poly, polykey);
  poly1305_update(&poly, ct, msg_len);
  poly1305_final(&poly, tag);

  torsion_memzero(&salsa, sizeof(salsa));
}

int
secretbox_open(unsigned char *msg,
               const unsigned char *sealed,
               size_t sealed_len,
               const unsigned char *key,
               const unsigned char *nonce) {
  const unsigned char *tag, *ct;
  unsigned char polykey[32];
  unsigned char mac[16];
  poly1305_t poly;
  salsa20_t salsa;
  size_t ct_len;
  int ret;

  if (sealed_len < 16)
    return 0;

  tag = sealed;
  ct = sealed + 16;
  ct_len = sealed_len - 16;

  salsa20_init(&salsa, key, 32, nonce, 24, 0);
  salsa20_crypt(&salsa, polykey, zero32, 32);

  poly1305_init(&poly, polykey);
  poly1305_update(&poly, ct, ct_len);
  poly1305_final(&poly, mac);

  ret = torsion_memequal(mac, tag, 16);

  salsa20_crypt(&salsa, msg, ct, ct_len);

  torsion_memzero(&salsa, sizeof(salsa));

  return ret;
}

void
secretbox_derive(unsigned char *key, const unsigned char *secret) {
  salsa20_derive(key, secret, 32, zero32);
}
