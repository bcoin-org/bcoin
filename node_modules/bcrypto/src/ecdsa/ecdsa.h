#ifndef _BCRYPTO_ECDSA_H
#define _BCRYPTO_ECDSA_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#if defined(__cplusplus)
extern "C" {
#endif

bool
bcrypto_ecdsa_privkey_generate(
  const char *name,
  uint8_t **priv,
  size_t *priv_len
);

bool
bcrypto_ecdsa_privkey_export(
  const char *name,
  const uint8_t *priv,
  size_t priv_len,
  bool compress,
  uint8_t **out,
  size_t *out_len
);

bool
bcrypto_ecdsa_privkey_import(
  const char *name,
  const uint8_t *raw,
  size_t raw_len,
  uint8_t **out,
  size_t *out_len
);

bool
bcrypto_ecdsa_privkey_export_pkcs8(
  const char *name,
  const uint8_t *priv,
  size_t priv_len,
  bool compress,
  uint8_t **out,
  size_t *out_len
);

bool
bcrypto_ecdsa_privkey_import_pkcs8(
  const char *name,
  const uint8_t *raw,
  size_t raw_len,
  uint8_t **out,
  size_t *out_len
);

bool
bcrypto_ecdsa_privkey_tweak_add(
  const char *name,
  const uint8_t *priv,
  size_t priv_len,
  const uint8_t *tweak,
  size_t tweak_len,
  uint8_t **npriv,
  size_t *npriv_len
);

bool
bcrypto_ecdsa_privkey_tweak_mul(
  const char *name,
  const uint8_t *priv,
  size_t priv_len,
  const uint8_t *tweak,
  size_t tweak_len,
  uint8_t **npriv,
  size_t *npriv_len
);

bool
bcrypto_ecdsa_privkey_negate(
  const char *name,
  const uint8_t *priv,
  size_t priv_len,
  uint8_t **npriv,
  size_t *npriv_len
);

bool
bcrypto_ecdsa_privkey_inverse(
  const char *name,
  const uint8_t *priv,
  size_t priv_len,
  uint8_t **npriv,
  size_t *npriv_len
);

bool
bcrypto_ecdsa_pubkey_create(
  const char *name,
  const uint8_t *priv,
  size_t priv_len,
  bool compress,
  uint8_t **pub,
  size_t *pub_len
);

bool
bcrypto_ecdsa_pubkey_convert(
  const char *name,
  const uint8_t *pub,
  size_t pub_len,
  bool compress,
  uint8_t **npub,
  size_t *npub_len
);

bool
bcrypto_ecdsa_pubkey_verify(
  const char *name,
  const uint8_t *pub,
  size_t pub_len
);

bool
bcrypto_ecdsa_pubkey_export_spki(
  const char *name,
  const uint8_t *pub,
  size_t pub_len,
  bool compress,
  uint8_t **out,
  size_t *out_len
);

bool
bcrypto_ecdsa_pubkey_import_spki(
  const char *name,
  const uint8_t *raw,
  size_t raw_len,
  bool compress,
  uint8_t **out,
  size_t *out_len
);

bool
bcrypto_ecdsa_pubkey_tweak_add(
  const char *name,
  const uint8_t *pub,
  size_t pub_len,
  const uint8_t *tweak,
  size_t tweak_len,
  bool compress,
  uint8_t **npub,
  size_t *npub_len
);

bool
bcrypto_ecdsa_pubkey_tweak_mul(
  const char *name,
  const uint8_t *pub,
  size_t pub_len,
  const uint8_t *tweak,
  size_t tweak_len,
  bool compress,
  uint8_t **npub,
  size_t *npub_len
);

bool
bcrypto_ecdsa_pubkey_add(
  const char *name,
  const uint8_t *pub1,
  size_t pub1_len,
  const uint8_t *pub2,
  size_t pub2_len,
  bool compress,
  uint8_t **npub,
  size_t *npub_len
);

bool
bcrypto_ecdsa_pubkey_negate(
  const char *name,
  const uint8_t *pub,
  size_t pub_len,
  bool compress,
  uint8_t **npub,
  size_t *npub_len
);

bool
bcrypto_ecdsa_sign(
  const char *name,
  const uint8_t *msg,
  size_t msg_len,
  const uint8_t *priv,
  size_t priv_len,
  uint8_t **r,
  size_t *r_len,
  uint8_t **s,
  size_t *s_len
);

bool
bcrypto_ecdsa_verify(
  const char *name,
  const uint8_t *msg,
  size_t msg_len,
  const uint8_t *r,
  size_t r_len,
  const uint8_t *s,
  size_t s_len,
  const uint8_t *pub,
  size_t pub_len
);

bool
bcrypto_ecdsa_recover(
  const char *name,
  const uint8_t *msg,
  size_t msg_len,
  const uint8_t *r,
  size_t r_len,
  const uint8_t *s,
  size_t s_len,
  int param,
  bool compress,
  uint8_t **pub,
  size_t *pub_len
);

bool
bcrypto_ecdsa_derive(
  const char *name,
  const uint8_t *pub,
  size_t pub_len,
  const uint8_t *priv,
  size_t priv_len,
  bool compress,
  uint8_t **secret,
  size_t *secret_len
);

#if defined(__cplusplus)
}
#endif

#endif
