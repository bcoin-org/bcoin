#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "openssl/opensslv.h"
#include "ecdsa.h"

#if OPENSSL_VERSION_NUMBER >= 0x1010008fL

#include "openssl/ecdsa.h"
#include "openssl/objects.h"
#include "openssl/x509.h"
#include "../random/random.h"

// https://github.com/openssl/openssl/blob/master/include/openssl/obj_mac.h
// https://github.com/openssl/openssl/blob/master/include/openssl/bn.h
// https://github.com/openssl/openssl/blob/master/include/openssl/ec.h
// https://github.com/openssl/openssl/tree/master/crypto/bn
// https://github.com/openssl/openssl/tree/master/crypto/ec
// https://github.com/openssl/openssl/blob/master/crypto/ec/ec_key.c
// https://github.com/openssl/openssl/blob/master/crypto/ec/ec_oct.c
// https://wiki.openssl.org/index.php/Elliptic_Curve_Cryptography
// https://wiki.openssl.org/index.php/Elliptic_Curve_Diffie_Hellman

static int
bcrypto_ecdsa_curve(const char *name) {
  int type = -1;

  if (name == NULL)
    return type;

  if (strcmp(name, "P192") == 0)
    type = NID_X9_62_prime192v1;
  else if (strcmp(name, "P224") == 0)
    type = NID_secp224r1;
  else if (strcmp(name, "P256") == 0)
    type = NID_X9_62_prime256v1;
  else if (strcmp(name, "P384") == 0)
    type = NID_secp384r1;
  else if (strcmp(name, "P521") == 0)
    type = NID_secp521r1;
  else if (strcmp(name, "SECP256K1") == 0)
    type = NID_secp256k1;

  return type;
}

static size_t
bcrypto_ecdsa_size(int type) {
  switch (type) {
    case NID_X9_62_prime192v1:
      return 24;
    case NID_secp224r1:
      return 28;
    case NID_X9_62_prime256v1:
      return 32;
    case NID_secp384r1:
      return 48;
    case NID_secp521r1:
      return 66;
    case NID_secp256k1:
      return 32;
    default:
      return 0;
  }
}

static bool
bcrypto_ecdsa_valid_scalar(int type, const uint8_t *scalar, size_t len) {
  if (scalar == NULL)
    return false;

  return len == bcrypto_ecdsa_size(type);
}

static bool
bcrypto_ecdsa_valid_point(int type, const uint8_t *point, size_t len) {
  if (point == NULL)
    return false;

  size_t size = bcrypto_ecdsa_size(type);

  if (len < 1 + size)
    return false;

  switch (point[0]) {
    case 0x02:
    case 0x03:
      return len == 1 + size;
    case 0x04:
      return len == 1 + size * 2;
    case 0x06:
    case 0x07:
      return len == 1 + size * 2
          && (point[0] & 1) == (point[len - 1] & 1);
    default:
      return false;
  }
}

static BIGNUM *
bcrypto_ecdsa_order(int type) {
  BN_CTX *ctx = NULL;
  EC_KEY *key_ec = NULL;
  BIGNUM *order_bn = NULL;

  ctx = BN_CTX_new();

  if (!ctx)
    goto fail;

  // We need the group, and I have no
  // idea how to easily get it by nid
  // other than allocating a key!
  key_ec = EC_KEY_new_by_curve_name(type);

  if (!key_ec)
    goto fail;

  const EC_GROUP *group = EC_KEY_get0_group(key_ec);
  assert(group);

  order_bn = BN_new();

  if (!order_bn)
    goto fail;

  if (!EC_GROUP_get_order(group, order_bn, ctx))
    goto fail;

  EC_KEY_free(key_ec);
  BN_CTX_free(ctx);

  return order_bn;

fail:
  if (key_ec)
    EC_KEY_free(key_ec);

  if (order_bn)
    BN_free(order_bn);

  if (ctx)
    BN_CTX_free(ctx);

  return NULL;
}

static ECDSA_SIG *
bcrypto_ecdsa_rs2sig(
  const uint8_t *r,
  size_t r_len,
  const uint8_t *s,
  size_t s_len
) {
  ECDSA_SIG *sig_ec = NULL;
  BIGNUM *r_bn = NULL;
  BIGNUM *s_bn = NULL;

  sig_ec = ECDSA_SIG_new();

  if (!sig_ec)
    goto fail;

  r_bn = BN_bin2bn(r, r_len, NULL);

  if (!r_bn)
    goto fail;

  s_bn = BN_bin2bn(s, s_len, NULL);

  if (!s_bn)
    goto fail;

  if (!ECDSA_SIG_set0(sig_ec, r_bn, s_bn))
    goto fail;

  return sig_ec;

fail:
  if (sig_ec)
    ECDSA_SIG_free(sig_ec);

  if (r_bn)
    BN_free(r_bn);

  if (s_bn)
    BN_free(s_bn);

  return NULL;
}

static bool
bcrypto_ecdsa_sig2rs(
  const EC_GROUP *group,
  const ECDSA_SIG *sig_ec,
  uint8_t **r,
  uint8_t **s
) {
  assert(group && sig_ec && r && s);

  BN_CTX *ctx = NULL;
  uint8_t *r_buf = NULL;
  uint8_t *s_buf = NULL;
  BIGNUM *order_bn = NULL;
  BIGNUM *half_bn = NULL;

  ctx = BN_CTX_new();

  if (!ctx)
    goto fail;

  const BIGNUM *r_bn = NULL;
  const BIGNUM *s_bn = NULL;

  ECDSA_SIG_get0(sig_ec, &r_bn, &s_bn);
  assert(r_bn && s_bn);

  order_bn = BN_new();
  half_bn = BN_new();

  if (!order_bn || !half_bn)
    goto fail;

  if (!EC_GROUP_get_order(group, order_bn, ctx))
    goto fail;

  if (!BN_rshift1(half_bn, order_bn))
    goto fail;

  if (BN_ucmp(s_bn, half_bn) > 0) {
    if (!BN_sub(order_bn, order_bn, s_bn))
      goto fail;
    s_bn = (const BIGNUM *)order_bn;
  }

  int bits = EC_GROUP_get_degree(group);
  size_t size = (bits + 7) / 8;

  assert((size_t)BN_num_bytes(r_bn) <= size);
  assert((size_t)BN_num_bytes(s_bn) <= size);

  r_buf = malloc(size);
  s_buf = malloc(size);

  if (!r_buf || !s_buf)
    goto fail;

  assert(BN_bn2binpad(r_bn, r_buf, size) > 0);
  assert(BN_bn2binpad(s_bn, s_buf, size) > 0);

  BN_free(order_bn);
  BN_free(half_bn);
  BN_CTX_free(ctx);

  *r = r_buf;
  *s = s_buf;

  return true;

fail:
  if (order_bn)
    BN_free(order_bn);

  if (half_bn)
    BN_free(half_bn);

  if (ctx)
    BN_CTX_free(ctx);

  if (r_buf)
    free(r_buf);

  if (s_buf)
    free(s_buf);

  return false;
}

bool
bcrypto_ecdsa_privkey_generate(
  const char *name,
  uint8_t **priv,
  size_t *priv_len
) {
  assert(priv && priv_len);

  EC_KEY *priv_ec = NULL;
  uint8_t *priv_buf = NULL;
  size_t priv_buf_len = 0;

  int type = bcrypto_ecdsa_curve(name);

  if (type == -1)
    goto fail;

  priv_ec = EC_KEY_new_by_curve_name(type);

  if (!priv_ec)
    goto fail;

  bcrypto_poll();

  if (!EC_KEY_generate_key(priv_ec))
    goto fail;

  priv_buf_len = EC_KEY_priv2buf(priv_ec, &priv_buf);

  if ((int)priv_buf_len <= 0)
    goto fail;

  EC_KEY_free(priv_ec);

  *priv = priv_buf;
  *priv_len = priv_buf_len;

  return true;

fail:
  if (priv_ec)
    EC_KEY_free(priv_ec);

  if (priv_buf)
    free(priv_buf);

  return false;
}

static bool
bcrypto_ecdsa_privkey_export2(
  const char *name,
  const uint8_t *priv,
  size_t priv_len,
  bool compress,
  bool no_params,
  uint8_t **out,
  size_t *out_len
) {
  assert(out && out_len);

  BN_CTX *ctx = NULL;
  EC_KEY *priv_ec = NULL;
  EC_POINT *pub_point = NULL;

  int type = bcrypto_ecdsa_curve(name);

  if (type == -1)
    goto fail;

  if (!bcrypto_ecdsa_valid_scalar(type, priv, priv_len))
    goto fail;

  ctx = BN_CTX_new();

  if (!ctx)
    goto fail;

  priv_ec = EC_KEY_new_by_curve_name(type);

  if (!priv_ec)
    goto fail;

  if (!EC_KEY_oct2priv(priv_ec, priv, priv_len))
    goto fail;

  const EC_GROUP *group = EC_KEY_get0_group(priv_ec);
  assert(group);

  pub_point = EC_POINT_new(group);

  if (!pub_point)
    goto fail;

  const BIGNUM *priv_bn = EC_KEY_get0_private_key(priv_ec);
  assert(priv_bn);

  if (!EC_POINT_mul(group, pub_point, priv_bn, NULL, NULL, ctx))
    goto fail;

  if (!EC_KEY_set_public_key(priv_ec, pub_point))
    goto fail;

  point_conversion_form_t form = compress
    ? POINT_CONVERSION_COMPRESSED
    : POINT_CONVERSION_UNCOMPRESSED;

  EC_KEY_set_conv_form(priv_ec, form);

  if (no_params) {
    EC_KEY_set_enc_flags(priv_ec,
      EC_KEY_get_enc_flags(priv_ec) | EC_PKEY_NO_PARAMETERS);
  }

  EC_KEY_set_asn1_flag(priv_ec, OPENSSL_EC_NAMED_CURVE);

  uint8_t *buf = NULL;
  int len = i2d_ECPrivateKey(priv_ec, &buf);

  if (len <= 0)
    goto fail;

  *out = buf;
  *out_len = (size_t)len;

  EC_KEY_free(priv_ec);
  EC_POINT_free(pub_point);
  BN_CTX_free(ctx);

  return true;

fail:
  if (priv_ec)
    EC_KEY_free(priv_ec);

  if (pub_point)
    EC_POINT_free(pub_point);

  if (ctx)
    BN_CTX_free(ctx);

  return false;
}

bool
bcrypto_ecdsa_privkey_export(
  const char *name,
  const uint8_t *priv,
  size_t priv_len,
  bool compress,
  uint8_t **out,
  size_t *out_len
) {
  return bcrypto_ecdsa_privkey_export2(
    name,
    priv,
    priv_len,
    compress,
    false,
    out,
    out_len
  );
}

bool
bcrypto_ecdsa_privkey_import(
  const char *name,
  const uint8_t *raw,
  size_t raw_len,
  uint8_t **out,
  size_t *out_len
) {
  assert(out && out_len);

  EC_KEY *priv_ec = NULL;

  int type = bcrypto_ecdsa_curve(name);

  if (type == -1)
    goto fail;

  priv_ec = EC_KEY_new_by_curve_name(type);

  if (!priv_ec)
    goto fail;

  EC_KEY_set_asn1_flag(priv_ec, OPENSSL_EC_NAMED_CURVE);

  const uint8_t *p = raw;

  if (!d2i_ECPrivateKey(&priv_ec, &p, raw_len))
    goto fail;

  *out_len = EC_KEY_priv2buf(priv_ec, out);

  if ((int)*out_len <= 0)
    goto fail;

  if (!bcrypto_ecdsa_valid_scalar(type, *out, *out_len))
    goto fail;

  EC_KEY_free(priv_ec);

  return true;

fail:
  if (priv_ec)
    EC_KEY_free(priv_ec);

  return false;
}

bool
bcrypto_ecdsa_privkey_export_pkcs8(
  const char *name,
  const uint8_t *priv,
  size_t priv_len,
  bool compress,
  uint8_t **out,
  size_t *out_len
) {
  // https://github.com/openssl/openssl/blob/32f803d/crypto/ec/ec_ameth.c#L217
  uint8_t *ep = NULL;
  size_t eplen = 0;
  PKCS8_PRIV_KEY_INFO *p8 = NULL;

  int type = bcrypto_ecdsa_curve(name);

  if (type == -1)
    goto fail;

  if (!bcrypto_ecdsa_privkey_export2(name, priv, priv_len,
                                    compress, true, &ep, &eplen)) {
    goto fail;
  }

  p8 = PKCS8_PRIV_KEY_INFO_new();

  if (!p8)
    goto fail;

  if (!PKCS8_pkey_set0(p8, OBJ_nid2obj(NID_X9_62_id_ecPublicKey), 0,
                       V_ASN1_OBJECT, OBJ_nid2obj(type), ep, (int)eplen)) {
    goto fail;
  }

  ep = NULL;

  uint8_t *buf = NULL;
  int len = i2d_PKCS8_PRIV_KEY_INFO(p8, &buf);

  if (len <= 0)
    goto fail;

  *out = buf;
  *out_len = (size_t)len;

  PKCS8_PRIV_KEY_INFO_free(p8);

  return true;

fail:
  if (ep)
    free(ep);

  if (p8)
    PKCS8_PRIV_KEY_INFO_free(p8);

  return false;
}

bool
bcrypto_ecdsa_privkey_import_pkcs8(
  const char *name,
  const uint8_t *raw,
  size_t raw_len,
  uint8_t **out,
  size_t *out_len
) {
  assert(out && out_len);

  // https://github.com/openssl/openssl/blob/32f803d/crypto/ec/ec_ameth.c#L184
  PKCS8_PRIV_KEY_INFO *p8 = NULL;
  const unsigned char *p = NULL;
  const void *pval;
  int ptype, pklen;
  const X509_ALGOR *palg;
  const ASN1_OBJECT *palgoid;

  int type = bcrypto_ecdsa_curve(name);

  if (type == -1)
    goto fail;

  const uint8_t *pp = raw;

  if (!d2i_PKCS8_PRIV_KEY_INFO(&p8, &pp, raw_len))
    goto fail;

  if (!PKCS8_pkey_get0(NULL, &p, &pklen, &palg, p8))
    goto fail;

  X509_ALGOR_get0(&palgoid, &ptype, &pval, palg);

  if (OBJ_obj2nid(palgoid) != NID_X9_62_id_ecPublicKey)
    goto fail;

  if (ptype == V_ASN1_OBJECT) {
    if (OBJ_obj2nid(pval) != type)
      goto fail;
  } else if (ptype != V_ASN1_UNDEF && ptype != V_ASN1_NULL) {
    goto fail;
  }

  if (!bcrypto_ecdsa_privkey_import(name, p, pklen, out, out_len))
    goto fail;

  PKCS8_PRIV_KEY_INFO_free(p8);

  return true;

fail:
  if (p8)
    PKCS8_PRIV_KEY_INFO_free(p8);

  return false;
}

bool
bcrypto_ecdsa_privkey_tweak_add(
  const char *name,
  const uint8_t *priv,
  size_t priv_len,
  const uint8_t *tweak,
  size_t tweak_len,
  uint8_t **npriv,
  size_t *npriv_len
) {
  assert(npriv && npriv_len);

  BN_CTX *ctx = NULL;
  BIGNUM *order_bn = NULL;
  BIGNUM *priv_bn = NULL;
  BIGNUM *tweak_bn = NULL;
  uint8_t *npriv_buf = NULL;

  int type = bcrypto_ecdsa_curve(name);

  if (type == -1)
    goto fail;

  if (!bcrypto_ecdsa_valid_scalar(type, priv, priv_len))
    goto fail;

  if (!bcrypto_ecdsa_valid_scalar(type, tweak, tweak_len))
    goto fail;

  ctx = BN_CTX_new();

  if (!ctx)
    goto fail;

  order_bn = bcrypto_ecdsa_order(type);

  if (!order_bn)
    goto fail;

  priv_bn = BN_bin2bn(priv, priv_len, NULL);

  if (!priv_bn)
    goto fail;

  if (BN_is_zero(priv_bn) || BN_ucmp(priv_bn, order_bn) >= 0)
    goto fail;

  tweak_bn = BN_bin2bn(tweak, tweak_len, NULL);

  if (!tweak_bn)
    goto fail;

  if (BN_ucmp(tweak_bn, order_bn) >= 0)
    goto fail;

  if (!BN_mod_add(priv_bn, priv_bn, tweak_bn, order_bn, ctx))
    goto fail;

  if (BN_is_zero(priv_bn))
    goto fail;

  size_t size = bcrypto_ecdsa_size(type);

  assert(size != 0);
  assert((size_t)BN_num_bytes(priv_bn) <= size);

  npriv_buf = malloc(size);

  if (!npriv_buf)
    goto fail;

  assert(BN_bn2binpad(priv_bn, npriv_buf, size) > 0);

  BN_free(order_bn);
  BN_clear_free(priv_bn);
  BN_clear_free(tweak_bn);
  BN_CTX_free(ctx);

  *npriv = npriv_buf;
  *npriv_len = size;

  return true;

fail:
  if (order_bn)
    BN_free(order_bn);

  if (priv_bn)
    BN_clear_free(priv_bn);

  if (tweak_bn)
    BN_clear_free(tweak_bn);

  if (ctx)
    BN_CTX_free(ctx);

  if (npriv_buf)
    free(npriv_buf);

  return false;
}

bool
bcrypto_ecdsa_privkey_tweak_mul(
  const char *name,
  const uint8_t *priv,
  size_t priv_len,
  const uint8_t *tweak,
  size_t tweak_len,
  uint8_t **npriv,
  size_t *npriv_len
) {
  assert(npriv && npriv_len);

  BN_CTX *ctx = NULL;
  BIGNUM *order_bn = NULL;
  BIGNUM *priv_bn = NULL;
  BIGNUM *tweak_bn = NULL;
  uint8_t *npriv_buf = NULL;

  int type = bcrypto_ecdsa_curve(name);

  if (type == -1)
    goto fail;

  if (!bcrypto_ecdsa_valid_scalar(type, priv, priv_len))
    goto fail;

  if (!bcrypto_ecdsa_valid_scalar(type, tweak, tweak_len))
    goto fail;

  ctx = BN_CTX_new();

  if (!ctx)
    goto fail;

  order_bn = bcrypto_ecdsa_order(type);

  if (!order_bn)
    goto fail;

  priv_bn = BN_bin2bn(priv, priv_len, NULL);

  if (!priv_bn)
    goto fail;

  if (BN_is_zero(priv_bn) || BN_ucmp(priv_bn, order_bn) >= 0)
    goto fail;

  tweak_bn = BN_bin2bn(tweak, tweak_len, NULL);

  if (!tweak_bn)
    goto fail;

  if (BN_is_zero(tweak_bn) || BN_ucmp(tweak_bn, order_bn) >= 0)
    goto fail;

  if (!BN_mod_mul(priv_bn, priv_bn, tweak_bn, order_bn, ctx))
    goto fail;

  if (BN_is_zero(priv_bn))
    goto fail;

  size_t size = bcrypto_ecdsa_size(type);

  assert(size != 0);
  assert((size_t)BN_num_bytes(priv_bn) <= size);

  npriv_buf = malloc(size);

  if (!npriv_buf)
    goto fail;

  assert(BN_bn2binpad(priv_bn, npriv_buf, size) > 0);

  BN_free(order_bn);
  BN_clear_free(priv_bn);
  BN_clear_free(tweak_bn);
  BN_CTX_free(ctx);

  *npriv = npriv_buf;
  *npriv_len = size;

  return true;

fail:
  if (order_bn)
    BN_free(order_bn);

  if (priv_bn)
    BN_clear_free(priv_bn);

  if (tweak_bn)
    BN_clear_free(tweak_bn);

  if (ctx)
    BN_CTX_free(ctx);

  if (npriv_buf)
    free(npriv_buf);

  return false;
}

bool
bcrypto_ecdsa_privkey_negate(
  const char *name,
  const uint8_t *priv,
  size_t priv_len,
  uint8_t **npriv,
  size_t *npriv_len
) {
  assert(npriv && npriv_len);

  BIGNUM *order_bn = NULL;
  BIGNUM *priv_bn = NULL;
  uint8_t *npriv_buf = NULL;

  int type = bcrypto_ecdsa_curve(name);

  if (type == -1)
    goto fail;

  if (!bcrypto_ecdsa_valid_scalar(type, priv, priv_len))
    goto fail;

  order_bn = bcrypto_ecdsa_order(type);

  if (!order_bn)
    goto fail;

  priv_bn = BN_bin2bn(priv, priv_len, NULL);

  if (!priv_bn)
    goto fail;

  if (BN_ucmp(priv_bn, order_bn) >= 0)
    goto fail;

  if (!BN_is_zero(priv_bn)) {
    if (!BN_sub(priv_bn, order_bn, priv_bn))
      goto fail;
  }

  size_t size = bcrypto_ecdsa_size(type);

  assert(size != 0);
  assert((size_t)BN_num_bytes(priv_bn) <= size);

  npriv_buf = malloc(size);

  if (!npriv_buf)
    goto fail;

  assert(BN_bn2binpad(priv_bn, npriv_buf, size) > 0);

  BN_free(order_bn);
  BN_clear_free(priv_bn);

  *npriv = npriv_buf;
  *npriv_len = size;

  return true;

fail:
  if (order_bn)
    BN_free(order_bn);

  if (priv_bn)
    BN_clear_free(priv_bn);

  if (npriv_buf)
    free(npriv_buf);

  return false;
}

bool
bcrypto_ecdsa_privkey_inverse(
  const char *name,
  const uint8_t *priv,
  size_t priv_len,
  uint8_t **npriv,
  size_t *npriv_len
) {
  assert(npriv && npriv_len);

  BN_CTX *ctx = NULL;
  BIGNUM *order_bn = NULL;
  BIGNUM *priv_bn = NULL;
  uint8_t *npriv_buf = NULL;

  int type = bcrypto_ecdsa_curve(name);

  if (type == -1)
    goto fail;

  if (!bcrypto_ecdsa_valid_scalar(type, priv, priv_len))
    goto fail;

  ctx = BN_CTX_new();

  if (!ctx)
    goto fail;

  order_bn = bcrypto_ecdsa_order(type);

  if (!order_bn)
    goto fail;

  priv_bn = BN_bin2bn(priv, priv_len, NULL);

  if (!priv_bn)
    goto fail;

  if (BN_is_zero(priv_bn) || BN_ucmp(priv_bn, order_bn) >= 0)
    goto fail;

  if (!BN_mod_inverse(priv_bn, priv_bn, order_bn, ctx))
    goto fail;

  if (BN_is_zero(priv_bn))
    goto fail;

  size_t size = bcrypto_ecdsa_size(type);

  assert(size != 0);
  assert((size_t)BN_num_bytes(priv_bn) <= size);

  npriv_buf = malloc(size);

  if (!npriv_buf)
    goto fail;

  assert(BN_bn2binpad(priv_bn, npriv_buf, size) > 0);

  BN_free(order_bn);
  BN_clear_free(priv_bn);
  BN_CTX_free(ctx);

  *npriv = npriv_buf;
  *npriv_len = size;

  return true;

fail:
  if (order_bn)
    BN_free(order_bn);

  if (priv_bn)
    BN_clear_free(priv_bn);

  if (ctx)
    BN_CTX_free(ctx);

  if (npriv_buf)
    free(npriv_buf);

  return false;
}

bool
bcrypto_ecdsa_pubkey_create(
  const char *name,
  const uint8_t *priv,
  size_t priv_len,
  bool compress,
  uint8_t **pub,
  size_t *pub_len
) {
  assert(pub && pub_len);

  BN_CTX *ctx = NULL;
  EC_KEY *priv_ec = NULL;
  EC_POINT *pub_point = NULL;
  uint8_t *pub_buf = NULL;
  size_t pub_buf_len = 0;

  int type = bcrypto_ecdsa_curve(name);

  if (type == -1)
    goto fail;

  if (!bcrypto_ecdsa_valid_scalar(type, priv, priv_len))
    goto fail;

  ctx = BN_CTX_new();

  if (!ctx)
    goto fail;

  priv_ec = EC_KEY_new_by_curve_name(type);

  if (!priv_ec)
    goto fail;

  if (!EC_KEY_oct2priv(priv_ec, priv, priv_len))
    goto fail;

  const EC_GROUP *group = EC_KEY_get0_group(priv_ec);
  assert(group);

  pub_point = EC_POINT_new(group);

  if (!pub_point)
    goto fail;

  const BIGNUM *priv_bn = EC_KEY_get0_private_key(priv_ec);
  assert(priv_bn);

  if (!EC_POINT_mul(group, pub_point, priv_bn, NULL, NULL, ctx))
    goto fail;

  if (!EC_KEY_set_public_key(priv_ec, pub_point))
    goto fail;

  point_conversion_form_t form = compress
    ? POINT_CONVERSION_COMPRESSED
    : POINT_CONVERSION_UNCOMPRESSED;

  pub_buf_len = EC_KEY_key2buf(priv_ec, form, &pub_buf, ctx);

  if ((int)pub_buf_len <= 0)
    goto fail;

  EC_KEY_free(priv_ec);
  EC_POINT_free(pub_point);
  BN_CTX_free(ctx);

  *pub = pub_buf;
  *pub_len = pub_buf_len;

  return true;

fail:
  if (priv_ec)
    EC_KEY_free(priv_ec);

  if (pub_point)
    EC_POINT_free(pub_point);

  if (ctx)
    BN_CTX_free(ctx);

  if (pub_buf)
    free(pub_buf);

  return false;
}

bool
bcrypto_ecdsa_pubkey_convert(
  const char *name,
  const uint8_t *pub,
  size_t pub_len,
  bool compress,
  uint8_t **npub,
  size_t *npub_len
) {
  assert(npub && npub_len);

  BN_CTX *ctx = NULL;
  EC_KEY *pub_ec = NULL;
  uint8_t *npub_buf = NULL;
  size_t npub_buf_len = 0;

  int type = bcrypto_ecdsa_curve(name);

  if (type == -1)
    goto fail;

  if (!bcrypto_ecdsa_valid_point(type, pub, pub_len))
    goto fail;

  ctx = BN_CTX_new();

  if (!ctx)
    goto fail;

  pub_ec = EC_KEY_new_by_curve_name(type);

  if (!pub_ec)
    goto fail;

  if (!EC_KEY_oct2key(pub_ec, pub, pub_len, ctx))
    goto fail;

  point_conversion_form_t form = compress
    ? POINT_CONVERSION_COMPRESSED
    : POINT_CONVERSION_UNCOMPRESSED;

  npub_buf_len = EC_KEY_key2buf(pub_ec, form, &npub_buf, ctx);

  if ((int)npub_buf_len <= 0)
    goto fail;

  EC_KEY_free(pub_ec);
  BN_CTX_free(ctx);

  *npub = npub_buf;
  *npub_len = npub_buf_len;

  return true;

fail:
  if (pub_ec)
    EC_KEY_free(pub_ec);

  if (ctx)
    BN_CTX_free(ctx);

  if (npub_buf)
    free(npub_buf);

  return false;
}

bool
bcrypto_ecdsa_pubkey_verify(
  const char *name,
  const uint8_t *pub,
  size_t pub_len
) {
  BN_CTX *ctx = NULL;
  EC_KEY *pub_ec = NULL;

  int type = bcrypto_ecdsa_curve(name);

  if (type == -1)
    goto fail;

  if (!bcrypto_ecdsa_valid_point(type, pub, pub_len))
    goto fail;

  ctx = BN_CTX_new();

  if (!ctx)
    goto fail;

  pub_ec = EC_KEY_new_by_curve_name(type);

  if (!pub_ec)
    goto fail;

  if (!EC_KEY_oct2key(pub_ec, pub, pub_len, ctx))
    goto fail;

  if (!EC_KEY_check_key(pub_ec))
    goto fail;

  EC_KEY_free(pub_ec);
  BN_CTX_free(ctx);

  return true;

fail:
  if (pub_ec)
    EC_KEY_free(pub_ec);

  if (ctx)
    BN_CTX_free(ctx);

  return false;
}

bool
bcrypto_ecdsa_pubkey_export_spki(
  const char *name,
  const uint8_t *pub,
  size_t pub_len,
  bool compress,
  uint8_t **out,
  size_t *out_len
) {
  assert(out && out_len);

  BN_CTX *ctx = NULL;
  EC_KEY *pub_ec = NULL;

  int type = bcrypto_ecdsa_curve(name);

  if (type == -1)
    goto fail;

  if (!bcrypto_ecdsa_valid_point(type, pub, pub_len))
    goto fail;

  ctx = BN_CTX_new();

  if (!ctx)
    goto fail;

  pub_ec = EC_KEY_new_by_curve_name(type);

  if (!pub_ec)
    goto fail;

  if (!EC_KEY_oct2key(pub_ec, pub, pub_len, ctx))
    goto fail;

  point_conversion_form_t form = compress
    ? POINT_CONVERSION_COMPRESSED
    : POINT_CONVERSION_UNCOMPRESSED;

  EC_KEY_set_conv_form(pub_ec, form);
  EC_KEY_set_asn1_flag(pub_ec, OPENSSL_EC_NAMED_CURVE);

  uint8_t *buf = NULL;
  int len = i2d_EC_PUBKEY(pub_ec, &buf);

  if (len <= 0)
    goto fail;

  *out = buf;
  *out_len = (size_t)len;

  EC_KEY_free(pub_ec);
  BN_CTX_free(ctx);

  return true;

fail:
  if (pub_ec)
    EC_KEY_free(pub_ec);

  if (ctx)
    BN_CTX_free(ctx);

  return false;
}

bool
bcrypto_ecdsa_pubkey_import_spki(
  const char *name,
  const uint8_t *raw,
  size_t raw_len,
  bool compress,
  uint8_t **out,
  size_t *out_len
) {
  assert(out && out_len);

  BN_CTX *ctx = NULL;
  EC_KEY *pub_ec = NULL;

  int type = bcrypto_ecdsa_curve(name);

  if (type == -1)
    goto fail;

  pub_ec = EC_KEY_new_by_curve_name(type);

  if (!pub_ec)
    goto fail;

  ctx = BN_CTX_new();

  if (!ctx)
    goto fail;

  EC_KEY_set_asn1_flag(pub_ec, OPENSSL_EC_NAMED_CURVE);

  const uint8_t *p = raw;

  if (!d2i_EC_PUBKEY(&pub_ec, &p, raw_len))
    goto fail;

  point_conversion_form_t form = compress
    ? POINT_CONVERSION_COMPRESSED
    : POINT_CONVERSION_UNCOMPRESSED;

  *out_len = EC_KEY_key2buf(pub_ec, form, out, ctx);

  if ((int)*out_len <= 0)
    goto fail;

  if (!bcrypto_ecdsa_valid_point(type, *out, *out_len))
    goto fail;

  EC_KEY_free(pub_ec);
  BN_CTX_free(ctx);

  return true;

fail:
  if (pub_ec)
    EC_KEY_free(pub_ec);

  if (ctx)
    BN_CTX_free(ctx);

  return false;
}

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
) {
  assert(npub && npub_len);

  BN_CTX *ctx = NULL;
  EC_KEY *pub_ec = NULL;
  BIGNUM *tweak_bn = NULL;
  BIGNUM *order_bn = NULL;
  EC_POINT *tweak_point = NULL;
  uint8_t *npub_buf = NULL;
  size_t npub_buf_len = 0;

  ctx = BN_CTX_new();

  if (!ctx)
    goto fail;

  int type = bcrypto_ecdsa_curve(name);

  if (type == -1)
    goto fail;

  if (!bcrypto_ecdsa_valid_point(type, pub, pub_len))
    goto fail;

  if (!bcrypto_ecdsa_valid_scalar(type, tweak, tweak_len))
    goto fail;

  pub_ec = EC_KEY_new_by_curve_name(type);

  if (!pub_ec)
    goto fail;

  if (!EC_KEY_oct2key(pub_ec, pub, pub_len, ctx))
    goto fail;

  tweak_bn = BN_bin2bn(tweak, tweak_len, NULL);

  if (!tweak_bn)
    goto fail;

  const EC_POINT *key_point = EC_KEY_get0_public_key(pub_ec);
  assert(key_point);

  const EC_GROUP *group = EC_KEY_get0_group(pub_ec);
  assert(group);

  if (!EC_POINT_is_on_curve(group, key_point, ctx))
    goto fail;

  order_bn = BN_new();

  if (!order_bn)
    goto fail;

  if (!EC_GROUP_get_order(group, order_bn, ctx))
    goto fail;

  if (BN_ucmp(tweak_bn, order_bn) >= 0)
    goto fail;

  tweak_point = EC_POINT_new(group);

  if (!tweak_point)
    goto fail;

  if (!EC_POINT_mul(group, tweak_point, tweak_bn, NULL, NULL, ctx))
    goto fail;

  if (!EC_POINT_add(group, tweak_point, key_point, tweak_point, ctx))
    goto fail;

  if (EC_POINT_is_at_infinity(group, tweak_point))
    goto fail;

  point_conversion_form_t form = compress
    ? POINT_CONVERSION_COMPRESSED
    : POINT_CONVERSION_UNCOMPRESSED;

  npub_buf_len = EC_POINT_point2buf(group, tweak_point, form, &npub_buf, ctx);

  if ((int)npub_buf_len <= 0)
    goto fail;

  EC_KEY_free(pub_ec);
  BN_clear_free(tweak_bn);
  BN_free(order_bn);
  EC_POINT_free(tweak_point);
  BN_CTX_free(ctx);

  *npub = npub_buf;
  *npub_len = npub_buf_len;

  return true;

fail:
  if (pub_ec)
    EC_KEY_free(pub_ec);

  if (tweak_bn)
    BN_clear_free(tweak_bn);

  if (order_bn)
    BN_free(order_bn);

  if (tweak_point)
    EC_POINT_free(tweak_point);

  if (ctx)
    BN_CTX_free(ctx);

  if (npub_buf)
    free(npub_buf);

  return false;
}

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
) {
  return bcrypto_ecdsa_derive(name, pub, pub_len,
                              tweak, tweak_len,
                              compress, npub,
                              npub_len);
}

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
) {
  assert(npub && npub_len);

  BN_CTX *ctx = NULL;
  EC_KEY *pub1_ec = NULL;
  EC_KEY *pub2_ec = NULL;
  uint8_t *npub_buf = NULL;
  size_t npub_buf_len = 0;

  ctx = BN_CTX_new();

  if (!ctx)
    goto fail;

  int type = bcrypto_ecdsa_curve(name);

  if (type == -1)
    goto fail;

  if (!bcrypto_ecdsa_valid_point(type, pub1, pub1_len))
    goto fail;

  if (!bcrypto_ecdsa_valid_point(type, pub2, pub2_len))
    goto fail;

  pub1_ec = EC_KEY_new_by_curve_name(type);

  if (!pub1_ec)
    goto fail;

  pub2_ec = EC_KEY_new_by_curve_name(type);

  if (!pub2_ec)
    goto fail;

  if (!EC_KEY_oct2key(pub1_ec, pub1, pub1_len, ctx))
    goto fail;

  if (!EC_KEY_oct2key(pub2_ec, pub2, pub2_len, ctx))
    goto fail;

  const EC_POINT *key1_point = EC_KEY_get0_public_key(pub1_ec);
  assert(key1_point);

  const EC_POINT *key2_point = EC_KEY_get0_public_key(pub2_ec);
  assert(key2_point);

  const EC_GROUP *group = EC_KEY_get0_group(pub1_ec);
  assert(group);

  if (!EC_POINT_is_on_curve(group, key1_point, ctx))
    goto fail;

  if (!EC_POINT_is_on_curve(group, key2_point, ctx))
    goto fail;

  if (!EC_POINT_add(group, (EC_POINT *)key1_point, key1_point, key2_point, ctx))
    goto fail;

  if (EC_POINT_is_at_infinity(group, key1_point))
    goto fail;

  point_conversion_form_t form = compress
    ? POINT_CONVERSION_COMPRESSED
    : POINT_CONVERSION_UNCOMPRESSED;

  npub_buf_len = EC_POINT_point2buf(group, key1_point, form, &npub_buf, ctx);

  if ((int)npub_buf_len <= 0)
    goto fail;

  EC_KEY_free(pub1_ec);
  EC_KEY_free(pub2_ec);
  BN_CTX_free(ctx);

  *npub = npub_buf;
  *npub_len = npub_buf_len;

  return true;

fail:
  if (pub1_ec)
    EC_KEY_free(pub1_ec);

  if (pub2_ec)
    EC_KEY_free(pub2_ec);

  if (ctx)
    BN_CTX_free(ctx);

  if (npub_buf)
    free(npub_buf);

  return false;
}

bool
bcrypto_ecdsa_pubkey_negate(
  const char *name,
  const uint8_t *pub,
  size_t pub_len,
  bool compress,
  uint8_t **npub,
  size_t *npub_len
) {
  assert(npub && npub_len);

  BN_CTX *ctx = NULL;
  EC_KEY *pub_ec = NULL;
  uint8_t *npub_buf = NULL;
  size_t npub_buf_len = 0;

  ctx = BN_CTX_new();

  if (!ctx)
    goto fail;

  int type = bcrypto_ecdsa_curve(name);

  if (type == -1)
    goto fail;

  if (!bcrypto_ecdsa_valid_point(type, pub, pub_len))
    goto fail;

  pub_ec = EC_KEY_new_by_curve_name(type);

  if (!pub_ec)
    goto fail;

  if (!EC_KEY_oct2key(pub_ec, pub, pub_len, ctx))
    goto fail;

  const EC_POINT *key_point = EC_KEY_get0_public_key(pub_ec);
  assert(key_point);

  const EC_GROUP *group = EC_KEY_get0_group(pub_ec);
  assert(group);

  if (!EC_POINT_is_on_curve(group, key_point, ctx))
    goto fail;

  if (!EC_POINT_invert(group, (EC_POINT *)key_point, ctx))
    goto fail;

  if (EC_POINT_is_at_infinity(group, key_point))
    goto fail;

  point_conversion_form_t form = compress
    ? POINT_CONVERSION_COMPRESSED
    : POINT_CONVERSION_UNCOMPRESSED;

  npub_buf_len = EC_POINT_point2buf(group, key_point, form, &npub_buf, ctx);

  if ((int)npub_buf_len <= 0)
    goto fail;

  EC_KEY_free(pub_ec);
  BN_CTX_free(ctx);

  *npub = npub_buf;
  *npub_len = npub_buf_len;

  return true;

fail:
  if (pub_ec)
    EC_KEY_free(pub_ec);

  if (ctx)
    BN_CTX_free(ctx);

  if (npub_buf)
    free(npub_buf);

  return false;
}

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
) {
  assert(r && r_len && s && s_len);

  EC_KEY *priv_ec = NULL;
  ECDSA_SIG *sig_ec = NULL;

  int type = bcrypto_ecdsa_curve(name);

  if (type == -1)
    goto fail;

  if (!bcrypto_ecdsa_valid_scalar(type, priv, priv_len))
    goto fail;

  priv_ec = EC_KEY_new_by_curve_name(type);

  if (!priv_ec)
    goto fail;

  if (!EC_KEY_oct2priv(priv_ec, priv, priv_len))
    goto fail;

  bcrypto_poll();

  sig_ec = ECDSA_do_sign(msg, msg_len, priv_ec);

  if (!sig_ec)
    goto fail;

  const EC_GROUP *group = EC_KEY_get0_group(priv_ec);
  int bits = EC_GROUP_get_degree(group);
  size_t size = (bits + 7) / 8;

  if (!bcrypto_ecdsa_sig2rs(group, sig_ec, r, s))
    goto fail;

  *r_len = size;
  *s_len = size;

  EC_KEY_free(priv_ec);
  ECDSA_SIG_free(sig_ec);

  return true;

fail:
  if (priv_ec)
    EC_KEY_free(priv_ec);

  if (sig_ec)
    ECDSA_SIG_free(sig_ec);

  return false;
}

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
) {
  BN_CTX *ctx = NULL;
  EC_KEY *pub_ec = NULL;
  ECDSA_SIG *sig_ec = NULL;

  int type = bcrypto_ecdsa_curve(name);

  if (type == -1)
    goto fail;

  if (!bcrypto_ecdsa_valid_scalar(type, r, r_len))
    goto fail;

  if (!bcrypto_ecdsa_valid_scalar(type, s, s_len))
    goto fail;

  if (!bcrypto_ecdsa_valid_point(type, pub, pub_len))
    goto fail;

  ctx = BN_CTX_new();

  if (!ctx)
    goto fail;

  pub_ec = EC_KEY_new_by_curve_name(type);

  if (!pub_ec)
    goto fail;

  if (!EC_KEY_oct2key(pub_ec, pub, pub_len, ctx))
    goto fail;

  sig_ec = bcrypto_ecdsa_rs2sig(r, r_len, s, s_len);

  if (!sig_ec)
    goto fail;

  if (ECDSA_do_verify(msg, msg_len, sig_ec, pub_ec) <= 0)
    goto fail;

  EC_KEY_free(pub_ec);
  ECDSA_SIG_free(sig_ec);
  BN_CTX_free(ctx);

  return true;

fail:
  if (pub_ec)
    EC_KEY_free(pub_ec);

  if (sig_ec)
    ECDSA_SIG_free(sig_ec);

  if (ctx)
    BN_CTX_free(ctx);

  return false;
}

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
) {
  assert(pub && pub_len);

  BN_CTX *ctx = NULL;
  EC_KEY *pub_ec = NULL;
  ECDSA_SIG *sig_ec = NULL;
  BIGNUM *N_bn = NULL;
  BIGNUM *P_bn = NULL;
  BIGNUM *A_bn = NULL;
  BIGNUM *B_bn = NULL;
  BIGNUM *x_bn = NULL;
  EC_POINT *r_p = NULL;
  BIGNUM *rinv = NULL;
  BIGNUM *s1 = NULL;
  BIGNUM *s2 = NULL;
  BIGNUM *e_bn = NULL;
  EC_POINT *Q_p = NULL;

  int type = bcrypto_ecdsa_curve(name);

  if (type == -1)
    goto fail;

  if (!bcrypto_ecdsa_valid_scalar(type, r, r_len))
    goto fail;

  if (!bcrypto_ecdsa_valid_scalar(type, s, s_len))
    goto fail;

  ctx = BN_CTX_new();

  if (!ctx)
    goto fail;

  pub_ec = EC_KEY_new_by_curve_name(type);

  if (!pub_ec)
    goto fail;

  sig_ec = bcrypto_ecdsa_rs2sig(r, r_len, s, s_len);

  if (!sig_ec)
    goto fail;

  int y_odd = param & 1;
  int second_key = param >> 1;

  const BIGNUM *sig_r = NULL;
  const BIGNUM *sig_s = NULL;

  ECDSA_SIG_get0(sig_ec, &sig_r, &sig_s);
  assert(sig_r);
  assert(sig_s);

  N_bn = BN_new();
  P_bn = BN_new();
  A_bn = BN_new();
  B_bn = BN_new();

  if (!N_bn || !P_bn || !A_bn || !B_bn)
    goto fail;

  const EC_GROUP *group = EC_KEY_get0_group(pub_ec);
  assert(group);

  const EC_POINT *G_p = EC_GROUP_get0_generator(group);
  assert(G_p);

  if (!EC_GROUP_get_order(group, N_bn, ctx))
    goto fail;

  if (BN_is_zero(sig_r) || BN_ucmp(sig_r, N_bn) >= 0)
    goto fail;

  if (BN_is_zero(sig_s) || BN_ucmp(sig_s, N_bn) >= 0)
    goto fail;

  // TODO:
  // #if OPENSSL_VERSION_NUMBER >= 0x10200000L
  // if (!EC_GROUP_get_curve(group, P_bn, A_bn, B_bn, ctx))
  if (!EC_GROUP_get_curve_GFp(group, P_bn, A_bn, B_bn, ctx))
    goto fail;

  // if r >= p mod n and second_key
  //   fail
  if (second_key) {
    BIGNUM *res = BN_new();

    if (!res)
      goto fail;

    if (!BN_mod(res, P_bn, N_bn, ctx)) {
      BN_free(res);
      goto fail;
    }

    // if r >= p mod n
    if (BN_ucmp(sig_r, res) >= 0) {
      BN_free(res);
      goto fail;
    }

    BN_free(res);
  }

  x_bn = BN_new();

  if (!x_bn)
    goto fail;

  r_p = EC_POINT_new(group);

  if (!r_p)
    goto fail;

  // if (second_key)
  //   r = point_from_x(r + n, y_odd)
  // else
  //   r = point_from_x(r, y_odd)
  {
    if (second_key) {
      if (!BN_add(x_bn, sig_r, N_bn))
        goto fail;
    } else {
      if (!BN_copy(x_bn, sig_r))
        goto fail;
    }

    // TODO:
    // #if OPENSSL_VERSION_NUMBER >= 0x10200000L
    // if (!EC_POINT_set_compressed_coordinates(group, r_p, x_bn, y_odd, ctx))
    if (!EC_POINT_set_compressed_coordinates_GFp(group, r_p, x_bn, y_odd, ctx))
      goto fail;
  }

  // rinv = r^-1 mod n
  {
    rinv = BN_new();

    if (!rinv)
      goto fail;

    if (!BN_mod_inverse(rinv, sig_r, N_bn, ctx))
      goto fail;
  }

  // s1 = (-e * r^-1) mod n
  {
    e_bn = BN_bin2bn(msg, msg_len, NULL);

    if (!e_bn)
      goto fail;

    s1 = BN_new();

    if (!s1)
      goto fail;

    if (!BN_sub(s1, N_bn, e_bn))
      goto fail;

    if (!BN_mul(s1, s1, rinv, ctx))
      goto fail;

    if (!BN_mod(s1, s1, N_bn, ctx))
      goto fail;
  }

  // s2 = (s * r^-1) mod n
  {
    s2 = BN_new();

    if (!s2)
      goto fail;

    if (!BN_mul(s2, sig_s, rinv, ctx))
      goto fail;

    if (!BN_mod(s2, s2, N_bn, ctx))
      goto fail;
  }

  Q_p = EC_POINT_new(group);

  if (!Q_p)
    goto fail;

  // q = g * s1 + r * s2
  if (!EC_POINT_mul(group, Q_p, s1, r_p, s2, ctx))
    goto fail;

  if (EC_POINT_is_at_infinity(group, Q_p))
    goto fail;

  point_conversion_form_t form = compress
    ? POINT_CONVERSION_COMPRESSED
    : POINT_CONVERSION_UNCOMPRESSED;

  *pub_len = EC_POINT_point2buf(group, Q_p, form, pub, ctx);

  if ((int)*pub_len <= 0)
    goto fail;

  BN_CTX_free(ctx);
  EC_KEY_free(pub_ec);
  ECDSA_SIG_free(sig_ec);
  BN_free(N_bn);
  BN_free(P_bn);
  BN_free(A_bn);
  BN_free(B_bn);
  BN_free(x_bn);
  EC_POINT_free(r_p);
  BN_free(rinv);
  BN_free(s1);
  BN_free(s2);
  BN_free(e_bn);
  EC_POINT_free(Q_p);

  return true;

fail:
  if (ctx)
    BN_CTX_free(ctx);

  if (pub_ec)
    EC_KEY_free(pub_ec);

  if (sig_ec)
    ECDSA_SIG_free(sig_ec);

  if (N_bn)
    BN_free(N_bn);

  if (P_bn)
    BN_free(P_bn);

  if (A_bn)
    BN_free(A_bn);

  if (B_bn)
    BN_free(B_bn);

  if (x_bn)
    BN_free(x_bn);

  if (r_p)
    EC_POINT_free(r_p);

  if (rinv)
    BN_free(rinv);

  if (s1)
    BN_free(s1);

  if (s2)
    BN_free(s2);

  if (e_bn)
    BN_free(e_bn);

  if (Q_p)
    EC_POINT_free(Q_p);

  return false;
}

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
) {
  assert(secret && secret_len);

  BN_CTX *ctx = NULL;
  EC_KEY *priv_ec = NULL;
  EC_KEY *pub_ec = NULL;
  EC_POINT *secret_point = NULL;
  uint8_t *secret_buf = NULL;
  size_t secret_buf_len = 0;

  int type = bcrypto_ecdsa_curve(name);

  if (type == -1)
    goto fail;

  if (!bcrypto_ecdsa_valid_point(type, pub, pub_len))
    goto fail;

  if (!bcrypto_ecdsa_valid_scalar(type, priv, priv_len))
    goto fail;

  ctx = BN_CTX_new();

  if (!ctx)
    goto fail;

  priv_ec = EC_KEY_new_by_curve_name(type);

  if (!priv_ec)
    goto fail;

  if (!EC_KEY_oct2priv(priv_ec, priv, priv_len))
    goto fail;

  pub_ec = EC_KEY_new_by_curve_name(type);

  if (!pub_ec)
    goto fail;

  if (!EC_KEY_oct2key(pub_ec, pub, pub_len, ctx))
    goto fail;

  const BIGNUM *priv_bn = EC_KEY_get0_private_key(priv_ec);
  assert(priv_bn);

  const EC_POINT *pub_point = EC_KEY_get0_public_key(pub_ec);
  assert(pub_point);

  const EC_GROUP *group = EC_KEY_get0_group(priv_ec);
  assert(group);

  if (!EC_POINT_is_on_curve(group, pub_point, ctx))
    goto fail;

  secret_point = EC_POINT_new(group);

  if (!secret_point)
    goto fail;

  if (!EC_POINT_mul(group, secret_point, NULL, pub_point, priv_bn, ctx))
    goto fail;

  if (EC_POINT_is_at_infinity(group, secret_point))
    goto fail;

  point_conversion_form_t form = compress
    ? POINT_CONVERSION_COMPRESSED
    : POINT_CONVERSION_UNCOMPRESSED;

  secret_buf_len = EC_POINT_point2buf(
    group,
    secret_point,
    form,
    &secret_buf,
    NULL
  );

  if ((int)secret_buf_len <= 0)
    goto fail;

  EC_KEY_free(priv_ec);
  EC_KEY_free(pub_ec);
  EC_POINT_free(secret_point);
  BN_CTX_free(ctx);

  *secret = secret_buf;
  *secret_len = secret_buf_len;

  return true;

fail:
  if (priv_ec)
    EC_KEY_free(priv_ec);

  if (pub_ec)
    EC_KEY_free(pub_ec);

  if (secret_point)
    EC_POINT_free(secret_point);

  if (ctx)
    BN_CTX_free(ctx);

  if (secret_buf)
    free(secret_buf);

  return false;
}

#else

bool
bcrypto_ecdsa_privkey_generate(
  const char *name,
  uint8_t **priv,
  size_t *priv_len
) {
  return false;
}

bool
bcrypto_ecdsa_privkey_export(
  const char *name,
  const uint8_t *priv,
  size_t priv_len,
  bool compress,
  uint8_t **out,
  size_t *out_len
) {
  return false;
}

bool
bcrypto_ecdsa_privkey_import(
  const char *name,
  const uint8_t *raw,
  size_t raw_len,
  uint8_t **out,
  size_t *out_len
) {
  return false;
}

bool
bcrypto_ecdsa_privkey_export_pkcs8(
  const char *name,
  const uint8_t *priv,
  size_t priv_len,
  bool compress,
  uint8_t **out,
  size_t *out_len
) {
  return false;
}

bool
bcrypto_ecdsa_privkey_import_pkcs8(
  const char *name,
  const uint8_t *raw,
  size_t raw_len,
  uint8_t **out,
  size_t *out_len
) {
  return false;
}

bool
bcrypto_ecdsa_privkey_tweak_add(
  const char *name,
  const uint8_t *priv,
  size_t priv_len,
  const uint8_t *tweak,
  size_t tweak_len,
  uint8_t **npriv,
  size_t *npriv_len
) {
  return false;
}

bool
bcrypto_ecdsa_privkey_tweak_mul(
  const char *name,
  const uint8_t *priv,
  size_t priv_len,
  const uint8_t *tweak,
  size_t tweak_len,
  uint8_t **npriv,
  size_t *npriv_len
) {
  return false;
}

bool
bcrypto_ecdsa_privkey_negate(
  const char *name,
  const uint8_t *priv,
  size_t priv_len,
  uint8_t **npriv,
  size_t *npriv_len
) {
  return false;
}

bool
bcrypto_ecdsa_privkey_inverse(
  const char *name,
  const uint8_t *priv,
  size_t priv_len,
  uint8_t **npriv,
  size_t *npriv_len
) {
  return false;
}

bool
bcrypto_ecdsa_pubkey_create(
  const char *name,
  const uint8_t *priv,
  size_t priv_len,
  bool compress,
  uint8_t **pub,
  size_t *pub_len
) {
  return false;
}

bool
bcrypto_ecdsa_pubkey_convert(
  const char *name,
  const uint8_t *pub,
  size_t pub_len,
  bool compress,
  uint8_t **npub,
  size_t *npub_len
) {
  return false;
}

bool
bcrypto_ecdsa_pubkey_verify(
  const char *name,
  const uint8_t *pub,
  size_t pub_len
) {
  return false;
}

bool
bcrypto_ecdsa_pubkey_export_spki(
  const char *name,
  const uint8_t *pub,
  size_t pub_len,
  bool compress,
  uint8_t **out,
  size_t *out_len
) {
  return false;
}

bool
bcrypto_ecdsa_pubkey_import_spki(
  const char *name,
  const uint8_t *raw,
  size_t raw_len,
  bool compress,
  uint8_t **out,
  size_t *out_len
) {
  return false;
}

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
) {
  return false;
}

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
) {
  return false;
}

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
) {
  return false;
}

bool
bcrypto_ecdsa_pubkey_negate(
  const char *name,
  const uint8_t *pub,
  size_t pub_len,
  bool compress,
  uint8_t **npub,
  size_t *npub_len
) {
  return false;
}

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
) {
  return false;
}

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
) {
  return false;
}

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
) {
  return false;
}

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
) {
  return false;
}

#endif
