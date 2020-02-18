#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include "openssl/opensslv.h"
#include "rsa.h"

#if OPENSSL_VERSION_NUMBER >= 0x1010008fL

#include "openssl/bn.h"
#include "openssl/crypto.h"
#include "openssl/evp.h"
#include "openssl/objects.h"
#include "openssl/rsa.h"
#include "openssl/x509.h"
#include "../random/random.h"

#define BCRYPTO_RSA_DEFAULT_BITS 2048
#define BCRYPTO_RSA_DEFAULT_EXP 65537
#define BCRYPTO_RSA_MIN_BITS 512
#define BCRYPTO_RSA_MAX_BITS 16384
#define BCRYPTO_RSA_MIN_EXP 3ull
#define BCRYPTO_RSA_MAX_EXP 0x1ffffffffull
#define BCRYPTO_RSA_MIN_EXP_BITS 2
#define BCRYPTO_RSA_MAX_EXP_BITS 33

void
bcrypto_rsa_key_init(bcrypto_rsa_key_t *key) {
  assert(key);
  memset((void *)key, 0x00, sizeof(bcrypto_rsa_key_t));
}

void
bcrypto_rsa_key_free(bcrypto_rsa_key_t *key) {
  assert(key);
  free((void *)key);
}

static size_t
bcrypto_count_bits(const uint8_t *in, size_t in_len) {
  if (in == NULL)
    return 0;

  size_t i = 0;

  for (; i < in_len; i++) {
    if (in[i] != 0)
      break;
  }

  size_t bits = (in_len - i) * 8;

  if (bits == 0)
    return 0;

  bits -= 8;

  uint32_t oct = in[i];

  while (oct) {
    bits += 1;
    oct >>= 1;
  }

  return bits;
}

static bool
bcrypto_rsa_sane_pubkey(const bcrypto_rsa_key_t *key) {
  if (key == NULL)
    return false;

  size_t nb = bcrypto_count_bits(key->nd, key->nl);

  if (nb < BCRYPTO_RSA_MIN_BITS || nb > BCRYPTO_RSA_MAX_BITS)
    return false;

  size_t eb = bcrypto_count_bits(key->ed, key->el);

  if (eb < BCRYPTO_RSA_MIN_EXP_BITS || eb > BCRYPTO_RSA_MAX_EXP_BITS)
    return false;

  if ((key->ed[key->el - 1] & 1) == 0)
    return false;

  return true;
}

static bool
bcrypto_rsa_sane_privkey(const bcrypto_rsa_key_t *key) {
  if (!bcrypto_rsa_sane_pubkey(key))
    return false;

  size_t nb = bcrypto_count_bits(key->nd, key->nl);
  size_t db = bcrypto_count_bits(key->dd, key->dl);

  if (db == 0 || db > nb)
    return false;

  size_t pb = bcrypto_count_bits(key->pd, key->pl);
  size_t qb = bcrypto_count_bits(key->qd, key->ql);

  if (nb > pb + qb)
    return false;

  size_t dpb = bcrypto_count_bits(key->dpd, key->dpl);

  if (dpb == 0 || dpb > pb)
    return false;

  size_t dqb = bcrypto_count_bits(key->dqd, key->dql);

  if (dqb == 0 || dqb > qb)
    return false;

  size_t qib = bcrypto_count_bits(key->qid, key->qil);

  if (qib == 0 || qib > pb)
    return false;

  return true;
}

static bool
bcrypto_rsa_sane_compute(const bcrypto_rsa_key_t *key) {
  if (key == NULL)
    return false;

  size_t nb = bcrypto_count_bits(key->nd, key->nl);
  size_t eb = bcrypto_count_bits(key->ed, key->el);
  size_t db = bcrypto_count_bits(key->dd, key->dl);
  size_t pb = bcrypto_count_bits(key->pd, key->pl);
  size_t qb = bcrypto_count_bits(key->qd, key->ql);
  size_t dpb = bcrypto_count_bits(key->dpd, key->dpl);
  size_t dqb = bcrypto_count_bits(key->dqd, key->dql);
  size_t qib = bcrypto_count_bits(key->qid, key->qil);

  if (pb == 0 || qb == 0)
    return false;

  if (eb == 0 && db == 0)
    return false;

  if (nb != 0) {
    if (nb < BCRYPTO_RSA_MIN_BITS || nb > BCRYPTO_RSA_MAX_BITS)
      return false;

    if (nb > pb + qb)
      return false;
  }

  if (eb != 0) {
    if (eb < BCRYPTO_RSA_MIN_EXP_BITS || eb > BCRYPTO_RSA_MAX_EXP_BITS)
      return false;

    if ((key->ed[key->el - 1] & 1) == 0)
      return false;
  }

  if (db != 0) {
    if (db > pb + qb)
      return false;
  }

  if (dpb != 0) {
    if (dpb > pb)
      return false;
  }

  if (dqb != 0) {
    if (dqb > qb)
      return false;
  }

  if (qib != 0) {
    if (qib > pb)
      return false;
  }

  return true;
}

static bool
bcrypto_rsa_needs_compute(const bcrypto_rsa_key_t *key) {
  if (key == NULL)
    return false;

  return bcrypto_count_bits(key->nd, key->nl) == 0
      || bcrypto_count_bits(key->ed, key->el) == 0
      || bcrypto_count_bits(key->dd, key->dl) == 0
      || bcrypto_count_bits(key->dpd, key->dpl) == 0
      || bcrypto_count_bits(key->dqd, key->dql) == 0
      || bcrypto_count_bits(key->qid, key->qil) == 0;
}

static RSA *
bcrypto_rsa_key2priv(const bcrypto_rsa_key_t *priv) {
  if (priv == NULL)
    return NULL;

  RSA *priv_r = NULL;
  BIGNUM *n = NULL;
  BIGNUM *e = NULL;
  BIGNUM *d = NULL;
  BIGNUM *p = NULL;
  BIGNUM *q = NULL;
  BIGNUM *dp = NULL;
  BIGNUM *dq = NULL;
  BIGNUM *qi = NULL;

  priv_r = RSA_new();

  if (!priv_r)
    goto fail;

  n = BN_bin2bn(priv->nd, priv->nl, NULL);
  e = BN_bin2bn(priv->ed, priv->el, NULL);
  d = BN_bin2bn(priv->dd, priv->dl, NULL);
  p = BN_bin2bn(priv->pd, priv->pl, NULL);
  q = BN_bin2bn(priv->qd, priv->ql, NULL);
  dp = BN_bin2bn(priv->dpd, priv->dpl, NULL);
  dq = BN_bin2bn(priv->dqd, priv->dql, NULL);
  qi = BN_bin2bn(priv->qid, priv->qil, NULL);

  if (!n || !e || !d || !p || !q || !dp || !dq || !qi)
    goto fail;

  if (!RSA_set0_key(priv_r, n, e, d))
    goto fail;

  n = NULL;
  e = NULL;
  d = NULL;

  if (!RSA_set0_factors(priv_r, p, q))
    goto fail;

  p = NULL;
  q = NULL;

  if (!RSA_set0_crt_params(priv_r, dp, dq, qi))
    goto fail;

  return priv_r;

fail:
  if (priv_r)
    RSA_free(priv_r);

  if (n)
    BN_free(n);

  if (e)
    BN_free(e);

  if (d)
    BN_free(d);

  if (p)
    BN_free(p);

  if (q)
    BN_free(q);

  if (dp)
    BN_free(dp);

  if (dq)
    BN_free(dq);

  if (qi)
    BN_free(qi);

  return NULL;
}

static RSA *
bcrypto_rsa_key2pub(const bcrypto_rsa_key_t *pub) {
  if (pub == NULL)
    return NULL;

  RSA *pub_r = NULL;
  BIGNUM *n = NULL;
  BIGNUM *e = NULL;

  pub_r = RSA_new();

  if (!pub_r)
    goto fail;

  n = BN_bin2bn(pub->nd, pub->nl, NULL);
  e = BN_bin2bn(pub->ed, pub->el, NULL);

  if (!n || !e)
    goto fail;

  if (!RSA_set0_key(pub_r, n, e, NULL))
    goto fail;

  return pub_r;

fail:
  if (pub_r)
    RSA_free(pub_r);

  if (n)
    BN_free(n);

  if (e)
    BN_free(e);

  return NULL;
}

static bcrypto_rsa_key_t *
bcrypto_rsa_priv2key(const RSA *priv_r) {
  if (priv_r == NULL)
    return NULL;

  uint8_t *arena = NULL;

  const BIGNUM *n = NULL;
  const BIGNUM *e = NULL;
  const BIGNUM *d = NULL;
  const BIGNUM *p = NULL;
  const BIGNUM *q = NULL;
  const BIGNUM *dp = NULL;
  const BIGNUM *dq = NULL;
  const BIGNUM *qi = NULL;

  RSA_get0_key(priv_r, &n, &e, &d);
  RSA_get0_factors(priv_r, &p, &q);
  RSA_get0_crt_params(priv_r, &dp, &dq, &qi);

  if (!n || !e || !d || !p || !q || !dp || !dq || !qi)
    goto fail;

  size_t nl = BN_num_bytes(n);
  size_t el = BN_num_bytes(e);
  size_t dl = BN_num_bytes(d);
  size_t pl = BN_num_bytes(p);
  size_t ql = BN_num_bytes(q);
  size_t dpl = BN_num_bytes(dp);
  size_t dql = BN_num_bytes(dq);
  size_t qil = BN_num_bytes(qi);

  size_t kl = sizeof(bcrypto_rsa_key_t);
  size_t size = kl + nl + el + dl + pl + ql + dpl + dql + qil;

  arena = malloc(size);

  if (!arena)
    goto fail;

  size_t pos = 0;

  bcrypto_rsa_key_t *priv;

  priv = (bcrypto_rsa_key_t *)&arena[pos];
  bcrypto_rsa_key_init(priv);
  pos += kl;

  priv->nd = (uint8_t *)&arena[pos];
  priv->nl = nl;
  pos += nl;

  priv->ed = (uint8_t *)&arena[pos];
  priv->el = el;
  pos += el;

  priv->dd = (uint8_t *)&arena[pos];
  priv->dl = dl;
  pos += dl;

  priv->pd = (uint8_t *)&arena[pos];
  priv->pl = pl;
  pos += pl;

  priv->qd = (uint8_t *)&arena[pos];
  priv->ql = ql;
  pos += ql;

  priv->dpd = (uint8_t *)&arena[pos];
  priv->dpl = dpl;
  pos += dpl;

  priv->dqd = (uint8_t *)&arena[pos];
  priv->dql = dql;
  pos += dql;

  priv->qid = (uint8_t *)&arena[pos];
  priv->qil = qil;
  pos += qil;

  assert(BN_bn2bin(n, priv->nd) != -1);
  assert(BN_bn2bin(e, priv->ed) != -1);
  assert(BN_bn2bin(d, priv->dd) != -1);
  assert(BN_bn2bin(p, priv->pd) != -1);
  assert(BN_bn2bin(q, priv->qd) != -1);
  assert(BN_bn2bin(dp, priv->dpd) != -1);
  assert(BN_bn2bin(dq, priv->dqd) != -1);
  assert(BN_bn2bin(qi, priv->qid) != -1);

  return priv;

fail:
  if (arena)
    free(arena);

  return NULL;
}

static bcrypto_rsa_key_t *
bcrypto_rsa_pub2key(const RSA *pub_r) {
  if (pub_r == NULL)
    return NULL;

  uint8_t *arena = NULL;

  const BIGNUM *n = NULL;
  const BIGNUM *e = NULL;

  RSA_get0_key(pub_r, &n, &e, NULL);

  if (!n || !e)
    goto fail;

  size_t nl = BN_num_bytes(n);
  size_t el = BN_num_bytes(e);

  size_t kl = sizeof(bcrypto_rsa_key_t);
  size_t size = kl + nl + el;

  arena = malloc(size);

  if (!arena)
    goto fail;

  size_t pos = 0;

  bcrypto_rsa_key_t *pub;

  pub = (bcrypto_rsa_key_t *)&arena[pos];
  bcrypto_rsa_key_init(pub);
  pos += kl;

  pub->nd = (uint8_t *)&arena[pos];
  pub->nl = nl;
  pos += nl;

  pub->ed = (uint8_t *)&arena[pos];
  pub->el = el;
  pos += el;

  assert(BN_bn2bin(n, pub->nd) != -1);
  assert(BN_bn2bin(e, pub->ed) != -1);

  return pub;

fail:
  if (arena)
    free(arena);

  return NULL;
}

static int
bcrypto_rsa_hash_type(const char *alg) {
  if (alg == NULL)
    return -1;

  int type = -1;

  if (0)
    type = -1;

#ifdef NID_blake2b160
  else if (strcmp(alg, "BLAKE2B160") == 0)
    type = NID_blake2b160;
#endif

#ifdef NID_blake2b256
  else if (strcmp(alg, "BLAKE2B256") == 0)
    type = NID_blake2b256;
#endif

#ifdef NID_blake2b384
  else if (strcmp(alg, "BLAKE2B384") == 0)
    type = NID_blake2b384;
#endif

#ifdef NID_blake2b512
  else if (strcmp(alg, "BLAKE2B512") == 0)
    type = NID_blake2b512;
#endif

#ifdef NID_blake2s128
  else if (strcmp(alg, "BLAKE2S128") == 0)
    type = NID_blake2s128;
#endif

#ifdef NID_blake2s160
  else if (strcmp(alg, "BLAKE2S160") == 0)
    type = NID_blake2s160;
#endif

#ifdef NID_blake2s224
  else if (strcmp(alg, "BLAKE2S224") == 0)
    type = NID_blake2s224;
#endif

#ifdef NID_blake2s256
  else if (strcmp(alg, "BLAKE2S256") == 0)
    type = NID_blake2s256;
#endif

#ifdef NID_md2
  else if (strcmp(alg, "MD2") == 0)
    type = NID_md2;
#endif

  else if (strcmp(alg, "MD4") == 0)
    type = NID_md4;
  else if (strcmp(alg, "MD5") == 0)
    type = NID_md5;

#ifdef NID_md5_sha1
  else if (strcmp(alg, "MD5SHA1") == 0)
    type = NID_md5_sha1;
#endif

  else if (strcmp(alg, "RIPEMD160") == 0)
    type = NID_ripemd160;
  else if (strcmp(alg, "SHA1") == 0)
    type = NID_sha1;
  else if (strcmp(alg, "SHA224") == 0)
    type = NID_sha224;
  else if (strcmp(alg, "SHA256") == 0)
    type = NID_sha256;
  else if (strcmp(alg, "SHA384") == 0)
    type = NID_sha384;
  else if (strcmp(alg, "SHA512") == 0)
    type = NID_sha512;

#ifdef NID_sha3_224
  else if (strcmp(alg, "SHA3_224") == 0)
    type = NID_sha3_224;
#endif

#ifdef NID_sha3_256
  else if (strcmp(alg, "SHA3_256") == 0)
    type = NID_sha3_256;
#endif

#ifdef NID_sha3_384
  else if (strcmp(alg, "SHA3_384") == 0)
    type = NID_sha3_384;
#endif

#ifdef NID_sha3_512
  else if (strcmp(alg, "SHA3_512") == 0)
    type = NID_sha3_512;
#endif

#ifdef NID_shake128
  else if (strcmp(alg, "SHAKE128") == 0)
    type = NID_shake128;
#endif

#ifdef NID_shake256
  else if (strcmp(alg, "SHAKE256") == 0)
    type = NID_shake256;
#endif

#ifdef NID_whirlpool
  else if (strcmp(alg, "WHIRLPOOL") == 0)
    type = NID_whirlpool;
#endif

  return type;
}

static size_t
bcrypto_rsa_hash_size(int type) {
  switch (type) {
#ifdef NID_blake2b160
    case NID_blake2b160:
      return 20;
#endif

#ifdef NID_blake2b256
    case NID_blake2b256:
      return 32;
#endif

#ifdef NID_blake2b384
    case NID_blake2b384:
      return 48;
#endif

#ifdef NID_blake2b512
    case NID_blake2b512:
      return 64;
#endif

#ifdef NID_blake2s128
    case NID_blake2s128:
      return 16;
#endif

#ifdef NID_blake2s160
    case NID_blake2s160:
      return 20;
#endif

#ifdef NID_blake2s224
    case NID_blake2s224:
      return 28;
#endif

#ifdef NID_blake2s256
    case NID_blake2s256:
      return 32;
#endif

#ifdef NID_md2
    case NID_md2:
      return 16;
#endif

    case NID_md4:
      return 16;
    case NID_md5:
      return 16;

#ifdef NID_md5_sha1
    case NID_md5_sha1:
      return 36;
#endif

    case NID_ripemd160:
      return 20;
    case NID_sha1:
      return 20;
    case NID_sha224:
      return 28;
    case NID_sha256:
      return 32;
    case NID_sha384:
      return 48;
    case NID_sha512:
      return 64;

#ifdef NID_sha3_224
    case NID_sha3_224:
      return 28;
#endif

#ifdef NID_sha3_256
    case NID_sha3_256:
      return 32;
#endif

#ifdef NID_sha3_384
    case NID_sha3_384:
      return 48;
#endif

#ifdef NID_sha3_512
    case NID_sha3_512:
      return 64;
#endif

#ifdef NID_shake128
    case NID_shake128:
      return 16;
#endif

#ifdef NID_shake256
    case NID_shake256:
      return 32;
#endif

#ifdef NID_whirlpool
    case NID_whirlpool:
      return 64;
#endif

    default:
      return 0;
  }
}

static size_t
bcrypto_rsa_mod_size(const bcrypto_rsa_key_t *key) {
  if (key == NULL)
    return 0;

  return (bcrypto_count_bits(key->nd, key->nl) + 7) / 8;
}

static size_t
bcrypto_rsa_mod_bits(const bcrypto_rsa_key_t *key) {
  if (key == NULL)
    return 0;

  return bcrypto_count_bits(key->nd, key->nl);
}

bcrypto_rsa_key_t *
bcrypto_rsa_privkey_generate(int bits, unsigned long long exp) {
  RSA *priv_r = NULL;
  BIGNUM *exp_bn = NULL;

  if (bits < BCRYPTO_RSA_MIN_BITS || bits > BCRYPTO_RSA_MAX_BITS)
    goto fail;

  if (exp < BCRYPTO_RSA_MIN_EXP || exp > BCRYPTO_RSA_MAX_EXP)
    goto fail;

  if ((exp & 1ull) == 0ull)
    goto fail;

  priv_r = RSA_new();

  if (!priv_r)
    goto fail;

  exp_bn = BN_new();

  if (!exp_bn)
    goto fail;

  if (!BN_set_word(exp_bn, (BN_ULONG)exp))
    goto fail;

  bcrypto_poll();

  if (!RSA_generate_key_ex(priv_r, bits, exp_bn, NULL))
    goto fail;

  bcrypto_rsa_key_t *priv = bcrypto_rsa_priv2key(priv_r);

  if (!priv)
    goto fail;

  RSA_free(priv_r);
  BN_free(exp_bn);

  return priv;

fail:
  if (priv_r)
    RSA_free(priv_r);

  if (exp_bn)
    BN_free(exp_bn);

  return NULL;
}

bool
bcrypto_rsa_privkey_compute(
  const bcrypto_rsa_key_t *priv,
  bcrypto_rsa_key_t **key
) {
  assert(key);

  RSA *priv_r = NULL;
  BIGNUM *rsa_n = NULL;
  BIGNUM *rsa_e = NULL;
  BIGNUM *rsa_d = NULL;
  BIGNUM *rsa_p = NULL;
  BIGNUM *rsa_q = NULL;
  BIGNUM *rsa_dmp1 = NULL;
  BIGNUM *rsa_dmq1 = NULL;
  BIGNUM *rsa_iqmp = NULL;
  BN_CTX *ctx = NULL;
  BIGNUM *r0 = NULL;
  BIGNUM *r1 = NULL;
  BIGNUM *r2 = NULL;
  RSA *out_r = NULL;
  bcrypto_rsa_key_t *out = NULL;

  if (!bcrypto_rsa_sane_compute(priv))
    goto fail;

  if (!bcrypto_rsa_needs_compute(priv)) {
    *key = NULL;
    return true;
  }

  priv_r = bcrypto_rsa_key2priv(priv);

  if (!priv_r)
    goto fail;

  const BIGNUM *n = NULL;
  const BIGNUM *e = NULL;
  const BIGNUM *d = NULL;
  const BIGNUM *p = NULL;
  const BIGNUM *q = NULL;
  const BIGNUM *dp = NULL;
  const BIGNUM *dq = NULL;
  const BIGNUM *qi = NULL;

  RSA_get0_key(priv_r, &n, &e, &d);
  RSA_get0_factors(priv_r, &p, &q);
  RSA_get0_crt_params(priv_r, &dp, &dq, &qi);
  assert(n && e && d && p && q && dp && dq && qi);

  rsa_n = BN_new();
  rsa_e = BN_new();
  rsa_d = BN_new();
  rsa_p = BN_new();
  rsa_q = BN_new();
  rsa_dmp1 = BN_new();
  rsa_dmq1 = BN_new();
  rsa_iqmp = BN_new();

  if (!rsa_n
      || !rsa_e
      || !rsa_d
      || !rsa_p
      || !rsa_q
      || !rsa_dmp1
      || !rsa_dmq1
      || !rsa_iqmp) {
    goto fail;
  }

  if (!BN_copy(rsa_n, n)
      || !BN_copy(rsa_e, e)
      || !BN_copy(rsa_d, d)
      || !BN_copy(rsa_p, p)
      || !BN_copy(rsa_q, q)
      || !BN_copy(rsa_dmp1, dp)
      || !BN_copy(rsa_dmq1, dq)
      || !BN_copy(rsa_iqmp, qi)) {
    goto fail;
  }

  ctx = BN_CTX_new();
  r0 = BN_new();
  r1 = BN_new();
  r2 = BN_new();

  if (!ctx || !r0 || !r1 || !r2)
    goto fail;

  // See: https://github.com/openssl/openssl/blob/82eba37/crypto/rsa/rsa_gen.c

  if (BN_is_zero(rsa_n)) {
    // modulus n = p * q * r_3 * r_4
    if (!BN_mul(rsa_n, rsa_p, rsa_q, ctx))
      goto fail;
  }

  // p - 1
  if (!BN_sub(r1, rsa_p, BN_value_one()))
    goto fail;

  // q - 1
  if (!BN_sub(r2, rsa_q, BN_value_one()))
    goto fail;

  // (p - 1)(q - 1)
  if (!BN_mul(r0, r1, r2, ctx))
    goto fail;

  if (BN_is_zero(rsa_e)) {
    BIGNUM *pr0 = BN_new();

    if (pr0 == NULL)
      goto fail;

    BN_with_flags(pr0, r0, BN_FLG_CONSTTIME);

    if (!BN_mod_inverse(rsa_e, rsa_d, pr0, ctx)) {
      BN_free(pr0);
      goto fail;
    }

    BN_free(pr0);
  }

  if (BN_is_zero(rsa_d)) {
    BIGNUM *pr0 = BN_new();

    if (pr0 == NULL)
      goto fail;

    BN_with_flags(pr0, r0, BN_FLG_CONSTTIME);

    if (!BN_mod_inverse(rsa_d, rsa_e, pr0, ctx)) {
      BN_free(pr0);
      goto fail;
    }

    BN_free(pr0);
  }

  if (BN_is_zero(rsa_dmp1) || BN_is_zero(rsa_dmq1)) {
    BIGNUM *d = BN_new();

    if (d == NULL)
      goto fail;

    BN_with_flags(d, rsa_d, BN_FLG_CONSTTIME);

    // calculate d mod (p-1) and d mod (q - 1)
    if (!BN_mod(rsa_dmp1, d, r1, ctx)
        || !BN_mod(rsa_dmq1, d, r2, ctx)) {
      BN_free(d);
      goto fail;
    }

    BN_free(d);
  }

  if (BN_is_zero(rsa_iqmp)) {
    BIGNUM *p = BN_new();

    if (p == NULL)
      goto fail;

    BN_with_flags(p, rsa_p, BN_FLG_CONSTTIME);

    // calculate inverse of q mod p
    if (!BN_mod_inverse(rsa_iqmp, rsa_q, p, ctx)) {
      BN_free(p);
      goto fail;
    }

    BN_free(p);
  }

  out_r = RSA_new();

  if (!out_r)
    goto fail;

  assert(RSA_set0_key(out_r, rsa_n, rsa_e, rsa_d));

  rsa_n = NULL;
  rsa_e = NULL;
  rsa_d = NULL;

  assert(RSA_set0_factors(out_r, rsa_p, rsa_q));

  rsa_p = NULL;
  rsa_q = NULL;

  assert(RSA_set0_crt_params(out_r, rsa_dmp1, rsa_dmq1, rsa_iqmp));

  rsa_dmp1 = NULL;
  rsa_dmq1 = NULL;
  rsa_iqmp = NULL;

  out = bcrypto_rsa_priv2key(out_r);

  if (!out)
    goto fail;

  RSA_free(priv_r);
  BN_CTX_free(ctx);
  BN_free(r0);
  BN_free(r1);
  BN_free(r2);
  RSA_free(out_r);

  *key = out;

  return true;

fail:
  if (priv_r)
    RSA_free(priv_r);

  if (rsa_n)
    BN_free(rsa_n);

  if (rsa_e)
    BN_free(rsa_e);

  if (rsa_d)
    BN_free(rsa_d);

  if (rsa_p)
    BN_free(rsa_p);

  if (rsa_q)
    BN_free(rsa_q);

  if (rsa_dmp1)
    BN_free(rsa_dmp1);

  if (rsa_dmq1)
    BN_free(rsa_dmq1);

  if (rsa_iqmp)
    BN_free(rsa_iqmp);

  if (ctx)
    BN_CTX_free(ctx);

  if (r0)
    BN_free(r0);

  if (r1)
    BN_free(r1);

  if (r2)
    BN_free(r2);

  if (out_r)
    RSA_free(out_r);

  return false;
}

bool
bcrypto_rsa_privkey_verify(const bcrypto_rsa_key_t *priv) {
  RSA *priv_r = NULL;

  if (!bcrypto_rsa_sane_privkey(priv))
    goto fail;

  priv_r = bcrypto_rsa_key2priv(priv);

  if (!priv_r)
    goto fail;

  if (RSA_check_key(priv_r) <= 0)
    goto fail;

  RSA_free(priv_r);

  return true;

fail:
  if (priv_r)
    RSA_free(priv_r);

  return false;
}

bool
bcrypto_rsa_privkey_export(
  const bcrypto_rsa_key_t *priv,
  uint8_t **out,
  size_t *out_len
) {
  assert(out && out_len);

  if (!bcrypto_rsa_sane_privkey(priv))
    return false;

  RSA *priv_r = bcrypto_rsa_key2priv(priv);

  if (!priv_r)
    return false;

  uint8_t *buf = NULL;
  int len = i2d_RSAPrivateKey(priv_r, &buf);

  RSA_free(priv_r);

  if (len <= 0)
    return false;

  *out = buf;
  *out_len = (size_t)len;

  return true;
}

bcrypto_rsa_key_t *
bcrypto_rsa_privkey_import(
  const uint8_t *raw,
  size_t raw_len
) {
  RSA *priv_r = NULL;
  const uint8_t *p = raw;

  if (!d2i_RSAPrivateKey(&priv_r, &p, raw_len))
    return NULL;

  bcrypto_rsa_key_t *k = bcrypto_rsa_priv2key(priv_r);

  RSA_free(priv_r);

  return k;
}

bool
bcrypto_rsa_privkey_export_pkcs8(
  const bcrypto_rsa_key_t *priv,
  uint8_t **out,
  size_t *out_len
) {
  assert(out && out_len);

  // https://github.com/openssl/openssl/blob/32f803d/crypto/rsa/rsa_ameth.c#L142
  RSA *rsa = NULL;
  PKCS8_PRIV_KEY_INFO *p8 = NULL;
  unsigned char *rk = NULL;
  int rklen;

  if (!bcrypto_rsa_sane_privkey(priv))
    goto fail;

  rsa = bcrypto_rsa_key2priv(priv);

  if (!rsa)
    goto fail;

  p8 = PKCS8_PRIV_KEY_INFO_new();

  if (!p8)
    goto fail;

  rklen = i2d_RSAPrivateKey(rsa, &rk);

  if (rklen <= 0)
    goto fail;

  if (!PKCS8_pkey_set0(p8, OBJ_nid2obj(NID_rsaEncryption), 0,
                       V_ASN1_NULL, NULL, rk, rklen)) {
    goto fail;
  }

  rk = NULL;

  uint8_t *buf = NULL;
  int len = i2d_PKCS8_PRIV_KEY_INFO(p8, &buf);

  if (len <= 0)
    goto fail;

  *out = buf;
  *out_len = (size_t)len;

  RSA_free(rsa);
  PKCS8_PRIV_KEY_INFO_free(p8);

  return true;

fail:
  if (rsa)
    RSA_free(rsa);

  if (p8)
    PKCS8_PRIV_KEY_INFO_free(p8);

  if (rk)
    free(rk);

  return false;
}

bcrypto_rsa_key_t *
bcrypto_rsa_privkey_import_pkcs8(
  const uint8_t *raw,
  size_t raw_len
) {
  // https://github.com/openssl/openssl/blob/32f803d/crypto/rsa/rsa_ameth.c#L169
  PKCS8_PRIV_KEY_INFO *p8 = NULL;
  const unsigned char *p;
  RSA *rsa = NULL;
  int pklen;
  const X509_ALGOR *alg;
  const ASN1_OBJECT *algoid;
  const void *algp;
  int algptype;

  const uint8_t *pp = raw;

  if (!d2i_PKCS8_PRIV_KEY_INFO(&p8, &pp, raw_len))
    goto fail;

  if (!PKCS8_pkey_get0(NULL, &p, &pklen, &alg, p8))
    goto fail;

  // https://github.com/openssl/openssl/blob/32f803d/crypto/rsa/rsa_ameth.c#L54
  X509_ALGOR_get0(&algoid, &algptype, &algp, alg);

  if (OBJ_obj2nid(algoid) != NID_rsaEncryption)
    goto fail;

  if (algptype != V_ASN1_UNDEF && algptype != V_ASN1_NULL)
    goto fail;

  rsa = d2i_RSAPrivateKey(NULL, &p, pklen);

  if (!rsa)
    goto fail;

  bcrypto_rsa_key_t *k = bcrypto_rsa_priv2key(rsa);

  PKCS8_PRIV_KEY_INFO_free(p8);
  RSA_free(rsa);

  return k;

fail:
  if (p8)
    PKCS8_PRIV_KEY_INFO_free(p8);

  if (rsa)
    RSA_free(rsa);

  return NULL;
}

bool
bcrypto_rsa_pubkey_verify(const bcrypto_rsa_key_t *pub) {
  return bcrypto_rsa_sane_pubkey(pub);
}

bool
bcrypto_rsa_pubkey_export(
  const bcrypto_rsa_key_t *pub,
  uint8_t **out,
  size_t *out_len
) {
  assert(out && out_len);

  if (!bcrypto_rsa_sane_pubkey(pub))
    return false;

  RSA *pub_r = bcrypto_rsa_key2pub(pub);

  if (!pub_r)
    return false;

  uint8_t *buf = NULL;
  int len = i2d_RSAPublicKey(pub_r, &buf);

  RSA_free(pub_r);

  if (len <= 0)
    return false;

  *out = buf;
  *out_len = (size_t)len;

  return true;
}

bcrypto_rsa_key_t *
bcrypto_rsa_pubkey_import(
  const uint8_t *raw,
  size_t raw_len
) {
  RSA *pub_r = NULL;
  const uint8_t *p = raw;

  if (!d2i_RSAPublicKey(&pub_r, &p, raw_len))
    return NULL;

  bcrypto_rsa_key_t *k = bcrypto_rsa_pub2key(pub_r);

  RSA_free(pub_r);

  return k;
}

bool
bcrypto_rsa_pubkey_export_spki(
  const bcrypto_rsa_key_t *pub,
  uint8_t **out,
  size_t *out_len
) {
  assert(out && out_len);

  if (!bcrypto_rsa_sane_pubkey(pub))
    return false;

  RSA *pub_r = bcrypto_rsa_key2pub(pub);

  if (!pub_r)
    return false;

  uint8_t *buf = NULL;
  int len = i2d_RSA_PUBKEY(pub_r, &buf);

  RSA_free(pub_r);

  if (len <= 0)
    return false;

  *out = buf;
  *out_len = (size_t)len;

  return true;
}

bcrypto_rsa_key_t *
bcrypto_rsa_pubkey_import_spki(
  const uint8_t *raw,
  size_t raw_len
) {
  RSA *pub_r = NULL;
  const uint8_t *p = raw;

  if (!d2i_RSA_PUBKEY(&pub_r, &p, raw_len))
    return NULL;

  bcrypto_rsa_key_t *k = bcrypto_rsa_pub2key(pub_r);

  RSA_free(pub_r);

  return k;
}

bool
bcrypto_rsa_sign(
  const char *alg,
  const uint8_t *msg,
  size_t msg_len,
  const bcrypto_rsa_key_t *priv,
  uint8_t **sig,
  size_t *sig_len
) {
  assert(sig && sig_len);

  int type = -1;
  RSA *priv_r = NULL;
  unsigned int sig_buf_len = 0;
  uint8_t *sig_buf = NULL;
  int result = 0;

  type = bcrypto_rsa_hash_type(alg);

  if (type == -1)
    goto fail;

  if (msg == NULL || msg_len != bcrypto_rsa_hash_size(type))
    goto fail;

  if (!bcrypto_rsa_sane_privkey(priv))
    goto fail;

  priv_r = bcrypto_rsa_key2priv(priv);

  if (!priv_r)
    goto fail;

  sig_buf_len = RSA_size(priv_r);
  sig_buf = malloc(sig_buf_len);

  if (!sig_buf)
    goto fail;

  bcrypto_poll();

  // Protect against side-channel attacks.
  if (!RSA_blinding_on(priv_r, NULL))
    goto fail;

  // $ man RSA_sign
  // tlen is always modulus size.
  // https://github.com/openssl/openssl/blob/32f803d/crypto/rsa/rsa_sign.c#L69
  // https://github.com/openssl/openssl/blob/32f803d/crypto/rsa/rsa_ossl.c#L238
  result = RSA_sign(
    type,
    msg,
    msg_len,
    sig_buf,
    &sig_buf_len,
    priv_r
  );

  RSA_blinding_off(priv_r);

  if (!result)
    goto fail;

  assert((int)sig_buf_len == RSA_size(priv_r));

  RSA_free(priv_r);

  *sig = sig_buf;
  *sig_len = (size_t)sig_buf_len;

  return true;

fail:
  if (priv_r)
    RSA_free(priv_r);

  if (sig_buf)
    free(sig_buf);

  return false;
}

bool
bcrypto_rsa_verify(
  const char *alg,
  const uint8_t *msg,
  size_t msg_len,
  const uint8_t *sig,
  size_t sig_len,
  const bcrypto_rsa_key_t *pub
) {
  int type = -1;
  RSA *pub_r = NULL;

  type = bcrypto_rsa_hash_type(alg);

  if (type == -1)
    goto fail;

  if (msg == NULL || msg_len != bcrypto_rsa_hash_size(type))
    goto fail;

  if (sig == NULL || sig_len != bcrypto_rsa_mod_size(pub))
    goto fail;

  if (!bcrypto_rsa_sane_pubkey(pub))
    goto fail;

  pub_r = bcrypto_rsa_key2pub(pub);

  if (!pub_r)
    goto fail;

  // flen _must_ be modulus length.
  // https://github.com/openssl/openssl/blob/32f803d/crypto/rsa/rsa_sign.c#L124
  if (RSA_verify(type, msg, msg_len, sig, sig_len, pub_r) <= 0)
    goto fail;

  RSA_free(pub_r);

  return true;
fail:
  if (pub_r)
    RSA_free(pub_r);

  return false;
}

bool
bcrypto_rsa_encrypt(
  const uint8_t *msg,
  size_t msg_len,
  const bcrypto_rsa_key_t *pub,
  uint8_t **ct,
  size_t *ct_len
) {
  assert(ct && ct_len);

  RSA *pub_r = NULL;
  uint8_t *c = NULL;
  int c_len = 0;

  if (!bcrypto_rsa_sane_pubkey(pub))
    goto fail;

  pub_r = bcrypto_rsa_key2pub(pub);

  if (!pub_r)
    goto fail;

  c = malloc(RSA_size(pub_r));

  if (!c)
    goto fail;

  bcrypto_poll();

  // $ man RSA_public_encrypt
  // flen must be size of modulus.
  // tlen is always modulus size.
  // https://github.com/openssl/openssl/blob/32f803d/crypto/rsa/rsa_ossl.c#L67
  // https://github.com/openssl/openssl/blob/32f803d/crypto/rsa/rsa_none.c#L14
  c_len = RSA_public_encrypt(
    msg_len,          // int flen
    msg,              // const uint8_t *from
    c,                // uint8_t *to
    pub_r,            // RSA *rsa
    RSA_PKCS1_PADDING // int padding
  );

  if (c_len <= 0)
    goto fail;

  assert(c_len == RSA_size(pub_r));

  RSA_free(pub_r);

  *ct = c;
  *ct_len = (size_t)c_len;

  return true;

fail:
  if (pub_r)
    RSA_free(pub_r);

  if (c)
    free(c);

  return false;
}

bool
bcrypto_rsa_decrypt(
  const uint8_t *msg,
  size_t msg_len,
  const bcrypto_rsa_key_t *priv,
  uint8_t **pt,
  size_t *pt_len
) {
  assert(pt && pt_len);

  RSA *priv_r = NULL;
  uint8_t *out = NULL;
  int out_len = 0;

  if (msg == NULL || msg_len != bcrypto_rsa_mod_size(priv))
    goto fail;

  if (!bcrypto_rsa_sane_privkey(priv))
    goto fail;

  priv_r = bcrypto_rsa_key2priv(priv);

  if (!priv_r)
    goto fail;

  out = malloc(RSA_size(priv_r));

  if (!out)
    goto fail;

  bcrypto_poll();

  // Protect against side-channel attacks.
  if (!RSA_blinding_on(priv_r, NULL))
    goto fail;

  // $ man RSA_private_decrypt
  // flen can be smaller than modulus.
  // tlen is less than modulus size for pkcs1.
  // https://github.com/openssl/openssl/blob/32f803d/crypto/rsa/rsa_ossl.c#L374
  out_len = RSA_private_decrypt(
    msg_len,          // int flen
    msg,              // const uint8_t *from
    out,              // uint8_t *to
    priv_r,           // RSA *rsa
    RSA_PKCS1_PADDING // int padding
  );

  RSA_blinding_off(priv_r);

  if (out_len < 0)
    goto fail;

  if (out_len == 0) {
    free(out);
    out = NULL;
  }

  RSA_free(priv_r);

  *pt = out;
  *pt_len = (size_t)out_len;

  return true;

fail:
  if (priv_r)
    RSA_free(priv_r);

  if (out)
    free(out);

  return false;
}

bool
bcrypto_rsa_encrypt_oaep(
  const char *alg,
  const uint8_t *msg,
  size_t msg_len,
  const bcrypto_rsa_key_t *pub,
  const uint8_t *label,
  size_t label_len,
  uint8_t **ct,
  size_t *ct_len
) {
  assert(ct && ct_len);

  int type = -1;
  const EVP_MD *md = NULL;
  RSA *pub_r = NULL;
  uint8_t *em = NULL;
  uint8_t *c = NULL;
  int result = 0;
  int c_len = 0;

  type = bcrypto_rsa_hash_type(alg);

  if (type == -1)
    goto fail;

  md = EVP_get_digestbynid(type);

  if (!md)
    goto fail;

  if (!bcrypto_rsa_sane_pubkey(pub))
    goto fail;

  pub_r = bcrypto_rsa_key2pub(pub);

  if (!pub_r)
    goto fail;

  em = malloc(RSA_size(pub_r));

  if (!em)
    goto fail;

  c = malloc(RSA_size(pub_r));

  if (!c)
    goto fail;

  memset(em, 0x00, RSA_size(pub_r));

  bcrypto_poll();

  // $ man RSA_padding_add_PKCS1_OAEP
  // https://github.com/openssl/openssl/blob/82eba37/crypto/rsa/rsa_oaep.c#L41
  result = RSA_padding_add_PKCS1_OAEP_mgf1(
    em,              // uint8_t *to
    RSA_size(pub_r), // int tlen
    msg,             // const uint8_t *from
    msg_len,         // int flen
    label,           // const uint8_t *param
    label_len,       // int plen
    md,              // const EVP_MD *md
    md               // const EVP_MD *mgf1md
  );

  if (!result)
    goto fail;

  // $ man RSA_public_encrypt
  // flen must be size of modulus.
  // tlen is always modulus size.
  // https://github.com/openssl/openssl/blob/32f803d/crypto/rsa/rsa_ossl.c#L67
  c_len = RSA_public_encrypt(
    RSA_size(pub_r), // int flen
    em,              // const uint8_t *from
    c,               // uint8_t *to
    pub_r,           // RSA *rsa
    RSA_NO_PADDING   // int padding
  );

  OPENSSL_cleanse(em, RSA_size(pub_r));

  if (c_len <= 0)
    goto fail;

  assert(c_len == RSA_size(pub_r));

  RSA_free(pub_r);
  free(em);

  *ct = c;
  *ct_len = (size_t)c_len;

  return true;

fail:
  if (pub_r)
    RSA_free(pub_r);

  if (em)
    free(em);

  if (c)
    free(c);

  return false;
}

bool
bcrypto_rsa_decrypt_oaep(
  const char *alg,
  const uint8_t *msg,
  size_t msg_len,
  const bcrypto_rsa_key_t *priv,
  const uint8_t *label,
  size_t label_len,
  uint8_t **pt,
  size_t *pt_len
) {
  assert(pt && pt_len);

  int type = -1;
  const EVP_MD *md = NULL;
  RSA *priv_r = NULL;
  uint8_t *em = NULL;
  int em_len = 0;
  uint8_t *out = NULL;
  int out_len = 0;

  type = bcrypto_rsa_hash_type(alg);

  if (type == -1)
    goto fail;

  md = EVP_get_digestbynid(type);

  if (!md)
    goto fail;

  if (msg == NULL || msg_len != bcrypto_rsa_mod_size(priv))
    goto fail;

  if (!bcrypto_rsa_sane_privkey(priv))
    goto fail;

  priv_r = bcrypto_rsa_key2priv(priv);

  if (!priv_r)
    goto fail;

  em = malloc(RSA_size(priv_r));

  if (!em)
    goto fail;

  bcrypto_poll();

  // Protect against side-channel attacks.
  if (!RSA_blinding_on(priv_r, NULL))
    goto fail;

  memset(em, 0x00, RSA_size(priv_r));

  // $ man RSA_private_decrypt
  // flen can be smaller than modulus.
  // tlen is always modulus size.
  // https://github.com/openssl/openssl/blob/32f803d/crypto/rsa/rsa_ossl.c#L374
  em_len = RSA_private_decrypt(
    msg_len,       // int flen
    msg,           // const uint8_t *from
    em,            // uint8_t *to
    priv_r,        // RSA *rsa
    RSA_NO_PADDING // int padding
  );

  RSA_blinding_off(priv_r);

  if (em_len <= 0)
    goto fail;

  assert(em_len == RSA_size(priv_r));

  out = malloc(RSA_size(priv_r));

  if (!out) {
    OPENSSL_cleanse(em, RSA_size(priv_r));
    goto fail;
  }

  // https://github.com/openssl/openssl/blob/82eba37/crypto/rsa/rsa_oaep.c#L116
  out_len = RSA_padding_check_PKCS1_OAEP_mgf1(
    out,              // uint8_t *to
    RSA_size(priv_r), // int tlen
    em,               // const uint8_t *from
    em_len,           // int flen
    RSA_size(priv_r), // int num (modulus size)
    label,            // const uint8_t *param
    label_len,        // int plen
    md,               // const EVP_MD *md
    md                // const EVP_MD *mgf1md
  );

  OPENSSL_cleanse(em, RSA_size(priv_r));

  if (out_len < 0)
    goto fail;

  if (out_len == 0) {
    free(out);
    out = NULL;
  }

  RSA_free(priv_r);
  free(em);

  *pt = out;
  *pt_len = (size_t)out_len;

  return true;

fail:
  if (priv_r)
    RSA_free(priv_r);

  if (em)
    free(em);

  if (out)
    free(out);

  return false;
}

bool
bcrypto_rsa_sign_pss(
  const char *alg,
  const uint8_t *msg,
  size_t msg_len,
  const bcrypto_rsa_key_t *priv,
  int salt_len,
  uint8_t **sig,
  size_t *sig_len
) {
  assert(sig && sig_len);

  int type = -1;
  const EVP_MD *md = NULL;
  RSA *priv_r = NULL;
  uint8_t *em = NULL;
  int result = 0;
  uint8_t *c = NULL;
  int c_len = 0;

  type = bcrypto_rsa_hash_type(alg);

  if (type == -1)
    goto fail;

  md = EVP_get_digestbynid(type);

  if (!md)
    goto fail;

  if (msg == NULL || msg_len != bcrypto_rsa_hash_size(type))
    goto fail;

  if (!bcrypto_rsa_sane_privkey(priv))
    goto fail;

  if (salt_len < -1)
    goto fail;

  priv_r = bcrypto_rsa_key2priv(priv);

  if (!priv_r)
    goto fail;

  em = malloc(RSA_size(priv_r));

  if (!em)
    goto fail;

  if (salt_len == 0)
    salt_len = -2; // RSA_PSS_SALTLEN_MAX_SIGN
  else if (salt_len == -1)
    salt_len = -1; // RSA_PSS_SALTLEN_DIGEST

  memset(em, 0x00, RSA_size(priv_r));

  bcrypto_poll();

  // tlen is always modulus size.
  // https://github.com/openssl/openssl/blob/82eba37/crypto/rsa/rsa_pss.c#L145
  // https://github.com/openssl/openssl/blob/82eba37/crypto/rsa/rsa_pmeth.c#L122
  result = RSA_padding_add_PKCS1_PSS_mgf1(
    priv_r,  // RSA *rsa
    em,      // uint8_t *EM
    msg,     // const uint8_t *mHash
    md,      // const EVP_MD *Hash
    md,      // const EVP_MD *mgf1Hash
    salt_len // int sLen
  );

  if (!result)
    goto fail;

  c = malloc(RSA_size(priv_r));

  if (!c) {
    OPENSSL_cleanse(em, RSA_size(priv_r));
    goto fail;
  }

  // Protect against side-channel attacks.
  if (!RSA_blinding_on(priv_r, NULL)) {
    OPENSSL_cleanse(em, RSA_size(priv_r));
    goto fail;
  }

  // $ man RSA_private_encrypt
  // flen must be modulus size.
  // tlen is always modulus size.
  // https://github.com/openssl/openssl/blob/32f803d/crypto/rsa/rsa_ossl.c#L238
  c_len = RSA_private_encrypt(
    RSA_size(priv_r), // int flen
    em,               // const uint8_t *from
    c,                // uint8_t *to
    priv_r,           // RSA *rsa
    RSA_NO_PADDING    // int padding
  );

  OPENSSL_cleanse(em, RSA_size(priv_r));

  RSA_blinding_off(priv_r);

  if (c_len <= 0)
    goto fail;

  assert(c_len == RSA_size(priv_r));

  RSA_free(priv_r);
  free(em);

  *sig = c;
  *sig_len = (size_t)c_len;

  return true;

fail:
  if (priv_r)
    RSA_free(priv_r);

  if (em)
    free(em);

  if (c)
    free(c);

  return false;
}

bool
bcrypto_rsa_verify_pss(
  const char *alg,
  const uint8_t *msg,
  size_t msg_len,
  const uint8_t *sig,
  size_t sig_len,
  const bcrypto_rsa_key_t *pub,
  int salt_len
) {
  int type = 0;
  const EVP_MD *md = NULL;
  RSA *pub_r = NULL;
  uint8_t *em = NULL;
  int em_len = 0;
  int result = 0;

  type = bcrypto_rsa_hash_type(alg);

  if (type == -1)
    goto fail;

  md = EVP_get_digestbynid(type);

  if (!md)
    goto fail;

  if (msg == NULL || msg_len != bcrypto_rsa_hash_size(type))
    goto fail;

  if (sig == NULL || sig_len != bcrypto_rsa_mod_size(pub))
    goto fail;

  if (!bcrypto_rsa_sane_pubkey(pub))
    goto fail;

  pub_r = bcrypto_rsa_key2pub(pub);

  if (!pub_r)
    goto fail;

  em = malloc(RSA_size(pub_r));

  if (!em)
    goto fail;

  memset(em, 0x00, RSA_size(pub_r));

  // $ man RSA_public_decrypt
  // flen can be smaller than modulus size.
  // tlen is always modulus size.
  // https://github.com/openssl/openssl/blob/32f803d/crypto/rsa/rsa_ossl.c#L507
  em_len = RSA_public_decrypt(
    sig_len,       // int flen
    sig,           // const uint8_t *from
    em,            // uint8_t *to
    pub_r,         // RSA *rsa
    RSA_NO_PADDING // int padding
  );

  if (em_len <= 0)
    goto fail;

  assert(em_len == RSA_size(pub_r));

  if (salt_len == 0)
    salt_len = -2; // RSA_PSS_SALTLEN_AUTO
  else if (salt_len == -1)
    salt_len = -1; // RSA_PSS_SALTLEN_DIGEST

  // https://github.com/openssl/openssl/blob/82eba37/crypto/rsa/rsa_pss.c#L32
  result = RSA_verify_PKCS1_PSS_mgf1(
    pub_r,   // RSA *rsa
    msg,     // const uint8_t *mHash
    md,      // const EVP_MD *Hash
    md,      // const EVP_MD *mgf1Hash
    em,      // const uint8_t *EM
    salt_len // int sLen
  );

  OPENSSL_cleanse(em, RSA_size(pub_r));

  if (!result)
    goto fail;

  RSA_free(pub_r);
  free(em);

  return true;

fail:
  if (pub_r)
    RSA_free(pub_r);

  if (em)
    free(em);

  return false;
}

bool
bcrypto_rsa_encrypt_raw(
  const uint8_t *msg,
  size_t msg_len,
  const bcrypto_rsa_key_t *pub,
  uint8_t **out,
  size_t *out_len
) {
  assert(out && out_len);

  RSA *pub_r = NULL;
  uint8_t *c = NULL;
  int c_len = 0;

  if (!bcrypto_rsa_sane_pubkey(pub))
    goto fail;

  pub_r = bcrypto_rsa_key2pub(pub);

  if (!pub_r)
    goto fail;

  c = malloc(RSA_size(pub_r));

  if (!c)
    goto fail;

  // $ man RSA_public_encrypt
  // flen must be size of modulus.
  // tlen is always modulus size.
  // https://github.com/openssl/openssl/blob/32f803d/crypto/rsa/rsa_ossl.c#L67
  c_len = RSA_public_encrypt(
    msg_len,       // int flen
    msg,           // const uint8_t *from
    c,             // uint8_t *to
    pub_r,         // RSA *rsa
    RSA_NO_PADDING // int padding
  );

  if (c_len <= 0)
    goto fail;

  assert(c_len == RSA_size(pub_r));

  RSA_free(pub_r);

  *out = c;
  *out_len = (size_t)c_len;

  return true;

fail:
  if (pub_r)
    RSA_free(pub_r);

  if (c)
    free(c);

  return false;
}

bool
bcrypto_rsa_decrypt_raw(
  const uint8_t *msg,
  size_t msg_len,
  const bcrypto_rsa_key_t *priv,
  uint8_t **out,
  size_t *out_len
) {
  assert(out && out_len);

  RSA *priv_r = NULL;
  uint8_t *em = NULL;
  int em_len = 0;

  if (!bcrypto_rsa_sane_privkey(priv))
    goto fail;

  priv_r = bcrypto_rsa_key2priv(priv);

  if (!priv_r)
    goto fail;

  em = malloc(RSA_size(priv_r));

  if (!em)
    goto fail;

  bcrypto_poll();

  // Protect against side-channel attacks.
  if (!RSA_blinding_on(priv_r, NULL))
    goto fail;

  // $ man RSA_private_decrypt
  // flen can be smaller than modulus.
  // tlen is always modulus size.
  // https://github.com/openssl/openssl/blob/32f803d/crypto/rsa/rsa_ossl.c#L374
  em_len = RSA_private_decrypt(
    msg_len,          // int flen
    msg,              // const uint8_t *from
    em,               // uint8_t *to
    priv_r,           // RSA *rsa
    RSA_NO_PADDING    // int padding
  );

  RSA_blinding_off(priv_r);

  if (em_len <= 0)
    goto fail;

  assert(em_len == RSA_size(priv_r));

  RSA_free(priv_r);

  *out = em;
  *out_len = (size_t)em_len;

  return true;

fail:
  if (priv_r)
    RSA_free(priv_r);

  if (em)
    free(em);

  return false;
}

bool
bcrypto_rsa_veil(
  const uint8_t *msg,
  size_t msg_len,
  size_t bits,
  const bcrypto_rsa_key_t *pub,
  uint8_t **out,
  size_t *out_len
) {
  assert(out && out_len);

  bool ret = false;
  BN_CTX *ctx = NULL;
  BIGNUM *c0 = NULL;
  BIGNUM *n = NULL;
  BIGNUM *ctlim = NULL;
  BIGNUM *rlim = NULL;
  BIGNUM *c1 = NULL;
  BIGNUM *cr = NULL;
  uint8_t *c = NULL;
  int c_len = 0;

  if (msg == NULL || msg_len != bcrypto_rsa_mod_size(pub))
    goto fail;

  if (!bcrypto_rsa_sane_pubkey(pub))
    goto fail;

  // Can't make ciphertext smaller.
  if (bits < bcrypto_rsa_mod_bits(pub))
    goto fail;

  ctx = BN_CTX_new();
  c0 = BN_bin2bn(msg, msg_len, NULL);
  n = BN_bin2bn(pub->nd, pub->nl, NULL);
  ctlim = BN_new();
  rlim = BN_new();
  c1 = BN_new();
  cr = BN_new();

  if (!ctx || !c0 || !n || !ctlim || !rlim || !c1 || !cr)
    goto fail;

  // Invalid ciphertext.
  if (BN_ucmp(c0, n) >= 0)
    goto fail;

  // ctlim = 1 << (bits + 0)
  if (!BN_set_word(ctlim, 1)
      || !BN_lshift(ctlim, ctlim, bits)) {
    goto fail;
  }

  // rlim = (ctlim - c0 + n - 1) / n
  if (!BN_copy(rlim, ctlim)
      || !BN_sub(rlim, rlim, c0)
      || !BN_add(rlim, rlim, n)
      || !BN_sub(rlim, rlim, BN_value_one())
      || !BN_div(rlim, NULL, rlim, n, ctx)) {
    goto fail;
  }

  // c1 = ctlim
  if (!BN_copy(c1, ctlim))
    goto fail;

  bcrypto_poll();

  // while c1 >= ctlim
  while (BN_ucmp(c1, ctlim) >= 0) {
    // cr = random_int(rlim)
    if (!BN_rand_range(cr, rlim))
      goto fail;

    if (BN_ucmp(rlim, BN_value_one()) > 0 && BN_is_zero(cr))
      continue;

    // c1 = c0 + cr * n
    if (!BN_mul(cr, cr, n, ctx))
      goto fail;

    if (!BN_add(c1, c0, cr))
      goto fail;
  }

  if (!BN_mod(cr, c1, n, ctx))
    goto fail;

  assert(BN_ucmp(cr, c0) == 0);
  assert((size_t)BN_num_bits(c1) <= bits);

  c_len = (bits + 7) / 8;
  c = malloc(c_len);

  if (!c)
    goto fail;

  assert(BN_bn2binpad(c1, c, c_len) != -1);

  *out = c;
  *out_len = c_len;
  c = NULL;

  ret = true;
fail:
  if (ctx)
    BN_CTX_free(ctx);
  if (c0)
    BN_free(c0);
  if (n)
    BN_free(n);
  if (ctlim)
    BN_free(ctlim);
  if (rlim)
    BN_free(rlim);
  if (c1)
    BN_free(c1);
  if (cr)
    BN_free(cr);
  if (c)
    free(c);
  return ret;
}

bool
bcrypto_rsa_unveil(
  const uint8_t *msg,
  size_t msg_len,
  size_t bits,
  const bcrypto_rsa_key_t *pub,
  uint8_t **out,
  size_t *out_len
) {
  assert(out && out_len);

  bool ret = false;
  BN_CTX *ctx = NULL;
  BIGNUM *c1 = NULL;
  BIGNUM *n = NULL;
  uint8_t *c = NULL;
  int c_len = 0;

  size_t klen = bcrypto_rsa_mod_size(pub);

  if (msg == NULL || msg_len < klen)
    goto fail;

  if (!bcrypto_rsa_sane_pubkey(pub))
    goto fail;

  if (bcrypto_count_bits(msg, msg_len) > bits)
    goto fail;

  ctx = BN_CTX_new();
  c1 = BN_bin2bn(msg, msg_len, NULL);
  n = BN_bin2bn(pub->nd, pub->nl, NULL);

  if (!ctx || !c1 || !n)
    goto fail;

  // c0 = c1 % n
  if (!BN_mod(c1, c1, n, ctx))
    goto fail;

  assert((size_t)BN_num_bytes(c1) <= klen);

  c_len = klen;
  c = malloc(c_len);

  if (!c)
    goto fail;

  assert(BN_bn2binpad(c1, c, c_len) != -1);

  *out = c;
  *out_len = c_len;
  c = NULL;

  ret = true;
fail:
  if (ctx)
    BN_CTX_free(ctx);
  if (c1)
    BN_free(c1);
  if (n)
    BN_free(n);
  if (c)
    free(c);
  return ret;
}

bool
bcrypto_rsa_has_hash(const char *alg) {
  int type = bcrypto_rsa_hash_type(alg);

  if (type == -1)
    return false;

  return EVP_get_digestbynid(type) != NULL;
}

#else

void
bcrypto_rsa_key_init(bcrypto_rsa_key_t *key) {}

void
bcrypto_rsa_key_free(bcrypto_rsa_key_t *key) {}

bcrypto_rsa_key_t *
bcrypto_rsa_privkey_generate(int bits, unsigned long long exp) {
  return NULL;
}

bool
bcrypto_rsa_privkey_compute(
  const bcrypto_rsa_key_t *priv,
  bcrypto_rsa_key_t **key
) {
  return NULL;
}

bool
bcrypto_rsa_privkey_verify(const bcrypto_rsa_key_t *priv) {
  return false;
}

bool
bcrypto_rsa_privkey_export(
  const bcrypto_rsa_key_t *priv,
  uint8_t **out,
  size_t *out_len
) {
  return false;
}

bcrypto_rsa_key_t *
bcrypto_rsa_privkey_import(
  const uint8_t *raw,
  size_t raw_len
) {
  return NULL;
}

bool
bcrypto_rsa_privkey_export_pkcs8(
  const bcrypto_rsa_key_t *priv,
  uint8_t **out,
  size_t *out_len
) {
  return false;
}

bcrypto_rsa_key_t *
bcrypto_rsa_privkey_import_pkcs8(
  const uint8_t *raw,
  size_t raw_len
) {
  return NULL;
}

bool
bcrypto_rsa_pubkey_verify(const bcrypto_rsa_key_t *pub) {
  return false;
}

bool
bcrypto_rsa_pubkey_export(
  const bcrypto_rsa_key_t *pub,
  uint8_t **out,
  size_t *out_len
) {
  return false;
}

bcrypto_rsa_key_t *
bcrypto_rsa_pubkey_import(
  const uint8_t *raw,
  size_t raw_len
) {
  return NULL;
}

bool
bcrypto_rsa_pubkey_export_spki(
  const bcrypto_rsa_key_t *pub,
  uint8_t **out,
  size_t *out_len
) {
  return false;
}

bcrypto_rsa_key_t *
bcrypto_rsa_pubkey_import_spki(
  const uint8_t *raw,
  size_t raw_len
) {
  return NULL;
}

bool
bcrypto_rsa_sign(
  const char *alg,
  const uint8_t *msg,
  size_t msg_len,
  const bcrypto_rsa_key_t *priv,
  uint8_t **sig,
  size_t *sig_len
) {
  return false;
}

bool
bcrypto_rsa_verify(
  const char *alg,
  const uint8_t *msg,
  size_t msg_len,
  const uint8_t *sig,
  size_t sig_len,
  const bcrypto_rsa_key_t *pub
) {
  return false;
}

bool
bcrypto_rsa_encrypt(
  const uint8_t *msg,
  size_t msg_len,
  const bcrypto_rsa_key_t *pub,
  uint8_t **ct,
  size_t *ct_len
) {
  return false;
}

bool
bcrypto_rsa_decrypt(
  const uint8_t *msg,
  size_t msg_len,
  const bcrypto_rsa_key_t *priv,
  uint8_t **pt,
  size_t *pt_len
) {
  return false;
}

bool
bcrypto_rsa_encrypt_oaep(
  const char *alg,
  const uint8_t *msg,
  size_t msg_len,
  const bcrypto_rsa_key_t *pub,
  const uint8_t *label,
  size_t label_len,
  uint8_t **ct,
  size_t *ct_len
) {
  return false;
}

bool
bcrypto_rsa_decrypt_oaep(
  const char *alg,
  const uint8_t *msg,
  size_t msg_len,
  const bcrypto_rsa_key_t *priv,
  const uint8_t *label,
  size_t label_len,
  uint8_t **pt,
  size_t *pt_len
) {
  return false;
}

bool
bcrypto_rsa_sign_pss(
  const char *alg,
  const uint8_t *msg,
  size_t msg_len,
  const bcrypto_rsa_key_t *priv,
  int salt_len,
  uint8_t **sig,
  size_t *sig_len
) {
  return false;
}

bool
bcrypto_rsa_verify_pss(
  const char *alg,
  const uint8_t *msg,
  size_t msg_len,
  const uint8_t *sig,
  size_t sig_len,
  const bcrypto_rsa_key_t *pub,
  int salt_len
) {
  return false;
}

bool
bcrypto_rsa_encrypt_raw(
  const uint8_t *msg,
  size_t msg_len,
  const bcrypto_rsa_key_t *pub,
  uint8_t **out,
  size_t *out_len
) {
  return false;
}

bool
bcrypto_rsa_decrypt_raw(
  const uint8_t *msg,
  size_t msg_len,
  const bcrypto_rsa_key_t *priv,
  uint8_t **out,
  size_t *out_len
) {
  return false;
}

bool
bcrypto_rsa_has_hash(const char *alg) {
  return false;
}

#endif
