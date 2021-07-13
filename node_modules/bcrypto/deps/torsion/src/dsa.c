/*!
 * dsa.c - dsa for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 *
 * Parts of this software are based on golang/go:
 *   Copyright (c) 2009 The Go Authors. All rights reserved.
 *   https://github.com/golang/go
 *
 * References:
 *
 *   [FIPS186] Federal Information Processing Standards Publication
 *     National Institute of Standards and Technology
 *     http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
 *
 *   [DSA] Digital Signature Algorithm (wikipedia)
 *     https://en.wikipedia.org/wiki/Digital_Signature_Algorithm
 *
 *   [RFC6979] Deterministic Usage of the Digital Signature
 *             Algorithm (DSA) and Elliptic Curve Digital
 *             Signature Algorithm (ECDSA)
 *     T. Pornin
 *     https://tools.ietf.org/html/rfc6979
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <torsion/drbg.h>
#include <torsion/dsa.h>
#include <torsion/hash.h>
#include <torsion/util.h>
#include "asn1.h"
#include "internal.h"
#include "mpi.h"

/*
 * Structs
 */

typedef struct dsa_group_s {
  mpz_t p;
  mpz_t q;
  mpz_t g;
} dsa_group_t;

typedef struct dsa_pub_s {
  mpz_t p;
  mpz_t q;
  mpz_t g;
  mpz_t y;
} dsa_pub_t;

typedef struct dsa_priv_s {
  mpz_t p;
  mpz_t q;
  mpz_t g;
  mpz_t y;
  mpz_t x;
} dsa_priv_t;

typedef struct dsa_sig_s {
  mpz_t r;
  mpz_t s;
} dsa_sig_t;

/*
 * Group
 */

static void
dsa_group_init(dsa_group_t *group) {
  mpz_init(group->p);
  mpz_init(group->q);
  mpz_init(group->g);
}

static void
dsa_group_clear(dsa_group_t *group) {
  mpz_cleanse(group->p);
  mpz_cleanse(group->q);
  mpz_cleanse(group->g);
}

static void
dsa_group_roset_priv(dsa_group_t *group, const dsa_priv_t *k) {
  mpz_roset(group->p, k->p);
  mpz_roset(group->q, k->q);
  mpz_roset(group->g, k->g);
}

static void
dsa_group_roset_pub(dsa_group_t *group, const dsa_pub_t *k) {
  mpz_roset(group->p, k->p);
  mpz_roset(group->q, k->q);
  mpz_roset(group->g, k->g);
}

static int
dsa_group_import(dsa_group_t *group, const unsigned char *data, size_t len) {
  if (!asn1_read_seq(&data, &len, 1))
    return 0;

  if (!asn1_read_mpz(group->p, &data, &len, 1))
    return 0;

  if (!asn1_read_mpz(group->q, &data, &len, 1))
    return 0;

  if (!asn1_read_mpz(group->g, &data, &len, 1))
    return 0;

  if (len != 0)
    return 0;

  return 1;
}

static void
dsa_group_export(unsigned char *out,
                 size_t *out_len,
                 const dsa_group_t *group) {
  size_t size = 0;
  size_t pos = 0;

  size += asn1_size_mpz(group->p);
  size += asn1_size_mpz(group->q);
  size += asn1_size_mpz(group->g);

  pos = asn1_write_seq(out, pos, size);
  pos = asn1_write_mpz(out, pos, group->p);
  pos = asn1_write_mpz(out, pos, group->q);
  pos = asn1_write_mpz(out, pos, group->g);

  *out_len = pos;
}

static int
dsa_group_import_dumb(dsa_group_t *group,
                      const unsigned char *data,
                      size_t len) {
  if (!asn1_read_dumb(group->p, &data, &len))
    return 0;

  if (!asn1_read_dumb(group->q, &data, &len))
    return 0;

  if (!asn1_read_dumb(group->g, &data, &len))
    return 0;

  return 1;
}

static void
dsa_group_export_dumb(unsigned char *out,
                      size_t *out_len,
                      const dsa_group_t *group) {
  size_t pos = 0;

  pos = asn1_write_dumb(out, pos, group->p);
  pos = asn1_write_dumb(out, pos, group->q);
  pos = asn1_write_dumb(out, pos, group->g);

  *out_len = pos;
}

static int
dsa_group_generate(dsa_group_t *group, int bits, const unsigned char *entropy) {
  /* [FIPS186] Page 31, Appendix A.1.
   *           Page 41, Appendix A.2.
   * [DSA] "Parameter generation".
   */
  int L = bits;
  int N = bits < 2048 ? 160 : 256;
  mpz_t q, p, t, h, pm1, e, g;
  drbg_t rng;
  int i, b;

  if (!(L == 1024 && N == 160)
      && !(L == 2048 && N == 224)
      && !(L == 2048 && N == 256)
      && !(L == 3072 && N == 256)) {
    return 0;
  }

  mpz_init(q);
  mpz_init(p);
  mpz_init(t);
  mpz_init(h);
  mpz_init(pm1);
  mpz_init(e);
  mpz_init(g);

  drbg_init(&rng, HASH_SHA256, entropy, ENTROPY_SIZE);

  for (;;) {
    mpz_urandomb(q, N, drbg_rng, &rng);

    mpz_setbit(q, 0);
    mpz_setbit(q, N - 1);

    if (!mpz_probab_prime_p(q, 64, drbg_rng, &rng))
      continue;

    for (i = 0; i < 4 * L; i++) {
      mpz_urandomb(p, L, drbg_rng, &rng);

      mpz_setbit(p, 0);
      mpz_setbit(p, L - 1);

      mpz_mod(t, p, q);
      mpz_sub_ui(t, t, 1);
      mpz_sub(p, p, t);

      b = mpz_bitlen(p);

      if (b < L || b > DSA_MAX_BITS)
        continue;

      if (!mpz_probab_prime_p(p, 64, drbg_rng, &rng))
        continue;

      goto done;
    }
  }

done:
  mpz_set_ui(h, 2);
  mpz_sub_ui(pm1, p, 1);
  mpz_quo(e, pm1, q);

  for (;;) {
    mpz_powm(g, h, e, p);

    if (mpz_cmp_ui(g, 1) == 0) {
      mpz_add_ui(h, h, 1);
      continue;
    }

    break;
  }

  mpz_set(group->p, p);
  mpz_set(group->q, q);
  mpz_set(group->g, g);

  mpz_cleanse(q);
  mpz_cleanse(p);
  mpz_cleanse(t);
  mpz_cleanse(h);
  mpz_cleanse(pm1);
  mpz_cleanse(e);
  mpz_cleanse(g);

  torsion_cleanse(&rng, sizeof(rng));

  return 1;
}

static int
dsa_group_is_sane(const dsa_group_t *group) {
  int pbits = mpz_bitlen(group->p);
  int qbits = mpz_bitlen(group->q);
  mpz_t pm1;
  int ret = 0;

  mpz_init(pm1);

  if (pbits < DSA_MIN_BITS || pbits > DSA_MAX_BITS)
    goto fail;

  if (qbits != 160 && qbits != 224 && qbits != 256)
    goto fail;

  if (mpz_cmp_ui(group->g, 2) < 0 || mpz_cmp(group->g, group->p) >= 0)
    goto fail;

  if (!mpz_odd_p(group->p))
    goto fail;

  if (!mpz_odd_p(group->q))
    goto fail;

  mpz_sub_ui(pm1, group->p, 1);

  if (mpz_cmp(group->g, pm1) >= 0)
    goto fail;

  ret = 1;
fail:
  mpz_clear(pm1);
  return ret;
}

static int
dsa_group_verify(const dsa_group_t *group) {
  mpz_t t;
  int ret;

  if (!dsa_group_is_sane(group))
    return 0;

  mpz_init(t);
  mpz_powm(t, group->g, group->q, group->p);

  ret = (mpz_cmp_ui(t, 1) == 0);

  mpz_cleanse(t);

  return ret;
}

/*
 * Public Key
 */

static void
dsa_pub_init(dsa_pub_t *k) {
  mpz_init(k->p);
  mpz_init(k->q);
  mpz_init(k->g);
  mpz_init(k->y);
}

static void
dsa_pub_clear(dsa_pub_t *k) {
  mpz_cleanse(k->p);
  mpz_cleanse(k->q);
  mpz_cleanse(k->g);
  mpz_cleanse(k->y);
}

static void
dsa_pub_roset_priv(dsa_pub_t *r, const dsa_priv_t *k) {
  mpz_roset(r->p, k->p);
  mpz_roset(r->q, k->q);
  mpz_roset(r->g, k->g);
  mpz_roset(r->y, k->y);
}

static int
dsa_pub_import(dsa_pub_t *k, const unsigned char *data, size_t len) {
  if (!asn1_read_seq(&data, &len, 1))
    return 0;

  if (!asn1_read_mpz(k->y, &data, &len, 1))
    return 0;

  if (!asn1_read_mpz(k->p, &data, &len, 1))
    return 0;

  if (!asn1_read_mpz(k->q, &data, &len, 1))
    return 0;

  if (!asn1_read_mpz(k->g, &data, &len, 1))
    return 0;

  if (len != 0)
    return 0;

  return 1;
}

static void
dsa_pub_export(unsigned char *out, size_t *out_len, const dsa_pub_t *k) {
  size_t size = 0;
  size_t pos = 0;

  size += asn1_size_mpz(k->y);
  size += asn1_size_mpz(k->p);
  size += asn1_size_mpz(k->q);
  size += asn1_size_mpz(k->g);

  pos = asn1_write_seq(out, pos, size);
  pos = asn1_write_mpz(out, pos, k->y);
  pos = asn1_write_mpz(out, pos, k->p);
  pos = asn1_write_mpz(out, pos, k->q);
  pos = asn1_write_mpz(out, pos, k->g);

  *out_len = pos;
}

static int
dsa_pub_import_dumb(dsa_pub_t *k, const unsigned char *data, size_t len) {
  if (!asn1_read_dumb(k->p, &data, &len))
    return 0;

  if (!asn1_read_dumb(k->q, &data, &len))
    return 0;

  if (!asn1_read_dumb(k->g, &data, &len))
    return 0;

  if (!asn1_read_dumb(k->y, &data, &len))
    return 0;

  return 1;
}

static void
dsa_pub_export_dumb(unsigned char *out, size_t *out_len, const dsa_pub_t *k) {
  size_t pos = 0;

  pos = asn1_write_dumb(out, pos, k->p);
  pos = asn1_write_dumb(out, pos, k->q);
  pos = asn1_write_dumb(out, pos, k->g);
  pos = asn1_write_dumb(out, pos, k->y);

  *out_len = pos;
}

static int
dsa_pub_is_sane(const dsa_pub_t *k) {
  dsa_group_t group;
  mpz_t pm1;
  int ret = 0;

  dsa_group_roset_pub(&group, k);

  if (!dsa_group_is_sane(&group))
    return 0;

  mpz_init(pm1);
  mpz_sub_ui(pm1, k->p, 1);

  if (mpz_cmp_ui(k->y, 2) < 0 || mpz_cmp(k->y, pm1) >= 0)
    goto fail;

  ret = 1;
fail:
  mpz_cleanse(pm1);
  return ret;
}

static int
dsa_pub_verify(const dsa_pub_t *k) {
  dsa_group_t group;
  mpz_t t;
  int ret;

  dsa_group_roset_pub(&group, k);

  if (!dsa_group_verify(&group))
    return 0;

  if (!dsa_pub_is_sane(k))
    return 0;

  mpz_init(t);
  mpz_powm(t, k->y, k->q, k->p);

  ret = (mpz_cmp_ui(t, 1) == 0);

  mpz_cleanse(t);

  return ret;
}

/*
 * Private Key
 */

static void
dsa_priv_init(dsa_priv_t *k) {
  mpz_init(k->p);
  mpz_init(k->q);
  mpz_init(k->g);
  mpz_init(k->y);
  mpz_init(k->x);
}

static void
dsa_priv_clear(dsa_priv_t *k) {
  mpz_cleanse(k->p);
  mpz_cleanse(k->q);
  mpz_cleanse(k->g);
  mpz_cleanse(k->y);
  mpz_cleanse(k->x);
}

static int
dsa_priv_import(dsa_priv_t *k, const unsigned char *data, size_t len) {
  if (!asn1_read_seq(&data, &len, 1))
    return 0;

  if (!asn1_read_version(&data, &len, 0, 1))
    return 0;

  if (!asn1_read_mpz(k->p, &data, &len, 1))
    return 0;

  if (!asn1_read_mpz(k->q, &data, &len, 1))
    return 0;

  if (!asn1_read_mpz(k->g, &data, &len, 1))
    return 0;

  if (!asn1_read_mpz(k->y, &data, &len, 1))
    return 0;

  if (!asn1_read_mpz(k->x, &data, &len, 1))
    return 0;

  if (len != 0)
    return 0;

  return 1;
}

static void
dsa_priv_export(unsigned char *out, size_t *out_len, const dsa_priv_t *k) {
  size_t size = 0;
  size_t pos = 0;

  size += asn1_size_version(0);
  size += asn1_size_mpz(k->p);
  size += asn1_size_mpz(k->q);
  size += asn1_size_mpz(k->g);
  size += asn1_size_mpz(k->y);
  size += asn1_size_mpz(k->x);

  pos = asn1_write_seq(out, pos, size);
  pos = asn1_write_version(out, pos, 0);
  pos = asn1_write_mpz(out, pos, k->p);
  pos = asn1_write_mpz(out, pos, k->q);
  pos = asn1_write_mpz(out, pos, k->g);
  pos = asn1_write_mpz(out, pos, k->y);
  pos = asn1_write_mpz(out, pos, k->x);

  *out_len = pos;
}

static int
dsa_priv_import_dumb(dsa_priv_t *k, const unsigned char *data, size_t len) {
  if (!asn1_read_dumb(k->p, &data, &len))
    return 0;

  if (!asn1_read_dumb(k->q, &data, &len))
    return 0;

  if (!asn1_read_dumb(k->g, &data, &len))
    return 0;

  if (!asn1_read_dumb(k->y, &data, &len))
    return 0;

  if (!asn1_read_dumb(k->x, &data, &len))
    return 0;

  return 1;
}

static void
dsa_priv_export_dumb(unsigned char *out, size_t *out_len, const dsa_priv_t *k) {
  size_t pos = 0;

  pos = asn1_write_dumb(out, pos, k->p);
  pos = asn1_write_dumb(out, pos, k->q);
  pos = asn1_write_dumb(out, pos, k->g);
  pos = asn1_write_dumb(out, pos, k->y);
  pos = asn1_write_dumb(out, pos, k->x);

  *out_len = pos;
}

static int
dsa_priv_is_sane(const dsa_priv_t *k) {
  dsa_pub_t pub;

  dsa_pub_roset_priv(&pub, k);

  if (!dsa_pub_is_sane(&pub))
    return 0;

  if (mpz_sgn(k->x) == 0)
    return 0;

  return mpz_cmp(k->x, k->q) < 0;
}

static int
dsa_priv_verify(const dsa_priv_t *k) {
  dsa_pub_t pub;
  mpz_t y;
  int ret;

  if (!dsa_priv_is_sane(k))
    return 0;

  dsa_pub_roset_priv(&pub, k);

  if (!dsa_pub_verify(&pub))
    return 0;

  mpz_init(y);
  mpz_powm_sec(y, k->g, k->x, k->p);

  ret = (mpz_cmp(y, k->y) == 0);

  mpz_cleanse(y);

  return ret;
}

static void
dsa_priv_create(dsa_priv_t *k,
                const dsa_group_t *group,
                const unsigned char *entropy) {
  drbg_t rng;

  mpz_set(k->p, group->p);
  mpz_set(k->q, group->q);
  mpz_set(k->g, group->g);

  drbg_init(&rng, HASH_SHA256, entropy, ENTROPY_SIZE);

  do {
    mpz_urandomm(k->x, k->q, drbg_rng, &rng);
  } while (mpz_sgn(k->x) == 0);

  mpz_powm_sec(k->y, k->g, k->x, k->p);

  torsion_cleanse(&rng, sizeof(rng));
}

static int
dsa_priv_generate(dsa_priv_t *k, int bits, const unsigned char *entropy) {
  unsigned char entropy1[ENTROPY_SIZE];
  unsigned char entropy2[ENTROPY_SIZE];
  dsa_group_t group;
  drbg_t rng;
  int ret = 0;

  dsa_group_init(&group);

  drbg_init(&rng, HASH_SHA256, entropy, ENTROPY_SIZE);
  drbg_generate(&rng, entropy2, ENTROPY_SIZE);
  drbg_generate(&rng, entropy1, ENTROPY_SIZE);

  if (!dsa_group_generate(&group, bits, entropy1))
    goto fail;

  dsa_priv_create(k, &group, entropy2);
  ret = 1;
fail:
  dsa_group_clear(&group);
  torsion_cleanse(&rng, sizeof(rng));
  torsion_cleanse(entropy1, sizeof(entropy1));
  torsion_cleanse(entropy2, sizeof(entropy2));
  return ret;
}

static int
dsa_priv_recover(dsa_priv_t *k) {
  dsa_group_t group;

  dsa_group_roset_priv(&group, k);

  if (!dsa_group_is_sane(&group))
    return 0;

  if (mpz_sgn(k->x) == 0)
    return 0;

  if (mpz_cmp(k->x, k->q) >= 0)
    return 0;

  mpz_powm_sec(k->y, k->g, k->x, k->p);

  return 1;
}

/*
 * Signature
 */

static void
dsa_sig_init(dsa_sig_t *sig) {
  mpz_init(sig->r);
  mpz_init(sig->s);
}

static void
dsa_sig_clear(dsa_sig_t *sig) {
  mpz_cleanse(sig->r);
  mpz_cleanse(sig->s);
}

static int
dsa_sig_is_sane(const dsa_sig_t *sig) {
  return mpz_bytelen(sig->r) <= DSA_MAX_QSIZE
      && mpz_bytelen(sig->s) <= DSA_MAX_QSIZE;
}

static int
dsa_sig_import_der(dsa_sig_t *sig, const unsigned char *data, size_t len) {
  if (!asn1_read_seq(&data, &len, 1))
    return 0;

  if (!asn1_read_mpz(sig->r, &data, &len, 1))
    return 0;

  if (!asn1_read_mpz(sig->s, &data, &len, 1))
    return 0;

  if (len != 0)
    return 0;

  return 1;
}

static void
dsa_sig_export_der(unsigned char *out, size_t *out_len, const dsa_sig_t *sig) {
  size_t size = 0;
  size_t pos = 0;

  size += asn1_size_mpz(sig->r);
  size += asn1_size_mpz(sig->s);

  pos = asn1_write_seq(out, pos, size);
  pos = asn1_write_mpz(out, pos, sig->r);
  pos = asn1_write_mpz(out, pos, sig->s);

  *out_len = pos;
}

static int
dsa_sig_import_rs(dsa_sig_t *sig,
                  const unsigned char *data,
                  size_t len,
                  size_t qsize) {
  if (qsize == 0)
    qsize = len >> 1;

  if (len != qsize * 2)
    return 0;

  mpz_import(sig->r, data, qsize, 1);
  mpz_import(sig->s, data + qsize, qsize, 1);

  return 1;
}

static int
dsa_sig_export_rs(unsigned char *out, size_t *out_len,
                  const dsa_sig_t *sig, size_t qsize) {
  if (mpz_bytelen(sig->r) > qsize
      || mpz_bytelen(sig->s) > qsize) {
    return 0;
  }

  mpz_export(out, sig->r, qsize, 1);
  mpz_export(out + qsize, sig->s, qsize, 1);

  *out_len = qsize * 2;

  return 1;
}

/*
 * DSA
 */

int
dsa_params_create(unsigned char *out, size_t *out_len,
                  const unsigned char *key, size_t key_len) {
  dsa_priv_t priv;
  dsa_pub_t pub;
  dsa_group_t group;
  int ret = 0;

  dsa_priv_init(&priv);
  dsa_pub_init(&pub);

  if (dsa_priv_import(&priv, key, key_len))
    dsa_group_roset_priv(&group, &priv);
  else if (dsa_pub_import(&pub, key, key_len))
    dsa_group_roset_pub(&group, &pub);
  else
    goto fail;

  if (!dsa_group_is_sane(&group))
    goto fail;

  dsa_group_export(out, out_len, &group);
  ret = 1;
fail:
  dsa_priv_clear(&priv);
  dsa_pub_clear(&pub);
  return ret;
}

int
dsa_params_generate(unsigned char *out,
                    size_t *out_len,
                    unsigned int bits,
                    const unsigned char *entropy) {
  dsa_group_t group;
  int ret = 0;

  dsa_group_init(&group);

  if (bits > DSA_MAX_BITS)
    goto fail;

  if (!dsa_group_generate(&group, bits, entropy))
    goto fail;

  dsa_group_export(out, out_len, &group);
  ret = 1;
fail:
  dsa_group_clear(&group);
  return ret;
}

unsigned int
dsa_params_bits(const unsigned char *params, size_t params_len) {
  unsigned int bits = 0;
  dsa_group_t group;

  dsa_group_init(&group);

  if (!dsa_group_import(&group, params, params_len))
    goto fail;

  if (!dsa_group_is_sane(&group))
    goto fail;

  bits = mpz_bitlen(group.p);
fail:
  dsa_group_clear(&group);
  return bits;
}

unsigned int
dsa_params_qbits(const unsigned char *params, size_t params_len) {
  unsigned int bits = 0;
  dsa_group_t group;

  dsa_group_init(&group);

  if (!dsa_group_import(&group, params, params_len))
    goto fail;

  if (!dsa_group_is_sane(&group))
    goto fail;

  bits = mpz_bitlen(group.q);
fail:
  dsa_group_clear(&group);
  return bits;
}

int
dsa_params_verify(const unsigned char *params, size_t params_len) {
  dsa_group_t group;
  int ret = 0;

  dsa_group_init(&group);

  if (!dsa_group_import(&group, params, params_len))
    goto fail;

  ret = dsa_group_verify(&group);
fail:
  dsa_group_clear(&group);
  return ret;
}

int
dsa_params_import(unsigned char *out, size_t *out_len,
                  const unsigned char *params, size_t params_len) {
  dsa_group_t group;
  int ret = 0;

  dsa_group_init(&group);

  if (!dsa_group_import_dumb(&group, params, params_len))
    goto fail;

  if (!dsa_group_is_sane(&group))
    goto fail;

  dsa_group_export(out, out_len, &group);
  ret = 1;
fail:
  dsa_group_clear(&group);
  return ret;
}

int
dsa_params_export(unsigned char *out, size_t *out_len,
                  const unsigned char *params, size_t params_len) {
  dsa_group_t group;
  int ret = 0;

  dsa_group_init(&group);

  if (!dsa_group_import(&group, params, params_len))
    goto fail;

  if (!dsa_group_is_sane(&group))
    goto fail;

  dsa_group_export_dumb(out, out_len, &group);
  ret = 1;
fail:
  dsa_group_clear(&group);
  return ret;
}

int
dsa_privkey_create(unsigned char *out,
                   size_t *out_len,
                   const unsigned char *params,
                   size_t params_len,
                   const unsigned char *entropy) {
  dsa_group_t group;
  dsa_priv_t k;
  int ret = 0;

  dsa_group_init(&group);
  dsa_priv_init(&k);

  if (!dsa_group_import(&group, params, params_len))
    goto fail;

  if (!dsa_group_is_sane(&group))
    goto fail;

  dsa_priv_create(&k, &group, entropy);

  dsa_priv_export(out, out_len, &k);
  ret = 1;
fail:
  dsa_group_clear(&group);
  dsa_priv_clear(&k);
  return ret;
}

int
dsa_privkey_generate(unsigned char *out,
                     size_t *out_len,
                     unsigned int bits,
                     const unsigned char *entropy) {
  dsa_priv_t k;
  int ret = 0;

  dsa_priv_init(&k);

  if (bits > DSA_MAX_BITS)
    goto fail;

  if (!dsa_priv_generate(&k, bits, entropy))
    goto fail;

  dsa_priv_export(out, out_len, &k);
  ret = 1;
fail:
  dsa_priv_clear(&k);
  return ret;
}

unsigned int
dsa_privkey_bits(const unsigned char *key, size_t key_len) {
  unsigned int bits = 0;
  dsa_priv_t k;

  dsa_priv_init(&k);

  if (!dsa_priv_import(&k, key, key_len))
    goto fail;

  if (!dsa_priv_is_sane(&k))
    goto fail;

  bits = mpz_bitlen(k.p);
fail:
  dsa_priv_clear(&k);
  return bits;
}

unsigned int
dsa_privkey_qbits(const unsigned char *key, size_t key_len) {
  unsigned int bits = 0;
  dsa_priv_t k;

  dsa_priv_init(&k);

  if (!dsa_priv_import(&k, key, key_len))
    goto fail;

  if (!dsa_priv_is_sane(&k))
    goto fail;

  bits = mpz_bitlen(k.q);
fail:
  dsa_priv_clear(&k);
  return bits;
}

int
dsa_privkey_verify(const unsigned char *key, size_t key_len) {
  dsa_priv_t k;
  int ret = 0;

  dsa_priv_init(&k);

  if (!dsa_priv_import(&k, key, key_len))
    goto fail;

  ret = dsa_priv_verify(&k);
fail:
  dsa_priv_clear(&k);
  return ret;
}

int
dsa_privkey_import(unsigned char *out, size_t *out_len,
                   const unsigned char *key, size_t key_len) {
  dsa_priv_t k;
  int ret = 0;

  dsa_priv_init(&k);

  if (!dsa_priv_import_dumb(&k, key, key_len))
    goto fail;

  if (!dsa_priv_recover(&k))
    goto fail;

  dsa_priv_export(out, out_len, &k);
  ret = 1;
fail:
  dsa_priv_clear(&k);
  return ret;
}

int
dsa_privkey_export(unsigned char *out, size_t *out_len,
                   const unsigned char *key, size_t key_len) {
  dsa_priv_t k;
  int ret = 0;

  dsa_priv_init(&k);

  if (!dsa_priv_import(&k, key, key_len))
    goto fail;

  if (!dsa_priv_is_sane(&k))
    goto fail;

  dsa_priv_export_dumb(out, out_len, &k);
  ret = 1;
fail:
  dsa_priv_clear(&k);
  return ret;
}

int
dsa_pubkey_create(unsigned char *out, size_t *out_len,
                  const unsigned char *key, size_t key_len) {
  dsa_priv_t k;
  dsa_pub_t p;
  int ret = 0;

  dsa_priv_init(&k);

  if (!dsa_priv_import(&k, key, key_len))
    goto fail;

  if (!dsa_priv_is_sane(&k))
    goto fail;

  dsa_pub_roset_priv(&p, &k);
  dsa_pub_export(out, out_len, &p);
  ret = 1;
fail:
  dsa_priv_clear(&k);
  return ret;
}

unsigned int
dsa_pubkey_bits(const unsigned char *key, size_t key_len) {
  unsigned int bits = 0;
  dsa_pub_t k;

  dsa_pub_init(&k);

  if (!dsa_pub_import(&k, key, key_len))
    goto fail;

  if (!dsa_pub_is_sane(&k))
    goto fail;

  bits = mpz_bitlen(k.p);
fail:
  dsa_pub_clear(&k);
  return bits;
}

unsigned int
dsa_pubkey_qbits(const unsigned char *key, size_t key_len) {
  unsigned int bits = 0;
  dsa_pub_t k;

  dsa_pub_init(&k);

  if (!dsa_pub_import(&k, key, key_len))
    goto fail;

  if (!dsa_pub_is_sane(&k))
    goto fail;

  bits = mpz_bitlen(k.q);
fail:
  dsa_pub_clear(&k);
  return bits;
}

int
dsa_pubkey_verify(const unsigned char *key, size_t key_len) {
  dsa_pub_t k;
  int ret = 0;

  dsa_pub_init(&k);

  if (!dsa_pub_import(&k, key, key_len))
    goto fail;

  ret = dsa_pub_verify(&k);
fail:
  dsa_pub_clear(&k);
  return ret;
}

int
dsa_pubkey_import(unsigned char *out, size_t *out_len,
                  const unsigned char *key, size_t key_len) {
  dsa_pub_t k;
  int ret = 0;

  dsa_pub_init(&k);

  if (!dsa_pub_import_dumb(&k, key, key_len))
    goto fail;

  if (!dsa_pub_is_sane(&k))
    goto fail;

  dsa_pub_export(out, out_len, &k);
  ret = 1;
fail:
  dsa_pub_clear(&k);
  return ret;
}

int
dsa_pubkey_export(unsigned char *out, size_t *out_len,
                  const unsigned char *key, size_t key_len) {
  dsa_pub_t k;
  int ret = 0;

  dsa_pub_init(&k);

  if (!dsa_pub_import(&k, key, key_len))
    goto fail;

  if (!dsa_pub_is_sane(&k))
    goto fail;

  dsa_pub_export_dumb(out, out_len, &k);
  ret = 1;
fail:
  dsa_pub_clear(&k);
  return ret;
}

int
dsa_sig_export(unsigned char *out,
               size_t *out_len,
               const unsigned char *sig,
               size_t sig_len,
               size_t qsize) {
  dsa_sig_t S;
  int ret = 0;

  dsa_sig_init(&S);

  if (sig_len > DSA_MAX_QSIZE * 2)
    goto fail;

  if (qsize != 0 && qsize > DSA_MAX_QSIZE)
    goto fail;

  if (!dsa_sig_import_rs(&S, sig, sig_len, qsize))
    goto fail;

  if (!dsa_sig_is_sane(&S))
    goto fail;

  dsa_sig_export_der(out, out_len, &S);
  ret = 1;
fail:
  dsa_sig_clear(&S);
  return ret;
}

int
dsa_sig_import(unsigned char *out,
               size_t *out_len,
               const unsigned char *sig,
               size_t sig_len,
               size_t qsize) {
  dsa_sig_t S;
  int ret = 0;

  dsa_sig_init(&S);

  if (!dsa_sig_import_der(&S, sig, sig_len))
    goto fail;

  if (!dsa_sig_is_sane(&S))
    goto fail;

  ret = dsa_sig_export_rs(out, out_len, &S, qsize);
fail:
  dsa_sig_clear(&S);
  return ret;
}

static int
dsa_reduce(mpz_t m, const unsigned char *msg, size_t msg_len, const mpz_t q) {
  /* Byte array to integer conversion.
   *
   * [FIPS186] Page 68, Appendix C.2.
   *
   * Note that the FIPS186 behavior
   * differs from OpenSSL's behavior.
   * We replicate OpenSSL which takes
   * the left-most ceil(log2(q+1)) bits
   * modulo the order.
   */
  size_t bits = mpz_bitlen(q);
  size_t bytes = (bits + 7) / 8;
  int ret = 1;

  /* Truncate. */
  if (msg_len > bytes)
    msg_len = bytes;

  /* Import and pad. */
  mpz_import(m, msg, msg_len, 1);

  /* Shift by the remaining bits. */
  if (msg_len * 8 > bits)
    mpz_quo_2exp(m, m, msg_len * 8 - bits);

  /* Reduce (m < 2^ceil(log2(q+1))). */
  if (mpz_cmp(m, q) >= 0) {
    mpz_sub(m, m, q);
    ret = 0;
  }

  ASSERT(mpz_cmp(m, q) < 0);

  return ret;
}

int
dsa_sign(unsigned char *out, size_t *out_len,
         const unsigned char *msg, size_t msg_len,
         const unsigned char *key, size_t key_len,
         const unsigned char *entropy) {
  /* DSA Signing.
   *
   * [FIPS186] Page 19, Section 4.6.
   * [DSA] "Signing".
   * [RFC6979] Page 9, Section 2.4.
   * [RFC6979] Page 10, Section 3.2.
   *
   * Assumptions:
   *
   *   - Let `m` be an integer reduced from bytes.
   *   - Let `x` be a secret non-zero scalar.
   *   - Let `k` be a random non-zero scalar.
   *   - r != 0, s != 0.
   *
   * Computation:
   *
   *   k = random integer in [1,q-1]
   *   r' = g^k mod p
   *   r = r' mod q
   *   s = (r * x + m) / k mod q
   *   S = (r, s)
   *
   * We can blind the scalar arithmetic
   * with a random integer `b` like so:
   *
   *   b = random integer in [1,q-1]
   *   s = (r * (x * b) + m * b) / (k * b) mod q
   *
   * Note that `k` must remain secret,
   * otherwise an attacker can compute:
   *
   *   x = (s * k - m) / r mod q
   *
   * This means that if two signatures
   * share the same `r` value, an attacker
   * can compute:
   *
   *   k = (m1 - m2) / (s1 - s2) mod q
   *   x = (s1 * k - m1) / r mod q
   *
   * Assuming:
   *
   *   s1 = (r * x + m1) / k mod q
   *   s2 = (r * x + m2) / k mod q
   *
   * To mitigate this, `k` can be generated
   * deterministically using the HMAC-DRBG
   * construction described in [RFC6979].
   */
  unsigned char bytes[DSA_MAX_QSIZE * 2];
  mpz_t m, b, bx, bm, k, r, s;
  drbg_t drbg, rng;
  dsa_priv_t priv;
  dsa_sig_t S;
  size_t qsize;
  int ret = 0;

  mpz_init(m);
  mpz_init(b);
  mpz_init(bx);
  mpz_init(bm);
  mpz_init(k);
  mpz_init(r);
  mpz_init(s);

  dsa_priv_init(&priv);

  if (!dsa_priv_import(&priv, key, key_len))
    goto fail;

  if (!dsa_priv_is_sane(&priv))
    goto fail;

  qsize = mpz_bytelen(priv.q);

  dsa_reduce(m, msg, msg_len, priv.q);

  mpz_export(bytes, priv.x, qsize, 1);
  mpz_export(bytes + qsize, m, qsize, 1);

  drbg_init(&drbg, HASH_SHA256, bytes, qsize * 2);
  drbg_init(&rng, HASH_SHA256, entropy, ENTROPY_SIZE);

  for (;;) {
    mpz_urandomm(b, priv.q, drbg_rng, &rng);

    if (mpz_sgn(b) == 0)
      continue;

    drbg_generate(&drbg, bytes, qsize);

    if (!dsa_reduce(k, bytes, qsize, priv.q))
      continue;

    if (mpz_sgn(k) == 0)
      continue;

    mpz_powm_sec(r, priv.g, k, priv.p);
    mpz_mod(r, r, priv.q);

    if (mpz_sgn(r) == 0)
      continue;

    /* Blind. */
    mpz_mul(k, k, b);
    mpz_mod(k, k, priv.q);
    mpz_mul(bx, priv.x, b);
    mpz_mod(bx, bx, priv.q);
    mpz_mul(bm, m, b);
    mpz_mod(bm, bm, priv.q);

    /* Can only fail if `q` is not prime. */
    if (!mpz_invert(k, k, priv.q))
      goto fail;

    /* Sign. */
    mpz_mul(s, r, bx);
    mpz_add(s, s, bm);
    mpz_mod(s, s, priv.q);
    mpz_mul(s, s, k);
    mpz_mod(s, s, priv.q);

    if (mpz_sgn(s) == 0)
      continue;

    mpz_roset(S.r, r);
    mpz_roset(S.s, s);

    ret = dsa_sig_export_rs(out, out_len, &S, qsize);

    break;
  }

fail:
  mpz_cleanse(m);
  mpz_cleanse(b);
  mpz_cleanse(bx);
  mpz_cleanse(bm);
  mpz_cleanse(k);
  mpz_cleanse(r);
  mpz_cleanse(s);
  dsa_priv_clear(&priv);
  torsion_cleanse(&drbg, sizeof(drbg));
  torsion_cleanse(&rng, sizeof(rng));
  torsion_cleanse(bytes, sizeof(bytes));
  return ret;
}

int
dsa_verify(const unsigned char *msg, size_t msg_len,
           const unsigned char *sig, size_t sig_len,
           const unsigned char *key, size_t key_len) {
  /* DSA Verification.
   *
   * [FIPS186] Page 19, Section 4.7.
   * [DSA] "Verifying a signature".
   *
   * Assumptions:
   *
   *   - Let `m` be an integer reduced from bytes.
   *   - Let `r` and `s` be signature elements.
   *   - Let `y` be a valid group element.
   *   - r != 0, r < q.
   *   - s != 0, s < q.
   *
   * Computation:
   *
   *   u1 = m / s mod q
   *   u2 = r / s mod q
   *   r' = g^u1 * y^u2 mod p
   *   r == r' mod q
   */
  mpz_t r, s, m, si, u1, u2, e1, e2, re;
  dsa_pub_t k;
  dsa_sig_t S;
  size_t qsize;
  int ret = 0;

  mpz_init(m);
  mpz_init(si);
  mpz_init(u1);
  mpz_init(u2);
  mpz_init(e1);
  mpz_init(e2);
  mpz_init(re);

  dsa_pub_init(&k);
  dsa_sig_init(&S);

  if (!dsa_pub_import(&k, key, key_len))
    goto fail;

  if (!dsa_pub_is_sane(&k))
    goto fail;

  qsize = mpz_bytelen(k.q);

  if (!dsa_sig_import_rs(&S, sig, sig_len, qsize))
    goto fail;

  if (!dsa_sig_is_sane(&S))
    goto fail;

  mpz_roset(r, S.r);
  mpz_roset(s, S.s);

  if (mpz_sgn(r) == 0 || mpz_cmp(r, k.q) >= 0)
    goto fail;

  if (mpz_sgn(s) == 0 || mpz_cmp(s, k.q) >= 0)
    goto fail;

  dsa_reduce(m, msg, msg_len, k.q);

  if (!mpz_invert(si, s, k.q))
    goto fail;

  mpz_mul(u1, m, si);
  mpz_mod(u1, u1, k.q);
  mpz_mul(u2, r, si);
  mpz_mod(u2, u2, k.q);
  mpz_powm(e1, k.g, u1, k.p);
  mpz_powm(e2, k.y, u2, k.p);
  mpz_mul(re, e1, e2);
  mpz_mod(re, re, k.p);
  mpz_mod(re, re, k.q);

  ret = (mpz_cmp(re, r) == 0);
fail:
  mpz_cleanse(m);
  mpz_cleanse(si);
  mpz_cleanse(u1);
  mpz_cleanse(u2);
  mpz_cleanse(e1);
  mpz_cleanse(e2);
  mpz_cleanse(re);
  dsa_pub_clear(&k);
  dsa_sig_clear(&S);
  return ret;
}

int
dsa_derive(unsigned char *out, size_t *out_len,
           const unsigned char *pub, size_t pub_len,
           const unsigned char *priv, size_t priv_len) {
  dsa_pub_t k1;
  dsa_priv_t k2;
  mpz_t e;
  int ret = 0;

  dsa_pub_init(&k1);
  dsa_priv_init(&k2);

  mpz_init(e);

  if (!dsa_pub_import(&k1, pub, pub_len))
    goto fail;

  if (!dsa_priv_import(&k2, priv, priv_len))
    goto fail;

  if (mpz_cmp(k1.p, k2.p) != 0
      || mpz_cmp(k1.q, k2.q) != 0
      || mpz_cmp(k1.g, k2.g) != 0) {
    goto fail;
  }

  if (!dsa_priv_is_sane(&k2))
    goto fail;

  if (!dsa_pub_verify(&k1))
    goto fail;

  mpz_powm_sec(e, k1.y, k2.x, k1.p);

  *out_len = mpz_bytelen(k1.p);
  mpz_export(out, e, *out_len, 1);
  ret = 1;
fail:
  dsa_pub_clear(&k1);
  dsa_priv_clear(&k2);
  mpz_cleanse(e);
  return ret;
}
