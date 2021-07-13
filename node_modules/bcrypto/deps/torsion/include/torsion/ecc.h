/*!
 * ecc.h - elliptic curves for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 */

#ifndef _TORSION_ECC_H
#define _TORSION_ECC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include "common.h"

/*
 * Symbol Aliases
 */

#define wei_curve_create torsion_wei_curve_create
#define wei_curve_destroy torsion_wei_curve_destroy
#define wei_scratch_destroy torsion_wei_scratch_destroy
#define wei_curve_scalar_size torsion_wei_curve_scalar_size
#define wei_curve_scalar_bits torsion_wei_curve_scalar_bits
#define wei_curve_field_size torsion_wei_curve_field_size
#define wei_curve_field_bits torsion_wei_curve_field_bits
#define wei_curve_randomize torsion_wei_curve_randomize
#define wei_scratch_create torsion_wei_scratch_create

#define mont_curve_create torsion_mont_curve_create
#define mont_curve_destroy torsion_mont_curve_destroy
#define mont_curve_scalar_size torsion_mont_curve_scalar_size
#define mont_curve_scalar_bits torsion_mont_curve_scalar_bits
#define mont_curve_field_size torsion_mont_curve_field_size
#define mont_curve_field_bits torsion_mont_curve_field_bits

#define edwards_curve_create torsion_edwards_curve_create
#define edwards_curve_destroy torsion_edwards_curve_destroy
#define edwards_curve_randomize torsion_edwards_curve_randomize
#define edwards_curve_scalar_size torsion_edwards_curve_scalar_size
#define edwards_curve_scalar_bits torsion_edwards_curve_scalar_bits
#define edwards_curve_field_size torsion_edwards_curve_field_size
#define edwards_curve_field_bits torsion_edwards_curve_field_bits
#define edwards_scratch_create torsion_edwards_scratch_create
#define edwards_scratch_destroy torsion_edwards_scratch_destroy

#define ecdsa_privkey_size torsion_ecdsa_privkey_size
#define ecdsa_pubkey_size torsion_ecdsa_pubkey_size
#define ecdsa_sig_size torsion_ecdsa_sig_size
#define ecdsa_privkey_generate torsion_ecdsa_privkey_generate
#define ecdsa_privkey_verify torsion_ecdsa_privkey_verify
#define ecdsa_privkey_export torsion_ecdsa_privkey_export
#define ecdsa_privkey_import torsion_ecdsa_privkey_import
#define ecdsa_privkey_tweak_add torsion_ecdsa_privkey_tweak_add
#define ecdsa_privkey_tweak_mul torsion_ecdsa_privkey_tweak_mul
#define ecdsa_privkey_negate torsion_ecdsa_privkey_negate
#define ecdsa_privkey_invert torsion_ecdsa_privkey_invert
#define ecdsa_pubkey_create torsion_ecdsa_pubkey_create
#define ecdsa_pubkey_convert torsion_ecdsa_pubkey_convert
#define ecdsa_pubkey_from_uniform torsion_ecdsa_pubkey_from_uniform
#define ecdsa_pubkey_to_uniform torsion_ecdsa_pubkey_to_uniform
#define ecdsa_pubkey_from_hash torsion_ecdsa_pubkey_from_hash
#define ecdsa_pubkey_to_hash torsion_ecdsa_pubkey_to_hash
#define ecdsa_pubkey_verify torsion_ecdsa_pubkey_verify
#define ecdsa_pubkey_export torsion_ecdsa_pubkey_export
#define ecdsa_pubkey_import torsion_ecdsa_pubkey_import
#define ecdsa_pubkey_tweak_add torsion_ecdsa_pubkey_tweak_add
#define ecdsa_pubkey_tweak_mul torsion_ecdsa_pubkey_tweak_mul
#define ecdsa_pubkey_add torsion_ecdsa_pubkey_add
#define ecdsa_pubkey_combine torsion_ecdsa_pubkey_combine
#define ecdsa_pubkey_negate torsion_ecdsa_pubkey_negate
#define ecdsa_sig_export torsion_ecdsa_sig_export
#define ecdsa_sig_import_lax torsion_ecdsa_sig_import_lax
#define ecdsa_sig_import torsion_ecdsa_sig_import
#define ecdsa_sig_normalize torsion_ecdsa_sig_normalize
#define ecdsa_is_low_s torsion_ecdsa_is_low_s
#define ecdsa_sign torsion_ecdsa_sign
#define ecdsa_sign_internal torsion_ecdsa_sign_internal
#define ecdsa_verify torsion_ecdsa_verify
#define ecdsa_recover torsion_ecdsa_recover
#define ecdsa_derive torsion_ecdsa_derive

#define schnorr_legacy_support torsion_schnorr_legacy_support
#define schnorr_legacy_sig_size torsion_schnorr_legacy_sig_size
#define schnorr_legacy_sign torsion_schnorr_legacy_sign
#define schnorr_legacy_verify torsion_schnorr_legacy_verify
#define schnorr_legacy_verify_batch torsion_schnorr_legacy_verify_batch

#define schnorr_privkey_size torsion_schnorr_privkey_size
#define schnorr_pubkey_size torsion_schnorr_pubkey_size
#define schnorr_sig_size torsion_schnorr_sig_size
#define schnorr_privkey_generate torsion_schnorr_privkey_generate
#define schnorr_privkey_verify torsion_schnorr_privkey_verify
#define schnorr_privkey_export torsion_schnorr_privkey_export
#define schnorr_privkey_import torsion_schnorr_privkey_import
#define schnorr_privkey_tweak_add torsion_schnorr_privkey_tweak_add
#define schnorr_privkey_tweak_mul torsion_schnorr_privkey_tweak_mul
#define schnorr_privkey_invert torsion_schnorr_privkey_invert
#define schnorr_pubkey_create torsion_schnorr_pubkey_create
#define schnorr_pubkey_from_uniform torsion_schnorr_pubkey_from_uniform
#define schnorr_pubkey_to_uniform torsion_schnorr_pubkey_to_uniform
#define schnorr_pubkey_from_hash torsion_schnorr_pubkey_from_hash
#define schnorr_pubkey_to_hash torsion_schnorr_pubkey_to_hash
#define schnorr_pubkey_verify torsion_schnorr_pubkey_verify
#define schnorr_pubkey_export torsion_schnorr_pubkey_export
#define schnorr_pubkey_import torsion_schnorr_pubkey_import
#define schnorr_pubkey_tweak_add torsion_schnorr_pubkey_tweak_add
#define schnorr_pubkey_tweak_add_check torsion_schnorr_pubkey_tweak_add_check
#define schnorr_pubkey_tweak_mul torsion_schnorr_pubkey_tweak_mul
#define schnorr_pubkey_tweak_mul_check torsion_schnorr_pubkey_tweak_mul_check
#define schnorr_pubkey_add torsion_schnorr_pubkey_add
#define schnorr_pubkey_combine torsion_schnorr_pubkey_combine
#define schnorr_sign torsion_schnorr_sign
#define schnorr_verify torsion_schnorr_verify
#define schnorr_verify_batch torsion_schnorr_verify_batch
#define schnorr_derive torsion_schnorr_derive

#define ecdh_privkey_size torsion_ecdh_privkey_size
#define ecdh_pubkey_size torsion_ecdh_pubkey_size
#define ecdh_privkey_generate torsion_ecdh_privkey_generate
#define ecdh_privkey_verify torsion_ecdh_privkey_verify
#define ecdh_privkey_export torsion_ecdh_privkey_export
#define ecdh_privkey_import torsion_ecdh_privkey_import
#define ecdh_pubkey_create torsion_ecdh_pubkey_create
#define ecdh_pubkey_convert torsion_ecdh_pubkey_convert
#define ecdh_pubkey_from_uniform torsion_ecdh_pubkey_from_uniform
#define ecdh_pubkey_to_uniform torsion_ecdh_pubkey_to_uniform
#define ecdh_pubkey_from_hash torsion_ecdh_pubkey_from_hash
#define ecdh_pubkey_to_hash torsion_ecdh_pubkey_to_hash
#define ecdh_pubkey_verify torsion_ecdh_pubkey_verify
#define ecdh_pubkey_export torsion_ecdh_pubkey_export
#define ecdh_pubkey_import torsion_ecdh_pubkey_import
#define ecdh_pubkey_is_small torsion_ecdh_pubkey_is_small
#define ecdh_pubkey_has_torsion torsion_ecdh_pubkey_has_torsion
#define ecdh_derive torsion_ecdh_derive

#define eddsa_privkey_size torsion_eddsa_privkey_size
#define eddsa_pubkey_size torsion_eddsa_pubkey_size
#define eddsa_sig_size torsion_eddsa_sig_size
#define eddsa_privkey_generate torsion_eddsa_privkey_generate
#define eddsa_scalar_generate torsion_eddsa_scalar_generate
#define eddsa_privkey_expand torsion_eddsa_privkey_expand
#define eddsa_privkey_convert torsion_eddsa_privkey_convert
#define eddsa_privkey_verify torsion_eddsa_privkey_verify
#define eddsa_privkey_export torsion_eddsa_privkey_export
#define eddsa_privkey_import torsion_eddsa_privkey_import
#define eddsa_scalar_verify torsion_eddsa_scalar_verify
#define eddsa_scalar_is_zero torsion_eddsa_scalar_is_zero
#define eddsa_scalar_clamp torsion_eddsa_scalar_clamp
#define eddsa_scalar_tweak_add torsion_eddsa_scalar_tweak_add
#define eddsa_scalar_tweak_mul torsion_eddsa_scalar_tweak_mul
#define eddsa_scalar_reduce torsion_eddsa_scalar_reduce
#define eddsa_scalar_negate torsion_eddsa_scalar_negate
#define eddsa_scalar_invert torsion_eddsa_scalar_invert
#define eddsa_pubkey_from_scalar torsion_eddsa_pubkey_from_scalar
#define eddsa_pubkey_create torsion_eddsa_pubkey_create
#define eddsa_pubkey_convert torsion_eddsa_pubkey_convert
#define eddsa_pubkey_from_uniform torsion_eddsa_pubkey_from_uniform
#define eddsa_pubkey_to_uniform torsion_eddsa_pubkey_to_uniform
#define eddsa_pubkey_from_hash torsion_eddsa_pubkey_from_hash
#define eddsa_pubkey_to_hash torsion_eddsa_pubkey_to_hash
#define eddsa_pubkey_verify torsion_eddsa_pubkey_verify
#define eddsa_pubkey_export torsion_eddsa_pubkey_export
#define eddsa_pubkey_import torsion_eddsa_pubkey_import
#define eddsa_pubkey_is_infinity torsion_eddsa_pubkey_is_infinity
#define eddsa_pubkey_is_small torsion_eddsa_pubkey_is_small
#define eddsa_pubkey_has_torsion torsion_eddsa_pubkey_has_torsion
#define eddsa_pubkey_tweak_add torsion_eddsa_pubkey_tweak_add
#define eddsa_pubkey_tweak_mul torsion_eddsa_pubkey_tweak_mul
#define eddsa_pubkey_add torsion_eddsa_pubkey_add
#define eddsa_pubkey_combine torsion_eddsa_pubkey_combine
#define eddsa_pubkey_negate torsion_eddsa_pubkey_negate
#define eddsa_sign_with_scalar torsion_eddsa_sign_with_scalar
#define eddsa_sign torsion_eddsa_sign
#define eddsa_sign_tweak_add torsion_eddsa_sign_tweak_add
#define eddsa_sign_tweak_mul torsion_eddsa_sign_tweak_mul
#define eddsa_verify torsion_eddsa_verify
#define eddsa_verify_single torsion_eddsa_verify_single
#define eddsa_verify_batch torsion_eddsa_verify_batch
#define eddsa_derive_with_scalar torsion_eddsa_derive_with_scalar
#define eddsa_derive torsion_eddsa_derive

#define ristretto_privkey_size torsion_ristretto_privkey_size
#define ristretto_pubkey_size torsion_ristretto_pubkey_size
#define ristretto_privkey_generate torsion_ristretto_privkey_generate
#define ristretto_privkey_from_uniform torsion_ristretto_privkey_from_uniform
#define ristretto_privkey_verify torsion_ristretto_privkey_verify
#define ristretto_privkey_is_zero torsion_ristretto_privkey_is_zero
#define ristretto_privkey_export torsion_ristretto_privkey_export
#define ristretto_privkey_import torsion_ristretto_privkey_import
#define ristretto_privkey_tweak_add torsion_ristretto_privkey_tweak_add
#define ristretto_privkey_tweak_mul torsion_ristretto_privkey_tweak_mul
#define ristretto_privkey_negate torsion_ristretto_privkey_negate
#define ristretto_privkey_invert torsion_ristretto_privkey_invert
#define ristretto_pubkey_create torsion_ristretto_pubkey_create
#define ristretto_pubkey_from_uniform torsion_ristretto_pubkey_from_uniform
#define ristretto_pubkey_to_uniform torsion_ristretto_pubkey_to_uniform
#define ristretto_pubkey_from_hash torsion_ristretto_pubkey_from_hash
#define ristretto_pubkey_to_hash torsion_ristretto_pubkey_to_hash
#define ristretto_pubkey_verify torsion_ristretto_pubkey_verify
#define ristretto_pubkey_is_infinity torsion_ristretto_pubkey_is_infinity
#define ristretto_pubkey_tweak_add torsion_ristretto_pubkey_tweak_add
#define ristretto_pubkey_tweak_mul torsion_ristretto_pubkey_tweak_mul
#define ristretto_pubkey_add torsion_ristretto_pubkey_add
#define ristretto_pubkey_combine torsion_ristretto_pubkey_combine
#define ristretto_pubkey_negate torsion_ristretto_pubkey_negate
#define ristretto_derive torsion_ristretto_derive

#define test_ecc_internal __torsion_test_ecc_internal


/*
 * Defs
 */

#define WEI_MAX_FIELD_SIZE 66
#define WEI_MAX_SCALAR_SIZE 66

#define MONT_MAX_FIELD_SIZE 56
#define MONT_MAX_SCALAR_SIZE 56

#define EDWARDS_MAX_FIELD_SIZE 56
#define EDWARDS_MAX_SCALAR_SIZE 56

#define ECDSA_MAX_PRIV_SIZE WEI_MAX_SCALAR_SIZE /* 66 */
#define ECDSA_MAX_PUB_SIZE (1 + WEI_MAX_FIELD_SIZE * 2) /* 133 */
#define ECDSA_MAX_SIG_SIZE (WEI_MAX_SCALAR_SIZE * 2) /* 132 */
#define ECDSA_MAX_DER_SIZE (9 + ECDSA_MAX_SIG_SIZE) /* 141 */

#define SCHNORR_LEGACY_MAX_PRIV_SIZE ECDSA_MAX_PRIV_SIZE
#define SCHNORR_LEGACY_MAX_PUB_SIZE ECDSA_MAX_PUB_SIZE
#define SCHNORR_LEGACY_MAX_SIG_SIZE \
  (WEI_MAX_FIELD_SIZE + WEI_MAX_SCALAR_SIZE) /* 132 */

#define SCHNORR_MAX_PRIV_SIZE WEI_MAX_SCALAR_SIZE /* 66 */
#define SCHNORR_MAX_PUB_SIZE WEI_MAX_FIELD_SIZE /* 66 */
#define SCHNORR_MAX_SIG_SIZE \
  (WEI_MAX_FIELD_SIZE + WEI_MAX_SCALAR_SIZE) /* 132 */

#define ECDH_MAX_PRIV_SIZE MONT_MAX_SCALAR_SIZE /* 56 */
#define ECDH_MAX_PUB_SIZE MONT_MAX_FIELD_SIZE /* 56 */

#define EDDSA_MAX_PRIV_SIZE (EDWARDS_MAX_FIELD_SIZE + 1) /* 57 */
#define EDDSA_MAX_PUB_SIZE (EDWARDS_MAX_FIELD_SIZE + 1) /* 57 */
#define EDDSA_MAX_PREFIX_SIZE (EDWARDS_MAX_FIELD_SIZE + 1) /* 57 */
#define EDDSA_MAX_SIG_SIZE (EDDSA_MAX_PUB_SIZE * 2) /* 114 */

#define RISTRETTO_MAX_PRIV_SIZE EDWARDS_MAX_SCALAR_SIZE /* 56 */
#define RISTRETTO_MAX_PUB_SIZE EDWARDS_MAX_FIELD_SIZE /* 56 */

/*
 * Curves
 */

#define WEI_CURVE_P192 0
#define WEI_CURVE_P224 1
#define WEI_CURVE_P256 2
#define WEI_CURVE_P384 3
#define WEI_CURVE_P521 4
#define WEI_CURVE_SECP256K1 5
#define WEI_CURVE_MAX 5

#define MONT_CURVE_X25519 0
#define MONT_CURVE_X448 1
#define MONT_CURVE_MAX 1

#define EDWARDS_CURVE_ED25519 0
#define EDWARDS_CURVE_ED448 1
#define EDWARDS_CURVE_ED1174 2
#define EDWARDS_CURVE_MAX 2

/*
 * Types
 */

typedef struct wei_s wei_curve_t;
typedef struct wei_scratch_s wei_scratch_t;
typedef struct mont_s mont_curve_t;
typedef struct edwards_s edwards_curve_t;
typedef struct edwards_scratch_s edwards_scratch_t;

typedef void ecdsa_redefine_f(void *, size_t);

/*
 * Short Weierstrass Curve
 */

TORSION_EXTERN wei_curve_t *
wei_curve_create(int type);

TORSION_EXTERN void
wei_curve_destroy(wei_curve_t *ec);

TORSION_EXTERN void
wei_curve_randomize(wei_curve_t *ec, const unsigned char *entropy);

TORSION_EXTERN size_t
wei_curve_scalar_size(const wei_curve_t *ec);

TORSION_EXTERN unsigned int
wei_curve_scalar_bits(const wei_curve_t *ec);

TORSION_EXTERN size_t
wei_curve_field_size(const wei_curve_t *ec);

TORSION_EXTERN unsigned int
wei_curve_field_bits(const wei_curve_t *ec);

TORSION_EXTERN wei_scratch_t *
wei_scratch_create(const wei_curve_t *ec, size_t size);

TORSION_EXTERN void
wei_scratch_destroy(const wei_curve_t *ec, wei_scratch_t *scratch);

/*
 * Montgomery Curve
 */

TORSION_EXTERN mont_curve_t *
mont_curve_create(int type);

TORSION_EXTERN void
mont_curve_destroy(mont_curve_t *ec);

TORSION_EXTERN size_t
mont_curve_scalar_size(const mont_curve_t *ec);

TORSION_EXTERN unsigned int
mont_curve_scalar_bits(const mont_curve_t *ec);

TORSION_EXTERN size_t
mont_curve_field_size(const mont_curve_t *ec);

TORSION_EXTERN unsigned int
mont_curve_field_bits(const mont_curve_t *ec);

/*
 * Edwards Curve
 */

TORSION_EXTERN edwards_curve_t *
edwards_curve_create(int type);

TORSION_EXTERN void
edwards_curve_destroy(edwards_curve_t *ec);

TORSION_EXTERN void
edwards_curve_randomize(edwards_curve_t *ec, const unsigned char *entropy);

TORSION_EXTERN size_t
edwards_curve_scalar_size(const edwards_curve_t *ec);

TORSION_EXTERN unsigned int
edwards_curve_scalar_bits(const edwards_curve_t *ec);

TORSION_EXTERN size_t
edwards_curve_field_size(const edwards_curve_t *ec);

TORSION_EXTERN unsigned int
edwards_curve_field_bits(const edwards_curve_t *ec);

TORSION_EXTERN edwards_scratch_t *
edwards_scratch_create(const edwards_curve_t *ec, size_t size);

TORSION_EXTERN void
edwards_scratch_destroy(const edwards_curve_t *ec, edwards_scratch_t *scratch);

/*
 * ECDSA
 */

TORSION_EXTERN size_t
ecdsa_privkey_size(const wei_curve_t *ec);

TORSION_EXTERN size_t
ecdsa_pubkey_size(const wei_curve_t *ec, int compact);

TORSION_EXTERN size_t
ecdsa_sig_size(const wei_curve_t *ec);

TORSION_EXTERN void
ecdsa_privkey_generate(const wei_curve_t *ec,
                       unsigned char *out,
                       const unsigned char *entropy);

TORSION_EXTERN int
ecdsa_privkey_verify(const wei_curve_t *ec, const unsigned char *priv);

TORSION_EXTERN int
ecdsa_privkey_export(const wei_curve_t *ec,
                     unsigned char *out,
                     const unsigned char *priv);

TORSION_EXTERN int
ecdsa_privkey_import(const wei_curve_t *ec,
                     unsigned char *out,
                     const unsigned char *bytes,
                     size_t len);

TORSION_EXTERN int
ecdsa_privkey_tweak_add(const wei_curve_t *ec,
                        unsigned char *out,
                        const unsigned char *priv,
                        const unsigned char *tweak);

TORSION_EXTERN int
ecdsa_privkey_tweak_mul(const wei_curve_t *ec,
                        unsigned char *out,
                        const unsigned char *priv,
                        const unsigned char *tweak);

TORSION_EXTERN int
ecdsa_privkey_negate(const wei_curve_t *ec,
                     unsigned char *out,
                     const unsigned char *priv);

TORSION_EXTERN int
ecdsa_privkey_invert(const wei_curve_t *ec,
                     unsigned char *out,
                     const unsigned char *priv);

TORSION_EXTERN int
ecdsa_pubkey_create(const wei_curve_t *ec,
                    unsigned char *pub,
                    size_t *pub_len,
                    const unsigned char *priv,
                    int compact);

TORSION_EXTERN int
ecdsa_pubkey_convert(const wei_curve_t *ec,
                     unsigned char *out,
                     size_t *out_len,
                     const unsigned char *pub,
                     size_t pub_len,
                     int compact);

TORSION_EXTERN void
ecdsa_pubkey_from_uniform(const wei_curve_t *ec,
                          unsigned char *out,
                          size_t *out_len,
                          const unsigned char *bytes,
                          int compact);

TORSION_EXTERN int
ecdsa_pubkey_to_uniform(const wei_curve_t *ec,
                        unsigned char *out,
                        const unsigned char *pub,
                        size_t pub_len,
                        unsigned int hint);

TORSION_EXTERN int
ecdsa_pubkey_from_hash(const wei_curve_t *ec,
                       unsigned char *out,
                       size_t *out_len,
                       const unsigned char *bytes,
                       int compact);

TORSION_EXTERN int
ecdsa_pubkey_to_hash(const wei_curve_t *ec,
                     unsigned char *out,
                     const unsigned char *pub,
                     size_t pub_len,
                     unsigned int subgroup,
                     const unsigned char *entropy);

TORSION_EXTERN int
ecdsa_pubkey_verify(const wei_curve_t *ec,
                    const unsigned char *pub,
                    size_t pub_len);

TORSION_EXTERN int
ecdsa_pubkey_export(const wei_curve_t *ec,
                    unsigned char *x_raw,
                    unsigned char *y_raw,
                    const unsigned char *pub,
                    size_t pub_len);

TORSION_EXTERN int
ecdsa_pubkey_import(const wei_curve_t *ec,
                    unsigned char *out,
                    size_t *out_len,
                    const unsigned char *x_raw,
                    size_t x_len,
                    const unsigned char *y_raw,
                    size_t y_len,
                    int sign,
                    int compact);

TORSION_EXTERN int
ecdsa_pubkey_tweak_add(const wei_curve_t *ec,
                       unsigned char *out,
                       size_t *out_len,
                       const unsigned char *pub,
                       size_t pub_len,
                       const unsigned char *tweak,
                       int compact);

TORSION_EXTERN int
ecdsa_pubkey_tweak_mul(const wei_curve_t *ec,
                       unsigned char *out,
                       size_t *out_len,
                       const unsigned char *pub,
                       size_t pub_len,
                       const unsigned char *tweak,
                       int compact);

TORSION_EXTERN int
ecdsa_pubkey_add(const wei_curve_t *ec,
                 unsigned char *out,
                 size_t *out_len,
                 const unsigned char *pub1,
                 size_t pub_len1,
                 const unsigned char *pub2,
                 size_t pub_len2,
                 int compact);

TORSION_EXTERN int
ecdsa_pubkey_combine(const wei_curve_t *ec,
                     unsigned char *out,
                     size_t *out_len,
                     const unsigned char *const *pubs,
                     const size_t *pub_lens,
                     size_t len,
                     int compact);

TORSION_EXTERN int
ecdsa_pubkey_negate(const wei_curve_t *ec,
                    unsigned char *out,
                    size_t *out_len,
                    const unsigned char *pub,
                    size_t pub_len,
                    int compact);

TORSION_EXTERN int
ecdsa_sig_export(const wei_curve_t *ec,
                 unsigned char *out,
                 size_t *out_len,
                 const unsigned char *sig);

TORSION_EXTERN int
ecdsa_sig_import_lax(const wei_curve_t *ec,
                     unsigned char *out,
                     const unsigned char *der,
                     size_t der_len);

TORSION_EXTERN int
ecdsa_sig_import(const wei_curve_t *ec,
                 unsigned char *out,
                 const unsigned char *der,
                 size_t der_len);

TORSION_EXTERN int
ecdsa_sig_normalize(const wei_curve_t *ec,
                    unsigned char *out,
                    const unsigned char *sig);

TORSION_EXTERN int
ecdsa_is_low_s(const wei_curve_t *ec, const unsigned char *sig);

TORSION_EXTERN int
ecdsa_sign(const wei_curve_t *ec,
           unsigned char *sig,
           unsigned int *param,
           const unsigned char *msg,
           size_t msg_len,
           const unsigned char *priv);

TORSION_EXTERN int
ecdsa_sign_internal(const wei_curve_t *ec,
                    unsigned char *sig,
                    unsigned int *param,
                    const unsigned char *msg,
                    size_t msg_len,
                    const unsigned char *priv,
                    ecdsa_redefine_f *redefine);

TORSION_EXTERN int
ecdsa_verify(const wei_curve_t *ec,
             const unsigned char *msg,
             size_t msg_len,
             const unsigned char *sig,
             const unsigned char *pub,
             size_t pub_len);

TORSION_EXTERN int
ecdsa_recover(const wei_curve_t *ec,
              unsigned char *pub,
              size_t *pub_len,
              const unsigned char *msg,
              size_t msg_len,
              const unsigned char *sig,
              unsigned int param,
              int compact);

TORSION_EXTERN int
ecdsa_derive(const wei_curve_t *ec,
             unsigned char *secret,
             size_t *secret_len,
             const unsigned char *pub,
             size_t pub_len,
             const unsigned char *priv,
             int compact);

/*
 * Schnorr Legacy
 */

TORSION_EXTERN int
schnorr_legacy_support(const wei_curve_t *ec);

#define schnorr_legacy_privkey_size ecdsa_privkey_size
#define schnorr_legacy_pubkey_size ecdsa_pubkey_size

TORSION_EXTERN size_t
schnorr_legacy_sig_size(const wei_curve_t *ec);

#define schnorr_legacy_privkey_generate ecdsa_privkey_generate
#define schnorr_legacy_privkey_verify ecdsa_privkey_verify
#define schnorr_legacy_privkey_export ecdsa_privkey_export
#define schnorr_legacy_privkey_import ecdsa_privkey_import
#define schnorr_legacy_privkey_tweak_add ecdsa_privkey_tweak_add
#define schnorr_legacy_privkey_tweak_mul ecdsa_privkey_tweak_mul
#define schnorr_legacy_privkey_negate ecdsa_privkey_negate
#define schnorr_legacy_privkey_invert ecdsa_privkey_invert
#define schnorr_legacy_pubkey_create ecdsa_pubkey_create
#define schnorr_legacy_pubkey_convert ecdsa_pubkey_convert
#define schnorr_legacy_pubkey_from_uniform ecdsa_pubkey_from_uniform
#define schnorr_legacy_pubkey_to_uniform ecdsa_pubkey_to_uniform
#define schnorr_legacy_pubkey_from_hash ecdsa_pubkey_from_hash
#define schnorr_legacy_pubkey_to_hash ecdsa_pubkey_to_hash
#define schnorr_legacy_pubkey_verify ecdsa_pubkey_verify
#define schnorr_legacy_pubkey_export ecdsa_pubkey_export
#define schnorr_legacy_pubkey_import ecdsa_pubkey_import
#define schnorr_legacy_pubkey_tweak_add ecdsa_pubkey_tweak_add
#define schnorr_legacy_pubkey_tweak_mul ecdsa_pubkey_tweak_mul
#define schnorr_legacy_pubkey_add ecdsa_pubkey_add
#define schnorr_legacy_pubkey_combine ecdsa_pubkey_combine
#define schnorr_legacy_pubkey_negate ecdsa_pubkey_negate

TORSION_EXTERN int
schnorr_legacy_sign(const wei_curve_t *ec,
                    unsigned char *sig,
                    const unsigned char *msg,
                    size_t msg_len,
                    const unsigned char *priv);

TORSION_EXTERN int
schnorr_legacy_verify(const wei_curve_t *ec,
                      const unsigned char *msg,
                      size_t msg_len,
                      const unsigned char *sig,
                      const unsigned char *pub,
                      size_t pub_len);

TORSION_EXTERN int
schnorr_legacy_verify_batch(const wei_curve_t *ec,
                            const unsigned char *const *msgs,
                            const size_t *msg_lens,
                            const unsigned char *const *sigs,
                            const unsigned char *const *pubs,
                            const size_t *pub_lens,
                            size_t len,
                            wei_scratch_t *scratch);

#define schnorr_legacy_derive ecdsa_derive

/*
 * Schnorr
 */

TORSION_EXTERN size_t
schnorr_privkey_size(const wei_curve_t *ec);

TORSION_EXTERN size_t
schnorr_pubkey_size(const wei_curve_t *ec);

TORSION_EXTERN size_t
schnorr_sig_size(const wei_curve_t *ec);

TORSION_EXTERN void
schnorr_privkey_generate(const wei_curve_t *ec,
                         unsigned char *out,
                         const unsigned char *entropy);

TORSION_EXTERN int
schnorr_privkey_verify(const wei_curve_t *ec, const unsigned char *priv);

TORSION_EXTERN int
schnorr_privkey_export(const wei_curve_t *ec,
                       unsigned char *d_raw,
                       unsigned char *x_raw,
                       unsigned char *y_raw,
                       const unsigned char *priv);

TORSION_EXTERN int
schnorr_privkey_import(const wei_curve_t *ec,
                       unsigned char *out,
                       const unsigned char *bytes,
                       size_t len);

TORSION_EXTERN int
schnorr_privkey_tweak_add(const wei_curve_t *ec,
                          unsigned char *out,
                          const unsigned char *priv,
                          const unsigned char *tweak);

TORSION_EXTERN int
schnorr_privkey_tweak_mul(const wei_curve_t *ec,
                          unsigned char *out,
                          const unsigned char *priv,
                          const unsigned char *tweak);

TORSION_EXTERN int
schnorr_privkey_invert(const wei_curve_t *ec,
                       unsigned char *out,
                       const unsigned char *priv);

TORSION_EXTERN int
schnorr_pubkey_create(const wei_curve_t *ec,
                      unsigned char *pub,
                      const unsigned char *priv);

TORSION_EXTERN void
schnorr_pubkey_from_uniform(const wei_curve_t *ec,
                            unsigned char *out,
                            const unsigned char *bytes);

TORSION_EXTERN int
schnorr_pubkey_to_uniform(const wei_curve_t *ec,
                          unsigned char *out,
                          const unsigned char *pub,
                          unsigned int hint);

TORSION_EXTERN int
schnorr_pubkey_from_hash(const wei_curve_t *ec,
                         unsigned char *out,
                         const unsigned char *bytes);

TORSION_EXTERN int
schnorr_pubkey_to_hash(const wei_curve_t *ec,
                       unsigned char *out,
                       const unsigned char *pub,
                       unsigned int subgroup,
                       const unsigned char *entropy);

TORSION_EXTERN int
schnorr_pubkey_verify(const wei_curve_t *ec, const unsigned char *pub);

TORSION_EXTERN int
schnorr_pubkey_export(const wei_curve_t *ec,
                      unsigned char *x_raw,
                      unsigned char *y_raw,
                      const unsigned char *pub);

TORSION_EXTERN int
schnorr_pubkey_import(const wei_curve_t *ec,
                      unsigned char *out,
                      const unsigned char *x_raw,
                      size_t x_len,
                      const unsigned char *y_raw,
                      size_t y_len);

TORSION_EXTERN int
schnorr_pubkey_tweak_add(const wei_curve_t *ec,
                         unsigned char *out,
                         int *negated,
                         const unsigned char *pub,
                         const unsigned char *tweak);

TORSION_EXTERN int
schnorr_pubkey_tweak_add_check(const wei_curve_t *ec,
                               const unsigned char *pub,
                               const unsigned char *tweak,
                               const unsigned char *expect,
                               int negated);

TORSION_EXTERN int
schnorr_pubkey_tweak_mul(const wei_curve_t *ec,
                         unsigned char *out,
                         int *negated,
                         const unsigned char *pub,
                         const unsigned char *tweak);

TORSION_EXTERN int
schnorr_pubkey_tweak_mul_check(const wei_curve_t *ec,
                               const unsigned char *pub,
                               const unsigned char *tweak,
                               const unsigned char *expect,
                               int negated);

TORSION_EXTERN int
schnorr_pubkey_add(const wei_curve_t *ec,
                   unsigned char *out,
                   const unsigned char *pub1,
                   const unsigned char *pub2);

TORSION_EXTERN int
schnorr_pubkey_combine(const wei_curve_t *ec,
                       unsigned char *out,
                       const unsigned char *const *pubs,
                       size_t len);

TORSION_EXTERN int
schnorr_sign(const wei_curve_t *ec,
             unsigned char *sig,
             const unsigned char *msg,
             size_t msg_len,
             const unsigned char *priv,
             const unsigned char *aux);

TORSION_EXTERN int
schnorr_verify(const wei_curve_t *ec,
               const unsigned char *msg,
               size_t msg_len,
               const unsigned char *sig,
               const unsigned char *pub);

TORSION_EXTERN int
schnorr_verify_batch(const wei_curve_t *ec,
                     const unsigned char *const *msgs,
                     const size_t *msg_lens,
                     const unsigned char *const *sigs,
                     const unsigned char *const *pubs,
                     size_t len,
                     wei_scratch_t *scratch);

TORSION_EXTERN int
schnorr_derive(const wei_curve_t *ec,
               unsigned char *secret,
               const unsigned char *pub,
               const unsigned char *priv);

/*
 * ECDH
 */

TORSION_EXTERN size_t
ecdh_privkey_size(const mont_curve_t *ec);

TORSION_EXTERN size_t
ecdh_pubkey_size(const mont_curve_t *ec);

TORSION_EXTERN void
ecdh_privkey_generate(const mont_curve_t *ec,
                      unsigned char *out,
                      const unsigned char *entropy);

TORSION_EXTERN int
ecdh_privkey_verify(const mont_curve_t *ec, const unsigned char *priv);

TORSION_EXTERN int
ecdh_privkey_export(const mont_curve_t *ec,
                    unsigned char *out,
                    const unsigned char *priv);

TORSION_EXTERN int
ecdh_privkey_import(const mont_curve_t *ec,
                    unsigned char *out,
                    const unsigned char *bytes,
                    size_t len);

TORSION_EXTERN void
ecdh_pubkey_create(const mont_curve_t *ec,
                   unsigned char *pub,
                   const unsigned char *priv);

TORSION_EXTERN int
ecdh_pubkey_convert(const mont_curve_t *ec,
                    unsigned char *out,
                    const unsigned char *pub,
                    int sign);

TORSION_EXTERN void
ecdh_pubkey_from_uniform(const mont_curve_t *ec,
                         unsigned char *out,
                         const unsigned char *bytes);

TORSION_EXTERN int
ecdh_pubkey_to_uniform(const mont_curve_t *ec,
                       unsigned char *out,
                       const unsigned char *pub,
                       unsigned int hint);

TORSION_EXTERN int
ecdh_pubkey_from_hash(const mont_curve_t *ec,
                      unsigned char *out,
                      const unsigned char *bytes,
                      int pake);

TORSION_EXTERN int
ecdh_pubkey_to_hash(const mont_curve_t *ec,
                    unsigned char *out,
                    const unsigned char *pub,
                    unsigned int subgroup,
                    const unsigned char *entropy);

TORSION_EXTERN int
ecdh_pubkey_verify(const mont_curve_t *ec, const unsigned char *pub);

TORSION_EXTERN int
ecdh_pubkey_export(const mont_curve_t *ec,
                   unsigned char *x_raw,
                   unsigned char *y_raw,
                   const unsigned char *pub,
                   int sign);

TORSION_EXTERN int
ecdh_pubkey_import(const mont_curve_t *ec,
                   unsigned char *out,
                   const unsigned char *x_raw,
                   size_t x_len,
                   const unsigned char *y_raw,
                   size_t y_len);

TORSION_EXTERN int
ecdh_pubkey_is_small(const mont_curve_t *ec, const unsigned char *pub);

TORSION_EXTERN int
ecdh_pubkey_has_torsion(const mont_curve_t *ec, const unsigned char *pub);

TORSION_EXTERN int
ecdh_derive(const mont_curve_t *ec,
            unsigned char *secret,
            const unsigned char *pub,
            const unsigned char *priv);

/*
 * EdDSA
 */

TORSION_EXTERN size_t
eddsa_privkey_size(const edwards_curve_t *ec);

TORSION_EXTERN size_t
eddsa_pubkey_size(const edwards_curve_t *ec);

TORSION_EXTERN size_t
eddsa_sig_size(const edwards_curve_t *ec);

TORSION_EXTERN void
eddsa_privkey_generate(const edwards_curve_t *ec,
                       unsigned char *out,
                       const unsigned char *entropy);

TORSION_EXTERN void
eddsa_scalar_generate(const edwards_curve_t *ec,
                      unsigned char *out,
                      const unsigned char *entropy);

TORSION_EXTERN void
eddsa_privkey_expand(const edwards_curve_t *ec,
                     unsigned char *scalar,
                     unsigned char *prefix,
                     const unsigned char *priv);

TORSION_EXTERN void
eddsa_privkey_convert(const edwards_curve_t *ec,
                      unsigned char *scalar,
                      const unsigned char *priv);

TORSION_EXTERN int
eddsa_privkey_verify(const edwards_curve_t *ec, const unsigned char *priv);

TORSION_EXTERN int
eddsa_privkey_export(const edwards_curve_t *ec,
                     unsigned char *out,
                     const unsigned char *priv);

TORSION_EXTERN int
eddsa_privkey_import(const edwards_curve_t *ec,
                     unsigned char *out,
                     const unsigned char *bytes,
                     size_t len);

TORSION_EXTERN int
eddsa_scalar_verify(const edwards_curve_t *ec, const unsigned char *scalar);

TORSION_EXTERN int
eddsa_scalar_is_zero(const edwards_curve_t *ec, const unsigned char *scalar);

TORSION_EXTERN void
eddsa_scalar_clamp(const edwards_curve_t *ec,
                   unsigned char *out,
                   const unsigned char *scalar);

TORSION_EXTERN void
eddsa_scalar_tweak_add(const edwards_curve_t *ec,
                       unsigned char *out,
                       const unsigned char *scalar,
                       const unsigned char *tweak);

TORSION_EXTERN void
eddsa_scalar_tweak_mul(const edwards_curve_t *ec,
                       unsigned char *out,
                       const unsigned char *scalar,
                       const unsigned char *tweak);

TORSION_EXTERN void
eddsa_scalar_reduce(const edwards_curve_t *ec,
                    unsigned char *out,
                    const unsigned char *scalar);

TORSION_EXTERN void
eddsa_scalar_negate(const edwards_curve_t *ec,
                    unsigned char *out,
                    const unsigned char *scalar);

TORSION_EXTERN void
eddsa_scalar_invert(const edwards_curve_t *ec,
                    unsigned char *out,
                    const unsigned char *scalar);

TORSION_EXTERN void
eddsa_pubkey_from_scalar(const edwards_curve_t *ec,
                         unsigned char *pub,
                         const unsigned char *scalar);

TORSION_EXTERN void
eddsa_pubkey_create(const edwards_curve_t *ec,
                    unsigned char *pub,
                    const unsigned char *priv);

TORSION_EXTERN int
eddsa_pubkey_convert(const edwards_curve_t *ec,
                     unsigned char *out,
                     const unsigned char *pub);

TORSION_EXTERN void
eddsa_pubkey_from_uniform(const edwards_curve_t *ec,
                          unsigned char *out,
                          const unsigned char *bytes);

TORSION_EXTERN int
eddsa_pubkey_to_uniform(const edwards_curve_t *ec,
                        unsigned char *out,
                        const unsigned char *pub,
                        unsigned int hint);

TORSION_EXTERN void
eddsa_pubkey_from_hash(const edwards_curve_t *ec,
                       unsigned char *out,
                       const unsigned char *bytes,
                       int pake);

TORSION_EXTERN int
eddsa_pubkey_to_hash(const edwards_curve_t *ec,
                     unsigned char *out,
                     const unsigned char *pub,
                     unsigned int subgroup,
                     const unsigned char *entropy);

TORSION_EXTERN int
eddsa_pubkey_verify(const edwards_curve_t *ec, const unsigned char *pub);

TORSION_EXTERN int
eddsa_pubkey_export(const edwards_curve_t *ec,
                    unsigned char *x_raw,
                    unsigned char *y_raw,
                    const unsigned char *pub);

TORSION_EXTERN int
eddsa_pubkey_import(const edwards_curve_t *ec,
                    unsigned char *out,
                    const unsigned char *x_raw,
                    size_t x_len,
                    const unsigned char *y_raw,
                    size_t y_len,
                    int sign);

TORSION_EXTERN int
eddsa_pubkey_is_infinity(const edwards_curve_t *ec, const unsigned char *pub);

TORSION_EXTERN int
eddsa_pubkey_is_small(const edwards_curve_t *ec, const unsigned char *pub);

TORSION_EXTERN int
eddsa_pubkey_has_torsion(const edwards_curve_t *ec, const unsigned char *pub);

TORSION_EXTERN int
eddsa_pubkey_tweak_add(const edwards_curve_t *ec,
                       unsigned char *out,
                       const unsigned char *pub,
                       const unsigned char *tweak);

TORSION_EXTERN int
eddsa_pubkey_tweak_mul(const edwards_curve_t *ec,
                       unsigned char *out,
                       const unsigned char *pub,
                       const unsigned char *tweak);

TORSION_EXTERN int
eddsa_pubkey_add(const edwards_curve_t *ec,
                 unsigned char *out,
                 const unsigned char *pub1,
                 const unsigned char *pub2);

TORSION_EXTERN int
eddsa_pubkey_combine(const edwards_curve_t *ec,
                     unsigned char *out,
                     const unsigned char *const *pubs,
                     size_t len);

TORSION_EXTERN int
eddsa_pubkey_negate(const edwards_curve_t *ec,
                    unsigned char *out,
                    const unsigned char *pub);

TORSION_EXTERN void
eddsa_sign_with_scalar(const edwards_curve_t *ec,
                       unsigned char *sig,
                       const unsigned char *msg,
                       size_t msg_len,
                       const unsigned char *scalar,
                       const unsigned char *prefix,
                       int ph,
                       const unsigned char *ctx,
                       size_t ctx_len);

TORSION_EXTERN void
eddsa_sign(const edwards_curve_t *ec,
           unsigned char *sig,
           const unsigned char *msg,
           size_t msg_len,
           const unsigned char *priv,
           int ph,
           const unsigned char *ctx,
           size_t ctx_len);

TORSION_EXTERN void
eddsa_sign_tweak_add(const edwards_curve_t *ec,
                     unsigned char *sig,
                     const unsigned char *msg,
                     size_t msg_len,
                     const unsigned char *priv,
                     const unsigned char *tweak,
                     int ph,
                     const unsigned char *ctx,
                     size_t ctx_len);

TORSION_EXTERN void
eddsa_sign_tweak_mul(const edwards_curve_t *ec,
                     unsigned char *sig,
                     const unsigned char *msg,
                     size_t msg_len,
                     const unsigned char *priv,
                     const unsigned char *tweak,
                     int ph,
                     const unsigned char *ctx,
                     size_t ctx_len);

TORSION_EXTERN int
eddsa_verify(const edwards_curve_t *ec,
             const unsigned char *msg,
             size_t msg_len,
             const unsigned char *sig,
             const unsigned char *pub,
             int ph,
             const unsigned char *ctx,
             size_t ctx_len);

TORSION_EXTERN int
eddsa_verify_single(const edwards_curve_t *ec,
                    const unsigned char *msg,
                    size_t msg_len,
                    const unsigned char *sig,
                    const unsigned char *pub,
                    int ph,
                    const unsigned char *ctx,
                    size_t ctx_len);

TORSION_EXTERN int
eddsa_verify_batch(const edwards_curve_t *ec,
                   const unsigned char *const *msgs,
                   const size_t *msg_lens,
                   const unsigned char *const *sigs,
                   const unsigned char *const *pubs,
                   size_t len,
                   int ph,
                   const unsigned char *ctx,
                   size_t ctx_len,
                   edwards_scratch_t *scratch);

TORSION_EXTERN int
eddsa_derive_with_scalar(const edwards_curve_t *ec,
                         unsigned char *secret,
                         const unsigned char *pub,
                         const unsigned char *scalar);

TORSION_EXTERN int
eddsa_derive(const edwards_curve_t *ec,
             unsigned char *secret,
             const unsigned char *pub,
             const unsigned char *priv);

/*
 * Ristretto
 */

TORSION_EXTERN size_t
ristretto_privkey_size(const edwards_curve_t *ec);

TORSION_EXTERN size_t
ristretto_pubkey_size(const edwards_curve_t *ec);

TORSION_EXTERN void
ristretto_privkey_generate(const edwards_curve_t *ec,
                           unsigned char *out,
                           const unsigned char *entropy);

TORSION_EXTERN void
ristretto_privkey_from_uniform(const edwards_curve_t *ec,
                               unsigned char *out,
                               const unsigned char *bytes);

TORSION_EXTERN int
ristretto_privkey_verify(const edwards_curve_t *ec, const unsigned char *priv);

TORSION_EXTERN int
ristretto_privkey_is_zero(const edwards_curve_t *ec, const unsigned char *priv);

TORSION_EXTERN int
ristretto_privkey_export(const edwards_curve_t *ec,
                         unsigned char *out,
                         const unsigned char *priv);

TORSION_EXTERN int
ristretto_privkey_import(const edwards_curve_t *ec,
                         unsigned char *out,
                         const unsigned char *bytes,
                         size_t len);

TORSION_EXTERN int
ristretto_privkey_tweak_add(const edwards_curve_t *ec,
                            unsigned char *out,
                            const unsigned char *priv,
                            const unsigned char *tweak);

TORSION_EXTERN int
ristretto_privkey_tweak_mul(const edwards_curve_t *ec,
                            unsigned char *out,
                            const unsigned char *priv,
                            const unsigned char *tweak);

TORSION_EXTERN int
ristretto_privkey_negate(const edwards_curve_t *ec,
                         unsigned char *out,
                         const unsigned char *priv);

TORSION_EXTERN int
ristretto_privkey_invert(const edwards_curve_t *ec,
                         unsigned char *out,
                         const unsigned char *priv);

TORSION_EXTERN int
ristretto_pubkey_create(const edwards_curve_t *ec,
                        unsigned char *pub,
                        const unsigned char *priv);

TORSION_EXTERN void
ristretto_pubkey_from_uniform(const edwards_curve_t *ec,
                              unsigned char *out,
                              const unsigned char *bytes);

TORSION_EXTERN int
ristretto_pubkey_to_uniform(const edwards_curve_t *ec,
                            unsigned char *out,
                            const unsigned char *pub,
                            unsigned int hint);

TORSION_EXTERN void
ristretto_pubkey_from_hash(const edwards_curve_t *ec,
                           unsigned char *out,
                           const unsigned char *bytes);

TORSION_EXTERN int
ristretto_pubkey_to_hash(const edwards_curve_t *ec,
                         unsigned char *out,
                         const unsigned char *pub,
                         const unsigned char *entropy);

TORSION_EXTERN int
ristretto_pubkey_verify(const edwards_curve_t *ec, const unsigned char *pub);

TORSION_EXTERN int
ristretto_pubkey_is_infinity(const edwards_curve_t *ec,
                             const unsigned char *pub);

TORSION_EXTERN int
ristretto_pubkey_tweak_add(const edwards_curve_t *ec,
                           unsigned char *out,
                           const unsigned char *pub,
                           const unsigned char *tweak);

TORSION_EXTERN int
ristretto_pubkey_tweak_mul(const edwards_curve_t *ec,
                           unsigned char *out,
                           const unsigned char *pub,
                           const unsigned char *tweak);

TORSION_EXTERN int
ristretto_pubkey_add(const edwards_curve_t *ec,
                     unsigned char *out,
                     const unsigned char *pub1,
                     const unsigned char *pub2);

TORSION_EXTERN int
ristretto_pubkey_combine(const edwards_curve_t *ec,
                         unsigned char *out,
                         const unsigned char *const *pubs,
                         size_t len);

TORSION_EXTERN int
ristretto_pubkey_negate(const edwards_curve_t *ec,
                        unsigned char *out,
                        const unsigned char *pub);

TORSION_EXTERN int
ristretto_derive(const edwards_curve_t *ec,
                 unsigned char *secret,
                 const unsigned char *pub,
                 const unsigned char *priv);

/*
 * Testing
 */

struct hmac_drbg_s;

TORSION_EXTERN void
test_ecc_internal(struct hmac_drbg_s *rng);

#ifdef __cplusplus
}
#endif

#endif /* _TORSION_ECC_H */
