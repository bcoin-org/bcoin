#ifndef _TORSION_ECC_H
#define _TORSION_ECC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

/*
 * Symbol Aliases
 */

#define ecdsa_context_create torsion_ecdsa_context_create
#define ecdsa_context_destroy torsion_ecdsa_context_destroy
#define ecdsa_context_randomize torsion_ecdsa_context_randomize
#define ecdsa_scratch_create torsion_ecdsa_scratch_create
#define ecdsa_scratch_destroy torsion_ecdsa_scratch_destroy
#define ecdsa_scalar_size torsion_ecdsa_scalar_size
#define ecdsa_scalar_bits torsion_ecdsa_scalar_bits
#define ecdsa_field_size torsion_ecdsa_field_size
#define ecdsa_field_bits torsion_ecdsa_field_bits
#define ecdsa_privkey_size torsion_ecdsa_privkey_size
#define ecdsa_pubkey_size torsion_ecdsa_pubkey_size
#define ecdsa_sig_size torsion_ecdsa_sig_size
#define ecdsa_schnorr_size torsion_ecdsa_schnorr_size
#define ecdsa_privkey_generate torsion_ecdsa_privkey_generate
#define ecdsa_privkey_verify torsion_ecdsa_privkey_verify
#define ecdsa_privkey_export torsion_ecdsa_privkey_export
#define ecdsa_privkey_import torsion_ecdsa_privkey_import
#define ecdsa_privkey_tweak_add torsion_ecdsa_privkey_tweak_add
#define ecdsa_privkey_tweak_mul torsion_ecdsa_privkey_tweak_mul
#define ecdsa_privkey_reduce torsion_ecdsa_privkey_reduce
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
#define ecdsa_pubkey_combine torsion_ecdsa_pubkey_combine
#define ecdsa_pubkey_negate torsion_ecdsa_pubkey_negate
#define ecdsa_sig_export torsion_ecdsa_sig_export
#define ecdsa_sig_import_lax torsion_ecdsa_sig_import_lax
#define ecdsa_sig_import torsion_ecdsa_sig_import
#define ecdsa_sig_normalize torsion_ecdsa_sig_normalize
#define ecdsa_is_low_s torsion_ecdsa_is_low_s
#define ecdsa_sign torsion_ecdsa_sign
#define ecdsa_verify torsion_ecdsa_verify
#define ecdsa_recover torsion_ecdsa_recover
#define ecdsa_derive torsion_ecdsa_derive
#define ecdsa_schnorr_support torsion_ecdsa_schnorr_support
#define ecdsa_schnorr_sign torsion_ecdsa_schnorr_sign
#define ecdsa_schnorr_verify torsion_ecdsa_schnorr_verify
#define ecdsa_schnorr_verify_batch torsion_ecdsa_schnorr_verify_batch

#define schnorr_context_create torsion_schnorr_context_create
#define schnorr_context_destroy torsion_schnorr_context_destroy
#define schnorr_context_randomize torsion_schnorr_context_randomize
#define schnorr_scratch_create torsion_schnorr_scratch_create
#define schnorr_scratch_destroy torsion_schnorr_scratch_destroy
#define schnorr_scalar_size torsion_schnorr_scalar_size
#define schnorr_scalar_bits torsion_schnorr_scalar_bits
#define schnorr_field_size torsion_schnorr_field_size
#define schnorr_field_bits torsion_schnorr_field_bits
#define schnorr_privkey_size torsion_schnorr_privkey_size
#define schnorr_pubkey_size torsion_schnorr_pubkey_size
#define schnorr_sig_size torsion_schnorr_sig_size
#define schnorr_privkey_generate torsion_schnorr_privkey_generate
#define schnorr_privkey_verify torsion_schnorr_privkey_verify
#define schnorr_privkey_export torsion_schnorr_privkey_export
#define schnorr_privkey_import torsion_schnorr_privkey_import
#define schnorr_privkey_tweak_add torsion_schnorr_privkey_tweak_add
#define schnorr_privkey_tweak_mul torsion_schnorr_privkey_tweak_mul
#define schnorr_privkey_reduce torsion_schnorr_privkey_reduce
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
#define schnorr_pubkey_tweak_mul torsion_schnorr_pubkey_tweak_mul
#define schnorr_pubkey_tweak_test torsion_schnorr_pubkey_tweak_test
#define schnorr_pubkey_combine torsion_schnorr_pubkey_combine
#define schnorr_sign torsion_schnorr_sign
#define schnorr_verify torsion_schnorr_verify
#define schnorr_verify_batch torsion_schnorr_verify_batch
#define schnorr_derive torsion_schnorr_derive

#define ecdh_context_create torsion_ecdh_context_create
#define ecdh_context_destroy torsion_ecdh_context_destroy
#define ecdh_scalar_size torsion_ecdh_scalar_size
#define ecdh_scalar_bits torsion_ecdh_scalar_bits
#define ecdh_field_size torsion_ecdh_field_size
#define ecdh_field_bits torsion_ecdh_field_bits
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

#define eddsa_context_create torsion_eddsa_context_create
#define eddsa_context_destroy torsion_eddsa_context_destroy
#define eddsa_context_randomize torsion_eddsa_context_randomize
#define eddsa_scratch_create torsion_eddsa_scratch_create
#define eddsa_scratch_destroy torsion_eddsa_scratch_destroy
#define eddsa_scalar_size torsion_eddsa_scalar_size
#define eddsa_scalar_bits torsion_eddsa_scalar_bits
#define eddsa_field_size torsion_eddsa_field_size
#define eddsa_field_bits torsion_eddsa_field_bits
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

/*
 * Defs
 */

#define ECDSA_MAX_FIELD_SIZE 66
#define ECDSA_MAX_SCALAR_SIZE 66
#define ECDSA_MAX_PRIV_SIZE ECDSA_MAX_SCALAR_SIZE /* 66 */
#define ECDSA_MAX_PUB_SIZE (1 + ECDSA_MAX_FIELD_SIZE * 2) /* 133 */
#define ECDSA_MAX_SIG_SIZE (ECDSA_MAX_SCALAR_SIZE * 2) /* 132 */
#define ECDSA_MAX_DER_SIZE (9 + ECDSA_MAX_SIG_SIZE) /* 141 */
#define ECDSA_MAX_SCHNORR_SIZE (ECDSA_MAX_FIELD_SIZE + ECDSA_MAX_SCALAR_SIZE) /* 132 */

#define SCHNORR_MAX_FIELD_SIZE 66
#define SCHNORR_MAX_SCALAR_SIZE 66
#define SCHNORR_MAX_PRIV_SIZE SCHNORR_MAX_SCALAR_SIZE /* 66 */
#define SCHNORR_MAX_PUB_SIZE SCHNORR_MAX_FIELD_SIZE /* 66 */
#define SCHNORR_MAX_SIG_SIZE (SCHNORR_MAX_FIELD_SIZE + SCHNORR_MAX_SCALAR_SIZE) /* 132 */

#define ECDH_MAX_FIELD_SIZE 56
#define ECDH_MAX_SCALAR_SIZE 56
#define ECDH_MAX_PRIV_SIZE ECDH_MAX_SCALAR_SIZE /* 56 */
#define ECDH_MAX_PUB_SIZE ECDH_MAX_FIELD_SIZE /* 56 */

#define EDDSA_MAX_FIELD_SIZE 56
#define EDDSA_MAX_SCALAR_SIZE 56
#define EDDSA_MAX_PRIV_SIZE (EDDSA_MAX_FIELD_SIZE + 1) /* 57 */
#define EDDSA_MAX_PUB_SIZE (EDDSA_MAX_FIELD_SIZE + 1) /* 57 */
#define EDDSA_MAX_PREFIX_SIZE (EDDSA_MAX_FIELD_SIZE + 1) /* 57 */
#define EDDSA_MAX_SIG_SIZE (EDDSA_MAX_PUB_SIZE * 2) /* 114 */

/*
 * Curves
 */

#define ECDSA_CURVE_P192 0
#define ECDSA_CURVE_P224 1
#define ECDSA_CURVE_P256 2
#define ECDSA_CURVE_P384 3
#define ECDSA_CURVE_P521 4
#define ECDSA_CURVE_SECP256K1 5
#define ECDSA_CURVE_MAX 5

#define SCHNORR_CURVE_P192 0
#define SCHNORR_CURVE_P256 2
#define SCHNORR_CURVE_P384 3
#define SCHNORR_CURVE_P521 4
#define SCHNORR_CURVE_SECP256K1 5
#define SCHNORR_CURVE_MAX 5

#define ECDH_CURVE_X25519 0
#define ECDH_CURVE_X448 1
#define ECDH_CURVE_MAX 1

#define EDDSA_CURVE_ED25519 0
#define EDDSA_CURVE_ED448 1
#define EDDSA_CURVE_ED1174 2
#define EDDSA_CURVE_MAX 2

/*
 * Structs
 */

typedef struct _wei_s ecdsa_t;
typedef struct _wei_scratch_s ecdsa_scratch_t;
typedef struct _wei_s schnorr_t;
typedef struct _wei_scratch_s schnorr_scratch_t;
typedef struct _mont_s ecdh_t;
typedef struct _edwards_s eddsa_t;
typedef struct _edwards_scratch_s eddsa_scratch_t;

/*
 * ECDSA
 */

ecdsa_t *
ecdsa_context_create(int type);

void
ecdsa_context_destroy(ecdsa_t *ec);

void
ecdsa_context_randomize(ecdsa_t *ec, const unsigned char *entropy);

ecdsa_scratch_t *
ecdsa_scratch_create(const ecdsa_t *ec);

void
ecdsa_scratch_destroy(const ecdsa_t *ec, ecdsa_scratch_t *scratch);

size_t
ecdsa_scalar_size(const ecdsa_t *ec);

size_t
ecdsa_scalar_bits(const ecdsa_t *ec);

size_t
ecdsa_field_size(const ecdsa_t *ec);

size_t
ecdsa_field_bits(const ecdsa_t *ec);

size_t
ecdsa_privkey_size(const ecdsa_t *ec);

size_t
ecdsa_pubkey_size(const ecdsa_t *ec, int compact);

size_t
ecdsa_sig_size(const ecdsa_t *ec);

size_t
ecdsa_schnorr_size(const ecdsa_t *ec);

void
ecdsa_privkey_generate(const ecdsa_t *ec,
                       unsigned char *out,
                       const unsigned char *entropy);

int
ecdsa_privkey_verify(const ecdsa_t *ec, const unsigned char *priv);

int
ecdsa_privkey_export(const ecdsa_t *ec,
                     unsigned char *out,
                     const unsigned char *priv);

int
ecdsa_privkey_import(const ecdsa_t *ec,
                     unsigned char *out,
                     const unsigned char *bytes,
                     size_t len);

int
ecdsa_privkey_tweak_add(const ecdsa_t *ec,
                        unsigned char *out,
                        const unsigned char *priv,
                        const unsigned char *tweak);

int
ecdsa_privkey_tweak_mul(const ecdsa_t *ec,
                        unsigned char *out,
                        const unsigned char *priv,
                        const unsigned char *tweak);

int
ecdsa_privkey_reduce(const ecdsa_t *ec,
                     unsigned char *out,
                     const unsigned char *bytes,
                     size_t len);

int
ecdsa_privkey_negate(const ecdsa_t *ec,
                     unsigned char *out,
                     const unsigned char *priv);

int
ecdsa_privkey_invert(const ecdsa_t *ec,
                     unsigned char *out,
                     const unsigned char *priv);

int
ecdsa_pubkey_create(const ecdsa_t *ec,
                    unsigned char *pub,
                    size_t *pub_len,
                    const unsigned char *priv,
                    int compact);

int
ecdsa_pubkey_convert(const ecdsa_t *ec,
                     unsigned char *out,
                     size_t *out_len,
                     const unsigned char *pub,
                     size_t pub_len,
                     int compact);

void
ecdsa_pubkey_from_uniform(const ecdsa_t *ec,
                          unsigned char *out,
                          size_t *out_len,
                          const unsigned char *bytes,
                          int compact);

int
ecdsa_pubkey_to_uniform(const ecdsa_t *ec,
                        unsigned char *out,
                        const unsigned char *pub,
                        size_t pub_len,
                        unsigned int hint);

int
ecdsa_pubkey_from_hash(const ecdsa_t *ec,
                       unsigned char *out,
                       size_t *out_len,
                       const unsigned char *bytes,
                       int compact);

int
ecdsa_pubkey_to_hash(const ecdsa_t *ec,
                     unsigned char *out,
                     const unsigned char *pub,
                     size_t pub_len,
                     unsigned int subgroup,
                     const unsigned char *entropy);

int
ecdsa_pubkey_verify(const ecdsa_t *ec,
                    const unsigned char *pub,
                    size_t pub_len);

int
ecdsa_pubkey_export(const ecdsa_t *ec,
                    unsigned char *x_raw,
                    unsigned char *y_raw,
                    const unsigned char *pub,
                    size_t pub_len);

int
ecdsa_pubkey_import(const ecdsa_t *ec,
                    unsigned char *out,
                    size_t *out_len,
                    const unsigned char *x_raw,
                    size_t x_len,
                    const unsigned char *y_raw,
                    size_t y_len,
                    int sign,
                    int compact);

int
ecdsa_pubkey_tweak_add(const ecdsa_t *ec,
                       unsigned char *out,
                       size_t *out_len,
                       const unsigned char *pub,
                       size_t pub_len,
                       const unsigned char *tweak,
                       int compact);

int
ecdsa_pubkey_tweak_mul(const ecdsa_t *ec,
                       unsigned char *out,
                       size_t *out_len,
                       const unsigned char *pub,
                       size_t pub_len,
                       const unsigned char *tweak,
                       int compact);

int
ecdsa_pubkey_combine(const ecdsa_t *ec,
                     unsigned char *out,
                     size_t *out_len,
                     const unsigned char **pubs,
                     const size_t *pub_lens,
                     size_t len,
                     int compact);

int
ecdsa_pubkey_negate(const ecdsa_t *ec,
                    unsigned char *out,
                    size_t *out_len,
                    const unsigned char *pub,
                    size_t pub_len,
                    int compact);

int
ecdsa_sig_export(const ecdsa_t *ec,
                 unsigned char *out,
                 size_t *out_len,
                 const unsigned char *sig);

int
ecdsa_sig_import_lax(const ecdsa_t *ec,
                     unsigned char *out,
                     const unsigned char *der,
                     size_t der_len);

int
ecdsa_sig_import(const ecdsa_t *ec,
                 unsigned char *out,
                 const unsigned char *der,
                 size_t der_len);

int
ecdsa_sig_normalize(const ecdsa_t *ec,
                    unsigned char *out,
                    const unsigned char *sig);

int
ecdsa_is_low_s(const ecdsa_t *ec, const unsigned char *sig);

int
ecdsa_sign(const ecdsa_t *ec,
           unsigned char *sig,
           unsigned int *param,
           const unsigned char *msg,
           size_t msg_len,
           const unsigned char *priv);

int
ecdsa_verify(const ecdsa_t *ec,
             const unsigned char *msg,
             size_t msg_len,
             const unsigned char *sig,
             const unsigned char *pub,
             size_t pub_len);

int
ecdsa_recover(const ecdsa_t *ec,
              unsigned char *pub,
              size_t *pub_len,
              const unsigned char *msg,
              size_t msg_len,
              const unsigned char *sig,
              unsigned int param,
              int compact);

int
ecdsa_derive(const ecdsa_t *ec,
             unsigned char *secret,
             size_t *secret_len,
             const unsigned char *pub,
             size_t pub_len,
             const unsigned char *priv,
             int compact);

int
ecdsa_schnorr_support(const ecdsa_t *ec);

int
ecdsa_schnorr_sign(const ecdsa_t *ec,
                   unsigned char *sig,
                   const unsigned char *msg,
                   size_t msg_len,
                   const unsigned char *priv);

int
ecdsa_schnorr_verify(const ecdsa_t *ec,
                     const unsigned char *msg,
                     size_t msg_len,
                     const unsigned char *sig,
                     const unsigned char *pub,
                     size_t pub_len);

int
ecdsa_schnorr_verify_batch(const ecdsa_t *ec,
                           const unsigned char **msgs,
                           const size_t *msg_lens,
                           const unsigned char **sigs,
                           const unsigned char **pubs,
                           const size_t *pub_lens,
                           size_t len,
                           ecdsa_scratch_t *scratch);

/*
 * Schnorr
 */

schnorr_t *
schnorr_context_create(int type);

void
schnorr_context_destroy(schnorr_t *ec);

void
schnorr_context_randomize(schnorr_t *ec, const unsigned char *entropy);

schnorr_scratch_t *
schnorr_scratch_create(const schnorr_t *ec);

void
schnorr_scratch_destroy(const schnorr_t *ec, schnorr_scratch_t *scratch);

size_t
schnorr_scalar_size(const schnorr_t *ec);

size_t
schnorr_scalar_bits(const schnorr_t *ec);

size_t
schnorr_field_size(const schnorr_t *ec);

size_t
schnorr_field_bits(const schnorr_t *ec);

size_t
schnorr_privkey_size(const schnorr_t *ec);

size_t
schnorr_pubkey_size(const schnorr_t *ec);

size_t
schnorr_sig_size(const schnorr_t *ec);

void
schnorr_privkey_generate(const schnorr_t *ec,
                         unsigned char *out,
                         const unsigned char *entropy);

int
schnorr_privkey_verify(const schnorr_t *ec, const unsigned char *priv);

int
schnorr_privkey_export(const schnorr_t *ec,
                       unsigned char *d_raw,
                       unsigned char *x_raw,
                       unsigned char *y_raw,
                       const unsigned char *priv);

int
schnorr_privkey_import(const schnorr_t *ec,
                       unsigned char *out,
                       const unsigned char *bytes,
                       size_t len);

int
schnorr_privkey_tweak_add(const schnorr_t *ec,
                          unsigned char *out,
                          const unsigned char *priv,
                          const unsigned char *tweak);

int
schnorr_privkey_tweak_mul(const schnorr_t *ec,
                          unsigned char *out,
                          const unsigned char *priv,
                          const unsigned char *tweak);

int
schnorr_privkey_reduce(const schnorr_t *ec,
                       unsigned char *out,
                       const unsigned char *bytes,
                       size_t len);

int
schnorr_privkey_invert(const schnorr_t *ec,
                       unsigned char *out,
                       const unsigned char *priv);

int
schnorr_pubkey_create(const schnorr_t *ec,
                      unsigned char *pub,
                      const unsigned char *priv);

void
schnorr_pubkey_from_uniform(const schnorr_t *ec,
                            unsigned char *out,
                            const unsigned char *bytes);

int
schnorr_pubkey_to_uniform(const schnorr_t *ec,
                          unsigned char *out,
                          const unsigned char *pub,
                          unsigned int hint);

int
schnorr_pubkey_from_hash(const schnorr_t *ec,
                         unsigned char *out,
                         const unsigned char *bytes);

int
schnorr_pubkey_to_hash(const schnorr_t *ec,
                       unsigned char *out,
                       const unsigned char *pub,
                       unsigned int subgroup,
                       const unsigned char *entropy);

int
schnorr_pubkey_verify(const schnorr_t *ec, const unsigned char *pub);

int
schnorr_pubkey_export(const schnorr_t *ec,
                      unsigned char *x_raw,
                      unsigned char *y_raw,
                      const unsigned char *pub);

int
schnorr_pubkey_import(const schnorr_t *ec,
                      unsigned char *out,
                      const unsigned char *x_raw,
                      size_t x_len);

int
schnorr_pubkey_tweak_add(const schnorr_t *ec,
                         unsigned char *out,
                         int *negated,
                         const unsigned char *pub,
                         const unsigned char *tweak);

int
schnorr_pubkey_tweak_mul(const schnorr_t *ec,
                         unsigned char *out,
                         int *negated,
                         const unsigned char *pub,
                         const unsigned char *tweak);

int
schnorr_pubkey_tweak_test(const schnorr_t *ec,
                          int *result,
                          const unsigned char *pub,
                          const unsigned char *tweak,
                          const unsigned char *expect,
                          int negated);

int
schnorr_pubkey_combine(const schnorr_t *ec,
                       unsigned char *out,
                       const unsigned char **pubs,
                       size_t len);

int
schnorr_sign(const schnorr_t *ec,
             unsigned char *sig,
             const unsigned char *msg,
             size_t msg_len,
             const unsigned char *priv,
             const unsigned char *aux);

int
schnorr_verify(const schnorr_t *ec,
               const unsigned char *msg,
               size_t msg_len,
               const unsigned char *sig,
               const unsigned char *pub);

int
schnorr_verify_batch(const schnorr_t *ec,
                     const unsigned char **msgs,
                     const size_t *msg_lens,
                     const unsigned char **sigs,
                     const unsigned char **pubs,
                     size_t len,
                     schnorr_scratch_t *scratch);

int
schnorr_derive(const schnorr_t *ec,
               unsigned char *secret,
               const unsigned char *pub,
               const unsigned char *priv);

/*
 * ECDH
 */

ecdh_t *
ecdh_context_create(int type);

void
ecdh_context_destroy(ecdh_t *ec);

size_t
ecdh_scalar_size(const ecdh_t *ec);

size_t
ecdh_scalar_bits(const ecdh_t *ec);

size_t
ecdh_field_size(const ecdh_t *ec);

size_t
ecdh_field_bits(const ecdh_t *ec);

size_t
ecdh_privkey_size(const ecdh_t *ec);

size_t
ecdh_pubkey_size(const ecdh_t *ec);

void
ecdh_privkey_generate(const ecdh_t *ec,
                      unsigned char *out,
                      const unsigned char *entropy);

int
ecdh_privkey_verify(const ecdh_t *ec, const unsigned char *priv);

int
ecdh_privkey_export(const ecdh_t *ec,
                    unsigned char *out,
                    const unsigned char *priv);

int
ecdh_privkey_import(const ecdh_t *ec,
                    unsigned char *out,
                    const unsigned char *bytes,
                    size_t len);

void
ecdh_pubkey_create(const ecdh_t *ec,
                   unsigned char *pub,
                   const unsigned char *priv);

int
ecdh_pubkey_convert(const ecdh_t *ec,
                    unsigned char *out,
                    const unsigned char *pub,
                    int sign);

void
ecdh_pubkey_from_uniform(const ecdh_t *ec,
                         unsigned char *out,
                         const unsigned char *bytes);

int
ecdh_pubkey_to_uniform(const ecdh_t *ec,
                       unsigned char *out,
                       const unsigned char *pub,
                       unsigned int hint);

int
ecdh_pubkey_from_hash(const ecdh_t *ec,
                      unsigned char *out,
                      const unsigned char *bytes,
                      int pake);

int
ecdh_pubkey_to_hash(const ecdh_t *ec,
                    unsigned char *out,
                    const unsigned char *pub,
                    unsigned int subgroup,
                    const unsigned char *entropy);

int
ecdh_pubkey_verify(const ecdh_t *ec, const unsigned char *pub);

int
ecdh_pubkey_export(const ecdh_t *ec,
                   unsigned char *x_raw,
                   unsigned char *y_raw,
                   const unsigned char *pub,
                   int sign);

int
ecdh_pubkey_import(const ecdh_t *ec,
                   unsigned char *out,
                   const unsigned char *x_raw,
                   size_t x_len);

int
ecdh_pubkey_is_small(const ecdh_t *ec, const unsigned char *pub);

int
ecdh_pubkey_has_torsion(const ecdh_t *ec, const unsigned char *pub);

int
ecdh_derive(const ecdh_t *ec,
            unsigned char *secret,
            const unsigned char *pub,
            const unsigned char *priv);

/*
 * EdDSA
 */

eddsa_t *
eddsa_context_create(int type);

void
eddsa_context_destroy(eddsa_t *ec);

void
eddsa_context_randomize(eddsa_t *ec, const unsigned char *entropy);

eddsa_scratch_t *
eddsa_scratch_create(const eddsa_t *ec);

void
eddsa_scratch_destroy(const eddsa_t *ec, eddsa_scratch_t *scratch);

size_t
eddsa_scalar_size(const eddsa_t *ec);

size_t
eddsa_scalar_bits(const eddsa_t *ec);

size_t
eddsa_field_size(const eddsa_t *ec);

size_t
eddsa_field_bits(const eddsa_t *ec);

size_t
eddsa_privkey_size(const eddsa_t *ec);

size_t
eddsa_pubkey_size(const eddsa_t *ec);

size_t
eddsa_sig_size(const eddsa_t *ec);

void
eddsa_privkey_generate(const eddsa_t *ec,
                       unsigned char *out,
                       const unsigned char *entropy);

void
eddsa_scalar_generate(const eddsa_t *ec,
                      unsigned char *out,
                      const unsigned char *entropy);

void
eddsa_privkey_expand(const eddsa_t *ec,
                     unsigned char *scalar,
                     unsigned char *prefix,
                     const unsigned char *priv);

void
eddsa_privkey_convert(const eddsa_t *ec,
                      unsigned char *scalar,
                      const unsigned char *priv);

int
eddsa_privkey_verify(const eddsa_t *ec, const unsigned char *priv);

int
eddsa_privkey_export(const eddsa_t *ec,
                     unsigned char *out,
                     const unsigned char *priv);

int
eddsa_privkey_import(const eddsa_t *ec,
                     unsigned char *out,
                     const unsigned char *bytes,
                     size_t len);

int
eddsa_scalar_verify(const eddsa_t *ec, const unsigned char *scalar);

int
eddsa_scalar_is_zero(const eddsa_t *ec, const unsigned char *scalar);

void
eddsa_scalar_clamp(const eddsa_t *ec,
                   unsigned char *out,
                   const unsigned char *scalar);

void
eddsa_scalar_tweak_add(const eddsa_t *ec,
                       unsigned char *out,
                       const unsigned char *scalar,
                       const unsigned char *tweak);

void
eddsa_scalar_tweak_mul(const eddsa_t *ec,
                       unsigned char *out,
                       const unsigned char *scalar,
                       const unsigned char *tweak);

void
eddsa_scalar_reduce(const eddsa_t *ec,
                    unsigned char *out,
                    const unsigned char *bytes,
                    size_t len);

void
eddsa_scalar_negate(const eddsa_t *ec,
                    unsigned char *out,
                    const unsigned char *scalar);

void
eddsa_scalar_invert(const eddsa_t *ec,
                    unsigned char *out,
                    const unsigned char *scalar);

void
eddsa_pubkey_from_scalar(const eddsa_t *ec,
                         unsigned char *pub,
                         const unsigned char *scalar);

void
eddsa_pubkey_create(const eddsa_t *ec,
                    unsigned char *pub,
                    const unsigned char *priv);

int
eddsa_pubkey_convert(const eddsa_t *ec,
                     unsigned char *out,
                     const unsigned char *pub);

void
eddsa_pubkey_from_uniform(const eddsa_t *ec,
                          unsigned char *out,
                          const unsigned char *bytes);

int
eddsa_pubkey_to_uniform(const eddsa_t *ec,
                        unsigned char *out,
                        const unsigned char *pub,
                        unsigned int hint);

void
eddsa_pubkey_from_hash(const eddsa_t *ec,
                       unsigned char *out,
                       const unsigned char *bytes,
                       int pake);

int
eddsa_pubkey_to_hash(const eddsa_t *ec,
                     unsigned char *out,
                     const unsigned char *pub,
                     unsigned int subgroup,
                     const unsigned char *entropy);

int
eddsa_pubkey_verify(const eddsa_t *ec, const unsigned char *pub);

int
eddsa_pubkey_export(const eddsa_t *ec,
                    unsigned char *x_raw,
                    unsigned char *y_raw,
                    const unsigned char *pub);

int
eddsa_pubkey_import(const eddsa_t *ec,
                    unsigned char *out,
                    const unsigned char *x_raw,
                    size_t x_len,
                    const unsigned char *y_raw,
                    size_t y_len,
                    int sign);
int
eddsa_pubkey_is_infinity(const eddsa_t *ec, const unsigned char *pub);

int
eddsa_pubkey_is_small(const eddsa_t *ec, const unsigned char *pub);

int
eddsa_pubkey_has_torsion(const eddsa_t *ec, const unsigned char *pub);

int
eddsa_pubkey_tweak_add(const eddsa_t *ec,
                       unsigned char *out,
                       const unsigned char *pub,
                       const unsigned char *tweak);

int
eddsa_pubkey_tweak_mul(const eddsa_t *ec,
                       unsigned char *out,
                       const unsigned char *pub,
                       const unsigned char *tweak);

int
eddsa_pubkey_combine(const eddsa_t *ec,
                     unsigned char *out,
                     const unsigned char **pubs,
                     size_t len);

int
eddsa_pubkey_negate(const eddsa_t *ec,
                    unsigned char *out,
                    const unsigned char *pub);

void
eddsa_sign_with_scalar(const eddsa_t *ec,
                       unsigned char *sig,
                       const unsigned char *msg,
                       size_t msg_len,
                       const unsigned char *scalar,
                       const unsigned char *prefix,
                       int ph,
                       const unsigned char *ctx,
                       size_t ctx_len);

void
eddsa_sign(const eddsa_t *ec,
           unsigned char *sig,
           const unsigned char *msg,
           size_t msg_len,
           const unsigned char *priv,
           int ph,
           const unsigned char *ctx,
           size_t ctx_len);

void
eddsa_sign_tweak_add(const eddsa_t *ec,
                     unsigned char *sig,
                     const unsigned char *msg,
                     size_t msg_len,
                     const unsigned char *priv,
                     const unsigned char *tweak,
                     int ph,
                     const unsigned char *ctx,
                     size_t ctx_len);

void
eddsa_sign_tweak_mul(const eddsa_t *ec,
                     unsigned char *sig,
                     const unsigned char *msg,
                     size_t msg_len,
                     const unsigned char *priv,
                     const unsigned char *tweak,
                     int ph,
                     const unsigned char *ctx,
                     size_t ctx_len);

int
eddsa_verify(const eddsa_t *ec,
             const unsigned char *msg,
             size_t msg_len,
             const unsigned char *sig,
             const unsigned char *pub,
             int ph,
             const unsigned char *ctx,
             size_t ctx_len);

int
eddsa_verify_single(const eddsa_t *ec,
                    const unsigned char *msg,
                    size_t msg_len,
                    const unsigned char *sig,
                    const unsigned char *pub,
                    int ph,
                    const unsigned char *ctx,
                    size_t ctx_len);

int
eddsa_verify_batch(const eddsa_t *ec,
                   const unsigned char **msgs,
                   const size_t *msg_lens,
                   const unsigned char **sigs,
                   const unsigned char **pubs,
                   size_t len,
                   int ph,
                   const unsigned char *ctx,
                   size_t ctx_len,
                   eddsa_scratch_t *scratch);

int
eddsa_derive_with_scalar(const eddsa_t *ec,
                         unsigned char *secret,
                         const unsigned char *pub,
                         const unsigned char *scalar);
int
eddsa_derive(const eddsa_t *ec,
             unsigned char *secret,
             const unsigned char *pub,
             const unsigned char *priv);

#ifdef __cplusplus
}
#endif

#endif /* _TORSION_ECC_H */
