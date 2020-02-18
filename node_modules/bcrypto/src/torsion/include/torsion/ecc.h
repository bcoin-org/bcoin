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
ecdsa_context_create(const char *id);

void
ecdsa_context_destroy(ecdsa_t *ec);

void
ecdsa_context_randomize(ecdsa_t *ec, const unsigned char *entropy);

ecdsa_scratch_t *
ecdsa_scratch_create(ecdsa_t *ec);

void
ecdsa_scratch_destroy(ecdsa_t *ec, ecdsa_scratch_t *scratch);

size_t
ecdsa_scalar_size(ecdsa_t *ec);

size_t
ecdsa_scalar_bits(ecdsa_t *ec);

size_t
ecdsa_field_size(ecdsa_t *ec);

size_t
ecdsa_field_bits(ecdsa_t *ec);

size_t
ecdsa_privkey_size(ecdsa_t *ec);

size_t
ecdsa_pubkey_size(ecdsa_t *ec, int compact);

size_t
ecdsa_sig_size(ecdsa_t *ec);

size_t
ecdsa_schnorr_size(ecdsa_t *ec);

void
ecdsa_privkey_generate(ecdsa_t *ec,
                       unsigned char *out,
                       const unsigned char *entropy);

int
ecdsa_privkey_verify(ecdsa_t *ec, const unsigned char *priv);

int
ecdsa_privkey_export(ecdsa_t *ec,
                     unsigned char *out,
                     const unsigned char *priv);

int
ecdsa_privkey_import(ecdsa_t *ec,
                     unsigned char *out,
                     const unsigned char *bytes,
                     size_t len);

int
ecdsa_privkey_tweak_add(ecdsa_t *ec,
                        unsigned char *out,
                        const unsigned char *priv,
                        const unsigned char *tweak);

int
ecdsa_privkey_tweak_mul(ecdsa_t *ec,
                        unsigned char *out,
                        const unsigned char *priv,
                        const unsigned char *tweak);

int
ecdsa_privkey_reduce(ecdsa_t *ec,
                     unsigned char *out,
                     const unsigned char *bytes,
                     size_t len);

int
ecdsa_privkey_negate(ecdsa_t *ec,
                     unsigned char *out,
                     const unsigned char *priv);

int
ecdsa_privkey_invert(ecdsa_t *ec,
                     unsigned char *out,
                     const unsigned char *priv);

int
ecdsa_pubkey_create(ecdsa_t *ec,
                    unsigned char *pub,
                    size_t *pub_len,
                    const unsigned char *priv,
                    int compact);

int
ecdsa_pubkey_convert(ecdsa_t *ec,
                     unsigned char *out,
                     size_t *out_len,
                     const unsigned char *pub,
                     size_t pub_len,
                     int compact);

void
ecdsa_pubkey_from_uniform(ecdsa_t *ec,
                          unsigned char *out,
                          size_t *out_len,
                          const unsigned char *bytes,
                          int compact);

int
ecdsa_pubkey_to_uniform(ecdsa_t *ec,
                        unsigned char *out,
                        const unsigned char *pub,
                        size_t pub_len,
                        unsigned int hint);

int
ecdsa_pubkey_from_hash(ecdsa_t *ec,
                       unsigned char *out,
                       size_t *out_len,
                       const unsigned char *bytes,
                       int compact);

int
ecdsa_pubkey_to_hash(ecdsa_t *ec,
                     unsigned char *out,
                     const unsigned char *pub,
                     size_t pub_len,
                     const unsigned char *entropy);

int
ecdsa_pubkey_verify(ecdsa_t *ec, const unsigned char *pub, size_t pub_len);

int
ecdsa_pubkey_export(ecdsa_t *ec,
                    unsigned char *x,
                    unsigned char *y,
                    const unsigned char *pub,
                    size_t pub_len);

int
ecdsa_pubkey_import(ecdsa_t *ec,
                    unsigned char *out,
                    size_t *out_len,
                    const unsigned char *x,
                    size_t x_len,
                    const unsigned char *y,
                    size_t y_len,
                    int sign,
                    int compact);

int
ecdsa_pubkey_tweak_add(ecdsa_t *ec,
                       unsigned char *out,
                       size_t *out_len,
                       const unsigned char *pub,
                       size_t pub_len,
                       const unsigned char *tweak,
                       int compact);

int
ecdsa_pubkey_tweak_mul(ecdsa_t *ec,
                       unsigned char *out,
                       size_t *out_len,
                       const unsigned char *pub,
                       size_t pub_len,
                       const unsigned char *tweak,
                       int compact);

int
ecdsa_pubkey_combine(ecdsa_t *ec,
                     unsigned char *out,
                     size_t *out_len,
                     const unsigned char **pubs,
                     size_t *pub_lens,
                     size_t len,
                     int compact);

int
ecdsa_pubkey_negate(ecdsa_t *ec,
                    unsigned char *out,
                    size_t *out_len,
                    const unsigned char *pub,
                    size_t pub_len,
                    int compact);

int
ecdsa_sig_export(ecdsa_t *ec,
                 unsigned char *out,
                 size_t *out_len,
                 const unsigned char *sig);

int
ecdsa_sig_import_lax(ecdsa_t *ec,
                     unsigned char *out,
                     const unsigned char *der,
                     size_t der_len);

int
ecdsa_sig_import(ecdsa_t *ec,
                 unsigned char *out,
                 const unsigned char *der,
                 size_t der_len);

int
ecdsa_sig_normalize(ecdsa_t *ec, unsigned char *out, const unsigned char *sig);

int
ecdsa_is_low_s(ecdsa_t *ec, const unsigned char *sig);

int
ecdsa_sign(ecdsa_t *ec,
           unsigned char *sig,
           unsigned int *param,
           const unsigned char *msg,
           size_t msg_len,
           const unsigned char *priv);

int
ecdsa_verify(ecdsa_t *ec,
             const unsigned char *msg,
             size_t msg_len,
             const unsigned char *sig,
             const unsigned char *pub,
             size_t pub_len);

int
ecdsa_recover(ecdsa_t *ec,
              unsigned char *pub,
              size_t *pub_len,
              const unsigned char *msg,
              size_t msg_len,
              const unsigned char *sig,
              unsigned int param,
              int compact);

int
ecdsa_derive(ecdsa_t *ec,
             unsigned char *secret,
             size_t *secret_len,
             const unsigned char *pub,
             const size_t pub_len,
             const unsigned char *priv,
             int compact);

int
ecdsa_schnorr_support(ecdsa_t *ec);

int
ecdsa_schnorr_sign(ecdsa_t *ec,
                   unsigned char *sig,
                   const unsigned char *msg,
                   const unsigned char *priv);

int
ecdsa_schnorr_verify(ecdsa_t *ec,
                     const unsigned char *msg,
                     const unsigned char *sig,
                     const unsigned char *pub,
                     size_t pub_len);

int
ecdsa_schnorr_verify_batch(ecdsa_t *ec,
                           const unsigned char **msgs,
                           const unsigned char **sigs,
                           const unsigned char **pubs,
                           size_t *pub_lens,
                           size_t len,
                           ecdsa_scratch_t *scratch);

/*
 * Schnorr
 */

schnorr_t *
schnorr_context_create(const char *id);

void
schnorr_context_destroy(schnorr_t *ec);

void
schnorr_context_randomize(schnorr_t *ec, const unsigned char *entropy);

schnorr_scratch_t *
schnorr_scratch_create(schnorr_t *ec);

void
schnorr_scratch_destroy(schnorr_t *ec, schnorr_scratch_t *scratch);

size_t
schnorr_scalar_size(schnorr_t *ec);

size_t
schnorr_scalar_bits(schnorr_t *ec);

size_t
schnorr_field_size(schnorr_t *ec);

size_t
schnorr_field_bits(schnorr_t *ec);

size_t
schnorr_privkey_size(schnorr_t *ec);

size_t
schnorr_pubkey_size(schnorr_t *ec);

size_t
schnorr_sig_size(schnorr_t *ec);

void
schnorr_privkey_generate(schnorr_t *ec,
                         unsigned char *out,
                         const unsigned char *entropy);

int
schnorr_privkey_verify(schnorr_t *ec, const unsigned char *priv);

int
schnorr_privkey_export(schnorr_t *ec,
                       unsigned char *out,
                       const unsigned char *priv);

int
schnorr_privkey_import(schnorr_t *ec,
                       unsigned char *out,
                       const unsigned char *bytes,
                       size_t len);

int
schnorr_privkey_tweak_add(schnorr_t *ec,
                          unsigned char *out,
                          const unsigned char *priv,
                          const unsigned char *tweak);

int
schnorr_privkey_tweak_mul(schnorr_t *ec,
                          unsigned char *out,
                          const unsigned char *priv,
                          const unsigned char *tweak);

int
schnorr_privkey_reduce(schnorr_t *ec,
                       unsigned char *out,
                       const unsigned char *bytes,
                       size_t len);

int
schnorr_privkey_invert(schnorr_t *ec,
                       unsigned char *out,
                       const unsigned char *priv);

int
schnorr_pubkey_create(schnorr_t *ec,
                      unsigned char *pub,
                      const unsigned char *priv);

void
schnorr_pubkey_from_uniform(schnorr_t *ec,
                            unsigned char *out,
                            const unsigned char *bytes);

int
schnorr_pubkey_to_uniform(schnorr_t *ec,
                          unsigned char *out,
                          const unsigned char *pub,
                          unsigned int hint);

int
schnorr_pubkey_from_hash(schnorr_t *ec,
                         unsigned char *out,
                         const unsigned char *bytes);

int
schnorr_pubkey_to_hash(schnorr_t *ec,
                       unsigned char *out,
                       const unsigned char *pub,
                       const unsigned char *entropy);

int
schnorr_pubkey_verify(schnorr_t *ec,
                      unsigned char *out,
                      const unsigned char *pub);

int
schnorr_pubkey_export(schnorr_t *ec,
                      unsigned char *x,
                      unsigned char *y,
                      const unsigned char *pub);

int
schnorr_pubkey_import(schnorr_t *ec,
                      unsigned char *out,
                      const unsigned char *x,
                      size_t x_len);

int
schnorr_pubkey_tweak_add(schnorr_t *ec,
                         unsigned char *out,
                         const unsigned char *pub,
                         const unsigned char *tweak);

int
schnorr_pubkey_tweak_mul(schnorr_t *ec,
                         unsigned char *out,
                         const unsigned char *pub,
                         const unsigned char *tweak);

int
schnorr_pubkey_combine(schnorr_t *ec,
                       unsigned char *out,
                       const unsigned char **pubs,
                       size_t len);

int
schnorr_sign(schnorr_t *ec,
             unsigned char *sig,
             const unsigned char *msg,
             const unsigned char *priv);

int
schnorr_verify(schnorr_t *ec,
               const unsigned char *msg,
               const unsigned char *sig,
               const unsigned char *pub);

int
schnorr_verify_batch(schnorr_t *ec,
                     const unsigned char **msgs,
                     const unsigned char **sigs,
                     const unsigned char **pubs,
                     size_t len,
                     schnorr_scratch_t *scratch);

int
schnorr_derive(schnorr_t *ec,
               unsigned char *secret,
               const unsigned char *pub,
               const unsigned char *priv);

/*
 * ECDH
 */

ecdh_t *
ecdh_context_create(const char *id);

void
ecdh_context_destroy(ecdh_t *ec);

size_t
ecdh_scalar_size(ecdh_t *ec);

size_t
ecdh_scalar_bits(ecdh_t *ec);

size_t
ecdh_field_size(ecdh_t *ec);

size_t
ecdh_field_bits(ecdh_t *ec);

size_t
ecdh_privkey_size(ecdh_t *ec);

size_t
ecdh_pubkey_size(ecdh_t *ec);

void
ecdh_privkey_generate(ecdh_t *ec,
                      unsigned char *out,
                      const unsigned char *entropy);

int
ecdh_privkey_verify(ecdh_t *ec, const unsigned char *priv);

int
ecdh_privkey_export(ecdh_t *ec, unsigned char *out, const unsigned char *priv);

int
ecdh_privkey_import(ecdh_t *ec,
                    unsigned char *out,
                    const unsigned char *bytes,
                    size_t len);

void
ecdh_pubkey_create(ecdh_t *ec, unsigned char *pub, const unsigned char *priv);

int
ecdh_pubkey_convert(ecdh_t *ec,
                    unsigned char *out,
                    const unsigned char *pub,
                    int sign);

void
ecdh_pubkey_from_uniform(ecdh_t *ec,
                         unsigned char *out,
                         const unsigned char *bytes);

int
ecdh_pubkey_to_uniform(ecdh_t *ec,
                       unsigned char *out,
                       const unsigned char *pub,
                       unsigned int hint);

int
ecdh_pubkey_from_hash(ecdh_t *ec,
                      unsigned char *out,
                      const unsigned char *bytes,
                      int pake);

int
ecdh_pubkey_to_hash(ecdh_t *ec,
                    unsigned char *out,
                    const unsigned char *pub,
                    const unsigned char *entropy);

int
ecdh_pubkey_verify(ecdh_t *ec, const unsigned char *pub);

int
ecdh_pubkey_export(ecdh_t *ec,
                   unsigned char *x,
                   unsigned char *y,
                   const unsigned char *pub,
                   int sign);

int
ecdh_pubkey_import(ecdh_t *ec,
                   unsigned char *out,
                   const unsigned char *x,
                   size_t x_len);

int
ecdh_pubkey_is_small(ecdh_t *ec, const unsigned char *pub);

int
ecdh_pubkey_has_torsion(ecdh_t *ec, const unsigned char *pub);

int
ecdh_derive(ecdh_t *ec,
            unsigned char *secret,
            const unsigned char *pub,
            const unsigned char *priv);

/*
 * EdDSA
 */

eddsa_t *
eddsa_context_create(const char *id);

void
eddsa_context_destroy(eddsa_t *ec);

void
eddsa_context_randomize(eddsa_t *ec, const unsigned char *entropy);

eddsa_scratch_t *
eddsa_scratch_create(eddsa_t *ec);

void
eddsa_scratch_destroy(eddsa_t *ec, eddsa_scratch_t *scratch);

size_t
eddsa_scalar_size(eddsa_t *ec);

size_t
eddsa_scalar_bits(eddsa_t *ec);

size_t
eddsa_field_size(eddsa_t *ec);

size_t
eddsa_field_bits(eddsa_t *ec);

size_t
eddsa_privkey_size(eddsa_t *ec);

size_t
eddsa_pubkey_size(eddsa_t *ec);

size_t
eddsa_sig_size(eddsa_t *ec);

void
eddsa_privkey_generate(eddsa_t *ec,
                       unsigned char *out,
                       const unsigned char *entropy);

void
eddsa_scalar_generate(eddsa_t *ec,
                      unsigned char *out,
                      const unsigned char *entropy);

void
eddsa_privkey_expand(eddsa_t *ec,
                     unsigned char *scalar,
                     unsigned char *prefix,
                     const unsigned char *priv);

void
eddsa_privkey_convert(eddsa_t *ec,
                      unsigned char *scalar,
                      const unsigned char *priv);

int
eddsa_privkey_verify(eddsa_t *ec, const unsigned char *priv);

int
eddsa_privkey_export(eddsa_t *ec,
                     unsigned char *out,
                     const unsigned char *priv);

int
eddsa_privkey_import(eddsa_t *ec,
                     unsigned char *out,
                     const unsigned char *bytes,
                     size_t len);

int
eddsa_scalar_verify(eddsa_t *ec, const unsigned char *scalar);

int
eddsa_scalar_is_zero(eddsa_t *ec, const unsigned char *scalar);

void
eddsa_scalar_clamp(eddsa_t *ec,
                   unsigned char *out,
                   const unsigned char *scalar);

void
eddsa_scalar_tweak_add(eddsa_t *ec,
                       unsigned char *out,
                       const unsigned char *scalar,
                       const unsigned char *tweak);

void
eddsa_scalar_tweak_mul(eddsa_t *ec,
                       unsigned char *out,
                       const unsigned char *scalar,
                       const unsigned char *tweak);

void
eddsa_scalar_reduce(eddsa_t *ec,
                    unsigned char *out,
                    const unsigned char *bytes,
                    size_t len);

void
eddsa_scalar_negate(eddsa_t *ec,
                    unsigned char *out,
                    const unsigned char *scalar);

void
eddsa_scalar_invert(eddsa_t *ec,
                    unsigned char *out,
                    const unsigned char *scalar);

void
eddsa_pubkey_from_scalar(eddsa_t *ec,
                         unsigned char *pub,
                         const unsigned char *scalar);

void
eddsa_pubkey_create(eddsa_t *ec,
                    unsigned char *pub,
                    const unsigned char *priv);

int
eddsa_pubkey_convert(eddsa_t *ec,
                     unsigned char *out,
                     const unsigned char *pub);

void
eddsa_pubkey_from_uniform(eddsa_t *ec,
                          unsigned char *out,
                          const unsigned char *bytes);

int
eddsa_pubkey_to_uniform(eddsa_t *ec,
                        unsigned char *out,
                        const unsigned char *pub,
                        unsigned int hint);

void
eddsa_pubkey_from_hash(eddsa_t *ec,
                       unsigned char *out,
                       const unsigned char *bytes,
                       int pake);

int
eddsa_pubkey_to_hash(eddsa_t *ec,
                     unsigned char *out,
                     const unsigned char *pub,
                     const unsigned char *entropy);

int
eddsa_pubkey_verify(eddsa_t *ec, const unsigned char *pub);

int
eddsa_pubkey_export(eddsa_t *ec,
                    unsigned char *x,
                    unsigned char *y,
                    const unsigned char *pub);

int
eddsa_pubkey_import(eddsa_t *ec,
                    unsigned char *out,
                    const unsigned char *x,
                    size_t x_len,
                    const unsigned char *y,
                    size_t y_len,
                    int sign);
int
eddsa_pubkey_is_infinity(eddsa_t *ec, const unsigned char *pub);

int
eddsa_pubkey_is_small(eddsa_t *ec, const unsigned char *pub);

int
eddsa_pubkey_has_torsion(eddsa_t *ec, const unsigned char *pub);

int
eddsa_pubkey_tweak_add(eddsa_t *ec,
                       unsigned char *out,
                       const unsigned char *pub,
                       const unsigned char *tweak);

int
eddsa_pubkey_tweak_mul(eddsa_t *ec,
                       unsigned char *out,
                       const unsigned char *pub,
                       const unsigned char *tweak);

int
eddsa_pubkey_combine(eddsa_t *ec,
                     unsigned char *out,
                     const unsigned char **pubs,
                     size_t len);

int
eddsa_pubkey_negate(eddsa_t *ec,
                    unsigned char *out,
                    const unsigned char *pub);

void
eddsa_sign_with_scalar(eddsa_t *ec,
                       unsigned char *sig,
                       const unsigned char *msg,
                       size_t msg_len,
                       const unsigned char *scalar,
                       const unsigned char *prefix,
                       int ph,
                       const unsigned char *ctx,
                       size_t ctx_len);

void
eddsa_sign(eddsa_t *ec,
           unsigned char *sig,
           const unsigned char *msg,
           size_t msg_len,
           const unsigned char *priv,
           int ph,
           const unsigned char *ctx,
           size_t ctx_len);

void
eddsa_sign_tweak_add(eddsa_t *ec,
                     unsigned char *sig,
                     const unsigned char *msg,
                     size_t msg_len,
                     const unsigned char *priv,
                     const unsigned char *tweak,
                     int ph,
                     const unsigned char *ctx,
                     size_t ctx_len);

void
eddsa_sign_tweak_mul(eddsa_t *ec,
                     unsigned char *sig,
                     const unsigned char *msg,
                     size_t msg_len,
                     const unsigned char *priv,
                     const unsigned char *tweak,
                     int ph,
                     const unsigned char *ctx,
                     size_t ctx_len);

int
eddsa_verify(eddsa_t *ec,
             const unsigned char *msg,
             size_t msg_len,
             const unsigned char *sig,
             const unsigned char *pub,
             int ph,
             const unsigned char *ctx,
             size_t ctx_len);

int
eddsa_verify_single(eddsa_t *ec,
                    const unsigned char *msg,
                    size_t msg_len,
                    const unsigned char *sig,
                    const unsigned char *pub,
                    int ph,
                    const unsigned char *ctx,
                    size_t ctx_len);

int
eddsa_verify_batch(eddsa_t *ec,
                   const unsigned char **msgs,
                   size_t *msg_lens,
                   const unsigned char **sigs,
                   const unsigned char **pubs,
                   size_t len,
                   int ph,
                   const unsigned char *ctx,
                   size_t ctx_len,
                   eddsa_scratch_t *scratch);

int
eddsa_derive_with_scalar(eddsa_t *ec,
                         unsigned char *secret,
                         const unsigned char *pub,
                         const unsigned char *scalar);
int
eddsa_derive(eddsa_t *ec,
             unsigned char *secret,
             const unsigned char *pub,
             const unsigned char *priv);

#ifdef __cplusplus
}
#endif

#endif /* _TORSION_ECC_H */
