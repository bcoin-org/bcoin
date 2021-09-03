/*!
 * dsa.h - dsa for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 */

#ifndef TORSION_DSA_H
#define TORSION_DSA_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include "common.h"

/*
 * Symbol Aliases
 */

#define dsa_params_create torsion_dsa_params_create
#define dsa_params_generate torsion_dsa_params_generate
#define dsa_params_bits torsion_dsa_params_bits
#define dsa_params_qbits torsion_dsa_params_qbits
#define dsa_params_verify torsion_dsa_params_verify
#define dsa_params_import torsion_dsa_params_import
#define dsa_params_export torsion_dsa_params_export
#define dsa_privkey_create torsion_dsa_privkey_create
#define dsa_privkey_generate torsion_dsa_privkey_generate
#define dsa_privkey_bits torsion_dsa_privkey_bits
#define dsa_privkey_qbits torsion_dsa_privkey_qbits
#define dsa_privkey_verify torsion_dsa_privkey_verify
#define dsa_privkey_import torsion_dsa_privkey_import
#define dsa_privkey_export torsion_dsa_privkey_export
#define dsa_pubkey_create torsion_dsa_pubkey_create
#define dsa_pubkey_bits torsion_dsa_pubkey_bits
#define dsa_pubkey_qbits torsion_dsa_pubkey_qbits
#define dsa_pubkey_verify torsion_dsa_pubkey_verify
#define dsa_pubkey_import torsion_dsa_pubkey_import
#define dsa_pubkey_export torsion_dsa_pubkey_export
#define dsa_sig_export torsion_dsa_sig_export
#define dsa_sig_import torsion_dsa_sig_import
#define dsa_sign torsion_dsa_sign
#define dsa_verify torsion_dsa_verify
#define dsa_derive torsion_dsa_derive

/*
 * Definitions
 */

#define DSA_DEFAULT_BITS 2048
#define DSA_MIN_BITS 512
#define DSA_MAX_BITS 10000
#define DSA_MIN_SIZE 64
#define DSA_MAX_SIZE 1250
#define DSA_MIN_QBITS 160
#define DSA_MAX_QBITS 256
#define DSA_MIN_QSIZE 20
#define DSA_MAX_QSIZE 32
#define DSA_MAX_SIG_SIZE 64
#define DSA_MAX_DER_SIZE 73

/* 2549 */
#define DSA_MAX_PARAMS_SIZE (0    \
  + 4 /* seq */                   \
  + 4 + 1 + DSA_MAX_SIZE /* p */  \
  + 2 + 1 + DSA_MAX_QSIZE /* q */ \
  + 4 + 1 + DSA_MAX_SIZE /* g */  \
)

/* 3804 */
#define DSA_MAX_PUB_SIZE (0       \
  + 4 /* seq */                   \
  + 4 + 1 + DSA_MAX_SIZE /* y */  \
  + 4 + 1 + DSA_MAX_SIZE /* p */  \
  + 2 + 1 + DSA_MAX_QSIZE /* q */ \
  + 4 + 1 + DSA_MAX_SIZE /* g */  \
)

/* 3842 */
#define DSA_MAX_PRIV_SIZE (0      \
  + 4 /* seq */                   \
  + 3 /* version */               \
  + 4 + 1 + DSA_MAX_SIZE /* p */  \
  + 2 + 1 + DSA_MAX_QSIZE /* q */ \
  + 4 + 1 + DSA_MAX_SIZE /* g */  \
  + 4 + 1 + DSA_MAX_SIZE /* y */  \
  + 2 + 1 + DSA_MAX_QSIZE /* x */ \
)

/*
 * DSA
 */

TORSION_EXTERN int
dsa_params_create(unsigned char *out, size_t *out_len,
                  const unsigned char *key, size_t key_len);

TORSION_EXTERN int
dsa_params_generate(unsigned char *out,
                    size_t *out_len,
                    unsigned int bits,
                    const unsigned char *entropy);

TORSION_EXTERN unsigned int
dsa_params_bits(const unsigned char *params, size_t params_len);

TORSION_EXTERN unsigned int
dsa_params_qbits(const unsigned char *params, size_t params_len);

TORSION_EXTERN int
dsa_params_verify(const unsigned char *params, size_t params_len);

TORSION_EXTERN int
dsa_params_import(unsigned char *out, size_t *out_len,
                  const unsigned char *params, size_t params_len);

TORSION_EXTERN int
dsa_params_export(unsigned char *out, size_t *out_len,
                  const unsigned char *params, size_t params_len);

TORSION_EXTERN int
dsa_privkey_create(unsigned char *out,
                   size_t *out_len,
                   const unsigned char *params,
                   size_t params_len,
                   const unsigned char *entropy);

TORSION_EXTERN int
dsa_privkey_generate(unsigned char *out,
                     size_t *out_len,
                     unsigned int bits,
                     const unsigned char *entropy);

TORSION_EXTERN unsigned int
dsa_privkey_bits(const unsigned char *key, size_t key_len);

TORSION_EXTERN unsigned int
dsa_privkey_qbits(const unsigned char *key, size_t key_len);

TORSION_EXTERN int
dsa_privkey_verify(const unsigned char *key, size_t key_len);

TORSION_EXTERN int
dsa_privkey_import(unsigned char *out, size_t *out_len,
                   const unsigned char *key, size_t key_len);

TORSION_EXTERN int
dsa_privkey_export(unsigned char *out, size_t *out_len,
                   const unsigned char *key, size_t key_len);

TORSION_EXTERN int
dsa_pubkey_create(unsigned char *out, size_t *out_len,
                  const unsigned char *key, size_t key_len);

TORSION_EXTERN unsigned int
dsa_pubkey_bits(const unsigned char *key, size_t key_len);

TORSION_EXTERN unsigned int
dsa_pubkey_qbits(const unsigned char *key, size_t key_len);

TORSION_EXTERN int
dsa_pubkey_verify(const unsigned char *key, size_t key_len);

TORSION_EXTERN int
dsa_pubkey_import(unsigned char *out, size_t *out_len,
                  const unsigned char *key, size_t key_len);

TORSION_EXTERN int
dsa_pubkey_export(unsigned char *out, size_t *out_len,
                  const unsigned char *key, size_t key_len);

TORSION_EXTERN int
dsa_sig_export(unsigned char *out,
               size_t *out_len,
               const unsigned char *sig,
               size_t sig_len,
               size_t qsize);

TORSION_EXTERN int
dsa_sig_import(unsigned char *out,
               size_t *out_len,
               const unsigned char *sig,
               size_t sig_len,
               size_t qsize);

TORSION_EXTERN int
dsa_sign(unsigned char *out, size_t *out_len,
         const unsigned char *msg, size_t msg_len,
         const unsigned char *key, size_t key_len,
         const unsigned char *entropy);

TORSION_EXTERN int
dsa_verify(const unsigned char *msg, size_t msg_len,
           const unsigned char *sig, size_t sig_len,
           const unsigned char *key, size_t key_len);

TORSION_EXTERN int
dsa_derive(unsigned char *out, size_t *out_len,
           const unsigned char *pub, size_t pub_len,
           const unsigned char *priv, size_t priv_len);

#ifdef __cplusplus
}
#endif

#endif /* TORSION_DSA_H */
