#ifndef _TORSION_RSA_H
#define _TORSION_RSA_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

/*
 * Symbol Aliases
 */

#define rsa_privkey_generate torsion_rsa_privkey_generate
#define rsa_privkey_bits torsion_rsa_privkey_bits
#define rsa_privkey_verify torsion_rsa_privkey_verify
#define rsa_privkey_import torsion_rsa_privkey_import
#define rsa_privkey_export torsion_rsa_privkey_export
#define rsa_pubkey_create torsion_rsa_pubkey_create
#define rsa_pubkey_bits torsion_rsa_pubkey_bits
#define rsa_pubkey_verify torsion_rsa_pubkey_verify
#define rsa_pubkey_import torsion_rsa_pubkey_import
#define rsa_pubkey_export torsion_rsa_pubkey_export
#define rsa_sign torsion_rsa_sign
#define rsa_verify torsion_rsa_verify
#define rsa_encrypt torsion_rsa_encrypt
#define rsa_decrypt torsion_rsa_decrypt
#define rsa_encrypt_oaep torsion_rsa_encrypt_oaep
#define rsa_decrypt_oaep torsion_rsa_decrypt_oaep
#define rsa_sign_pss torsion_rsa_sign_pss
#define rsa_verify_pss torsion_rsa_verify_pss
#define rsa_encrypt_raw torsion_rsa_encrypt_raw
#define rsa_decrypt_raw torsion_rsa_decrypt_raw
#define rsa_veil torsion_rsa_veil
#define rsa_unveil torsion_rsa_unveil

/*
 * Defs
 */

#define RSA_DEFAULT_MOD_BITS 2048
#define RSA_DEFAULT_EXP 65537
#define RSA_MIN_MOD_BITS 512
#define RSA_MAX_MOD_BITS 16384
#define RSA_MIN_MOD_SIZE ((RSA_MIN_MOD_BITS + 7) / 8)
#define RSA_MAX_MOD_SIZE ((RSA_MAX_MOD_BITS + 7) / 8)
#define RSA_MIN_EXP 3ull
#define RSA_MAX_EXP 0x1ffffffffull
#define RSA_MIN_EXP_BITS 2
#define RSA_MAX_EXP_BITS 33
#define RSA_MIN_EXP_SIZE 1
#define RSA_MAX_EXP_SIZE 5
#define RSA_SALT_LENGTH_AUTO 0
#define RSA_SALT_LENGTH_HASH -1

/* Limits:
 * 4096 = 2614
 * 8192 = 5174
 * 16384 = 10294
 */

#define RSA_MAX_PRIV_SIZE (0                  \
  + 4 /* seq */                               \
  + 3 /* version */                           \
  + 4 + 1 + RSA_MAX_MOD_SIZE /* n */          \
  + 2 + 1 + RSA_MAX_EXP_SIZE /* e */          \
  + 4 + 1 + RSA_MAX_MOD_SIZE /* d */          \
  + 4 + 1 + RSA_MAX_MOD_SIZE / 2 + 1 /* p */  \
  + 4 + 1 + RSA_MAX_MOD_SIZE / 2 + 1 /* q */  \
  + 4 + 1 + RSA_MAX_MOD_SIZE / 2 + 1 /* dp */ \
  + 4 + 1 + RSA_MAX_MOD_SIZE / 2 + 1 /* dq */ \
  + 4 + 1 + RSA_MAX_MOD_SIZE /* qi */         \
)

/* Limits:
 * 4096 = 529
 * 8192 = 1041
 * 16384 = 2065
 */

#define RSA_MAX_PUB_SIZE (0          \
  + 4 /* seq */                      \
  + 4 + 1 + RSA_MAX_MOD_SIZE /* n */ \
  + 2 + 1 + RSA_MAX_EXP_SIZE /* e */ \
)

/*
 * RSA
 */

int
rsa_privkey_generate(unsigned char *out,
                     size_t *out_len,
                     unsigned long bits,
                     unsigned long long exp,
                     const unsigned char *entropy);

size_t
rsa_privkey_bits(const unsigned char *key, size_t key_len);

int
rsa_privkey_verify(const unsigned char *key, size_t key_len);

int
rsa_privkey_import(unsigned char *out,
                   size_t *out_len,
                   const unsigned char *key,
                   size_t key_len,
                   const unsigned char *entropy);

int
rsa_privkey_export(unsigned char *out,
                   size_t *out_len,
                   const unsigned char *key,
                   size_t key_len);

int
rsa_pubkey_create(unsigned char *out,
                  size_t *out_len,
                  const unsigned char *key,
                  size_t key_len);

size_t
rsa_pubkey_bits(const unsigned char *key, size_t key_len);

int
rsa_pubkey_verify(const unsigned char *key, size_t key_len);

int
rsa_pubkey_import(unsigned char *out,
                  size_t *out_len,
                  const unsigned char *key,
                  size_t key_len);

int
rsa_pubkey_export(unsigned char *out,
                  size_t *out_len,
                  const unsigned char *key,
                  size_t key_len);

int
rsa_sign(unsigned char *out,
         size_t *out_len,
         int type,
         const unsigned char *msg,
         size_t msg_len,
         const unsigned char *key,
         size_t key_len,
         const unsigned char *entropy);

int
rsa_verify(int type,
           const unsigned char *msg,
           size_t msg_len,
           const unsigned char *sig,
           size_t sig_len,
           const unsigned char *key,
           size_t key_len);

int
rsa_encrypt(unsigned char *out,
            size_t *out_len,
            const unsigned char *msg,
            size_t msg_len,
            const unsigned char *key,
            size_t key_len,
            const unsigned char *entropy);

int
rsa_decrypt(unsigned char *out,
            size_t *out_len,
            const unsigned char *msg,
            size_t msg_len,
            const unsigned char *key,
            size_t key_len,
            const unsigned char *entropy);

int
rsa_sign_pss(unsigned char *out,
             size_t *out_len,
             int type,
             const unsigned char *msg,
             size_t msg_len,
             const unsigned char *key,
             size_t key_len,
             int salt_len,
             const unsigned char *entropy);

int
rsa_verify_pss(int type,
               const unsigned char *msg,
               size_t msg_len,
               const unsigned char *sig,
               size_t sig_len,
               const unsigned char *key,
               size_t key_len,
               int salt_len);

int
rsa_encrypt_oaep(unsigned char *out,
                 size_t *out_len,
                 int type,
                 const unsigned char *msg,
                 size_t msg_len,
                 const unsigned char *key,
                 size_t key_len,
                 const unsigned char *label,
                 size_t label_len,
                 const unsigned char *entropy);

int
rsa_decrypt_oaep(unsigned char *out,
                 size_t *out_len,
                 int type,
                 const unsigned char *msg,
                 size_t msg_len,
                 const unsigned char *key,
                 size_t key_len,
                 const unsigned char *label,
                 size_t label_len,
                 const unsigned char *entropy);

int
rsa_veil(unsigned char *out,
         size_t *out_len,
         const unsigned char *msg,
         size_t msg_len,
         size_t bits,
         const unsigned char *key,
         size_t key_len,
         const unsigned char *entropy);

int
rsa_unveil(unsigned char *out,
           size_t *out_len,
           const unsigned char *msg,
           size_t msg_len,
           size_t bits,
           const unsigned char *key,
           size_t key_len);

#ifdef __cplusplus
}
#endif

#endif /* _TORSION_RSA_H */
