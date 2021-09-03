/*!
 * cipher.h - ciphers for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 */

#ifndef TORSION_CIPHER_H
#define TORSION_CIPHER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "common.h"

/*
 * Symbol Aliases
 */

#define aes_init torsion_aes_init
#define aes_init_encrypt torsion_aes_init_encrypt
#define aes_init_decrypt torsion_aes_init_decrypt
#define aes_encrypt torsion_aes_encrypt
#define aes_decrypt torsion_aes_decrypt
#define arc2_init torsion_arc2_init
#define arc2_encrypt torsion_arc2_encrypt
#define arc2_decrypt torsion_arc2_decrypt
#define blowfish_init torsion_blowfish_init
#define blowfish_encrypt torsion_blowfish_encrypt
#define blowfish_decrypt torsion_blowfish_decrypt
#define camellia_init torsion_camellia_init
#define camellia_encrypt torsion_camellia_encrypt
#define camellia_decrypt torsion_camellia_decrypt
#define cast5_init torsion_cast5_init
#define cast5_encrypt torsion_cast5_encrypt
#define cast5_decrypt torsion_cast5_decrypt
#define des_init torsion_des_init
#define des_encrypt torsion_des_encrypt
#define des_decrypt torsion_des_decrypt
#define des_ede_init torsion_des_ede_init
#define des_ede_encrypt torsion_des_ede_encrypt
#define des_ede_decrypt torsion_des_ede_decrypt
#define des_ede3_init torsion_des_ede3_init
#define des_ede3_encrypt torsion_des_ede3_encrypt
#define des_ede3_decrypt torsion_des_ede3_decrypt
#define idea_init torsion_idea_init
#define idea_init_encrypt torsion_idea_init_encrypt
#define idea_init_decrypt torsion_idea_init_decrypt
#define idea_encrypt torsion_idea_encrypt
#define idea_decrypt torsion_idea_decrypt
#define serpent_init torsion_serpent_init
#define serpent_encrypt torsion_serpent_encrypt
#define serpent_decrypt torsion_serpent_decrypt
#define twofish_init torsion_twofish_init
#define twofish_encrypt torsion_twofish_encrypt
#define twofish_decrypt torsion_twofish_decrypt
#define pkcs7_pad torsion_pkcs7_pad
#define pkcs7_unpad torsion_pkcs7_unpad
#define cipher_key_size torsion_cipher_key_size
#define cipher_block_size torsion_cipher_block_size
#define cipher_init torsion_cipher_init
#define cipher_encrypt torsion_cipher_encrypt
#define cipher_decrypt torsion_cipher_decrypt
#define ecb_encrypt torsion_ecb_encrypt
#define ecb_decrypt torsion_ecb_decrypt
#define ecb_steal torsion_ecb_steal
#define ecb_unsteal torsion_ecb_unsteal
#define cbc_init torsion_cbc_init
#define cbc_encrypt torsion_cbc_encrypt
#define cbc_decrypt torsion_cbc_decrypt
#define cbc_steal torsion_cbc_steal
#define cbc_unsteal torsion_cbc_unsteal
#define xts_init torsion_xts_init
#define xts_setup torsion_xts_setup
#define xts_encrypt torsion_xts_encrypt
#define xts_decrypt torsion_xts_decrypt
#define xts_steal torsion_xts_steal
#define xts_unsteal torsion_xts_unsteal
#define ctr_init torsion_ctr_init
#define ctr_crypt torsion_ctr_crypt
#define cfb_init torsion_cfb_init
#define cfb_encrypt torsion_cfb_encrypt
#define cfb_decrypt torsion_cfb_decrypt
#define ofb_init torsion_ofb_init
#define ofb_crypt torsion_ofb_crypt
#define gcm_init torsion_gcm_init
#define gcm_aad torsion_gcm_aad
#define gcm_encrypt torsion_gcm_encrypt
#define gcm_decrypt torsion_gcm_decrypt
#define gcm_digest torsion_gcm_digest
#define ccm_init torsion_ccm_init
#define ccm_setup torsion_ccm_setup
#define ccm_encrypt torsion_ccm_encrypt
#define ccm_decrypt torsion_ccm_decrypt
#define ccm_digest torsion_ccm_digest
#define eax_init torsion_eax_init
#define eax_aad torsion_eax_aad
#define eax_encrypt torsion_eax_encrypt
#define eax_decrypt torsion_eax_decrypt
#define eax_digest torsion_eax_digest
#define cipher_stream_init torsion_cipher_stream_init
#define cipher_stream_set_padding torsion_cipher_stream_set_padding
#define cipher_stream_set_aad torsion_cipher_stream_set_aad
#define cipher_stream_set_ccm torsion_cipher_stream_set_ccm
#define cipher_stream_set_tag torsion_cipher_stream_set_tag
#define cipher_stream_get_tag torsion_cipher_stream_get_tag
#define cipher_stream_update torsion_cipher_stream_update
#define cipher_stream_crypt torsion_cipher_stream_crypt
#define cipher_stream_update_size torsion_cipher_stream_update_size
#define cipher_stream_final torsion_cipher_stream_final
#define cipher_stream_final_size torsion_cipher_stream_final_size
#define cipher_static_encrypt torsion_cipher_static_encrypt
#define cipher_static_decrypt torsion_cipher_static_decrypt

/*
 * Definitions
 */

#define CIPHER_MAX_BLOCK_SIZE 16
#define CIPHER_MAX_TAG_SIZE 16

#define CIPHER_BLOCKS(n) \
  (((n) + CIPHER_MAX_BLOCK_SIZE - 1) / CIPHER_MAX_BLOCK_SIZE)

/* One extra block due to ctx->last. */
#define CIPHER_MAX_UPDATE_SIZE(n) \
  ((CIPHER_BLOCKS(n) + 1) * CIPHER_MAX_BLOCK_SIZE)

/* 2 * n - 1 bytes due to XTS mode. */
#define CIPHER_MAX_FINAL_SIZE (2 * CIPHER_MAX_BLOCK_SIZE - 1)

#define CIPHER_MAX_ENCRYPT_SIZE(n) CIPHER_MAX_UPDATE_SIZE(n)
#define CIPHER_MAX_DECRYPT_SIZE(n) CIPHER_MAX_UPDATE_SIZE(n)

/*
 * Ciphers
 */

typedef enum cipher_id {
  CIPHER_AES128,
  CIPHER_AES192,
  CIPHER_AES256,
  CIPHER_ARC2,
  CIPHER_ARC2_GUTMANN,
  CIPHER_ARC2_40,
  CIPHER_ARC2_64,
  CIPHER_ARC2_128,
  CIPHER_ARC2_128_GUTMANN,
  CIPHER_BLOWFISH,
  CIPHER_CAMELLIA128,
  CIPHER_CAMELLIA192,
  CIPHER_CAMELLIA256,
  CIPHER_CAST5,
  CIPHER_DES,
  CIPHER_DES_EDE,
  CIPHER_DES_EDE3,
  CIPHER_IDEA,
  CIPHER_SERPENT128,
  CIPHER_SERPENT192,
  CIPHER_SERPENT256,
  CIPHER_TWOFISH128,
  CIPHER_TWOFISH192,
  CIPHER_TWOFISH256
} cipher_id_t;

/*
 * Modes
 */

typedef enum mode_id {
  CIPHER_MODE_RAW,
  CIPHER_MODE_ECB,
  CIPHER_MODE_CBC,
  CIPHER_MODE_CTS,
  CIPHER_MODE_XTS,
  CIPHER_MODE_CTR,
  CIPHER_MODE_CFB,
  CIPHER_MODE_OFB,
  CIPHER_MODE_GCM,
  CIPHER_MODE_CCM,
  CIPHER_MODE_EAX
} mode_id_t;

/*
 * Types
 */

typedef struct aes_s {
  int rounds;
  uint32_t enckey[60];
  uint32_t deckey[60];
} aes_t;

typedef struct arc2_s {
  uint16_t k[64];
} arc2_t;

typedef struct blowfish_s {
  uint32_t S[4][256];
  uint32_t P[18];
} blowfish_t;

typedef struct camellia_s {
  unsigned int bits;
  uint32_t key[68];
} camellia_t;

typedef struct cast5_s {
  uint32_t masking[16];
  uint8_t rotate[16];
} cast5_t;

typedef struct des_s {
  uint32_t keys[32];
} des_t;

typedef struct des_ede_s {
  des_t x;
  des_t y;
} des_ede_t;

typedef struct des_ede3_s {
  des_t x;
  des_t y;
  des_t z;
} des_ede3_t;

typedef struct idea_s {
  uint16_t enckey[52];
  uint16_t deckey[52];
} idea_t;

typedef struct serpent_s {
  uint32_t subkeys[132];
} serpent_t;

typedef struct twofish_s {
  uint32_t S[4][256];
  uint32_t k[40];
} twofish_t;

typedef struct cipher_s {
  cipher_id_t type;
  size_t size;
  union {
    aes_t aes;
    arc2_t arc2;
    blowfish_t blowfish;
    camellia_t camellia;
    cast5_t cast5;
    des_t des;
    des_ede_t ede;
    des_ede3_t ede3;
    idea_t idea;
    serpent_t serpent;
    twofish_t twofish;
  } ctx;
} cipher_t;

typedef struct block_mode_s {
  unsigned char tweak[CIPHER_MAX_BLOCK_SIZE];
  unsigned char prev[CIPHER_MAX_BLOCK_SIZE];
} block_mode_t;

/* Avoid violating ISO C section 7.1.3. */
#define stream_mode_t xstream_mode_t

typedef struct stream_mode_s {
  unsigned char state[CIPHER_MAX_BLOCK_SIZE];
  unsigned char iv[CIPHER_MAX_BLOCK_SIZE];
  size_t pos;
} stream_mode_t;

typedef block_mode_t cbc_t;
typedef block_mode_t xts_t;
typedef stream_mode_t ctr_t;
typedef stream_mode_t cfb_t;
typedef stream_mode_t ofb_t;

struct ghash_fe_s {
  uint64_t lo;
  uint64_t hi;
};

struct ghash_s {
  struct ghash_fe_s state;
  struct ghash_fe_s table[16];
  unsigned char block[16];
  uint64_t adlen;
  uint64_t ctlen;
  size_t pos;
};

typedef struct gcm_s {
  ctr_t ctr;
  struct ghash_s hash;
  unsigned char mask[16];
} gcm_t;

struct cmac_s {
  unsigned char mac[CIPHER_MAX_BLOCK_SIZE];
  size_t pos;
};

typedef struct ccm_s {
  ctr_t ctr;
  struct cmac_s hash;
} ccm_t;

typedef struct eax_s {
  ctr_t ctr;
  struct cmac_s hash1;
  struct cmac_s hash2;
  unsigned char mask[CIPHER_MAX_BLOCK_SIZE];
} eax_t;

struct cipher_mode_s {
  mode_id_t type;
  union {
    block_mode_t block;
    stream_mode_t stream;
    gcm_t gcm;
    ccm_t ccm;
    eax_t eax;
  } mode;
};

typedef struct cipher_stream_s {
  int encrypt;
  int padding;
  int unpad;
  size_t block_size;
  size_t block_pos;
  size_t last_size;
  size_t tag_len;
  size_t ccm_len;
  unsigned char block[CIPHER_MAX_BLOCK_SIZE];
  unsigned char last[CIPHER_MAX_BLOCK_SIZE];
  unsigned char tag[CIPHER_MAX_TAG_SIZE];
  cipher_t cipher;
  struct cipher_mode_s mode;
} cipher_stream_t;

/*
 * AES
 */

TORSION_EXTERN void
aes_init(aes_t *ctx, unsigned int bits, const unsigned char *key);

TORSION_EXTERN void
aes_init_encrypt(aes_t *ctx, unsigned int bits, const unsigned char *key);

TORSION_EXTERN void
aes_init_decrypt(aes_t *ctx);

TORSION_EXTERN void
aes_encrypt(const aes_t *ctx, unsigned char *dst, const unsigned char *src);

TORSION_EXTERN void
aes_decrypt(const aes_t *ctx, unsigned char *dst, const unsigned char *src);

/*
 * ARC2
 */

TORSION_EXTERN void
arc2_init(arc2_t *ctx,
          const unsigned char *key,
          size_t key_len,
          unsigned int ekb);

TORSION_EXTERN void
arc2_encrypt(const arc2_t *ctx, unsigned char *dst, const unsigned char *src);

TORSION_EXTERN void
arc2_decrypt(const arc2_t *ctx, unsigned char *dst, const unsigned char *src);

/*
 * Blowfish
 */

TORSION_EXTERN void
blowfish_init(blowfish_t *ctx,
              const unsigned char *key, size_t key_len,
              const unsigned char *salt, size_t salt_len);

TORSION_EXTERN void
blowfish_encrypt(const blowfish_t *ctx,
                 unsigned char *dst,
                 const unsigned char *src);

TORSION_EXTERN void
blowfish_decrypt(const blowfish_t *ctx,
                 unsigned char *dst,
                 const unsigned char *src);

/*
 * Camellia
 */

TORSION_EXTERN void
camellia_init(camellia_t *ctx, unsigned int bits, const unsigned char *key);

TORSION_EXTERN void
camellia_encrypt(const camellia_t *ctx,
                 unsigned char *dst,
                 const unsigned char *src);

TORSION_EXTERN void
camellia_decrypt(const camellia_t *ctx,
                 unsigned char *dst,
                 const unsigned char *src);

/*
 * CAST5
 */

TORSION_EXTERN void
cast5_init(cast5_t *ctx, const unsigned char *key);

TORSION_EXTERN void
cast5_encrypt(const cast5_t *ctx,
              unsigned char *dst,
              const unsigned char *src);

TORSION_EXTERN void
cast5_decrypt(const cast5_t *ctx,
              unsigned char *dst,
              const unsigned char *src);

/*
 * DES
 */

TORSION_EXTERN void
des_init(des_t *ctx, const unsigned char *key);

TORSION_EXTERN void
des_encrypt(const des_t *ctx, unsigned char *dst, const unsigned char *src);

TORSION_EXTERN void
des_decrypt(const des_t *ctx, unsigned char *dst, const unsigned char *src);

/*
 * DES-EDE
 */

TORSION_EXTERN void
des_ede_init(des_ede_t *ctx, const unsigned char *key);

TORSION_EXTERN void
des_ede_encrypt(const des_ede_t *ctx,
                unsigned char *dst,
                const unsigned char *src);

TORSION_EXTERN void
des_ede_decrypt(const des_ede_t *ctx,
                unsigned char *dst,
                const unsigned char *src);

/*
 * DES-EDE3
 */

TORSION_EXTERN void
des_ede3_init(des_ede3_t *ctx, const unsigned char *key);

TORSION_EXTERN void
des_ede3_encrypt(const des_ede3_t *ctx,
                 unsigned char *dst,
                 const unsigned char *src);

TORSION_EXTERN void
des_ede3_decrypt(const des_ede3_t *ctx,
                 unsigned char *dst,
                 const unsigned char *src);

/*
 * IDEA
 */

TORSION_EXTERN void
idea_init(idea_t *ctx, const unsigned char *key);

TORSION_EXTERN void
idea_init_encrypt(idea_t *ctx, const unsigned char *key);

TORSION_EXTERN void
idea_init_decrypt(idea_t *ctx);

TORSION_EXTERN void
idea_encrypt(const idea_t *ctx, unsigned char *dst, const unsigned char *src);

TORSION_EXTERN void
idea_decrypt(const idea_t *ctx, unsigned char *dst, const unsigned char *src);

/*
 * Serpent
 */

TORSION_EXTERN void
serpent_init(serpent_t *ctx, unsigned int bits, const unsigned char *key);

TORSION_EXTERN void
serpent_encrypt(const serpent_t *ctx,
                unsigned char *dst,
                const unsigned char *src);

TORSION_EXTERN void
serpent_decrypt(const serpent_t *ctx,
                unsigned char *dst,
                const unsigned char *src);

/*
 * Twofish
 */

TORSION_EXTERN void
twofish_init(twofish_t *ctx, unsigned int bits, const unsigned char *key);

TORSION_EXTERN void
twofish_encrypt(const twofish_t *ctx,
                unsigned char *dst,
                const unsigned char *src);

TORSION_EXTERN void
twofish_decrypt(const twofish_t *ctx,
                unsigned char *dst,
                const unsigned char *src);

/*
 * PKCS7
 */

TORSION_EXTERN void
pkcs7_pad(unsigned char *dst,
          const unsigned char *src,
          size_t len,
          size_t size);

TORSION_EXTERN int
pkcs7_unpad(unsigned char *dst,
            size_t *len,
            const unsigned char *src,
            size_t size);

/*
 * Cipher
 */

TORSION_EXTERN size_t
cipher_key_size(cipher_id_t type);

TORSION_EXTERN size_t
cipher_block_size(cipher_id_t type);

TORSION_EXTERN int
cipher_init(cipher_t *ctx,
            cipher_id_t type,
            const unsigned char *key,
            size_t key_len);

TORSION_EXTERN void
cipher_encrypt(const cipher_t *ctx,
               unsigned char *dst,
               const unsigned char *src);

TORSION_EXTERN void
cipher_decrypt(const cipher_t *ctx,
               unsigned char *dst,
               const unsigned char *src);

/*
 * ECB
 */

TORSION_EXTERN void
ecb_encrypt(const cipher_t *cipher, unsigned char *dst,
            const unsigned char *src, size_t len);

TORSION_EXTERN void
ecb_decrypt(const cipher_t *cipher, unsigned char *dst,
            const unsigned char *src, size_t len);

TORSION_EXTERN void
ecb_steal(const cipher_t *cipher,
          unsigned char *last, /* last ciphertext */
          unsigned char *block, /* partial block */
          size_t len);

TORSION_EXTERN void
ecb_unsteal(const cipher_t *cipher,
            unsigned char *last, /* last plaintext */
            unsigned char *block, /* partial block */
            size_t len);

/*
 * CBC
 */

TORSION_EXTERN void
cbc_init(cbc_t *mode, const cipher_t *cipher, const unsigned char *iv);

TORSION_EXTERN void
cbc_encrypt(cbc_t *mode, const cipher_t *cipher,
            unsigned char *dst, const unsigned char *src, size_t len);

TORSION_EXTERN void
cbc_decrypt(cbc_t *mode, const cipher_t *cipher,
            unsigned char *dst, const unsigned char *src, size_t len);

TORSION_EXTERN void
cbc_steal(cbc_t *mode,
          const cipher_t *cipher,
          unsigned char *last, /* last ciphertext */
          unsigned char *block, /* partial block */
          size_t len);

TORSION_EXTERN void
cbc_unsteal(cbc_t *mode,
            const cipher_t *cipher,
            unsigned char *last, /* last plaintext */
            unsigned char *block, /* partial block */
            size_t len);

/*
 * XTS
 */

TORSION_EXTERN void
xts_init(xts_t *mode, const cipher_t *cipher, const unsigned char *iv);

TORSION_EXTERN int
xts_setup(xts_t *mode, const cipher_t *cipher,
          const unsigned char *key, size_t key_len);

TORSION_EXTERN void
xts_encrypt(xts_t *mode, const cipher_t *cipher,
            unsigned char *dst, const unsigned char *src, size_t len);

TORSION_EXTERN void
xts_decrypt(xts_t *mode, const cipher_t *cipher,
            unsigned char *dst, const unsigned char *src, size_t len);

TORSION_EXTERN void
xts_steal(xts_t *mode,
          const cipher_t *cipher,
          unsigned char *last, /* last ciphertext */
          unsigned char *block, /* partial block */
          size_t len);

TORSION_EXTERN void
xts_unsteal(xts_t *mode,
            const cipher_t *cipher,
            unsigned char *last, /* last plaintext */
            unsigned char *block, /* partial block */
            size_t len);

/*
 * CTR
 */

TORSION_EXTERN void
ctr_init(ctr_t *mode, const cipher_t *cipher, const unsigned char *iv);

TORSION_EXTERN void
ctr_crypt(ctr_t *mode, const cipher_t *cipher,
          unsigned char *dst, const unsigned char *src, size_t len);

/*
 * CFB
 */

TORSION_EXTERN void
cfb_init(cfb_t *mode, const cipher_t *cipher, const unsigned char *iv);

TORSION_EXTERN void
cfb_encrypt(cfb_t *mode, const cipher_t *cipher,
            unsigned char *dst, const unsigned char *src, size_t len);

TORSION_EXTERN void
cfb_decrypt(cfb_t *mode, const cipher_t *cipher,
            unsigned char *dst, const unsigned char *src, size_t len);

/*
 * OFB
 */

TORSION_EXTERN void
ofb_init(ofb_t *mode, const cipher_t *cipher, const unsigned char *iv);

TORSION_EXTERN void
ofb_crypt(ofb_t *mode, const cipher_t *cipher,
          unsigned char *dst, const unsigned char *src, size_t len);

/*
 * GCM
 */

TORSION_EXTERN int
gcm_init(gcm_t *mode, const cipher_t *cipher,
         const unsigned char *iv, size_t iv_len);

TORSION_EXTERN void
gcm_aad(gcm_t *mode, const unsigned char *aad, size_t len);

TORSION_EXTERN void
gcm_encrypt(gcm_t *mode, const cipher_t *cipher,
            unsigned char *dst, const unsigned char *src, size_t len);

TORSION_EXTERN void
gcm_decrypt(gcm_t *mode, const cipher_t *cipher,
            unsigned char *dst, const unsigned char *src, size_t len);

TORSION_EXTERN void
gcm_digest(gcm_t *mode, unsigned char *mac);

/*
 * CCM
 */

TORSION_EXTERN int
ccm_init(ccm_t *mode, const cipher_t *cipher,
         const unsigned char *iv, size_t iv_len);

TORSION_EXTERN int
ccm_setup(ccm_t *mode, const cipher_t *cipher,
          size_t msg_len, size_t tag_len,
          const unsigned char *aad, size_t aad_len);

TORSION_EXTERN void
ccm_encrypt(ccm_t *mode, const cipher_t *cipher,
            unsigned char *dst, const unsigned char *src, size_t len);

TORSION_EXTERN void
ccm_decrypt(ccm_t *mode, const cipher_t *cipher,
            unsigned char *dst, const unsigned char *src, size_t len);

TORSION_EXTERN void
ccm_digest(ccm_t *mode, const cipher_t *cipher, unsigned char *mac);

/*
 * EAX
 */

TORSION_EXTERN int
eax_init(eax_t *mode, const cipher_t *cipher,
         const unsigned char *iv, size_t iv_len);

TORSION_EXTERN void
eax_aad(eax_t *mode, const cipher_t *cipher,
        const unsigned char *aad, size_t len);

TORSION_EXTERN void
eax_encrypt(eax_t *mode, const cipher_t *cipher,
            unsigned char *dst, const unsigned char *src, size_t len);

TORSION_EXTERN void
eax_decrypt(eax_t *mode, const cipher_t *cipher,
            unsigned char *dst, const unsigned char *src, size_t len);

TORSION_EXTERN void
eax_digest(eax_t *mode, const cipher_t *cipher, unsigned char *mac);

/*
 * Cipher Stream
 */

TORSION_EXTERN int
cipher_stream_init(cipher_stream_t *ctx,
                   cipher_id_t type, mode_id_t mode, int encrypt,
                   const unsigned char *key, size_t key_len,
                   const unsigned char *iv, size_t iv_len);

TORSION_EXTERN int
cipher_stream_set_padding(cipher_stream_t *ctx, int padding);

TORSION_EXTERN int
cipher_stream_set_aad(cipher_stream_t *ctx,
                      const unsigned char *aad,
                      size_t len);

TORSION_EXTERN int
cipher_stream_set_ccm(cipher_stream_t *ctx,
                      size_t msg_len,
                      size_t tag_len,
                      const unsigned char *aad,
                      size_t aad_len);

TORSION_EXTERN int
cipher_stream_set_tag(cipher_stream_t *ctx,
                      const unsigned char *tag,
                      size_t len);

TORSION_EXTERN int
cipher_stream_get_tag(cipher_stream_t *ctx, unsigned char *tag, size_t *len);

TORSION_EXTERN void
cipher_stream_update(cipher_stream_t *ctx,
                     unsigned char *output, size_t *output_len,
                     const unsigned char *input, size_t input_len);

TORSION_EXTERN int
cipher_stream_crypt(cipher_stream_t *ctx,
                    unsigned char *dst,
                    const unsigned char *src,
                    size_t len);

TORSION_EXTERN size_t
cipher_stream_update_size(const cipher_stream_t *ctx, size_t input_len);

TORSION_EXTERN int
cipher_stream_final(cipher_stream_t *ctx,
                    unsigned char *output,
                    size_t *output_len);

TORSION_EXTERN size_t
cipher_stream_final_size(const cipher_stream_t *ctx);

/*
 * Static Encryption/Decryption
 */

TORSION_EXTERN int
cipher_static_encrypt(unsigned char *ct,
                      size_t *ct_len,
                      cipher_id_t type,
                      mode_id_t mode,
                      const unsigned char *key,
                      size_t key_len,
                      const unsigned char *iv,
                      size_t iv_len,
                      const unsigned char *pt,
                      size_t pt_len);

TORSION_EXTERN int
cipher_static_decrypt(unsigned char *pt,
                      size_t *pt_len,
                      cipher_id_t type,
                      mode_id_t mode,
                      const unsigned char *key,
                      size_t key_len,
                      const unsigned char *iv,
                      size_t iv_len,
                      const unsigned char *ct,
                      size_t ct_len);

#ifdef __cplusplus
}
#endif

#endif /* TORSION_CIPHER_H */
