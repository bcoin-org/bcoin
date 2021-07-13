/*!
 * kdf.c - kdf for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 *
 * Parts of this software are based on Tarsnap/scrypt:
 *   Copyright (c) 2005-2016, Colin Percival. All rights reserved.
 *   Copyright (c) 2005-2016, Tarsnap Backup Inc. All rights reserved.
 *   Copyright (c) 2014, Sean Kelly. All rights reserved.
 *   https://github.com/Tarsnap/scrypt
 *
 * Parts of this software are based on joyent/node-bcrypt-pbkdf:
 *   Copyright (c) 2016, Joyent Inc
 *   https://github.com/joyent/node-bcrypt-pbkdf
 *
 * Parts of this software are based on golang/crypto:
 *   Copyright (c) 2009 The Go Authors. All rights reserved.
 *   https://github.com/golang/crypto
 */

#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <torsion/cipher.h>
#include <torsion/hash.h>
#include <torsion/kdf.h>
#include <torsion/util.h>
#include "bio.h"

/*
 * Bcrypt
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/Bcrypt
 *   http://www.usenix.org/events/usenix99/provos/provos_html/node1.html
 *   https://hackernoon.com/the-bcrypt-protocol-is-kind-of-a-mess-4aace5eb31bd
 *   https://github.com/openbsd/src/blob/master/lib/libc/crypt/bcrypt.c
 *   https://github.com/openssh/openssh-portable
 *   https://github.com/openssh/openssh-portable/blob/master/openbsd-compat/bcrypt_pbkdf.c
 *   https://github.com/openssh/openssh-portable/blob/master/openbsd-compat/blowfish.c
 *   https://github.com/joyent/node-bcrypt-pbkdf/blob/master/index.js
 */

#define BCRYPT_VERSION '2'

#define BCRYPT_CIPHERTEXT192 "OrpheanBeholderScryDoubt"
#define BCRYPT_BLOCKS192 6
#define BCRYPT_SIZE192 24
#define BCRYPT_SALT192 16
#define BCRYPT_HASH192 23

#define BCRYPT_CIPHERTEXT256 "OxychromaticBlowfishSwatDynamite"
#define BCRYPT_BLOCKS256 8
#define BCRYPT_SIZE256 32

static const char base64_charset[] =
  "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

static const int8_t base64_table[256] = {
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1,  0,  1,
  54, 55, 56, 57, 58, 59, 60, 61,
  62, 63, -1, -1, -1, -1, -1, -1,
  -1,  2,  3,  4,  5,  6,  7,  8,
   9, 10, 11, 12, 13, 14, 15, 16,
  17, 18, 19, 20, 21, 22, 23, 24,
  25, 26, 27, -1, -1, -1, -1, -1,
  -1, 28, 29, 30, 31, 32, 33, 34,
  35, 36, 37, 38, 39, 40, 41, 42,
  43, 44, 45, 46, 47, 48, 49, 50,
  51, 52, 53, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1
};

static char *
base64_encode(char *dst, const uint8_t *src, size_t len) {
  uint8_t c1, c2;
  size_t i = 0;
  size_t j = 0;

  while (i < len) {
    c1 = src[i++];
    dst[j++] = base64_charset[c1 >> 2];
    c1 = (c1 & 3) << 4;

    if (i >= len) {
      dst[j++] = base64_charset[c1];
      break;
    }

    c2 = src[i++];
    c1 |= (c2 >> 4) & 15;
    dst[j++] = base64_charset[c1];
    c1 = (c2 & 15) << 2;

    if (i >= len) {
      dst[j++] = base64_charset[c1];
      break;
    }

    c2 = src[i++];
    c1 |= (c2 >> 6) & 3;
    dst[j++] = base64_charset[c1];
    dst[j++] = base64_charset[c2 & 63];
  }

  dst[j] = '\0';

  return dst + j;
}

static const char *
base64_decode(uint8_t *dst, size_t len, const char *src) {
  uint8_t c1, c2, c3, c4;
  size_t i = 0;
  size_t j = 0;

  while (j < len) {
    c1 = base64_table[(uint8_t)src[i++]];

    if (c1 & 0x80)
      return NULL;

    c2 = base64_table[(uint8_t)src[i++]];

    if (c2 & 0x80)
      return NULL;

    dst[j++] = (c1 << 2) | ((c2 & 48) >> 4);

    if (j >= len)
      break;

    c3 = base64_table[(uint8_t)src[i++]];

    if (c3 & 0x80)
      return NULL;

    dst[j++] = ((c2 & 15) << 4) | ((c3 & 60) >> 2);

    if (j >= len)
      break;

    c4 = base64_table[(uint8_t)src[i++]];

    if (c4 & 0x80)
      return NULL;

    dst[j++] = ((c3 & 3) << 6) | c4;
  }

  return src + i;
}

static void
bcrypt_encode(char *out,
              char minor,
              unsigned int rounds,
              const unsigned char *salt,
              const unsigned char *hash) {
  ASSERT(rounds >= 4 && rounds <= 31);

  *out++ = '$';
  *out++ = BCRYPT_VERSION;
  *out++ = minor;
  *out++ = '$';
  *out++ = '0' + (rounds / 10);
  *out++ = '0' + (rounds % 10);
  *out++ = '$';

  out = base64_encode(out, salt, BCRYPT_SALT192);
  out = base64_encode(out, hash, BCRYPT_HASH192);
}

static int
bcrypt_decode(char *minor,
              unsigned int *rounds,
              unsigned char *salt,
              unsigned char *hash,
              const char *str) {
  int hi, lo;

  if (str[0] != '$' || str[1] != BCRYPT_VERSION)
    return 0;

  *minor = str[2];

  if (*minor != 'a' && *minor != 'b')
    return 0;

  if (str[3] != '$')
    return 0;

  if (str[4] == '\0' || str[5] == '\0')
    return 0;

  hi = (int)str[4] - 0x30;
  lo = (int)str[5] - 0x30;

  if (hi < 0 || hi > 9 || lo < 0 || lo > 9)
    return 0;

  *rounds = hi * 10 + lo;

  if (*rounds < 4 || *rounds > 31)
    return 0;

  if (str[6] != '$')
    return 0;

  str += 7;
  str = base64_decode(salt, BCRYPT_SALT192, str);

  if (str == NULL)
    return 0;

  str = base64_decode(hash, BCRYPT_HASH192, str);

  if (str == NULL)
    return 0;

  if (*str != '\0')
    return 0;

  return 1;
}

void
bcrypt_hash192(unsigned char *out,
               const unsigned char *pass, size_t pass_len,
               const unsigned char *salt, size_t salt_len,
               unsigned int rounds) {
  static const unsigned char ciphertext[] = BCRYPT_CIPHERTEXT192;
  uint32_t cdata[BCRYPT_BLOCKS192];
  blowfish_t state;
  uint32_t i;
  size_t off;
  int j;

  if (rounds < 4)
    rounds = 4;
  else if (rounds > 31)
    rounds = 31;

  blowfish_init(&state, pass, pass_len, salt, salt_len);

  for (i = 0; i < (UINT32_C(1) << rounds); i++) {
    blowfish_expand0state(&state, pass, pass_len);
    blowfish_expand0state(&state, salt, salt_len);
  }

  off = 0;

  for (j = 0; j < BCRYPT_BLOCKS192; j++)
    cdata[j] = blowfish_stream2word(ciphertext, BCRYPT_SIZE192, &off);

  for (j = 0; j < 64; j++)
    blowfish_enc(&state, cdata, BCRYPT_BLOCKS192);

  for (j = 0; j < BCRYPT_BLOCKS192; j++)
    write32be(out + j * 4, cdata[j]);

  torsion_cleanse(cdata, sizeof(cdata));
  torsion_cleanse(&state, sizeof(state));
}

void
bcrypt_hash256(unsigned char *out,
               const unsigned char *pass, size_t pass_len,
               const unsigned char *salt, size_t salt_len,
               unsigned int rounds) {
  static const unsigned char ciphertext[] = BCRYPT_CIPHERTEXT256;
  uint32_t cdata[BCRYPT_BLOCKS256];
  blowfish_t state;
  uint32_t i;
  size_t off;
  int j;

  if (rounds < 4)
    rounds = 4;
  else if (rounds > 31)
    rounds = 31;

  blowfish_init(&state, pass, pass_len, salt, salt_len);

  for (i = 0; i < (UINT32_C(1) << rounds); i++) {
    blowfish_expand0state(&state, salt, salt_len);
    blowfish_expand0state(&state, pass, pass_len);
  }

  off = 0;

  for (j = 0; j < BCRYPT_BLOCKS256; j++)
    cdata[j] = blowfish_stream2word(ciphertext, BCRYPT_SIZE256, &off);

  for (j = 0; j < 64; j++)
    blowfish_enc(&state, cdata, BCRYPT_BLOCKS256);

  for (j = 0; j < BCRYPT_BLOCKS256; j++)
    write32le(out + j * 4, cdata[j]);

  torsion_cleanse(cdata, sizeof(cdata));
  torsion_cleanse(&state, sizeof(state));
}

int
bcrypt_pbkdf(unsigned char *key,
             const unsigned char *pass, size_t pass_len,
             const unsigned char *salt, size_t salt_len,
             unsigned int rounds, size_t size) {
  size_t i, j, stride, amount, keylen, amt, count, dest;
  unsigned char out[BCRYPT_SIZE256];
  unsigned char tmpout[BCRYPT_SIZE256];
  unsigned char sha2pass[64];
  unsigned char sha2salt[64];
  unsigned char ctr[4];
  sha512_t shash, hash;

  if (rounds == 0
      || pass_len == 0
      || salt_len == 0
      || size == 0
      || size > (BCRYPT_SIZE256 * BCRYPT_SIZE256)
      || salt_len > ((size_t)1 << 20)) {
    return 0;
  }

  stride = (size + BCRYPT_SIZE256 - 1) / BCRYPT_SIZE256;
  amount = (size + stride - 1) / stride;

  sha512_init(&hash);
  sha512_update(&hash, pass, pass_len);
  sha512_final(&hash, sha2pass);

  /* Zero for struct assignment. */
  memset(&shash, 0, sizeof(shash));

  sha512_init(&shash);
  sha512_update(&shash, salt, salt_len);

  keylen = size;
  amt = amount;

  for (count = 1; keylen > 0; count++) {
    write32be(ctr, count);

    hash = shash;
    sha512_update(&hash, ctr, 4);
    sha512_final(&hash, sha2salt);

    bcrypt_hash256(tmpout, sha2pass, 64, sha2salt, 64, 6);

    memcpy(out, tmpout, BCRYPT_SIZE256);

    for (i = 1; i < rounds; i++) {
      sha512_init(&hash);
      sha512_update(&hash, tmpout, BCRYPT_SIZE256);
      sha512_final(&hash, sha2salt);

      bcrypt_hash256(tmpout, sha2pass, 64, sha2salt, 64, 6);

      for (j = 0; j < BCRYPT_SIZE256; j++)
        out[j] ^= tmpout[j];
    }

    if (amt > keylen)
      amt = keylen;

    for (i = 0; i < amt; i++) {
      dest = i * stride + (count - 1);

      if (dest >= size)
        break;

      key[dest] = out[i];
    }

    keylen -= i;
  }

  torsion_cleanse(out, sizeof(out));
  torsion_cleanse(tmpout, sizeof(tmpout));
  torsion_cleanse(sha2pass, sizeof(sha2pass));
  torsion_cleanse(sha2salt, sizeof(sha2salt));
  torsion_cleanse(&shash, sizeof(shash));
  torsion_cleanse(&hash, sizeof(hash));

  return 1;
}

int
bcrypt_derive(unsigned char *out,
              const unsigned char *pass, size_t pass_len,
              const unsigned char *salt, size_t salt_len,
              unsigned int rounds, char minor) {
  unsigned char tmp[BCRYPT_SIZE192];
  unsigned char key[255];
  size_t key_len;

  if (rounds < 4 || rounds > 31)
    return 0;

  if (salt_len != BCRYPT_SALT192)
    return 0;

  if (pass_len >= 255) {
    memcpy(key, pass, 255);
  } else {
    if (pass_len > 0)
      memcpy(key, pass, pass_len);

    key[pass_len] = 0;
  }

  switch (minor) {
    case 'a':
      key_len = (pass_len + 1) & 0xff;
      break;
    case 'b':
      key_len = pass_len;
      if (key_len > 72)
        key_len = 72;
      key_len += 1;
      break;
    default:
      return 0;
  }

  bcrypt_hash192(tmp, key, key_len, salt, salt_len, rounds);

  memcpy(out, tmp, BCRYPT_HASH192);

  torsion_cleanse(tmp, sizeof(tmp));
  torsion_cleanse(key, sizeof(key));

  return 1;
}

int
bcrypt_generate(char *out,
                const unsigned char *pass, size_t pass_len,
                const unsigned char *salt, size_t salt_len,
                unsigned int rounds, char minor) {
  unsigned char hash[BCRYPT_HASH192];

  if (!bcrypt_derive(hash, pass, pass_len, salt, salt_len, rounds, minor))
    return 0;

  bcrypt_encode(out, minor, rounds, salt, hash);

  return 1;
}

int
bcrypt_generate_with_salt64(char *out,
                            const unsigned char *pass,
                            size_t pass_len,
                            const char *salt64,
                            unsigned int rounds,
                            char minor) {
  /* Useful for testing. */
  unsigned char salt[BCRYPT_SALT192];

  salt64 = base64_decode(salt, BCRYPT_SALT192, salt64);

  if (salt64 == NULL)
    return 0;

  if (*salt64 != '\0')
    return 0;

  return bcrypt_generate(out, pass, pass_len,
                              salt, sizeof(salt),
                              rounds, minor);
}

int
bcrypt_verify(const unsigned char *pass, size_t pass_len, const char *record) {
  char minor;
  unsigned int rounds;
  unsigned char salt[BCRYPT_SALT192];
  unsigned char expect[BCRYPT_HASH192];
  unsigned char hash[BCRYPT_HASH192];

  if (!bcrypt_decode(&minor, &rounds, salt, expect, record))
    return 0;

  if (!bcrypt_derive(hash, pass, pass_len, salt, sizeof(salt), rounds, minor))
    return 0;

  return torsion_memequal(hash, expect, BCRYPT_HASH192);
}

/*
 * EB2K (OpenSSL Legacy)
 *
 * Resources:
 *   https://github.com/openssl/openssl/blob/2e9d61e/crypto/evp/evp_key.c
 */

int
eb2k_derive(unsigned char *key,
            unsigned char *iv,
            int type,
            const unsigned char *passwd,
            size_t passwd_len,
            const unsigned char *salt,
            size_t salt_len,
            size_t key_len,
            size_t iv_len) {
  size_t hash_size = hash_output_size(type);
  unsigned char prev[HASH_MAX_OUTPUT_SIZE];
  unsigned char *block;
  size_t block_len, want;
  size_t prev_len = 0;
  hash_t hash;

  if (salt_len > 8)
    salt_len = 8;

  if (!hash_has_backend(type))
    return 0;

  if (salt_len != 0 && salt_len != 8)
    return 0;

  if (key_len + iv_len < iv_len)
    return 0;

  while (key_len + iv_len > 0) {
    hash_init(&hash, type);
    hash_update(&hash, prev, prev_len);
    hash_update(&hash, passwd, passwd_len);
    hash_update(&hash, salt, salt_len);
    hash_final(&hash, prev, hash_size);

    prev_len = hash_size;

    block = prev;
    block_len = prev_len;

    if (key_len > 0) {
      want = block_len;

      if (want > key_len)
        want = key_len;

      memcpy(key, block, want);

      key += want;
      key_len -= want;

      block += want;
      block_len -= want;
    }

    if (iv_len > 0) {
      want = block_len;

      if (want > iv_len)
        want = iv_len;

      memcpy(iv, block, want);

      iv += want;
      iv_len -= want;
    }
  }

  torsion_cleanse(prev, sizeof(prev));
  torsion_cleanse(&hash, sizeof(hash));

  return 1;
}

/*
 * HKDF
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/HKDF
 *   https://tools.ietf.org/html/rfc5869
 */

int
hkdf_extract(unsigned char *out, int type,
             const unsigned char *ikm, size_t ikm_len,
             const unsigned char *salt, size_t salt_len) {
  hmac_t hmac;

  if (!hash_has_backend(type))
    return 0;

  hmac_init(&hmac, type, salt, salt_len);
  hmac_update(&hmac, ikm, ikm_len);
  hmac_final(&hmac, out);

  return 1;
}

int
hkdf_expand(unsigned char *out,
            int type,
            const unsigned char *prk,
            const unsigned char *info,
            size_t info_len,
            size_t len) {
  size_t hash_size = hash_output_size(type);
  unsigned char prev[HASH_MAX_OUTPUT_SIZE];
  size_t prev_len = 0;
  hmac_t pmac, hmac;
  size_t i, blocks;
  uint8_t ctr = 0;

  if (!hash_has_backend(type))
    return 0;

  if (len + hash_size - 1 < len)
    return 0;

  blocks = (len + hash_size - 1) / hash_size;

  if (blocks > 255)
    return 0;

  if (len == 0)
    return 1;

  /* Zero for struct assignment. */
  memset(&pmac, 0, sizeof(pmac));

  hmac_init(&pmac, type, prk, hash_size);

  for (i = 0; i < blocks; i++) {
    ctr += 1;

    hmac = pmac;
    hmac_update(&hmac, prev, prev_len);
    hmac_update(&hmac, info, info_len);
    hmac_update(&hmac, &ctr, 1);
    hmac_final(&hmac, prev);

    prev_len = hash_size;

    if (hash_size > len)
      hash_size = len;

    memcpy(out, prev, hash_size);

    out += hash_size;
    len -= hash_size;
  }

  torsion_cleanse(prev, sizeof(prev));
  torsion_cleanse(&pmac, sizeof(pmac));
  torsion_cleanse(&hmac, sizeof(hmac));

  return 1;
}

/*
 * PBKDF2
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/PBKDF2
 *   https://tools.ietf.org/html/rfc2898
 *   https://tools.ietf.org/html/rfc2898#section-5.2
 *   https://tools.ietf.org/html/rfc6070
 *   https://www.emc.com/collateral/white-papers/h11302-pkcs5v2-1-password-based-cryptography-standard-wp.pdf
 *   http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf
 */

int
pbkdf2_derive(unsigned char *out,
              int type,
              const unsigned char *pass,
              size_t pass_len,
              const unsigned char *salt,
              size_t salt_len,
              uint32_t iter,
              size_t len) {
  size_t hash_size = hash_output_size(type);
  unsigned char block[HASH_MAX_OUTPUT_SIZE];
  unsigned char mac[HASH_MAX_OUTPUT_SIZE];
  unsigned char ctr[4];
  hmac_t pmac, smac, hmac;
  size_t i, k, blocks;
  uint32_t j;

  if (!hash_has_backend(type))
    return 0;

  if (len + hash_size - 1 < len)
    return 0;

  blocks = (len + hash_size - 1) / hash_size;

  if (blocks > UINT32_MAX)
    return 0;

  if (len == 0)
    return 1;

  /* Zero for struct assignment. */
  memset(&pmac, 0, sizeof(pmac));
  memset(&smac, 0, sizeof(smac));

  hmac_init(&pmac, type, pass, pass_len);

  smac = pmac;

  hmac_update(&smac, salt, salt_len);

  for (i = 0; i < blocks; i++) {
    write32be(ctr, i + 1);

    hmac = smac;
    hmac_update(&hmac, ctr, 4);
    hmac_final(&hmac, block);

    memcpy(mac, block, hash_size);

    for (j = 1; j < iter; j++) {
      hmac = pmac;
      hmac_update(&hmac, mac, hash_size);
      hmac_final(&hmac, mac);

      for (k = 0; k < hash_size; k++)
        block[k] ^= mac[k];
    }

    if (hash_size > len)
      hash_size = len;

    memcpy(out, block, hash_size);

    out += hash_size;
    len -= hash_size;
  }

  torsion_cleanse(block, sizeof(block));
  torsion_cleanse(mac, sizeof(mac));
  torsion_cleanse(&pmac, sizeof(pmac));
  torsion_cleanse(&smac, sizeof(smac));
  torsion_cleanse(&hmac, sizeof(hmac));

  return 1;
}

/*
 * PGPDF
 *
 * Resources:
 *   https://github.com/golang/crypto/tree/master/openpgp
 */

int
pgpdf_derive_simple(unsigned char *out,
                    int type,
                    const unsigned char *pass,
                    size_t pass_len,
                    size_t len) {
  return pgpdf_derive_salted(out, type, pass, pass_len, NULL, 0, len);
}

int
pgpdf_derive_salted(unsigned char *out,
                    int type,
                    const unsigned char *pass,
                    size_t pass_len,
                    const unsigned char *salt,
                    size_t salt_len,
                    size_t len) {
  static const unsigned char zero = 0;
  size_t hash_size = hash_output_size(type);
  unsigned char buf[HASH_MAX_OUTPUT_SIZE];
  size_t i, j;
  hash_t hash;

  if (!hash_has_backend(type))
    return 0;

  i = 0;

  while (len > 0) {
    hash_init(&hash, type);

    for (j = 0; j < i; j++)
      hash_update(&hash, &zero, 1);

    hash_update(&hash, salt, salt_len);
    hash_update(&hash, pass, pass_len);
    hash_final(&hash, buf, hash_size);

    if (hash_size > len)
      hash_size = len;

    memcpy(out, buf, hash_size);

    out += hash_size;
    len -= hash_size;
    i += 1;
  }

  torsion_cleanse(buf, sizeof(buf));
  torsion_cleanse(&hash, sizeof(hash));

  return 1;
}

int
pgpdf_derive_iterated(unsigned char *out,
                      int type,
                      const unsigned char *pass,
                      size_t pass_len,
                      const unsigned char *salt,
                      size_t salt_len,
                      size_t count,
                      size_t len) {
  static const unsigned char zero = 0;
  size_t hash_size = hash_output_size(type);
  unsigned char buf[HASH_MAX_OUTPUT_SIZE];
  size_t i, j, w, combined, todo;
  hash_t hash;

  if (!hash_has_backend(type))
    return 0;

  combined = salt_len + pass_len;

  if (combined < salt_len)
    return 0;

  if (count < combined)
    count = combined;

  if (count + combined < count)
    return 0;

  i = 0;

  while (len > 0) {
    hash_init(&hash, type);

    for (j = 0; j < i; j++)
      hash_update(&hash, &zero, 1);

    w = 0;

    while (w < count) {
      if (w + combined > count) {
        todo = count - w;

        if (todo < salt_len) {
          hash_update(&hash, salt, todo);
        } else {
          hash_update(&hash, salt, salt_len);
          hash_update(&hash, pass, todo - salt_len);
        }

        break;
      }

      hash_update(&hash, salt, salt_len);
      hash_update(&hash, pass, pass_len);

      w += combined;
    }

    hash_final(&hash, buf, hash_size);

    if (hash_size > len)
      hash_size = len;

    memcpy(out, buf, hash_size);

    out += hash_size;
    len -= hash_size;
    i += 1;
  }

  torsion_cleanse(buf, sizeof(buf));
  torsion_cleanse(&hash, sizeof(hash));

  return 1;
}

/*
 * Scrypt
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/Scrypt
 *   http://www.tarsnap.com/scrypt.html
 *   http://www.tarsnap.com/scrypt/scrypt.pdf
 *   https://github.com/Tarsnap/scrypt/blob/master/lib/crypto/crypto_scrypt-ref.c
 */

static void blkcpy(uint8_t *, const uint8_t *, size_t);
static void blkxor(uint8_t *, const uint8_t *, size_t);
static void salsa20_8(uint8_t *);
static void blockmix_salsa8(uint8_t *, uint8_t *, size_t);
static uint64_t integerify(const uint8_t *, size_t);
static void smix(uint8_t *, size_t, uint64_t, uint8_t *, uint8_t *);

int
scrypt_derive(unsigned char *out,
              const unsigned char *pass,
              size_t pass_len,
              const unsigned char *salt,
              size_t salt_len,
              uint64_t N,
              uint32_t r,
              uint32_t p,
              size_t len) {
  uint64_t len64 = len;
  int t = HASH_SHA256;
  uint8_t *B = NULL;
  uint8_t *V = NULL;
  uint8_t *XY = NULL;
  size_t R = r;
  size_t P = p;
  int ret = 0;
  size_t i;

  if (N == 0 || R == 0 || P == 0)
    return 0;

  if (len64 > ((UINT64_C(1) << 32) - 1) * 32)
    return 0;

  if ((uint64_t)R * (uint64_t)P >= (UINT64_C(1) << 30))
    return 0;

  if (R > SIZE_MAX / 128 / P)
    return 0;

  if (R > SIZE_MAX / 256)
    return 0;

  if (N > SIZE_MAX / 128 / R)
    return 0;

  if ((N & (N - 1)) != 0)
    return 0;

  if (len == 0)
    return 1;

  B = malloc(128 * R * P);
  XY = malloc(256 * R);
  V = malloc(128 * R * N);

  if (B == NULL || XY == NULL || V == NULL)
    goto fail;

  if (!pbkdf2_derive(B, t, pass, pass_len, salt, salt_len, 1, P * 128 * R))
    goto fail;

  for (i = 0; i < P; i++)
    smix(&B[i * 128 * R], R, N, V, XY);

  if (!pbkdf2_derive(out, t, pass, pass_len, B, P * 128 * R, 1, len))
    goto fail;

  ret = 1;
fail:
  if (B != NULL) {
    torsion_cleanse(B, 128 * R * P);
    free(B);
  }

  if (XY != NULL) {
    torsion_cleanse(XY, 256 * R);
    free(XY);
  }

  if (V != NULL) {
    torsion_cleanse(V, 128 * R * N);
    free(V);
  }

  return ret;
}

static void
blkcpy(uint8_t *dst, const uint8_t *src, size_t len) {
  size_t i;

  for (i = 0; i < len; i++)
    dst[i] = src[i];
}

static void
blkxor(uint8_t *dst, const uint8_t *src, size_t len) {
  size_t i;

  for (i = 0; i < len; i++)
    dst[i] ^= src[i];
}

static void
salsa20_8(uint8_t *B) {
  uint32_t B32[16];
  uint32_t x[16];
  int i;

  /* Convert little-endian values in. */
  for (i = 0; i < 16; i++)
    B32[i] = read32le(&B[i * 4]);

  /* Compute x = doubleround^4(B32). */
  for (i = 0; i < 16; i++)
    x[i] = B32[i];

  for (i = 0; i < 8; i += 2) {
#define R(a, b) (((a) << (b)) | ((a) >> (32 - (b))))
    /* Operate on columns. */
    x[ 4] ^= R(x[ 0] + x[12],  7);
    x[ 8] ^= R(x[ 4] + x[ 0],  9);
    x[12] ^= R(x[ 8] + x[ 4], 13);
    x[ 0] ^= R(x[12] + x[ 8], 18);

    x[ 9] ^= R(x[ 5] + x[ 1],  7);
    x[13] ^= R(x[ 9] + x[ 5],  9);
    x[ 1] ^= R(x[13] + x[ 9], 13);
    x[ 5] ^= R(x[ 1] + x[13], 18);

    x[14] ^= R(x[10] + x[ 6],  7);
    x[ 2] ^= R(x[14] + x[10],  9);
    x[ 6] ^= R(x[ 2] + x[14], 13);
    x[10] ^= R(x[ 6] + x[ 2], 18);

    x[ 3] ^= R(x[15] + x[11],  7);
    x[ 7] ^= R(x[ 3] + x[15],  9);
    x[11] ^= R(x[ 7] + x[ 3], 13);
    x[15] ^= R(x[11] + x[ 7], 18);

    /* Operate on rows. */
    x[ 1] ^= R(x[ 0] + x[ 3],  7);
    x[ 2] ^= R(x[ 1] + x[ 0],  9);
    x[ 3] ^= R(x[ 2] + x[ 1], 13);
    x[ 0] ^= R(x[ 3] + x[ 2], 18);

    x[ 6] ^= R(x[ 5] + x[ 4],  7);
    x[ 7] ^= R(x[ 6] + x[ 5],  9);
    x[ 4] ^= R(x[ 7] + x[ 6], 13);
    x[ 5] ^= R(x[ 4] + x[ 7], 18);

    x[11] ^= R(x[10] + x[ 9],  7);
    x[ 8] ^= R(x[11] + x[10],  9);
    x[ 9] ^= R(x[ 8] + x[11], 13);
    x[10] ^= R(x[ 9] + x[ 8], 18);

    x[12] ^= R(x[15] + x[14],  7);
    x[13] ^= R(x[12] + x[15],  9);
    x[14] ^= R(x[13] + x[12], 13);
    x[15] ^= R(x[14] + x[13], 18);
#undef R
  }

  /* Compute B32 = B32 + x. */
  for (i = 0; i < 16; i++)
    B32[i] += x[i];

  /* Convert little-endian values out. */
  for (i = 0; i < 16; i++)
    write32le(&B[4 * i], B32[i]);
}

static void
blockmix_salsa8(uint8_t *B, uint8_t *Y, size_t r) {
  uint8_t X[64];
  size_t i;

  /* 1: X <-- B_{2r - 1} */
  blkcpy(X, &B[(2 * r - 1) * 64], 64);

  /* 2: for i = 0 to 2r - 1 do */
  for (i = 0; i < 2 * r; i++) {
    /* 3: X <-- H(X \xor B_i) */
    blkxor(X, &B[i * 64], 64);
    salsa20_8(X);

    /* 4: Y_i <-- X */
    blkcpy(&Y[i * 64], X, 64);
  }

  /* 6: B' <-- (Y_0, Y_2 ... Y_{2r-2}, Y_1, Y_3 ... Y_{2r-1}) */
  for (i = 0; i < r; i++)
    blkcpy(&B[i * 64], &Y[(i * 2) * 64], 64);

  for (i = 0; i < r; i++)
    blkcpy(&B[(i + r) * 64], &Y[(i * 2 + 1) * 64], 64);
}

static uint64_t
integerify(const uint8_t *B, size_t r) {
  const uint8_t *X = &B[(2 * r - 1) * 64];

  return read64le(X);
}

static void
smix(uint8_t *B, size_t r, uint64_t N, uint8_t *V, uint8_t *XY) {
  uint8_t *X = XY;
  uint8_t *Y = &XY[128 * r];
  uint64_t i;
  uint64_t j;

  /* 1: X <-- B */
  blkcpy(X, B, 128 * r);

  /* 2: for i = 0 to N - 1 do */
  for (i = 0; i < N; i++) {
    /* 3: V_i <-- X */
    blkcpy(&V[i * (128 * r)], X, 128 * r);

    /* 4: X <-- H(X) */
    blockmix_salsa8(X, Y, r);
  }

  /* 6: for i = 0 to N - 1 do */
  for (i = 0; i < N; i++) {
    /* 7: j <-- Integerify(X) mod N */
    j = integerify(X, r) & (N - 1);

    /* 8: X <-- H(X \xor V_j) */
    blkxor(X, &V[j * (128 * r)], 128 * r);
    blockmix_salsa8(X, Y, r);
  }

  /* 10: B' <-- X */
  blkcpy(B, X, 128 * r);
}
