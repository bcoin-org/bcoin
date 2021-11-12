/*!
 * encoding.h - string encodings for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 */

#ifndef TORSION_ENCODING_H
#define TORSION_ENCODING_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "common.h"

/*
 * Symbol Aliases
 */

#define base16_encode_size torsion_base16_encode_size
#define base16_encode torsion_base16_encode
#define base16_decode_size torsion_base16_decode_size
#define base16_decode torsion_base16_decode
#define base16_test torsion_base16_test
#define base16le_encode_size torsion_base16le_encode_size
#define base16le_encode torsion_base16le_encode
#define base16le_decode_size torsion_base16le_decode_size
#define base16le_decode torsion_base16le_decode
#define base16le_test torsion_base16le_test
#define base32_encode_size torsion_base32_encode_size
#define base32_encode torsion_base32_encode
#define base32_decode_size torsion_base32_decode_size
#define base32_decode torsion_base32_decode
#define base32_test torsion_base32_test
#define base32hex_encode_size torsion_base32hex_encode_size
#define base32hex_encode torsion_base32hex_encode
#define base32hex_decode_size torsion_base32hex_decode_size
#define base32hex_decode torsion_base32hex_decode
#define base32hex_test torsion_base32hex_test
#define base58_encode torsion_base58_encode
#define base58_decode torsion_base58_decode
#define base58_test torsion_base58_test
#define base64_encode_size torsion_base64_encode_size
#define base64_encode torsion_base64_encode
#define base64_decode_size torsion_base64_decode_size
#define base64_decode torsion_base64_decode
#define base64_test torsion_base64_test
#define base64url_encode_size torsion_base64url_encode_size
#define base64url_encode torsion_base64url_encode
#define base64url_decode_size torsion_base64url_decode_size
#define base64url_decode torsion_base64url_decode
#define base64url_test torsion_base64url_test
#define bech32_serialize torsion_bech32_serialize
#define bech32_deserialize torsion_bech32_deserialize
#define bech32_is torsion_bech32_is
#define bech32_convert_bits torsion_bech32_convert_bits
#define bech32_encode torsion_bech32_encode
#define bech32_decode torsion_bech32_decode
#define bech32_test torsion_bech32_test
#define cash32_serialize torsion_cash32_serialize
#define cash32_deserialize torsion_cash32_deserialize
#define cash32_is torsion_cash32_is
#define cash32_convert_bits torsion_cash32_convert_bits
#define cash32_encode torsion_cash32_encode
#define cash32_decode torsion_cash32_decode
#define cash32_test torsion_cash32_test

/*
 * Base16
 */

#define BASE16_ENCODE_SIZE(n) ((n) * 2)
#define BASE16_DECODE_SIZE(n) ((n) / 2)

TORSION_EXTERN size_t
base16_encode_size(size_t len);

TORSION_EXTERN void
base16_encode(char *dst, size_t *dstlen,
              const uint8_t *src, size_t srclen);

TORSION_EXTERN size_t
base16_decode_size(size_t len);

TORSION_EXTERN int
base16_decode(uint8_t *dst, size_t *dstlen,
              const char *src, size_t srclen);

TORSION_EXTERN int
base16_test(const char *str, size_t len);

/*
 * Base16 (Little Endian)
 */

#define BASE16LE_ENCODE_SIZE(n) BASE16_ENCODE_SIZE(n)
#define BASE16LE_DECODE_SIZE(n) BASE16_DECODE_SIZE(n)

TORSION_EXTERN size_t
base16le_encode_size(size_t len);

TORSION_EXTERN void
base16le_encode(char *dst, size_t *dstlen,
                const uint8_t *src, size_t srclen);

TORSION_EXTERN size_t
base16le_decode_size(size_t len);

TORSION_EXTERN int
base16le_decode(uint8_t *dst, size_t *dstlen,
                const char *src, size_t srclen);

TORSION_EXTERN int
base16le_test(const char *str, size_t len);

/*
 * Base32
 */

#define BASE32_ENCODE_SIZE(n) (((n) / 5) * 8 + 13)
#define BASE32_DECODE_SIZE(n) (((n) / 8) * 5 + 4)

TORSION_EXTERN size_t
base32_encode_size(size_t len, int pad);

TORSION_EXTERN void
base32_encode(char *dst, size_t *dstlen,
              const uint8_t *src, size_t srclen, int pad);

TORSION_EXTERN size_t
base32_decode_size(const char *str, size_t len);

TORSION_EXTERN int
base32_decode(uint8_t *dst, size_t *dstlen,
              const char *src, size_t srclen, int unpad);

TORSION_EXTERN int
base32_test(const char *src, size_t srclen, int unpad);

/*
 * Base32-Hex
 */

#define BASE32HEX_ENCODE_SIZE(n) BASE32_ENCODE_SIZE(n)
#define BASE32HEX_DECODE_SIZE(n) BASE32_DECODE_SIZE(n)

TORSION_EXTERN size_t
base32hex_encode_size(size_t len, int pad);

TORSION_EXTERN void
base32hex_encode(char *dst, size_t *dstlen,
                 const uint8_t *src, size_t srclen, int pad);

TORSION_EXTERN size_t
base32hex_decode_size(const char *str, size_t len);

TORSION_EXTERN int
base32hex_decode(uint8_t *dst, size_t *dstlen,
                 const char *src, size_t srclen, int unpad);

TORSION_EXTERN int
base32hex_test(const char *src, size_t srclen, int unpad);

/*
 * Base58
 */

#define BASE58_ENCODE_SIZE(n) ((n) * 2)
#define BASE58_DECODE_SIZE(n) (n)

TORSION_EXTERN int
base58_encode(char *dst, size_t *dstlen,
              const uint8_t *src, size_t srclen);

TORSION_EXTERN int
base58_decode(uint8_t *dst, size_t *dstlen,
              const char *src, size_t srclen);

TORSION_EXTERN int
base58_test(const char *str, size_t len);

/*
 * Base64
 */

#define BASE64_ENCODE_SIZE(n) (((n) / 3) * 4 + 4)
#define BASE64_DECODE_SIZE(n) ((((n) / 4) * 3) + 2)

TORSION_EXTERN size_t
base64_encode_size(size_t len);

TORSION_EXTERN void
base64_encode(char *dst, size_t *dstlen,
              const uint8_t *src, size_t srclen);

TORSION_EXTERN size_t
base64_decode_size(const char *str, size_t len);

TORSION_EXTERN int
base64_decode(uint8_t *dst, size_t *dstlen,
              const char *src, size_t srclen);

TORSION_EXTERN int
base64_test(const char *str, size_t len);

/*
 * Base64-URL
 */

#define BASE64URL_ENCODE_SIZE(n) BASE64_ENCODE_SIZE(n)
#define BASE64URL_DECODE_SIZE(n) BASE64_DECODE_SIZE(n)

TORSION_EXTERN size_t
base64url_encode_size(size_t len);

TORSION_EXTERN void
base64url_encode(char *dst, size_t *dstlen,
                 const uint8_t *src, size_t srclen);

TORSION_EXTERN size_t
base64url_decode_size(const char *str, size_t len);

TORSION_EXTERN int
base64url_decode(uint8_t *dst, size_t *dstlen,
                 const char *src, size_t srclen);

TORSION_EXTERN int
base64url_test(const char *str, size_t len);

/*
 * Bech32
 */

#define BECH32_MAX_HRP_SIZE 83
#define BECH32_MAX_SERIALIZE_SIZE 90
#define BECH32_MAX_DESERIALIZE_SIZE 83

#define BECH32_CONVERT_SIZE(srclen, srcbits, dstbits, pad) \
  (((srclen) * (srcbits) + ((dstbits) - 1) * (pad)) / (dstbits))

#define BECH32_MAX_VERSION 31
#define BECH32_MIN_HASH_SIZE 2
#define BECH32_MAX_HASH_SIZE 40

#define BECH32_MAX_DATA_SIZE \
  (1 + BECH32_CONVERT_SIZE(BECH32_MAX_HASH_SIZE, 8, 5, 1)) /* 65 */

#define BECH32_MAX_ENCODE_SIZE BECH32_MAX_SERIALIZE_SIZE
#define BECH32_MAX_DECODE_SIZE BECH32_MAX_HASH_SIZE

TORSION_EXTERN int
bech32_serialize(char *str,
                 const char *hrp,
                 const uint8_t *data,
                 size_t data_len,
                 uint32_t checksum);

TORSION_EXTERN int
bech32_deserialize(char *hrp,
                   uint8_t *data,
                   size_t *data_len,
                   const char *str,
                   uint32_t checksum);

TORSION_EXTERN int
bech32_is(const char *str, uint32_t checksum);

TORSION_EXTERN int
bech32_convert_bits(uint8_t *dst,
                    size_t *dstlen,
                    size_t dstbits,
                    const uint8_t *src,
                    size_t srclen,
                    size_t srcbits,
                    int pad);

TORSION_EXTERN int
bech32_encode(char *addr,
              const char *hrp,
              unsigned int version,
              const uint8_t *hash,
              size_t hash_len,
              uint32_t checksum);

TORSION_EXTERN int
bech32_decode(char *hrp,
              unsigned int *version,
              uint8_t *hash,
              size_t *hash_len,
              const char *addr,
              uint32_t checksum);

TORSION_EXTERN int
bech32_test(const char *addr, uint32_t checksum);

/*
 * Cash32
 */

#define CASH32_MAX_PREFIX_SIZE 83
#define CASH32_MAX_SERIALIZE_SIZE 196 /* 83 + 1 + 112 */
#define CASH32_MAX_DESERIALIZE_SIZE 188

#define CASH32_CONVERT_SIZE(srclen, srcbits, dstbits, pad) \
  (((srclen) * (srcbits) + ((dstbits) - 1) * (pad)) / (dstbits))

#define CASH32_MAX_TYPE 15
#define CASH32_MIN_HASH_SIZE 20
#define CASH32_MAX_HASH_SIZE 64

#define CASH32_MAX_DATA_SIZE \
  CASH32_CONVERT_SIZE(1 + CASH32_MAX_HASH_SIZE, 8, 5, 1) /* 104 */

#define CASH32_MAX_ENCODE_SIZE CASH32_MAX_SERIALIZE_SIZE
#define CASH32_MAX_DECODE_SIZE CASH32_MAX_HASH_SIZE

TORSION_EXTERN int
cash32_serialize(char *str,
                 const char *prefix,
                 const uint8_t *data,
                 size_t data_len);

TORSION_EXTERN int
cash32_deserialize(char *prefix,
                   uint8_t *data,
                   size_t *data_len,
                   const char *str,
                   const char *fallback);

TORSION_EXTERN int
cash32_is(const char *str, const char *fallback);

TORSION_EXTERN int
cash32_convert_bits(uint8_t *dst,
                    size_t *dstlen,
                    size_t dstbits,
                    const uint8_t *src,
                    size_t srclen,
                    size_t srcbits,
                    int pad);

TORSION_EXTERN int
cash32_encode(char *addr,
              const char *prefix,
              unsigned int type,
              const uint8_t *hash,
              size_t hash_len);

TORSION_EXTERN int
cash32_decode(unsigned int *type,
              uint8_t *hash,
              size_t *hash_len,
              const char *addr,
              const char *expect);

TORSION_EXTERN int
cash32_test(const char *addr, const char *expect);

#ifdef __cplusplus
}
#endif

#endif /* TORSION_ENCODING_H */
