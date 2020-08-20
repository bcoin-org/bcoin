#ifndef _TORSION_HASH_H
#define _TORSION_HASH_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

/*
 * Symbol Aliases
 */

#define md2_init torsion_md2_init
#define md2_update torsion_md2_update
#define md2_final torsion_md2_final
#define md4_init torsion_md4_init
#define md4_update torsion_md4_update
#define md4_final torsion_md4_final
#define md5_init torsion_md5_init
#define md5_update torsion_md5_update
#define md5_final torsion_md5_final
#define md5sha1_init torsion_md5sha1_init
#define md5sha1_update torsion_md5sha1_update
#define md5sha1_final torsion_md5sha1_final
#define ripemd160_init torsion_ripemd160_init
#define ripemd160_update torsion_ripemd160_update
#define ripemd160_final torsion_ripemd160_final
#define sha1_init torsion_sha1_init
#define sha1_update torsion_sha1_update
#define sha1_final torsion_sha1_final
#define sha224_init torsion_sha224_init
#define sha224_update torsion_sha224_update
#define sha224_final torsion_sha224_final
#define sha256_init torsion_sha256_init
#define sha256_update torsion_sha256_update
#define sha256_final torsion_sha256_final
#define sha384_init torsion_sha384_init
#define sha384_update torsion_sha384_update
#define sha384_final torsion_sha384_final
#define sha512_init torsion_sha512_init
#define sha512_update torsion_sha512_update
#define sha512_final torsion_sha512_final
#define hash160_init torsion_hash160_init
#define hash160_update torsion_hash160_update
#define hash160_final torsion_hash160_final
#define hash256_init torsion_hash256_init
#define hash256_update torsion_hash256_update
#define hash256_final torsion_hash256_final
#define keccak_init torsion_keccak_init
#define keccak_update torsion_keccak_update
#define keccak_final torsion_keccak_final
#define keccak224_init torsion_keccak224_init
#define keccak224_update torsion_keccak224_update
#define keccak224_final torsion_keccak224_final
#define keccak256_init torsion_keccak256_init
#define keccak256_update torsion_keccak256_update
#define keccak256_final torsion_keccak256_final
#define keccak384_init torsion_keccak384_init
#define keccak384_update torsion_keccak384_update
#define keccak384_final torsion_keccak384_final
#define keccak512_init torsion_keccak512_init
#define keccak512_update torsion_keccak512_update
#define keccak512_final torsion_keccak512_final
#define sha3_224_init torsion_sha3_224_init
#define sha3_224_update torsion_sha3_224_update
#define sha3_224_final torsion_sha3_224_final
#define sha3_256_init torsion_sha3_256_init
#define sha3_256_update torsion_sha3_256_update
#define sha3_256_final torsion_sha3_256_final
#define sha3_384_init torsion_sha3_384_init
#define sha3_384_update torsion_sha3_384_update
#define sha3_384_final torsion_sha3_384_final
#define sha3_512_init torsion_sha3_512_init
#define sha3_512_update torsion_sha3_512_update
#define sha3_512_final torsion_sha3_512_final
#define shake_init torsion_shake_init
#define shake_update torsion_shake_update
#define shake_final torsion_shake_final
#define shake128_init torsion_shake128_init
#define shake128_update torsion_shake128_update
#define shake128_final torsion_shake128_final
#define shake256_init torsion_shake256_init
#define shake256_update torsion_shake256_update
#define shake256_final torsion_shake256_final
#define blake2s_init torsion_blake2s_init
#define blake2s_update torsion_blake2s_update
#define blake2s_final torsion_blake2s_final
#define blake2s128_init torsion_blake2s128_init
#define blake2s128_update torsion_blake2s128_update
#define blake2s128_final torsion_blake2s128_final
#define blake2s160_init torsion_blake2s160_init
#define blake2s160_update torsion_blake2s160_update
#define blake2s160_final torsion_blake2s160_final
#define blake2s224_init torsion_blake2s224_init
#define blake2s224_update torsion_blake2s224_update
#define blake2s224_final torsion_blake2s224_final
#define blake2s256_init torsion_blake2s256_init
#define blake2s256_update torsion_blake2s256_update
#define blake2s256_final torsion_blake2s256_final
#define blake2b_init torsion_blake2b_init
#define blake2b_update torsion_blake2b_update
#define blake2b_final torsion_blake2b_final
#define blake2b160_init torsion_blake2b160_init
#define blake2b160_update torsion_blake2b160_update
#define blake2b160_final torsion_blake2b160_final
#define blake2b256_init torsion_blake2b256_init
#define blake2b256_update torsion_blake2b256_update
#define blake2b256_final torsion_blake2b256_final
#define blake2b384_init torsion_blake2b384_init
#define blake2b384_update torsion_blake2b384_update
#define blake2b384_final torsion_blake2b384_final
#define blake2b512_init torsion_blake2b512_init
#define blake2b512_update torsion_blake2b512_update
#define blake2b512_final torsion_blake2b512_final
#define gost94_init torsion_gost94_init
#define gost94_update torsion_gost94_update
#define gost94_final torsion_gost94_final
#define whirlpool_init torsion_whirlpool_init
#define whirlpool_update torsion_whirlpool_update
#define whirlpool_final torsion_whirlpool_final
#define hash_init torsion_hash_init
#define hash_update torsion_hash_update
#define hash_final torsion_hash_final
#define hash_output_size torsion_hash_output_size
#define hash_block_size torsion_hash_block_size
#define hmac_init torsion_hmac_init
#define hmac_update torsion_hmac_update
#define hmac_final torsion_hmac_final

/*
 * Defs
 */

#define HASH_MAX_OUTPUT_SIZE 64
#define HASH_MAX_BLOCK_SIZE 168

#define HASH_BLAKE2B_160 0
#define HASH_BLAKE2B_256 1
#define HASH_BLAKE2B_384 2
#define HASH_BLAKE2B_512 3
#define HASH_BLAKE2S_128 4
#define HASH_BLAKE2S_160 5
#define HASH_BLAKE2S_224 6
#define HASH_BLAKE2S_256 7
#define HASH_GOST94 8
#define HASH_HASH160 9
#define HASH_HASH256 10
#define HASH_KECCAK224 11
#define HASH_KECCAK256 12
#define HASH_KECCAK384 13
#define HASH_KECCAK512 14
#define HASH_MD2 15
#define HASH_MD4 16
#define HASH_MD5 17
#define HASH_MD5SHA1 18
#define HASH_RIPEMD160 19
#define HASH_SHA1 20
#define HASH_SHA224 21
#define HASH_SHA256 22
#define HASH_SHA384 23
#define HASH_SHA512 24
#define HASH_SHA3_224 25
#define HASH_SHA3_256 26
#define HASH_SHA3_384 27
#define HASH_SHA3_512 28
#define HASH_SHAKE128 29
#define HASH_SHAKE256 30
#define HASH_WHIRLPOOL 31
#define HASH_MAX 31

#define HASH_BLAKE2B HASH_BLAKE2B_256
#define HASH_BLAKE2S HASH_BLAKE2S_256
#define HASH_KECCAK HASH_KECCAK256
#define HASH_SHA3 HASH_SHA3_256
#define HASH_SHAKE HASH_SHAKE256

/*
 * Structs
 */

typedef struct _md2_s {
  unsigned char state[48];
  unsigned char checksum[16];
  unsigned char block[16];
  size_t size;
} md2_t;

typedef struct _md5_s {
  uint32_t state[4];
  uint8_t block[64];
  uint64_t size;
} md5_t;

typedef md5_t md4_t;

typedef struct _ripemd160_s {
  uint32_t state[5];
  uint8_t block[64];
  uint64_t size;
} ripemd160_t;

typedef struct _sha1_s {
  uint32_t state[5];
  uint8_t block[64];
  uint64_t size;
} sha1_t;

typedef struct _md5sha1_s {
  md5_t md5;
  sha1_t sha1;
} md5sha1_t;

typedef struct _sha256_s {
  uint32_t state[8];
  uint32_t _pad1, _pad2;
  uint8_t block[64];
  uint64_t size;
  uint32_t _pad3;
} sha256_t;

typedef sha256_t sha224_t;

typedef struct _sha512_s {
  uint64_t state[8];
  uint64_t _pad1, _pad2;
  uint8_t block[128];
  uint64_t size;
  uint64_t _pad3;
} sha512_t;

typedef sha512_t sha384_t;
typedef sha256_t hash160_t;
typedef sha256_t hash256_t;

typedef struct _keccak_s {
  size_t bs;
  uint64_t state[25];
  uint8_t block[168];
  size_t pos;
} keccak_t;

typedef struct _blake2s_s {
  uint32_t h[8];
  uint32_t t[2];
  uint32_t f[2];
  uint8_t buf[64];
  size_t buflen;
  size_t outlen;
} blake2s_t;

typedef struct _blake2b_s {
  uint64_t h[8];
  uint64_t t[2];
  uint64_t f[2];
  uint8_t buf[128];
  size_t buflen;
  size_t outlen;
} blake2b_t;

typedef struct _gost94_s {
  uint8_t state[32];
  uint8_t sigma[32];
  uint8_t block[32];
  uint64_t size;
} gost94_t;

typedef struct _whirlpool_s {
  uint64_t state[8];
  uint8_t block[64];
  uint64_t size;
} whirlpool_t;

typedef struct _hash_s {
  int type;
  union {
    md2_t md2;
    md5_t md5;
    md5sha1_t md5sha1;
    ripemd160_t ripemd160;
    sha1_t sha1;
    sha256_t sha256;
    sha512_t sha512;
    keccak_t keccak;
    blake2s_t blake2s;
    blake2b_t blake2b;
    gost94_t gost94;
    whirlpool_t whirlpool;
  } ctx;
} hash_t;

typedef struct _hmac_s {
  int type;
  hash_t inner;
  hash_t outer;
} hmac_t;

/*
 * MD2
 */

void
md2_init(md2_t *ctx);

void
md2_update(md2_t *ctx, const void *data, size_t len);

void
md2_final(md2_t *ctx, unsigned char *out);

/*
 * MD4
 */

void
md4_init(md4_t *ctx);

void
md4_update(md4_t *ctx, const void *data, size_t len);

void
md4_final(md4_t *ctx, unsigned char *out);

/*
 * MD5
 */

void
md5_init(md5_t *ctx);

void
md5_update(md5_t *ctx, const void *data, size_t len);

void
md5_final(md5_t *ctx, unsigned char *out);

/*
 * MD5SHA1
 */

void
md5sha1_init(md5sha1_t *ctx);

void
md5sha1_update(md5sha1_t *ctx, const void *data, size_t len);

void
md5sha1_final(md5sha1_t *ctx, unsigned char *out);

/*
 * RIPEMD160
 */

void
ripemd160_init(ripemd160_t *ctx);

void
ripemd160_update(ripemd160_t *ctx, const void *data, size_t len);

void
ripemd160_final(ripemd160_t *ctx, unsigned char *out);

/*
 * SHA1
 */

void
sha1_init(sha1_t *ctx);

void
sha1_update(sha1_t *ctx, const void *data, size_t len);

void
sha1_final(sha1_t *ctx, unsigned char *out);

/*
 * SHA224
 */

void
sha224_init(sha224_t *ctx);

void
sha224_update(sha224_t *ctx, const void *data, size_t len);

void
sha224_final(sha224_t *ctx, unsigned char *out);

/*
 * SHA256
 */

void
sha256_init(sha256_t *ctx);

void
sha256_update(sha256_t *ctx, const void *data, size_t len);

void
sha256_final(sha256_t *ctx, unsigned char *out);

/*
 * SHA384
 */

void
sha384_init(sha384_t *ctx);

void
sha384_update(sha384_t *ctx, const void *data, size_t len);

void
sha384_final(sha384_t *ctx, unsigned char *out);

/*
 * SHA512
 */

void
sha512_init(sha512_t *ctx);

void
sha512_update(sha512_t *ctx, const void *data, size_t len);

void
sha512_final(sha512_t *ctx, unsigned char *out);

/*
 * Hash160
 */

void
hash160_init(hash160_t *ctx);

void
hash160_update(hash160_t *ctx, const void *data, size_t len);

void
hash160_final(hash160_t *ctx, unsigned char *out);

/*
 * Hash256
 */

void
hash256_init(hash256_t *ctx);

void
hash256_update(hash256_t *ctx, const void *data, size_t len);

void
hash256_final(hash256_t *ctx, unsigned char *out);

/*
 * Keccak
 */

void
keccak_init(keccak_t *ctx, size_t bits);

void
keccak_update(keccak_t *ctx, const void *data, size_t len);

void
keccak_final(keccak_t *ctx, unsigned char *out, unsigned char pad, size_t len);

/*
 * BLAKE2s
 */

void
blake2s_init(blake2s_t *ctx,
             size_t outlen,
             const unsigned char *key,
             size_t keylen);

void
blake2s_update(blake2s_t *ctx, const void *data, size_t len);

void
blake2s_final(blake2s_t *ctx, unsigned char *out);

/*
 * BLAKE2b
 */

void
blake2b_init(blake2b_t *ctx,
             size_t outlen,
             const unsigned char *key,
             size_t keylen);

void
blake2b_update(blake2b_t *ctx, const void *data, size_t len);

void
blake2b_final(blake2b_t *ctx, unsigned char *out);

/*
 * GOST94
 */

void
gost94_init(gost94_t *ctx);

void
gost94_update(gost94_t *ctx, const void *data, size_t len);

void
gost94_final(gost94_t *ctx, unsigned char *out);

/*
 * Whirlpool
 */

void
whirlpool_init(whirlpool_t *ctx);

void
whirlpool_update(whirlpool_t *ctx, const void *data, size_t len);

void
whirlpool_final(whirlpool_t *ctx, unsigned char *out);

/*
 * Hash
 */

void
hash_init(hash_t *hash, int type);

void
hash_update(hash_t *hash, const void *data, size_t len);

void
hash_final(hash_t *hash, unsigned char *out, size_t len);

int
hash_has_backend(int type);

size_t
hash_output_size(int type);

size_t
hash_block_size(int type);

/*
 * HMAC
 */

void
hmac_init(hmac_t *hmac, int type, const unsigned char *key, size_t len);

void
hmac_update(hmac_t *hmac, const void *data, size_t len);

void
hmac_final(hmac_t *hmac, unsigned char *out);

#ifdef __cplusplus
}
#endif

#endif /* _TORSION_HASH_H */
