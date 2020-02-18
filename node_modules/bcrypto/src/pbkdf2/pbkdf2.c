#include <string.h>
#include "pbkdf2.h"
#include "openssl/evp.h"
#include "openssl/objects.h"

static int
bcrypto_pbkdf2_hash_type(const char *alg) {
  if (alg == NULL)
    return -1;

  int type = -1;

  if (0)
    type = -1;

#ifdef NID_blake2b160
  else if (strcmp(alg, "BLAKE2B160") == 0)
    type = NID_blake2b160;
#endif

#ifdef NID_blake2b256
  else if (strcmp(alg, "BLAKE2B256") == 0)
    type = NID_blake2b256;
#endif

#ifdef NID_blake2b384
  else if (strcmp(alg, "BLAKE2B384") == 0)
    type = NID_blake2b384;
#endif

#ifdef NID_blake2b512
  else if (strcmp(alg, "BLAKE2B512") == 0)
    type = NID_blake2b512;
#endif

#ifdef NID_blake2s128
  else if (strcmp(alg, "BLAKE2S128") == 0)
    type = NID_blake2s128;
#endif

#ifdef NID_blake2s160
  else if (strcmp(alg, "BLAKE2S160") == 0)
    type = NID_blake2s160;
#endif

#ifdef NID_blake2s224
  else if (strcmp(alg, "BLAKE2S224") == 0)
    type = NID_blake2s224;
#endif

#ifdef NID_blake2s256
  else if (strcmp(alg, "BLAKE2S256") == 0)
    type = NID_blake2s256;
#endif

#ifdef NID_md2
  else if (strcmp(alg, "MD2") == 0)
    type = NID_md2;
#endif

  else if (strcmp(alg, "MD4") == 0)
    type = NID_md4;
  else if (strcmp(alg, "MD5") == 0)
    type = NID_md5;

#ifdef NID_md5_sha1
  else if (strcmp(alg, "MD5SHA1") == 0)
    type = NID_md5_sha1;
#endif

  else if (strcmp(alg, "RIPEMD160") == 0)
    type = NID_ripemd160;
  else if (strcmp(alg, "SHA1") == 0)
    type = NID_sha1;
  else if (strcmp(alg, "SHA224") == 0)
    type = NID_sha224;
  else if (strcmp(alg, "SHA256") == 0)
    type = NID_sha256;
  else if (strcmp(alg, "SHA384") == 0)
    type = NID_sha384;
  else if (strcmp(alg, "SHA512") == 0)
    type = NID_sha512;

#ifdef NID_sha3_224
  else if (strcmp(alg, "SHA3_224") == 0)
    type = NID_sha3_224;
#endif

#ifdef NID_sha3_256
  else if (strcmp(alg, "SHA3_256") == 0)
    type = NID_sha3_256;
#endif

#ifdef NID_sha3_384
  else if (strcmp(alg, "SHA3_384") == 0)
    type = NID_sha3_384;
#endif

#ifdef NID_sha3_512
  else if (strcmp(alg, "SHA3_512") == 0)
    type = NID_sha3_512;
#endif

#ifdef NID_whirlpool
  else if (strcmp(alg, "WHIRLPOOL") == 0)
    type = NID_whirlpool;
#endif

  return type;
}

bool
bcrypto_pbkdf2(
  const char *name,
  const uint8_t *data,
  size_t datalen,
  const uint8_t *salt,
  size_t saltlen,
  uint32_t iter,
  uint8_t *key,
  size_t keylen
) {
  int type = bcrypto_pbkdf2_hash_type(name);

  if (type == -1)
    return false;

  const EVP_MD *md = EVP_get_digestbynid(type);

  if (md == NULL)
    return false;

  int ret = PKCS5_PBKDF2_HMAC((const char *)data,
                              datalen, salt,
                              saltlen, iter,
                              md, keylen, key);

  if (ret <= 0)
    return false;

  return true;
}

bool
bcrypto_pbkdf2_has_hash(const char *name) {
  int type = bcrypto_pbkdf2_hash_type(name);

  if (type == -1)
    return false;

  return EVP_get_digestbynid(type) != NULL;
}
