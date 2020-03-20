/**
 * bcrypto.cc - fast native bindings to crypto functions
 * Copyright (c) 2016-2020, Christopher Jeffrey (MIT License)
 * https://github.com/bcoin-org/bcrypto
 */

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <node_api.h>

#include <torsion/aead.h>
#include <torsion/chacha20.h>
#include <torsion/drbg.h>
#include <torsion/dsa.h>
#include <torsion/ecc.h>
#include <torsion/hash.h>
#include <torsion/kdf.h>
#include <torsion/poly1305.h>
#include <torsion/rsa.h>
#include <torsion/salsa20.h>
#include <torsion/siphash.h>
#include <torsion/util.h>

#include "base58/base58.h"
#include "bech32/bech32.h"
#include "cash32/cash32.h"
#include "murmur3/murmur3.h"

#ifdef BCRYPTO_USE_SECP256K1
#include "secp256k1/include/secp256k1.h"
#include "secp256k1/include/secp256k1_ecdh.h"
#include "secp256k1/include/secp256k1_elligator.h"
#include "secp256k1/include/secp256k1_extra.h"
#include "secp256k1/include/secp256k1_recovery.h"
#include "secp256k1/include/secp256k1_schnorrleg.h"
#ifdef BCRYPTO_USE_SECP256K1_LATEST
#include "secp256k1/include/secp256k1_schnorrsig.h"
#endif
#include "secp256k1/contrib/lax_der_parsing.h"
#endif

#define CHECK(expr) do {                               \
  if (!(expr)) {                                       \
    fprintf(stderr, "%s:%d: Assertion `%s' failed.\n", \
            __FILE__, __LINE__, #expr);                \
    fflush(stderr);                                    \
    abort();                                           \
  }                                                    \
} while (0)

#define ENTROPY_SIZE 32

#define JS_ERR_CONTEXT "Could not create context."
#define JS_ERR_SIGNATURE "Invalid signature."
#define JS_ERR_SIGNATURE_SIZE "Invalid signature size."
#define JS_ERR_PRIVKEY "Invalid private key."
#define JS_ERR_PRIVKEY_SIZE "Invalid private key size."
#define JS_ERR_PUBKEY "Invalid public key."
#define JS_ERR_PUBKEY_SIZE "Invalid public key size."
#define JS_ERR_SCALAR "Invalid scalar."
#define JS_ERR_SCALAR_SIZE "Invalid scalar size."
#define JS_ERR_POINT "Invalid point."
#define JS_ERR_POINT_SIZE "Invalid point size."
#define JS_ERR_SIGN "Could not sign."
#define JS_ERR_KEY "Invalid key."
#define JS_ERR_KEY_SIZE "Invalid key size."
#define JS_ERR_IV "Invalid IV."
#define JS_ERR_IV_SIZE "Invalid IV size."
#define JS_ERR_NONCE "Invalid nonce."
#define JS_ERR_NONCE_SIZE "Invalid nonce size."
#define JS_ERR_TAG "Invalid tag."
#define JS_ERR_TAG_SIZE "Invalid tag size."
#define JS_ERR_ENTROPY "Invalid entropy."
#define JS_ERR_ENTROPY_SIZE "Invalid entropy size."
#define JS_ERR_PREIMAGE "Invalid preimage."
#define JS_ERR_PREIMAGE_SIZE "Invalid preimage size."
#define JS_ERR_RECOVERY_PARAM "Invalid recovery parameter."
#define JS_ERR_NO_SCHNORR "Schnorr is not supported."
#define JS_ERR_RANDOM "Randomization failed."
#define JS_ERR_PREFIX_SIZE "Invalid prefix length."
#define JS_ERR_GENERATE "Could not generate key."
#define JS_ERR_ENCRYPT "Could not encrypt."
#define JS_ERR_DECRYPT "Could not decrypt."
#define JS_ERR_VEIL "Could not veil."
#define JS_ERR_UNVEIL "Could not unveil."
#define JS_ERR_PARAMS "Invalid params."
#define JS_ERR_INIT "Context is not initialized."
#define JS_ERR_STATE "Invalid state."
#define JS_ERR_ENCODE "Encoding failed."
#define JS_ERR_DECODE "Decoding failed."
#define JS_ERR_OUTPUT_SIZE "Invalid output size."
#define JS_ERR_NODE_SIZE "Invalid node sizes."
#define JS_ERR_DERIVE "Derivation failed."
#define JS_ERR_MSG_SIZE "Invalid message size."

#define JS_THROW(msg) do {                              \
  CHECK(napi_throw_error(env, NULL, (msg)) == napi_ok); \
  return NULL;                                          \
} while (0)

#define JS_ASSERT(cond, msg) if (!(cond)) JS_THROW(msg)

/*
 * Structs
 */

typedef struct bcrypto_blake2b_s {
  blake2b_t ctx;
  int started;
} bcrypto_blake2b_t;

typedef struct bcrypto_blake2s_s {
  blake2s_t ctx;
  int started;
} bcrypto_blake2s_t;

typedef struct bcrypto_chacha20_s {
  chacha20_t ctx;
  int started;
} bcrypto_chacha20_t;

typedef struct bcrypto_ecdh_s {
  ecdh_t *ctx;
  size_t scalar_size;
  size_t scalar_bits;
  size_t field_size;
  size_t field_bits;
} bcrypto_ecdh_t;

typedef struct bcrypto_ecdsa_s {
  ecdsa_t *ctx;
  ecdsa_scratch_t *scratch;
  size_t scalar_size;
  size_t scalar_bits;
  size_t field_size;
  size_t field_bits;
  size_t sig_size;
  size_t schnorr_size;
} bcrypto_ecdsa_t;

typedef struct bcrypto_eddsa_s {
  eddsa_t *ctx;
  eddsa_scratch_t *scratch;
  size_t scalar_size;
  size_t scalar_bits;
  size_t field_size;
  size_t field_bits;
  size_t priv_size;
  size_t pub_size;
  size_t sig_size;
} bcrypto_eddsa_t;

typedef struct bcrypto_hash_s {
  hash_t ctx;
  int type;
  int started;
} bcrypto_hash_t;

typedef struct bcrypto_hmac_s {
  hmac_t ctx;
  int type;
  int started;
} bcrypto_hmac_t;

typedef struct bcrypto_keccak_s {
  keccak_t ctx;
  int started;
} bcrypto_keccak_t;

typedef struct bcrypto_poly1305_s {
  poly1305_t ctx;
  int started;
} bcrypto_poly1305_t;

typedef struct bcrypto_salsa20_s {
  salsa20_t ctx;
  int started;
} bcrypto_salsa20_t;

typedef struct bcrypto_schnorr_s {
  schnorr_t *ctx;
  schnorr_scratch_t *scratch;
  size_t scalar_size;
  size_t scalar_bits;
  size_t field_size;
  size_t field_bits;
  size_t sig_size;
} bcrypto_schnorr_t;

#ifdef BCRYPTO_USE_SECP256K1
typedef struct bcrypto_secp256k1_s {
  secp256k1_context *ctx;
  secp256k1_scratch_space *scratch;
} bcrypto_secp256k1_t;
#endif

/*
 * Allocator
 */

static void *
safe_malloc(size_t size) {
  void *ptr;

  if (size == 0)
    return NULL;

  ptr = malloc(size);

  CHECK(ptr != NULL);

  memset(ptr, 0, size);

  return ptr;
}

static void
safe_free(void *ptr) {
  if (ptr != NULL)
    free(ptr);
}

static void *
safe_realloc(void *ptr, size_t size) {
  if (size == 0) {
    safe_free(ptr);
    return NULL;
  }

  ptr = realloc(ptr, size);

  CHECK(ptr != NULL);

  return ptr;
}

/*
 * N-API Extras
 */

static napi_status
read_value_string_utf8(napi_env env, napi_value value,
                       char **str, size_t *length) {
  char *buf;
  size_t buflen;
  napi_status status;

  status = napi_get_value_string_utf8(env, value, NULL, 0, &buflen);

  if (status != napi_ok)
    return status;

  buf = (char *)safe_malloc(buflen + 1);

  status = napi_get_value_string_utf8(env,
                                      value,
                                      buf,
                                      buflen + 1,
                                      length);

  if (status != napi_ok) {
    safe_free(buf);
    return status;
  }

  CHECK(*length == buflen);

  *str = buf;

  return napi_ok;
}

static void
finalize_buffer(napi_env env, void *data, void *hint) {
  safe_free(data);
}

static napi_status
create_external_buffer(napi_env env, size_t length,
                       void *data, napi_value *result) {
  return napi_create_external_buffer(env,
                                     length,
                                     data,
                                     finalize_buffer,
                                     NULL,
                                     result);
}

/*
 * AEAD
 */

static void
bcrypto_aead_destroy_(napi_env env, void *data, void *hint) {
  cleanse(data, sizeof(aead_t));
  safe_free(data);
}

static napi_value
bcrypto_aead_create(napi_env env, napi_callback_info info) {
  aead_t *ctx = (aead_t *)safe_malloc(sizeof(aead_t));
  napi_value handle;

  aead_init(ctx);

  CHECK(napi_create_external(env,
                             ctx,
                             bcrypto_aead_destroy_,
                             NULL,
                             &handle) == napi_ok);

  return handle;
}

static napi_value
bcrypto_aead_init(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  const uint8_t *key, *iv;
  size_t key_len, iv_len;
  aead_t *ctx;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ctx) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&key, &key_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&iv, &iv_len) == napi_ok);

  JS_ASSERT(key_len >= 32, JS_ERR_KEY_SIZE);
  JS_ASSERT(iv_len == 8 || iv_len == 12 || iv_len == 16
         || iv_len == 24 || iv_len == 28 || iv_len == 32, JS_ERR_IV_SIZE);

  aead_init(ctx);
  aead_setup(ctx, key, iv, iv_len);

  return argv[0];
}

static napi_value
bcrypto_aead_aad(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  const uint8_t *aad;
  size_t aad_len;
  aead_t *ctx;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ctx) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&aad, &aad_len) == napi_ok);

  JS_ASSERT(ctx->mode != -1, JS_ERR_INIT);
  JS_ASSERT(ctx->mode == 0, JS_ERR_STATE);

  aead_aad(ctx, aad, aad_len);

  return argv[0];
}

static napi_value
bcrypto_aead_encrypt(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t *msg;
  size_t msg_len;
  aead_t *ctx;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ctx) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&msg, &msg_len) == napi_ok);

  JS_ASSERT(ctx->mode != -1, JS_ERR_INIT);
  JS_ASSERT(ctx->mode == 0 || ctx->mode == 1, JS_ERR_STATE);

  aead_encrypt(ctx, msg, msg, msg_len);

  return argv[1];
}

static napi_value
bcrypto_aead_decrypt(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t *msg;
  size_t msg_len;
  aead_t *ctx;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ctx) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&msg, &msg_len) == napi_ok);

  JS_ASSERT(ctx->mode != -1, JS_ERR_INIT);
  JS_ASSERT(ctx->mode == 0 || ctx->mode == 2, JS_ERR_STATE);

  aead_decrypt(ctx, msg, msg, msg_len);

  return argv[1];
}

static napi_value
bcrypto_aead_auth(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  const uint8_t *msg;
  size_t msg_len;
  aead_t *ctx;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ctx) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&msg, &msg_len) == napi_ok);

  JS_ASSERT(ctx->mode != -1, JS_ERR_INIT);
  JS_ASSERT(ctx->mode == 0 || ctx->mode == 3, JS_ERR_STATE);

  aead_auth(ctx, msg, msg_len);

  return argv[1];
}

static napi_value
bcrypto_aead_final(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  uint8_t out[16];
  aead_t *ctx;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ctx) == napi_ok);

  JS_ASSERT(ctx->mode != -1, JS_ERR_INIT);

  aead_final(ctx, out);

  CHECK(napi_create_buffer_copy(env, 16, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_aead_destroy(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  aead_t *ctx;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ctx) == napi_ok);

  ctx->mode = -1;

  return argv[0];
}

static napi_value
bcrypto_aead_verify(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t mac[16];
  const uint8_t *tag;
  size_t tag_len;
  aead_t *ctx;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ctx) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&tag, &tag_len) == napi_ok);

  JS_ASSERT(ctx->mode != -1, JS_ERR_INIT);
  JS_ASSERT(tag_len == 16, JS_ERR_TAG_SIZE);

  aead_final(ctx, mac);

  ok = aead_verify(mac, tag);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_aead_static_encrypt(napi_env env, napi_callback_info info) {
  napi_value argv[4];
  size_t argc = 4;
  uint8_t out[16];
  const uint8_t *key, *iv, *aad;
  size_t key_len, iv_len, aad_len;
  uint8_t *msg;
  size_t msg_len;
  aead_t ctx;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 4);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&key, &key_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&iv, &iv_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[3], (void **)&aad, &aad_len) == napi_ok);

  JS_ASSERT(key_len >= 32, JS_ERR_KEY_SIZE);
  JS_ASSERT(iv_len == 8 || iv_len == 12 || iv_len == 16
         || iv_len == 24 || iv_len == 28 || iv_len == 32, JS_ERR_IV_SIZE);

  aead_init(&ctx);
  aead_setup(&ctx, key, iv, iv_len);
  aead_aad(&ctx, aad, aad_len);
  aead_encrypt(&ctx, msg, msg, msg_len);
  aead_final(&ctx, out);

  cleanse(&ctx, sizeof(aead_t));

  CHECK(napi_create_buffer_copy(env, 16, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_aead_static_decrypt(napi_env env, napi_callback_info info) {
  napi_value argv[5];
  size_t argc = 5;
  uint8_t mac[16];
  const uint8_t *key, *iv, *tag, *aad;
  size_t key_len, iv_len, tag_len, aad_len;
  uint8_t *msg;
  size_t msg_len;
  aead_t ctx;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 5);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&key, &key_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&iv, &iv_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[3], (void **)&tag, &tag_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[4], (void **)&aad, &aad_len) == napi_ok);

  JS_ASSERT(key_len >= 32, JS_ERR_KEY_SIZE);
  JS_ASSERT(iv_len == 8 || iv_len == 12 || iv_len == 16
         || iv_len == 24 || iv_len == 28 || iv_len == 32, JS_ERR_IV_SIZE);
  JS_ASSERT(tag_len == 16, JS_ERR_TAG_SIZE);

  aead_init(&ctx);
  aead_setup(&ctx, key, iv, iv_len);
  aead_aad(&ctx, aad, aad_len);
  aead_decrypt(&ctx, msg, msg, msg_len);
  aead_final(&ctx, mac);

  cleanse(&ctx, sizeof(aead_t));

  ok = aead_verify(mac, tag);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_aead_static_auth(napi_env env, napi_callback_info info) {
  napi_value argv[5];
  size_t argc = 5;
  uint8_t mac[16];
  const uint8_t *key, *iv, *msg, *tag, *aad;
  size_t key_len, iv_len, msg_len, tag_len, aad_len;
  aead_t ctx;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 5);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&key, &key_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&iv, &iv_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[3], (void **)&tag, &tag_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[4], (void **)&aad, &aad_len) == napi_ok);

  JS_ASSERT(key_len >= 32, JS_ERR_KEY_SIZE);
  JS_ASSERT(iv_len == 8 || iv_len == 12 || iv_len == 16
         || iv_len == 24 || iv_len == 28 || iv_len == 32, JS_ERR_IV_SIZE);
  JS_ASSERT(tag_len == 16, JS_ERR_TAG_SIZE);

  aead_init(&ctx);
  aead_setup(&ctx, key, iv, iv_len);
  aead_aad(&ctx, aad, aad_len);
  aead_auth(&ctx, msg, msg_len);
  aead_final(&ctx, mac);

  cleanse(&ctx, sizeof(aead_t));

  ok = aead_verify(mac, tag);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

/*
 * Base58
 */

static napi_value
bcrypto_base58_encode(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  char *out;
  size_t out_len;
  const uint8_t *data;
  size_t data_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&data,
                             &data_len) == napi_ok);

  JS_ASSERT(base58_encode(&out, &out_len, data, data_len), JS_ERR_ENCODE);

  CHECK(napi_create_string_utf8(env, out, out_len, &result) == napi_ok);

  safe_free(out);

  return result;
}

static napi_value
bcrypto_base58_decode(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  uint8_t *out;
  size_t out_len;
  char *str;
  size_t str_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(read_value_string_utf8(env, argv[0], &str, &str_len) == napi_ok);

  if (!base58_decode(&out, &out_len, str, str_len)) {
    safe_free(str);
    JS_THROW(JS_ERR_DECODE);
  }

  CHECK(create_external_buffer(env, out_len, out, &result) == napi_ok);

  safe_free(str);

  return result;
}

static napi_value
bcrypto_base58_test(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  char *str;
  size_t str_len;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(read_value_string_utf8(env, argv[0], &str, &str_len) == napi_ok);

  ok = base58_test(str, str_len);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  safe_free(str);

  return result;
}

/*
 * Bech32
 */

static napi_value
bcrypto_bech32_serialize(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  char out[93];
  char hrp[84 + 1];
  size_t hrp_len;
  const uint8_t *data;
  size_t data_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_string_utf8(env, argv[0],
                                   hrp, sizeof(hrp), &hrp_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&data,
                             &data_len) == napi_ok);

  JS_ASSERT(hrp_len != sizeof(hrp) - 1, JS_ERR_ENCODE);
  JS_ASSERT(bech32_serialize(out, hrp, data, data_len), JS_ERR_ENCODE);

  CHECK(napi_create_string_utf8(env, out, NAPI_AUTO_LENGTH,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_bech32_deserialize(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  char hrp[84];
  uint8_t data[84];
  char str[93 + 1];
  size_t data_len, str_len;
  napi_value hrpval, dataval, result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_value_string_utf8(env, argv[0],
                                   str, sizeof(str), &str_len) == napi_ok);

  JS_ASSERT(str_len != sizeof(str) - 1, JS_ERR_ENCODE);
  JS_ASSERT(bech32_deserialize(hrp, data, &data_len, str), JS_ERR_ENCODE);

  CHECK(napi_create_string_utf8(env, hrp, NAPI_AUTO_LENGTH,
                                &hrpval) == napi_ok);

  CHECK(napi_create_buffer_copy(env, data_len, data, NULL,
                                &dataval) == napi_ok);

  CHECK(napi_create_array_with_length(env, 2, &result) == napi_ok);
  CHECK(napi_set_element(env, result, 0, hrpval) == napi_ok);
  CHECK(napi_set_element(env, result, 1, dataval) == napi_ok);

  return result;
}

static napi_value
bcrypto_bech32_is(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  char str[93 + 1];
  size_t str_len;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_value_string_utf8(env, argv[0],
                                   str, sizeof(str), &str_len) == napi_ok);

  ok = str_len != sizeof(str) - 1 && bech32_is(str);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_bech32_convert_bits(napi_env env, napi_callback_info info) {
  napi_value argv[4];
  size_t argc = 4;
  uint8_t *out;
  size_t out_len;
  const uint8_t *data;
  size_t data_len;
  uint32_t frombits, tobits;
  bool pad;
  size_t size;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 4);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&data,
                             &data_len) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[1], &frombits) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[2], &tobits) == napi_ok);
  CHECK(napi_get_value_bool(env, argv[3], &pad) == napi_ok);

  JS_ASSERT(frombits >= 1 && frombits <= 255, JS_ERR_ENCODE);
  JS_ASSERT(tobits >= 1 && tobits <= 255, JS_ERR_ENCODE);

  size = (data_len * frombits + (tobits - 1)) / tobits;

  if (pad)
    size += 1;

  out = (uint8_t *)safe_malloc(size);
  out_len = 0;

  if (!bech32_convert_bits(out, &out_len, tobits,
                           data, data_len, frombits, pad)) {
    safe_free(out);
    JS_THROW(JS_ERR_ENCODE);
  }

  CHECK(create_external_buffer(env, out_len, out, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_bech32_encode(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  char out[93];
  char hrp[84 + 1];
  size_t hrp_len;
  uint32_t version;
  const uint8_t *data;
  size_t data_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_string_utf8(env, argv[0],
                                   hrp, sizeof(hrp), &hrp_len) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[1], &version) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&data,
                             &data_len) == napi_ok);

  JS_ASSERT(hrp_len != sizeof(hrp) - 1, JS_ERR_ENCODE);
  JS_ASSERT(bech32_encode(out, hrp, version, data, data_len), JS_ERR_ENCODE);

  CHECK(napi_create_string_utf8(env, out, NAPI_AUTO_LENGTH,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_bech32_decode(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  char hrp[84];
  int version;
  uint8_t data[40];
  char str[93 + 1];
  size_t data_len, str_len;
  napi_value hrpval, versionval, dataval, result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_value_string_utf8(env, argv[0],
                                   str, sizeof(str), &str_len) == napi_ok);

  JS_ASSERT(str_len != sizeof(str) - 1, JS_ERR_ENCODE);
  JS_ASSERT(bech32_decode(&version, data, &data_len, hrp, str), JS_ERR_ENCODE);

  CHECK(napi_create_string_utf8(env, hrp, NAPI_AUTO_LENGTH,
                                &hrpval) == napi_ok);

  CHECK(napi_create_uint32(env, version, &versionval) == napi_ok);

  CHECK(napi_create_buffer_copy(env, data_len, data, NULL,
                                &dataval) == napi_ok);

  CHECK(napi_create_array_with_length(env, 3, &result) == napi_ok);
  CHECK(napi_set_element(env, result, 0, hrpval) == napi_ok);
  CHECK(napi_set_element(env, result, 1, versionval) == napi_ok);
  CHECK(napi_set_element(env, result, 2, dataval) == napi_ok);

  return result;
}

static napi_value
bcrypto_bech32_test(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  char str[93 + 1];
  size_t str_len;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_value_string_utf8(env, argv[0],
                                   str, sizeof(str), &str_len) == napi_ok);

  ok = str_len != sizeof(str) - 1 && bech32_test(str);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

/*
 * BLAKE2b
 */

static void
bcrypto_blake2b_destroy(napi_env env, void *data, void *hint) {
  cleanse(data, sizeof(bcrypto_blake2b_t));
  safe_free(data);
}

static napi_value
bcrypto_blake2b_create(napi_env env, napi_callback_info info) {
  bcrypto_blake2b_t *blake =
    (bcrypto_blake2b_t *)safe_malloc(sizeof(bcrypto_blake2b_t));
  napi_value handle;

  blake->started = 0;

  CHECK(napi_create_external(env,
                             blake,
                             bcrypto_blake2b_destroy,
                             NULL,
                             &handle) == napi_ok);

  return handle;
}

static napi_value
bcrypto_blake2b_init(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint32_t out_len;
  const uint8_t *key;
  size_t key_len;
  bcrypto_blake2b_t *blake;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&blake) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[1], &out_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&key, &key_len) == napi_ok);

  JS_ASSERT(out_len != 0 && out_len <= 64, JS_ERR_OUTPUT_SIZE);
  JS_ASSERT(key_len <= 64, JS_ERR_KEY_SIZE);

  blake2b_init(&blake->ctx, out_len, key, key_len);
  blake->started = 1;

  return argv[0];
}

static napi_value
bcrypto_blake2b_update(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  const uint8_t *in;
  size_t in_len;
  bcrypto_blake2b_t *blake;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&blake) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&in, &in_len) == napi_ok);

  JS_ASSERT(blake->started, JS_ERR_INIT);

  blake2b_update(&blake->ctx, in, in_len);

  return argv[0];
}

static napi_value
bcrypto_blake2b_final(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  uint8_t out[64];
  size_t out_len;
  bcrypto_blake2b_t *blake;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_value_external(env, argv[0], (void **)&blake) == napi_ok);

  JS_ASSERT(blake->started, JS_ERR_INIT);

  out_len = blake->ctx.outlen;

  blake2b_final(&blake->ctx, out);
  blake->started = 0;

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_blake2b_digest(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[64];
  const uint8_t *in, *key;
  size_t in_len, key_len;
  uint32_t out_len;
  blake2b_t ctx;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&in, &in_len) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[1], &out_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&key, &key_len) == napi_ok);

  JS_ASSERT(out_len != 0 && out_len <= 64, JS_ERR_OUTPUT_SIZE);
  JS_ASSERT(key_len <= 64, JS_ERR_KEY_SIZE);

  blake2b_init(&ctx, out_len, key, key_len);
  blake2b_update(&ctx, in, in_len);
  blake2b_final(&ctx, out);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_blake2b_root(napi_env env, napi_callback_info info) {
  napi_value argv[4];
  size_t argc = 4;
  uint8_t out[64];
  const uint8_t *left, *right, *key;
  size_t left_len, right_len, key_len;
  uint32_t out_len;
  blake2b_t ctx;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 4);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&left,
                             &left_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&right,
                             &right_len) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[2], &out_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[3], (void **)&key, &key_len) == napi_ok);

  JS_ASSERT(out_len != 0 && out_len <= 64, JS_ERR_OUTPUT_SIZE);
  JS_ASSERT(key_len <= 64, JS_ERR_KEY_SIZE);
  JS_ASSERT(left_len == out_len && right_len == out_len, JS_ERR_NODE_SIZE);

  blake2b_init(&ctx, out_len, key, key_len);
  blake2b_update(&ctx, left, left_len);
  blake2b_update(&ctx, right, right_len);
  blake2b_final(&ctx, out);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_blake2b_multi(napi_env env, napi_callback_info info) {
  napi_value argv[5];
  size_t argc = 5;
  uint8_t out[64];
  const uint8_t *x, *y, *z, *key;
  size_t x_len, y_len, z_len, key_len;
  uint32_t out_len;
  blake2b_t ctx;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 5);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&x, &x_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&y, &y_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&z, &z_len) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[3], &out_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[4], (void **)&key, &key_len) == napi_ok);

  JS_ASSERT(out_len != 0 && out_len <= 64, JS_ERR_OUTPUT_SIZE);
  JS_ASSERT(key_len <= 64, JS_ERR_KEY_SIZE);

  blake2b_init(&ctx, out_len, key, key_len);
  blake2b_update(&ctx, x, x_len);
  blake2b_update(&ctx, y, y_len);
  blake2b_update(&ctx, z, z_len);
  blake2b_final(&ctx, out);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  return result;
}

/*
 * BLAKE2s
 */

static void
bcrypto_blake2s_destroy(napi_env env, void *data, void *hint) {
  cleanse(data, sizeof(bcrypto_blake2s_t));
  safe_free(data);
}

static napi_value
bcrypto_blake2s_create(napi_env env, napi_callback_info info) {
  bcrypto_blake2s_t *blake =
    (bcrypto_blake2s_t *)safe_malloc(sizeof(bcrypto_blake2s_t));
  napi_value handle;

  blake->started = 0;

  CHECK(napi_create_external(env,
                             blake,
                             bcrypto_blake2s_destroy,
                             NULL,
                             &handle) == napi_ok);

  return handle;
}

static napi_value
bcrypto_blake2s_init(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint32_t out_len;
  const uint8_t *key;
  size_t key_len;
  bcrypto_blake2s_t *blake;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&blake) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[1], &out_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&key, &key_len) == napi_ok);

  JS_ASSERT(out_len != 0 && out_len <= 64, JS_ERR_OUTPUT_SIZE);
  JS_ASSERT(key_len <= 64, JS_ERR_KEY_SIZE);

  blake2s_init(&blake->ctx, out_len, key, key_len);
  blake->started = 1;

  return argv[0];
}

static napi_value
bcrypto_blake2s_update(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  const uint8_t *in;
  size_t in_len;
  bcrypto_blake2s_t *blake;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&blake) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&in, &in_len) == napi_ok);

  JS_ASSERT(blake->started, JS_ERR_INIT);

  blake2s_update(&blake->ctx, in, in_len);

  return argv[0];
}

static napi_value
bcrypto_blake2s_final(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  uint8_t out[64];
  size_t out_len;
  bcrypto_blake2s_t *blake;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_value_external(env, argv[0], (void **)&blake) == napi_ok);

  JS_ASSERT(blake->started, JS_ERR_INIT);

  out_len = blake->ctx.outlen;

  blake2s_final(&blake->ctx, out);
  blake->started = 0;

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_blake2s_digest(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[64];
  const uint8_t *in, *key;
  size_t in_len, key_len;
  uint32_t out_len;
  blake2s_t ctx;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&in, &in_len) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[1], &out_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&key, &key_len) == napi_ok);

  JS_ASSERT(out_len != 0 && out_len <= 64, JS_ERR_OUTPUT_SIZE);
  JS_ASSERT(key_len <= 64, JS_ERR_KEY_SIZE);

  blake2s_init(&ctx, out_len, key, key_len);
  blake2s_update(&ctx, in, in_len);
  blake2s_final(&ctx, out);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_blake2s_root(napi_env env, napi_callback_info info) {
  napi_value argv[4];
  size_t argc = 4;
  uint8_t out[64];
  const uint8_t *left, *right, *key;
  size_t left_len, right_len, key_len;
  uint32_t out_len;
  blake2s_t ctx;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 4);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&left,
                             &left_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&right,
                             &right_len) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[2], &out_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[3], (void **)&key, &key_len) == napi_ok);

  JS_ASSERT(out_len != 0 && out_len <= 64, JS_ERR_OUTPUT_SIZE);
  JS_ASSERT(key_len <= 64, JS_ERR_KEY_SIZE);
  JS_ASSERT(left_len == out_len && right_len == out_len, JS_ERR_NODE_SIZE);

  blake2s_init(&ctx, out_len, key, key_len);
  blake2s_update(&ctx, left, left_len);
  blake2s_update(&ctx, right, right_len);
  blake2s_final(&ctx, out);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_blake2s_multi(napi_env env, napi_callback_info info) {
  napi_value argv[5];
  size_t argc = 5;
  uint8_t out[64];
  const uint8_t *x, *y, *z, *key;
  size_t x_len, y_len, z_len, key_len;
  uint32_t out_len;
  blake2s_t ctx;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 5);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&x, &x_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&y, &y_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&z, &z_len) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[3], &out_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[4], (void **)&key, &key_len) == napi_ok);

  JS_ASSERT(out_len != 0 && out_len <= 64, JS_ERR_OUTPUT_SIZE);
  JS_ASSERT(key_len <= 64, JS_ERR_KEY_SIZE);

  blake2s_init(&ctx, out_len, key, key_len);
  blake2s_update(&ctx, x, x_len);
  blake2s_update(&ctx, y, y_len);
  blake2s_update(&ctx, z, z_len);
  blake2s_final(&ctx, out);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  return result;
}

/*
 * Cash32
 */

static napi_value
bcrypto_cash32_serialize(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  char out[197];
  char prefix[84 + 1];
  size_t prefix_len;
  const uint8_t *data;
  size_t data_len;
  napi_value result;

  memset(out, 0, sizeof(out));

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_string_utf8(env, argv[0], prefix, sizeof(prefix),
                                   &prefix_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&data,
                             &data_len) == napi_ok);

  JS_ASSERT(prefix_len != sizeof(prefix) - 1, JS_ERR_ENCODE);
  JS_ASSERT(cash32_serialize(out, prefix, data, data_len), JS_ERR_ENCODE);

  CHECK(napi_create_string_utf8(env, out, NAPI_AUTO_LENGTH,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_cash32_deserialize(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  char prefix[84];
  uint8_t data[188];
  char str[197 + 1];
  char dprefix[84 + 1];
  size_t data_len, str_len, dprefix_len;
  napi_value prefixval, dataval, result;

  memset(prefix, 0, sizeof(prefix));
  memset(data, 0, sizeof(data));
  data_len = 0;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_string_utf8(env, argv[0],
                                   str, sizeof(str), &str_len) == napi_ok);
  CHECK(napi_get_value_string_utf8(env, argv[1], dprefix,
                                   sizeof(dprefix), &dprefix_len) == napi_ok);

  JS_ASSERT(str_len != sizeof(str) - 1, JS_ERR_ENCODE);
  JS_ASSERT(dprefix_len != sizeof(dprefix) - 1, JS_ERR_ENCODE);
  JS_ASSERT(cash32_deserialize(prefix, data, &data_len, dprefix, str),
            JS_ERR_ENCODE);

  CHECK(napi_create_string_utf8(env, prefix, NAPI_AUTO_LENGTH,
                                &prefixval) == napi_ok);

  CHECK(napi_create_buffer_copy(env, data_len, data, NULL,
                                &dataval) == napi_ok);

  CHECK(napi_create_array_with_length(env, 2, &result) == napi_ok);
  CHECK(napi_set_element(env, result, 0, prefixval) == napi_ok);
  CHECK(napi_set_element(env, result, 1, dataval) == napi_ok);

  return result;
}

static napi_value
bcrypto_cash32_is(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  char str[197 + 1];
  char dprefix[84 + 1];
  size_t str_len, dprefix_len;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_string_utf8(env, argv[0],
                                   str, sizeof(str), &str_len) == napi_ok);
  CHECK(napi_get_value_string_utf8(env, argv[1], dprefix,
                                   sizeof(dprefix), &dprefix_len) == napi_ok);

  ok = str_len != sizeof(str) - 1
    && dprefix_len != sizeof(dprefix) - 1
    && cash32_is(dprefix, str);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_cash32_convert_bits(napi_env env, napi_callback_info info) {
  napi_value argv[4];
  size_t argc = 4;
  uint8_t *out;
  size_t out_len;
  const uint8_t *data;
  size_t data_len;
  uint32_t frombits, tobits;
  bool pad;
  size_t size;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 4);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&data,
                             &data_len) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[1], &frombits) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[2], &tobits) == napi_ok);
  CHECK(napi_get_value_bool(env, argv[3], &pad) == napi_ok);

  JS_ASSERT(frombits >= 1 && frombits <= 255, JS_ERR_ENCODE);
  JS_ASSERT(tobits >= 1 && tobits <= 255, JS_ERR_ENCODE);

  size = (data_len * frombits + (tobits - 1)) / tobits;

  if (pad)
    size += 1;

  out = (uint8_t *)safe_malloc(size);
  out_len = 0;

  if (!cash32_convert_bits(out, &out_len, tobits,
                           data, data_len, frombits, pad)) {
    safe_free(out);
    JS_THROW(JS_ERR_ENCODE);
  }

  CHECK(create_external_buffer(env, out_len, out, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_cash32_encode(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  char out[197];
  char prefix[84 + 1];
  size_t prefix_len;
  uint32_t type;
  const uint8_t *data;
  size_t data_len;
  napi_value result;

  memset(out, 0, sizeof(out));

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_string_utf8(env, argv[0], prefix,
                                   sizeof(prefix), &prefix_len) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[1], &type) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&data,
                             &data_len) == napi_ok);

  JS_ASSERT(prefix_len != sizeof(prefix) - 1, JS_ERR_ENCODE);
  JS_ASSERT(type <= 15, JS_ERR_ENCODE);
  JS_ASSERT(cash32_encode(out, prefix, type, data, data_len), JS_ERR_ENCODE);

  CHECK(napi_create_string_utf8(env, out, NAPI_AUTO_LENGTH,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_cash32_decode(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  char prefix[84];
  int type;
  uint8_t data[64];
  char str[197 + 1];
  char dprefix[84 + 1];
  size_t data_len, str_len, dprefix_len;
  napi_value prefixval, typeval, dataval, result;

  memset(data, 0, sizeof(data));
  memset(prefix, 0, sizeof(prefix));

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_string_utf8(env, argv[0],
                                   str, sizeof(str), &str_len) == napi_ok);
  CHECK(napi_get_value_string_utf8(env, argv[1], dprefix,
                                   sizeof(dprefix), &dprefix_len) == napi_ok);

  JS_ASSERT(str_len != sizeof(str) - 1, JS_ERR_ENCODE);
  JS_ASSERT(dprefix_len != sizeof(dprefix) - 1, JS_ERR_ENCODE);
  JS_ASSERT(cash32_decode(&type, data, &data_len, prefix, dprefix, str),
            JS_ERR_ENCODE);

  CHECK(napi_create_string_utf8(env, prefix, NAPI_AUTO_LENGTH,
                                &prefixval) == napi_ok);

  CHECK(napi_create_uint32(env, type, &typeval) == napi_ok);

  CHECK(napi_create_buffer_copy(env, data_len, data, NULL,
                                &dataval) == napi_ok);

  CHECK(napi_create_array_with_length(env, 3, &result) == napi_ok);
  CHECK(napi_set_element(env, result, 0, prefixval) == napi_ok);
  CHECK(napi_set_element(env, result, 1, typeval) == napi_ok);
  CHECK(napi_set_element(env, result, 2, dataval) == napi_ok);

  return result;
}

static napi_value
bcrypto_cash32_test(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  char str[197 + 1];
  char dprefix[84 + 1];
  size_t str_len, dprefix_len;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_string_utf8(env, argv[0],
                                   str, sizeof(str), &str_len) == napi_ok);
  CHECK(napi_get_value_string_utf8(env, argv[1], dprefix,
                                   sizeof(dprefix), &dprefix_len) == napi_ok);

  ok = str_len != sizeof(str) - 1
    && dprefix_len != sizeof(dprefix) - 1
    && cash32_test(dprefix, str);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

/*
 * ChaCha20
 */

static void
bcrypto_chacha20_destroy_(napi_env env, void *data, void *hint) {
  cleanse(data, sizeof(bcrypto_chacha20_t));
  safe_free(data);
}

static napi_value
bcrypto_chacha20_create(napi_env env, napi_callback_info info) {
  bcrypto_chacha20_t *chacha =
    (bcrypto_chacha20_t *)safe_malloc(sizeof(bcrypto_chacha20_t));
  napi_value handle;

  chacha->started = 0;

  CHECK(napi_create_external(env,
                             chacha,
                             bcrypto_chacha20_destroy_,
                             NULL,
                             &handle) == napi_ok);

  return handle;
}

static napi_value
bcrypto_chacha20_init(napi_env env, napi_callback_info info) {
  napi_value argv[4];
  size_t argc = 4;
  const uint8_t *key, *nonce;
  size_t key_len, nonce_len;
  int64_t ctr;
  bcrypto_chacha20_t *chacha;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 4);
  CHECK(napi_get_value_external(env, argv[0], (void **)&chacha) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&key, &key_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&nonce,
                             &nonce_len) == napi_ok);
  CHECK(napi_get_value_int64(env, argv[3], &ctr) == napi_ok);

  JS_ASSERT(key_len == 16 || key_len == 32, JS_ERR_KEY_SIZE);
  JS_ASSERT(nonce_len == 8 || nonce_len == 12
         || nonce_len == 16 || nonce_len == 24
         || nonce_len == 28 || nonce_len == 32, JS_ERR_NONCE_SIZE);

  chacha20_init(&chacha->ctx, key, key_len, nonce, nonce_len, ctr);
  chacha->started = 1;

  return argv[0];
}

static napi_value
bcrypto_chacha20_encrypt(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t *msg;
  size_t msg_len;
  bcrypto_chacha20_t *chacha;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&chacha) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&msg, &msg_len) == napi_ok);

  JS_ASSERT(chacha->started, JS_ERR_INIT);

  chacha20_encrypt(&chacha->ctx, msg, msg, msg_len);

  return argv[1];
}

static napi_value
bcrypto_chacha20_destroy(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  bcrypto_chacha20_t *chacha;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_value_external(env, argv[0], (void **)&chacha) == napi_ok);

  chacha->started = 0;

  return argv[0];
}

static napi_value
bcrypto_chacha20_derive(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t out[32];
  const uint8_t *key, *nonce;
  size_t key_len, nonce_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&key, &key_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&nonce,
                             &nonce_len) == napi_ok);

  JS_ASSERT(key_len == 16 || key_len == 32, JS_ERR_KEY_SIZE);
  JS_ASSERT(nonce_len == 16, JS_ERR_NONCE_SIZE);

  chacha20_derive(out, key, key_len, nonce);

  CHECK(napi_create_buffer_copy(env, 32, out, NULL, &result) == napi_ok);

  return result;
}

/*
 * Cleanse
 */

static napi_value
bcrypto_cleanse(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  uint8_t *buf;
  size_t buf_len;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&buf, &buf_len) == napi_ok);

  cleanse(buf, buf_len);

  return argv[0];
}

/*
 * DSA
 */

static napi_value
bcrypto_dsa_params_create(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  uint8_t *out;
  size_t out_len;
  const uint8_t *key;
  size_t key_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&key, &key_len) == napi_ok);

  out = (uint8_t *)safe_malloc(DSA_MAX_PARAMS_SIZE);
  out_len = DSA_MAX_PARAMS_SIZE;

  if (!dsa_params_create(out, &out_len, key, key_len)) {
    safe_free(out);
    JS_THROW(JS_ERR_KEY);
  }

  out = (uint8_t *)safe_realloc(out, out_len);

  CHECK(create_external_buffer(env, out_len, out, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_dsa_params_generate(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t *out;
  size_t out_len;
  uint32_t bits;
  uint8_t *entropy;
  size_t entropy_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_uint32(env, argv[0], &bits) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&entropy,
                             &entropy_len) == napi_ok);

  JS_ASSERT(entropy_len == ENTROPY_SIZE, JS_ERR_ENTROPY_SIZE);

  out = (uint8_t *)safe_malloc(DSA_MAX_PARAMS_SIZE);
  out_len = DSA_MAX_PARAMS_SIZE;

  if (!dsa_params_generate(out, &out_len, bits, entropy)) {
    safe_free(out);
    JS_THROW(JS_ERR_GENERATE);
  }

  cleanse(entropy, entropy_len);

  out = (uint8_t *)safe_realloc(out, out_len);

  CHECK(create_external_buffer(env, out_len, out, &result) == napi_ok);

  return result;
}

typedef struct bcrypto_dsa_worker_s {
  uint32_t bits;
  uint8_t entropy[ENTROPY_SIZE];
  uint8_t *out;
  size_t out_len;
  const char *error;
  napi_async_work work;
  napi_deferred deferred;
} bcrypto_dsa_worker_t;

static void
bcrypto_dsa_execute_(napi_env env, void *data) {
  bcrypto_dsa_worker_t *w = (bcrypto_dsa_worker_t *)data;

  if (!dsa_params_generate(w->out, &w->out_len, w->bits, w->entropy)) {
    w->error = JS_ERR_GENERATE;
    return;
  }

  cleanse(w->entropy, ENTROPY_SIZE);

  w->out = (uint8_t *)safe_realloc(w->out, w->out_len);
}

static void
bcrypto_dsa_complete_(napi_env env, napi_status status, void *data) {
  bcrypto_dsa_worker_t *w = (bcrypto_dsa_worker_t *)data;
  napi_value result, strval;

  if (status != napi_ok)
    w->error = JS_ERR_GENERATE;

  if (w->error == NULL) {
    CHECK(create_external_buffer(env, w->out_len, w->out, &result) == napi_ok);
    CHECK(napi_resolve_deferred(env, w->deferred, result) == napi_ok);
  } else {
    CHECK(napi_create_string_utf8(env, w->error,
                                  NAPI_AUTO_LENGTH, &strval) == napi_ok);
    CHECK(napi_create_error(env, NULL, strval, &result) == napi_ok);
    CHECK(napi_reject_deferred(env, w->deferred, result) == napi_ok);
    safe_free(w->out);
  }

  CHECK(napi_delete_async_work(env, w->work) == napi_ok);

  safe_free(w);
}

static napi_value
bcrypto_dsa_params_generate_async(napi_env env, napi_callback_info info) {
  bcrypto_dsa_worker_t *worker;
  napi_value argv[2];
  size_t argc = 2;
  uint32_t bits;
  uint8_t *entropy;
  size_t entropy_len;
  napi_value name, result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_uint32(env, argv[0], &bits) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&entropy,
                             &entropy_len) == napi_ok);

  JS_ASSERT(entropy_len == ENTROPY_SIZE, JS_ERR_ENTROPY_SIZE);

  worker = (bcrypto_dsa_worker_t *)safe_malloc(sizeof(bcrypto_dsa_worker_t));
  worker->bits = bits;
  worker->out = (uint8_t *)safe_malloc(DSA_MAX_PARAMS_SIZE);
  worker->out_len = DSA_MAX_PARAMS_SIZE;
  worker->error = NULL;

  memcpy(worker->entropy, entropy, ENTROPY_SIZE);

  cleanse(entropy, entropy_len);

  CHECK(napi_create_string_utf8(env, "bcrypto:dsa_params_generate",
                                NAPI_AUTO_LENGTH, &name) == napi_ok);

  CHECK(napi_create_promise(env, &worker->deferred, &result) == napi_ok);

  CHECK(napi_create_async_work(env,
                               NULL,
                               name,
                               bcrypto_dsa_execute_,
                               bcrypto_dsa_complete_,
                               worker,
                               &worker->work) == napi_ok);

  CHECK(napi_queue_async_work(env, worker->work) == napi_ok);

  return result;
}

static napi_value
bcrypto_dsa_params_bits(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  size_t bits;
  const uint8_t *key;
  size_t key_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&key, &key_len) == napi_ok);

  bits = dsa_params_bits(key, key_len);

  JS_ASSERT(bits != 0, JS_ERR_PARAMS);

  CHECK(napi_create_uint32(env, bits, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_dsa_params_verify(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  const uint8_t *key;
  size_t key_len;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&key, &key_len) == napi_ok);

  ok = dsa_params_verify(key, key_len);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_dsa_params_import(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  uint8_t *out;
  size_t out_len;
  const uint8_t *key;
  size_t key_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&key, &key_len) == napi_ok);

  out = (uint8_t *)safe_malloc(DSA_MAX_PARAMS_SIZE);
  out_len = DSA_MAX_PARAMS_SIZE;

  if (!dsa_params_import(out, &out_len, key, key_len)) {
    safe_free(out);
    JS_THROW(JS_ERR_PARAMS);
  }

  out = (uint8_t *)safe_realloc(out, out_len);

  CHECK(create_external_buffer(env, out_len, out, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_dsa_params_export(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  uint8_t *out;
  size_t out_len;
  const uint8_t *key;
  size_t key_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&key, &key_len) == napi_ok);

  out = (uint8_t *)safe_malloc(DSA_MAX_PARAMS_SIZE);
  out_len = DSA_MAX_PARAMS_SIZE;

  if (!dsa_params_export(out, &out_len, key, key_len)) {
    safe_free(out);
    JS_THROW(JS_ERR_PARAMS);
  }

  out = (uint8_t *)safe_realloc(out, out_len);

  CHECK(create_external_buffer(env, out_len, out, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_dsa_privkey_create(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t *out;
  size_t out_len;
  const uint8_t *key;
  size_t key_len;
  uint8_t *entropy;
  size_t entropy_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&key, &key_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&entropy,
                             &entropy_len) == napi_ok);

  JS_ASSERT(entropy_len == ENTROPY_SIZE, JS_ERR_ENTROPY_SIZE);

  out = (uint8_t *)safe_malloc(DSA_MAX_PRIV_SIZE);
  out_len = DSA_MAX_PRIV_SIZE;

  if (!dsa_privkey_create(out, &out_len, key, key_len, entropy)) {
    safe_free(out);
    JS_THROW(JS_ERR_PARAMS);
  }

  cleanse(entropy, entropy_len);

  out = (uint8_t *)safe_realloc(out, out_len);

  CHECK(create_external_buffer(env, out_len, out, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_dsa_privkey_bits(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  size_t bits;
  const uint8_t *key;
  size_t key_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&key, &key_len) == napi_ok);

  bits = dsa_privkey_bits(key, key_len);

  JS_ASSERT(bits != 0, JS_ERR_PRIVKEY);

  CHECK(napi_create_uint32(env, bits, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_dsa_privkey_verify(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  const uint8_t *key;
  size_t key_len;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&key, &key_len) == napi_ok);

  ok = dsa_privkey_verify(key, key_len);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_dsa_privkey_import(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  uint8_t *out;
  size_t out_len;
  const uint8_t *key;
  size_t key_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&key, &key_len) == napi_ok);

  out = (uint8_t *)safe_malloc(DSA_MAX_PRIV_SIZE);
  out_len = DSA_MAX_PRIV_SIZE;

  if (!dsa_privkey_import(out, &out_len, key, key_len)) {
    safe_free(out);
    JS_THROW(JS_ERR_PRIVKEY);
  }

  out = (uint8_t *)safe_realloc(out, out_len);

  CHECK(create_external_buffer(env, out_len, out, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_dsa_privkey_export(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  uint8_t *out;
  size_t out_len;
  const uint8_t *key;
  size_t key_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&key, &key_len) == napi_ok);

  out = (uint8_t *)safe_malloc(DSA_MAX_PRIV_SIZE);
  out_len = DSA_MAX_PRIV_SIZE;

  if (!dsa_privkey_export(out, &out_len, key, key_len)) {
    safe_free(out);
    JS_THROW(JS_ERR_PRIVKEY);
  }

  out = (uint8_t *)safe_realloc(out, out_len);

  CHECK(create_external_buffer(env, out_len, out, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_dsa_pubkey_create(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  uint8_t *out;
  size_t out_len;
  const uint8_t *key;
  size_t key_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&key, &key_len) == napi_ok);

  out = (uint8_t *)safe_malloc(DSA_MAX_PUB_SIZE);
  out_len = DSA_MAX_PUB_SIZE;

  if (!dsa_pubkey_create(out, &out_len, key, key_len)) {
    safe_free(out);
    JS_THROW(JS_ERR_PRIVKEY);
  }

  out = (uint8_t *)safe_realloc(out, out_len);

  CHECK(create_external_buffer(env, out_len, out, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_dsa_pubkey_bits(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  size_t bits;
  const uint8_t *key;
  size_t key_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&key, &key_len) == napi_ok);

  bits = dsa_pubkey_bits(key, key_len);

  JS_ASSERT(bits != 0, JS_ERR_PUBKEY);

  CHECK(napi_create_uint32(env, bits, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_dsa_pubkey_verify(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  const uint8_t *key;
  size_t key_len;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&key, &key_len) == napi_ok);

  ok = dsa_pubkey_verify(key, key_len);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_dsa_pubkey_import(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  uint8_t *out;
  size_t out_len;
  const uint8_t *key;
  size_t key_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&key, &key_len) == napi_ok);

  out = (uint8_t *)safe_malloc(DSA_MAX_PUB_SIZE);
  out_len = DSA_MAX_PUB_SIZE;

  if (!dsa_pubkey_import(out, &out_len, key, key_len)) {
    safe_free(out);
    JS_THROW(JS_ERR_PUBKEY);
  }

  out = (uint8_t *)safe_realloc(out, out_len);

  CHECK(create_external_buffer(env, out_len, out, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_dsa_pubkey_export(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  uint8_t *out;
  size_t out_len;
  const uint8_t *key;
  size_t key_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&key, &key_len) == napi_ok);

  out = (uint8_t *)safe_malloc(DSA_MAX_PUB_SIZE);
  out_len = DSA_MAX_PUB_SIZE;

  if (!dsa_pubkey_export(out, &out_len, key, key_len)) {
    safe_free(out);
    JS_THROW(JS_ERR_PUBKEY);
  }

  out = (uint8_t *)safe_realloc(out, out_len);

  CHECK(create_external_buffer(env, out_len, out, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_dsa_signature_export(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t out[DSA_MAX_DER_SIZE];
  size_t out_len = DSA_MAX_DER_SIZE;
  const uint8_t *sig;
  size_t sig_len;
  uint32_t size;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&sig, &sig_len) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[1], &size) == napi_ok);

  JS_ASSERT(dsa_sig_export(out, &out_len, sig, sig_len, size),
            JS_ERR_SIGNATURE);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_dsa_signature_import(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t out[DSA_MAX_SIG_SIZE];
  size_t out_len = DSA_MAX_SIG_SIZE;
  const uint8_t *der;
  size_t der_len;
  uint32_t size;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&der, &der_len) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[1], &size) == napi_ok);

  JS_ASSERT(dsa_sig_import(out, &out_len, der, der_len, size),
            JS_ERR_SIGNATURE);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_dsa_sign(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[DSA_MAX_SIG_SIZE];
  size_t out_len = DSA_MAX_SIG_SIZE;
  const uint8_t *msg, *key;
  size_t msg_len, key_len;
  uint8_t *entropy;
  size_t entropy_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&key, &key_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&entropy,
                             &entropy_len) == napi_ok);

  JS_ASSERT(entropy_len == ENTROPY_SIZE, JS_ERR_ENTROPY_SIZE);
  JS_ASSERT(dsa_sign(out, &out_len, msg, msg_len, key, key_len, entropy),
            JS_ERR_SIGN);

  cleanse(entropy, entropy_len);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_dsa_sign_der(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[DSA_MAX_DER_SIZE];
  size_t out_len = DSA_MAX_DER_SIZE;
  const uint8_t *msg, *key;
  size_t msg_len, key_len;
  uint8_t *entropy;
  size_t entropy_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&key, &key_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&entropy,
                             &entropy_len) == napi_ok);

  JS_ASSERT(entropy_len == ENTROPY_SIZE, JS_ERR_ENTROPY_SIZE);
  JS_ASSERT(dsa_sign(out, &out_len, msg, msg_len, key, key_len, entropy),
            JS_ERR_SIGN);

  CHECK(dsa_sig_export(out, &out_len, out, out_len, 0));

  cleanse(entropy, entropy_len);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_dsa_verify(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  const uint8_t *msg, *sig, *key;
  size_t msg_len, sig_len, key_len;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&sig, &sig_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&key, &key_len) == napi_ok);

  ok = dsa_verify(msg, msg_len, sig, sig_len, key, key_len);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_dsa_verify_der(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t sig[DSA_MAX_SIG_SIZE];
  size_t sig_len = DSA_MAX_SIG_SIZE;
  const uint8_t *msg, *der, *key;
  size_t msg_len, der_len, key_len, size;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&der, &der_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&key, &key_len) == napi_ok);

  size = (dsa_pubkey_qbits(key, key_len) + 7) / 8;

  ok = size > 0
    && dsa_sig_import(sig, &sig_len, der, der_len, size)
    && dsa_verify(msg, msg_len, sig, sig_len, key, key_len);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_dsa_derive(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t *out;
  size_t out_len;
  const uint8_t *pub, *priv;
  size_t pub_len, priv_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&pub, &pub_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&priv,
                             &priv_len) == napi_ok);

  out = (uint8_t *)safe_malloc(DSA_MAX_SIZE);
  out_len = DSA_MAX_SIZE;

  if (!dsa_derive(out, &out_len, pub, pub_len, priv, priv_len)) {
    safe_free(out);
    JS_THROW(JS_ERR_PUBKEY);
  }

  out = (uint8_t *)safe_realloc(out, out_len);

  CHECK(create_external_buffer(env, out_len, out, &result) == napi_ok);

  return result;
}

/*
 * ECDH
 */

static void
bcrypto_ecdh_destroy(napi_env env, void *data, void *hint) {
  bcrypto_ecdh_t *ec = (bcrypto_ecdh_t *)data;

  ecdh_context_destroy(ec->ctx);
  safe_free(ec);
}

static napi_value
bcrypto_ecdh_create(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  uint32_t type;
  bcrypto_ecdh_t *ec;
  ecdh_t *ctx;
  napi_value handle;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_value_uint32(env, argv[0], &type) == napi_ok);

  JS_ASSERT(ctx = ecdh_context_create(type), JS_ERR_CONTEXT);

  ec = (bcrypto_ecdh_t *)safe_malloc(sizeof(bcrypto_ecdh_t));
  ec->ctx = ctx;
  ec->scalar_size = ecdh_scalar_size(ec->ctx);
  ec->scalar_bits = ecdh_scalar_bits(ec->ctx);
  ec->field_size = ecdh_field_size(ec->ctx);
  ec->field_bits = ecdh_field_bits(ec->ctx);

  CHECK(napi_create_external(env,
                             ec,
                             bcrypto_ecdh_destroy,
                             NULL,
                             &handle) == napi_ok);

  return handle;
}

static napi_value
bcrypto_ecdh_size(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  bcrypto_ecdh_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_create_uint32(env, ec->field_size, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_ecdh_bits(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  bcrypto_ecdh_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_create_uint32(env, ec->field_bits, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_ecdh_privkey_generate(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t *entropy;
  size_t entropy_len;
  uint8_t out[ECDH_MAX_PRIV_SIZE];
  bcrypto_ecdh_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&entropy,
                             &entropy_len) == napi_ok);

  JS_ASSERT(entropy_len == ENTROPY_SIZE, JS_ERR_ENTROPY_SIZE);

  ecdh_privkey_generate(ec->ctx, out, entropy);

  cleanse(entropy, entropy_len);

  CHECK(napi_create_buffer_copy(env,
                                ec->scalar_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_ecdh_privkey_verify(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  const uint8_t *priv;
  size_t priv_len;
  bcrypto_ecdh_t *ec;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&priv,
                             &priv_len) == napi_ok);

  ok = priv_len == ec->scalar_size && ecdh_privkey_verify(ec->ctx, priv);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_ecdh_privkey_export(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t out[ECDH_MAX_PRIV_SIZE];
  const uint8_t *priv;
  size_t priv_len;
  bcrypto_ecdh_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&priv,
                             &priv_len) == napi_ok);

  JS_ASSERT(priv_len == ec->scalar_size, JS_ERR_PRIVKEY_SIZE);
  JS_ASSERT(ecdh_privkey_export(ec->ctx, out, priv), JS_ERR_PRIVKEY);

  CHECK(napi_create_buffer_copy(env,
                                ec->scalar_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_ecdh_privkey_import(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t out[ECDH_MAX_PRIV_SIZE];
  const uint8_t *priv;
  size_t priv_len;
  bcrypto_ecdh_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&priv,
                             &priv_len) == napi_ok);

  JS_ASSERT(ecdh_privkey_import(ec->ctx, out, priv, priv_len),
            JS_ERR_PRIVKEY);

  CHECK(napi_create_buffer_copy(env,
                                ec->scalar_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_ecdh_pubkey_create(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t out[ECDH_MAX_PUB_SIZE];
  const uint8_t *priv;
  size_t priv_len;
  bcrypto_ecdh_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&priv,
                             &priv_len) == napi_ok);

  JS_ASSERT(priv_len == ec->scalar_size, JS_ERR_PRIVKEY_SIZE);

  ecdh_pubkey_create(ec->ctx, out, priv);

  CHECK(napi_create_buffer_copy(env,
                                ec->field_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_ecdh_pubkey_convert(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[EDDSA_MAX_PUB_SIZE];
  size_t out_len;
  const uint8_t *pub;
  size_t pub_len;
  int32_t sign;
  bcrypto_ecdh_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pub, &pub_len) == napi_ok);
  CHECK(napi_get_value_int32(env, argv[2], &sign) == napi_ok);

  JS_ASSERT(pub_len == ec->field_size, JS_ERR_PUBKEY_SIZE);
  JS_ASSERT(ecdh_pubkey_convert(ec->ctx, out, pub, sign), JS_ERR_PUBKEY);

  out_len = ec->field_size + ((ec->field_bits & 7) == 0);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_ecdh_pubkey_from_uniform(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t out[ECDH_MAX_PUB_SIZE];
  const uint8_t *data;
  size_t data_len;
  bcrypto_ecdh_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&data,
                             &data_len) == napi_ok);

  JS_ASSERT(data_len == ec->field_size, JS_ERR_PREIMAGE_SIZE);

  ecdh_pubkey_from_uniform(ec->ctx, out, data);

  CHECK(napi_create_buffer_copy(env,
                                ec->field_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_ecdh_pubkey_to_uniform(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[ECDH_MAX_FIELD_SIZE];
  const uint8_t *pub;
  size_t pub_len;
  uint32_t hint;
  bcrypto_ecdh_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pub,
                             &pub_len) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[2], &hint) == napi_ok);

  JS_ASSERT(pub_len == ec->field_size, JS_ERR_PUBKEY_SIZE);
  JS_ASSERT(ecdh_pubkey_to_uniform(ec->ctx, out, pub, hint), JS_ERR_PUBKEY);

  CHECK(napi_create_buffer_copy(env, ec->field_size,
                                out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_ecdh_pubkey_from_hash(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[ECDH_MAX_PUB_SIZE];
  const uint8_t *data;
  size_t data_len;
  bool pake;
  bcrypto_ecdh_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&data,
                             &data_len) == napi_ok);
  CHECK(napi_get_value_bool(env, argv[2], &pake) == napi_ok);

  JS_ASSERT(data_len == ec->field_size * 2, JS_ERR_PREIMAGE_SIZE);
  JS_ASSERT(ecdh_pubkey_from_hash(ec->ctx, out, data, pake), JS_ERR_PREIMAGE);

  CHECK(napi_create_buffer_copy(env,
                                ec->field_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_ecdh_pubkey_to_hash(napi_env env, napi_callback_info info) {
  napi_value argv[4];
  size_t argc = 4;
  uint8_t out[ECDH_MAX_FIELD_SIZE * 2];
  const uint8_t *pub;
  uint32_t subgroup;
  uint8_t *entropy;
  size_t pub_len, entropy_len;
  bcrypto_ecdh_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 4);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pub,
                             &pub_len) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[2], &subgroup) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[3], (void **)&entropy,
                             &entropy_len) == napi_ok);

  JS_ASSERT(pub_len == ec->field_size, JS_ERR_PUBKEY_SIZE);
  JS_ASSERT(entropy_len == ENTROPY_SIZE, JS_ERR_ENTROPY_SIZE);
  JS_ASSERT(ecdh_pubkey_to_hash(ec->ctx, out, pub, subgroup, entropy),
            JS_ERR_PUBKEY);

  cleanse(entropy, entropy_len);

  CHECK(napi_create_buffer_copy(env, ec->field_size * 2,
                                out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_ecdh_pubkey_verify(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  const uint8_t *pub;
  size_t pub_len;
  bcrypto_ecdh_t *ec;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pub,
                             &pub_len) == napi_ok);

  ok = pub_len == ec->field_size && ecdh_pubkey_verify(ec->ctx, pub);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_ecdh_pubkey_export(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t x[ECDH_MAX_FIELD_SIZE];
  uint8_t y[ECDH_MAX_FIELD_SIZE];
  const uint8_t *pub;
  size_t pub_len;
  int32_t sign;
  bcrypto_ecdh_t *ec;
  napi_value bx, by, result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pub,
                             &pub_len) == napi_ok);
  CHECK(napi_get_value_int32(env, argv[2], &sign) == napi_ok);

  JS_ASSERT(pub_len == ec->field_size, JS_ERR_PUBKEY_SIZE);
  JS_ASSERT(ecdh_pubkey_export(ec->ctx, x, y, pub, sign), JS_ERR_PUBKEY);

  CHECK(napi_create_buffer_copy(env, ec->field_size, x, NULL, &bx) == napi_ok);
  CHECK(napi_create_buffer_copy(env, ec->field_size, y, NULL, &by) == napi_ok);

  CHECK(napi_create_array_with_length(env, 2, &result) == napi_ok);
  CHECK(napi_set_element(env, result, 0, bx) == napi_ok);
  CHECK(napi_set_element(env, result, 1, by) == napi_ok);

  return result;
}

static napi_value
bcrypto_ecdh_pubkey_import(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t out[ECDH_MAX_PUB_SIZE];
  const uint8_t *x;
  size_t x_len;
  bcrypto_ecdh_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&x, &x_len) == napi_ok);

  JS_ASSERT(ecdh_pubkey_import(ec->ctx, out, x, x_len), JS_ERR_PUBKEY);

  CHECK(napi_create_buffer_copy(env,
                                ec->field_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_ecdh_pubkey_is_small(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  const uint8_t *pub;
  size_t pub_len;
  bcrypto_ecdh_t *ec;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pub,
                             &pub_len) == napi_ok);

  ok = pub_len == ec->field_size && ecdh_pubkey_is_small(ec->ctx, pub);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_ecdh_pubkey_has_torsion(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  const uint8_t *pub;
  size_t pub_len;
  bcrypto_ecdh_t *ec;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pub,
                             &pub_len) == napi_ok);

  ok = pub_len == ec->field_size && ecdh_pubkey_has_torsion(ec->ctx, pub);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_ecdh_derive(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[ECDH_MAX_PUB_SIZE];
  const uint8_t *pub, *priv;
  size_t pub_len, priv_len;
  bcrypto_ecdh_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pub, &pub_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&priv,
                             &priv_len) == napi_ok);

  JS_ASSERT(pub_len == ec->field_size, JS_ERR_PUBKEY_SIZE);
  JS_ASSERT(priv_len == ec->scalar_size, JS_ERR_PRIVKEY_SIZE);
  JS_ASSERT(ecdh_derive(ec->ctx, out, pub, priv), JS_ERR_PUBKEY);

  CHECK(napi_create_buffer_copy(env,
                                ec->field_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

/*
 * ECDSA
 */

static void
bcrypto_ecdsa_destroy(napi_env env, void *data, void *hint) {
  bcrypto_ecdsa_t *ec = (bcrypto_ecdsa_t *)data;

  ecdsa_scratch_destroy(ec->ctx, ec->scratch);
  ecdsa_context_destroy(ec->ctx);
  safe_free(ec);
}

static napi_value
bcrypto_ecdsa_create(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  uint32_t type;
  bcrypto_ecdsa_t *ec;
  ecdsa_t *ctx;
  napi_value handle;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_value_uint32(env, argv[0], &type) == napi_ok);

  JS_ASSERT(ctx = ecdsa_context_create(type), JS_ERR_CONTEXT);

  ec = (bcrypto_ecdsa_t *)safe_malloc(sizeof(bcrypto_ecdsa_t));
  ec->ctx = ctx;
  ec->scratch = ecdsa_scratch_create(ec->ctx);
  ec->scalar_size = ecdsa_scalar_size(ec->ctx);
  ec->scalar_bits = ecdsa_scalar_bits(ec->ctx);
  ec->field_size = ecdsa_field_size(ec->ctx);
  ec->field_bits = ecdsa_field_bits(ec->ctx);
  ec->sig_size = ecdsa_sig_size(ec->ctx);
  ec->schnorr_size = ecdsa_schnorr_size(ec->ctx);

  CHECK(ec->scratch != NULL);

  CHECK(napi_create_external(env,
                             ec,
                             bcrypto_ecdsa_destroy,
                             NULL,
                             &handle) == napi_ok);

  return handle;
}

static napi_value
bcrypto_ecdsa_size(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  bcrypto_ecdsa_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_create_uint32(env, ec->field_size, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_ecdsa_bits(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  bcrypto_ecdsa_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_create_uint32(env, ec->field_bits, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_ecdsa_randomize(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t *entropy;
  size_t entropy_len;
  bcrypto_ecdsa_t *ec;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&entropy,
                             &entropy_len) == napi_ok);

  JS_ASSERT(entropy_len == ENTROPY_SIZE, JS_ERR_ENTROPY_SIZE);

  ecdsa_context_randomize(ec->ctx, entropy);

  cleanse(entropy, entropy_len);

  return argv[0];
}

static napi_value
bcrypto_ecdsa_privkey_generate(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t *entropy;
  size_t entropy_len;
  uint8_t out[ECDSA_MAX_PRIV_SIZE];
  bcrypto_ecdsa_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&entropy,
                             &entropy_len) == napi_ok);

  JS_ASSERT(entropy_len == ENTROPY_SIZE, JS_ERR_ENTROPY_SIZE);

  ecdsa_privkey_generate(ec->ctx, out, entropy);

  cleanse(entropy, entropy_len);

  CHECK(napi_create_buffer_copy(env,
                                ec->scalar_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_ecdsa_privkey_verify(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  const uint8_t *priv;
  size_t priv_len;
  bcrypto_ecdsa_t *ec;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&priv,
                             &priv_len) == napi_ok);

  ok = priv_len == ec->scalar_size && ecdsa_privkey_verify(ec->ctx, priv);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_ecdsa_privkey_export(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t out[ECDSA_MAX_PRIV_SIZE];
  const uint8_t *priv;
  size_t priv_len;
  bcrypto_ecdsa_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&priv,
                             &priv_len) == napi_ok);

  JS_ASSERT(priv_len == ec->scalar_size, JS_ERR_PRIVKEY_SIZE);
  JS_ASSERT(ecdsa_privkey_export(ec->ctx, out, priv), JS_ERR_PRIVKEY);

  CHECK(napi_create_buffer_copy(env,
                                ec->scalar_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_ecdsa_privkey_import(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t out[ECDSA_MAX_PRIV_SIZE];
  const uint8_t *priv;
  size_t priv_len;
  bcrypto_ecdsa_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&priv,
                             &priv_len) == napi_ok);

  JS_ASSERT(ecdsa_privkey_import(ec->ctx, out, priv, priv_len), JS_ERR_PRIVKEY);

  CHECK(napi_create_buffer_copy(env,
                                ec->scalar_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_ecdsa_privkey_tweak_add(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[ECDSA_MAX_PRIV_SIZE];
  const uint8_t *priv, *tweak;
  size_t priv_len, tweak_len;
  bcrypto_ecdsa_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&priv,
                             &priv_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&tweak,
                             &tweak_len) == napi_ok);

  JS_ASSERT(priv_len == ec->scalar_size, JS_ERR_PRIVKEY_SIZE);
  JS_ASSERT(tweak_len == ec->scalar_size, JS_ERR_SCALAR_SIZE);
  JS_ASSERT(ecdsa_privkey_tweak_add(ec->ctx, out, priv, tweak), JS_ERR_PRIVKEY);

  CHECK(napi_create_buffer_copy(env,
                                ec->scalar_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_ecdsa_privkey_tweak_mul(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[ECDSA_MAX_PRIV_SIZE];
  const uint8_t *priv, *tweak;
  size_t priv_len, tweak_len;
  bcrypto_ecdsa_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&priv,
                             &priv_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&tweak,
                             &tweak_len) == napi_ok);

  JS_ASSERT(priv_len == ec->scalar_size, JS_ERR_PRIVKEY_SIZE);
  JS_ASSERT(tweak_len == ec->scalar_size, JS_ERR_SCALAR_SIZE);
  JS_ASSERT(ecdsa_privkey_tweak_mul(ec->ctx, out, priv, tweak), JS_ERR_PRIVKEY);

  CHECK(napi_create_buffer_copy(env,
                                ec->scalar_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_ecdsa_privkey_reduce(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t out[ECDSA_MAX_PRIV_SIZE];
  const uint8_t *priv;
  size_t priv_len;
  bcrypto_ecdsa_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&priv,
                             &priv_len) == napi_ok);

  JS_ASSERT(ecdsa_privkey_reduce(ec->ctx, out, priv, priv_len), JS_ERR_PRIVKEY);

  CHECK(napi_create_buffer_copy(env,
                                ec->scalar_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_ecdsa_privkey_negate(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t out[ECDSA_MAX_PRIV_SIZE];
  const uint8_t *priv;
  size_t priv_len;
  bcrypto_ecdsa_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&priv,
                             &priv_len) == napi_ok);

  JS_ASSERT(priv_len == ec->scalar_size, JS_ERR_PRIVKEY_SIZE);
  JS_ASSERT(ecdsa_privkey_negate(ec->ctx, out, priv), JS_ERR_PRIVKEY);

  CHECK(napi_create_buffer_copy(env,
                                ec->scalar_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_ecdsa_privkey_invert(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t out[ECDSA_MAX_PRIV_SIZE];
  const uint8_t *priv;
  size_t priv_len;
  bcrypto_ecdsa_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&priv,
                             &priv_len) == napi_ok);

  JS_ASSERT(priv_len == ec->scalar_size, JS_ERR_PRIVKEY_SIZE);
  JS_ASSERT(ecdsa_privkey_invert(ec->ctx, out, priv), JS_ERR_PRIVKEY);

  CHECK(napi_create_buffer_copy(env,
                                ec->scalar_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_ecdsa_pubkey_create(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[ECDSA_MAX_PUB_SIZE];
  size_t out_len = ECDSA_MAX_PUB_SIZE;
  const uint8_t *priv;
  size_t priv_len;
  bool compress;
  bcrypto_ecdsa_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&priv,
                             &priv_len) == napi_ok);
  CHECK(napi_get_value_bool(env, argv[2], &compress) == napi_ok);

  JS_ASSERT(priv_len == ec->scalar_size, JS_ERR_PRIVKEY_SIZE);
  JS_ASSERT(ecdsa_pubkey_create(ec->ctx, out, &out_len, priv, compress),
            JS_ERR_PRIVKEY);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_ecdsa_pubkey_convert(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[ECDSA_MAX_PUB_SIZE];
  size_t out_len = ECDSA_MAX_PUB_SIZE;
  const uint8_t *pub;
  size_t pub_len;
  bool compress;
  bcrypto_ecdsa_t *ec;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pub,
                             &pub_len) == napi_ok);
  CHECK(napi_get_value_bool(env, argv[2], &compress) == napi_ok);

  ok = ecdsa_pubkey_convert(ec->ctx, out, &out_len, pub, pub_len, compress);

  JS_ASSERT(ok, JS_ERR_PUBKEY);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_ecdsa_pubkey_from_uniform(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[ECDSA_MAX_PUB_SIZE];
  size_t out_len = ECDSA_MAX_PUB_SIZE;
  const uint8_t *data;
  size_t data_len;
  bool compress;
  bcrypto_ecdsa_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&data,
                             &data_len) == napi_ok);
  CHECK(napi_get_value_bool(env, argv[2], &compress) == napi_ok);

  JS_ASSERT(data_len == ec->field_size, JS_ERR_PREIMAGE_SIZE);

  ecdsa_pubkey_from_uniform(ec->ctx, out, &out_len, data, compress);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_ecdsa_pubkey_to_uniform(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[ECDSA_MAX_FIELD_SIZE];
  const uint8_t *pub;
  size_t pub_len;
  uint32_t hint;
  bcrypto_ecdsa_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pub,
                             &pub_len) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[2], &hint) == napi_ok);

  JS_ASSERT(ecdsa_pubkey_to_uniform(ec->ctx, out, pub, pub_len, hint),
            JS_ERR_PUBKEY);

  CHECK(napi_create_buffer_copy(env, ec->field_size,
                                out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_ecdsa_pubkey_from_hash(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[ECDSA_MAX_PUB_SIZE];
  size_t out_len = ECDSA_MAX_PUB_SIZE;
  const uint8_t *data;
  size_t data_len;
  bool compress;
  bcrypto_ecdsa_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&data,
                             &data_len) == napi_ok);
  CHECK(napi_get_value_bool(env, argv[2], &compress) == napi_ok);

  JS_ASSERT(data_len == ec->field_size * 2, JS_ERR_PREIMAGE_SIZE);
  JS_ASSERT(ecdsa_pubkey_from_hash(ec->ctx, out, &out_len, data, compress),
            JS_ERR_PREIMAGE);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_ecdsa_pubkey_to_hash(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[ECDSA_MAX_FIELD_SIZE * 2];
  const uint8_t *pub;
  uint8_t *entropy;
  size_t pub_len, entropy_len;
  bcrypto_ecdsa_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pub,
                             &pub_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&entropy,
                             &entropy_len) == napi_ok);

  JS_ASSERT(entropy_len == ENTROPY_SIZE, JS_ERR_ENTROPY_SIZE);
  JS_ASSERT(ecdsa_pubkey_to_hash(ec->ctx, out, pub, pub_len, 0, entropy),
            JS_ERR_PUBKEY);

  cleanse(entropy, entropy_len);

  CHECK(napi_create_buffer_copy(env, ec->field_size * 2,
                                out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_ecdsa_pubkey_verify(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  const uint8_t *pub;
  size_t pub_len;
  bcrypto_ecdsa_t *ec;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pub,
                             &pub_len) == napi_ok);

  ok = ecdsa_pubkey_verify(ec->ctx, pub, pub_len);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_ecdsa_pubkey_export(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t x[ECDSA_MAX_FIELD_SIZE];
  uint8_t y[ECDSA_MAX_FIELD_SIZE];
  const uint8_t *pub;
  size_t pub_len;
  bcrypto_ecdsa_t *ec;
  napi_value bx, by, result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pub,
                             &pub_len) == napi_ok);

  JS_ASSERT(ecdsa_pubkey_export(ec->ctx, x, y, pub, pub_len), JS_ERR_PUBKEY);

  CHECK(napi_create_buffer_copy(env, ec->field_size, x, NULL, &bx) == napi_ok);
  CHECK(napi_create_buffer_copy(env, ec->field_size, y, NULL, &by) == napi_ok);

  CHECK(napi_create_array_with_length(env, 2, &result) == napi_ok);
  CHECK(napi_set_element(env, result, 0, bx) == napi_ok);
  CHECK(napi_set_element(env, result, 1, by) == napi_ok);

  return result;
}

static napi_value
bcrypto_ecdsa_pubkey_import(napi_env env, napi_callback_info info) {
  napi_value argv[5];
  size_t argc = 5;
  uint8_t out[ECDSA_MAX_PUB_SIZE];
  size_t out_len = ECDSA_MAX_PUB_SIZE;
  const uint8_t *x, *y;
  size_t x_len, y_len;
  int32_t sign;
  bool compress;
  bcrypto_ecdsa_t *ec;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 5);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&x, &x_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&y, &y_len) == napi_ok);
  CHECK(napi_get_value_int32(env, argv[3], &sign) == napi_ok);
  CHECK(napi_get_value_bool(env, argv[4], &compress) == napi_ok);

  ok = ecdsa_pubkey_import(ec->ctx, out, &out_len,
                           x, x_len, y, y_len, sign,
                           compress);

  JS_ASSERT(ok, JS_ERR_PUBKEY);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_ecdsa_pubkey_tweak_add(napi_env env, napi_callback_info info) {
  napi_value argv[4];
  size_t argc = 4;
  uint8_t out[ECDSA_MAX_PUB_SIZE];
  size_t out_len = ECDSA_MAX_PUB_SIZE;
  const uint8_t *pub, *tweak;
  size_t pub_len, tweak_len;
  bool compress;
  bcrypto_ecdsa_t *ec;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 4);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pub,
                             &pub_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&tweak,
                             &tweak_len) == napi_ok);
  CHECK(napi_get_value_bool(env, argv[3], &compress) == napi_ok);

  JS_ASSERT(tweak_len == ec->scalar_size, JS_ERR_SCALAR_SIZE);

  ok = ecdsa_pubkey_tweak_add(ec->ctx, out, &out_len,
                              pub, pub_len, tweak, compress);

  JS_ASSERT(ok, JS_ERR_PUBKEY);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_ecdsa_pubkey_tweak_mul(napi_env env, napi_callback_info info) {
  napi_value argv[4];
  size_t argc = 4;
  uint8_t out[ECDSA_MAX_PUB_SIZE];
  size_t out_len = ECDSA_MAX_PUB_SIZE;
  const uint8_t *pub, *tweak;
  size_t pub_len, tweak_len;
  bool compress;
  bcrypto_ecdsa_t *ec;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 4);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pub,
                             &pub_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&tweak,
                             &tweak_len) == napi_ok);
  CHECK(napi_get_value_bool(env, argv[3], &compress) == napi_ok);

  JS_ASSERT(tweak_len == ec->scalar_size, JS_ERR_SCALAR_SIZE);

  ok = ecdsa_pubkey_tweak_mul(ec->ctx, out, &out_len,
                              pub, pub_len, tweak, compress);

  JS_ASSERT(ok, JS_ERR_PUBKEY);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_ecdsa_pubkey_combine(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[ECDSA_MAX_PUB_SIZE];
  size_t out_len = ECDSA_MAX_PUB_SIZE;
  uint32_t i, length;
  const uint8_t **pubs;
  size_t *pub_lens;
  bool compress;
  bcrypto_ecdsa_t *ec;
  napi_value item, result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_array_length(env, argv[1], &length) == napi_ok);
  CHECK(napi_get_value_bool(env, argv[2], &compress) == napi_ok);

  pubs = (const uint8_t **)safe_malloc(length * sizeof(uint8_t *));
  pub_lens = (size_t *)safe_malloc(length * sizeof(size_t));

  for (i = 0; i < length; i++) {
    CHECK(napi_get_element(env, argv[1], i, &item) == napi_ok);
    CHECK(napi_get_buffer_info(env, item, (void **)&pubs[i],
                               &pub_lens[i]) == napi_ok);
  }

  ok = ecdsa_pubkey_combine(ec->ctx, out, &out_len,
                            pubs, pub_lens, length,
                            compress);

  safe_free(pubs);
  safe_free(pub_lens);

  JS_ASSERT(ok, JS_ERR_PUBKEY);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_ecdsa_pubkey_negate(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[ECDSA_MAX_PUB_SIZE];
  size_t out_len = ECDSA_MAX_PUB_SIZE;
  const uint8_t *pub;
  size_t pub_len;
  bool compress;
  bcrypto_ecdsa_t *ec;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pub,
                             &pub_len) == napi_ok);
  CHECK(napi_get_value_bool(env, argv[2], &compress) == napi_ok);

  ok = ecdsa_pubkey_negate(ec->ctx, out, &out_len, pub, pub_len, compress);

  JS_ASSERT(ok, JS_ERR_PUBKEY);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_ecdsa_signature_normalize(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t out[ECDSA_MAX_SIG_SIZE];
  const uint8_t *sig;
  size_t sig_len;
  bcrypto_ecdsa_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&sig,
                             &sig_len) == napi_ok);

  JS_ASSERT(sig_len == ec->sig_size, JS_ERR_SIGNATURE_SIZE);
  JS_ASSERT(ecdsa_sig_normalize(ec->ctx, out, sig), JS_ERR_SIGNATURE);

  CHECK(napi_create_buffer_copy(env,
                                ec->sig_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_ecdsa_signature_normalize_der(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t out[ECDSA_MAX_DER_SIZE];
  size_t out_len = ECDSA_MAX_DER_SIZE;
  const uint8_t *sig;
  size_t sig_len;
  bcrypto_ecdsa_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&sig,
                             &sig_len) == napi_ok);

  JS_ASSERT(ecdsa_sig_import_lax(ec->ctx, out, sig, sig_len), JS_ERR_SIGNATURE);
  JS_ASSERT(ecdsa_sig_normalize(ec->ctx, out, out), JS_ERR_SIGNATURE);
  JS_ASSERT(ecdsa_sig_export(ec->ctx, out, &out_len, out), JS_ERR_SIGNATURE);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_ecdsa_signature_export(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t out[ECDSA_MAX_DER_SIZE];
  size_t out_len = ECDSA_MAX_DER_SIZE;
  const uint8_t *sig;
  size_t sig_len;
  bcrypto_ecdsa_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&sig,
                             &sig_len) == napi_ok);

  JS_ASSERT(sig_len == ec->sig_size, JS_ERR_SIGNATURE_SIZE);
  JS_ASSERT(ecdsa_sig_export(ec->ctx, out, &out_len, sig), JS_ERR_SIGNATURE);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_ecdsa_signature_import(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t out[ECDSA_MAX_SIG_SIZE];
  const uint8_t *sig;
  size_t sig_len;
  bcrypto_ecdsa_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&sig,
                             &sig_len) == napi_ok);

  JS_ASSERT(ecdsa_sig_import_lax(ec->ctx, out, sig, sig_len), JS_ERR_SIGNATURE);

  CHECK(napi_create_buffer_copy(env,
                                ec->sig_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_ecdsa_is_low_s(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  const uint8_t *sig;
  size_t sig_len;
  bcrypto_ecdsa_t *ec;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&sig,
                             &sig_len) == napi_ok);

  ok = sig_len == ec->sig_size && ecdsa_is_low_s(ec->ctx, sig);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_ecdsa_is_low_der(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t tmp[ECDSA_MAX_SIG_SIZE];
  const uint8_t *sig;
  size_t sig_len;
  bcrypto_ecdsa_t *ec;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&sig,
                             &sig_len) == napi_ok);

  ok = ecdsa_sig_import_lax(ec->ctx, tmp, sig, sig_len)
    && ecdsa_is_low_s(ec->ctx, tmp);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_ecdsa_sign(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[ECDSA_MAX_SIG_SIZE];
  const uint8_t *msg, *priv;
  size_t msg_len, priv_len;
  bcrypto_ecdsa_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&priv,
                             &priv_len) == napi_ok);

  JS_ASSERT(priv_len == ec->scalar_size, JS_ERR_PRIVKEY_SIZE);
  JS_ASSERT(ecdsa_sign(ec->ctx, out, NULL, msg, msg_len, priv), JS_ERR_SIGN);

  CHECK(napi_create_buffer_copy(env,
                                ec->sig_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_ecdsa_sign_recoverable(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[ECDSA_MAX_SIG_SIZE];
  unsigned int param;
  const uint8_t *msg, *priv;
  size_t msg_len, priv_len;
  bcrypto_ecdsa_t *ec;
  napi_value sigval, paramval, result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&priv,
                             &priv_len) == napi_ok);

  JS_ASSERT(priv_len == ec->scalar_size, JS_ERR_PRIVKEY_SIZE);
  JS_ASSERT(ecdsa_sign(ec->ctx, out, &param, msg, msg_len, priv), JS_ERR_SIGN);

  CHECK(napi_create_buffer_copy(env,
                                ec->sig_size,
                                out,
                                NULL,
                                &sigval) == napi_ok);

  CHECK(napi_create_uint32(env, param, &paramval) == napi_ok);

  CHECK(napi_create_array_with_length(env, 2, &result) == napi_ok);
  CHECK(napi_set_element(env, result, 0, sigval) == napi_ok);
  CHECK(napi_set_element(env, result, 1, paramval) == napi_ok);

  return result;
}

static napi_value
bcrypto_ecdsa_sign_der(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[ECDSA_MAX_DER_SIZE];
  size_t out_len = ECDSA_MAX_DER_SIZE;
  const uint8_t *msg, *priv;
  size_t msg_len, priv_len;
  bcrypto_ecdsa_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&priv,
                             &priv_len) == napi_ok);

  JS_ASSERT(priv_len == ec->scalar_size, JS_ERR_PRIVKEY_SIZE);
  JS_ASSERT(ecdsa_sign(ec->ctx, out, NULL, msg, msg_len, priv), JS_ERR_SIGN);
  JS_ASSERT(ecdsa_sig_export(ec->ctx, out, &out_len, out), JS_ERR_SIGN);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_ecdsa_sign_recoverable_der(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[ECDSA_MAX_DER_SIZE];
  size_t out_len = ECDSA_MAX_DER_SIZE;
  unsigned int param;
  const uint8_t *msg, *priv;
  size_t msg_len, priv_len;
  bcrypto_ecdsa_t *ec;
  napi_value sigval, paramval, result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&priv,
                             &priv_len) == napi_ok);

  JS_ASSERT(priv_len == ec->scalar_size, JS_ERR_PRIVKEY_SIZE);
  JS_ASSERT(ecdsa_sign(ec->ctx, out, &param, msg, msg_len, priv), JS_ERR_SIGN);
  JS_ASSERT(ecdsa_sig_export(ec->ctx, out, &out_len, out), JS_ERR_SIGN);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &sigval) == napi_ok);
  CHECK(napi_create_uint32(env, param, &paramval) == napi_ok);

  CHECK(napi_create_array_with_length(env, 2, &result) == napi_ok);
  CHECK(napi_set_element(env, result, 0, sigval) == napi_ok);
  CHECK(napi_set_element(env, result, 1, paramval) == napi_ok);

  return result;
}

static napi_value
bcrypto_ecdsa_verify(napi_env env, napi_callback_info info) {
  napi_value argv[4];
  size_t argc = 4;
  uint8_t tmp[ECDSA_MAX_SIG_SIZE];
  const uint8_t *msg, *sig, *pub;
  size_t msg_len, sig_len, pub_len;
  bcrypto_ecdsa_t *ec;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 4);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&sig, &sig_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[3], (void **)&pub, &pub_len) == napi_ok);

  ok = sig_len == ec->sig_size
    && ecdsa_sig_normalize(ec->ctx, tmp, sig)
    && ecdsa_verify(ec->ctx, msg, msg_len, tmp, pub, pub_len);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_ecdsa_verify_der(napi_env env, napi_callback_info info) {
  napi_value argv[4];
  size_t argc = 4;
  uint8_t tmp[ECDSA_MAX_SIG_SIZE];
  const uint8_t *msg, *sig, *pub;
  size_t msg_len, sig_len, pub_len;
  bcrypto_ecdsa_t *ec;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 4);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&sig, &sig_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[3], (void **)&pub, &pub_len) == napi_ok);

  ok = ecdsa_sig_import_lax(ec->ctx, tmp, sig, sig_len)
    && ecdsa_sig_normalize(ec->ctx, tmp, tmp)
    && ecdsa_verify(ec->ctx, msg, msg_len, tmp, pub, pub_len);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_ecdsa_recover(napi_env env, napi_callback_info info) {
  napi_value argv[5];
  size_t argc = 5;
  uint8_t tmp[ECDSA_MAX_SIG_SIZE];
  uint8_t out[ECDSA_MAX_PUB_SIZE];
  size_t out_len = ECDSA_MAX_PUB_SIZE;
  const uint8_t *msg, *sig;
  size_t msg_len, sig_len;
  uint32_t parm;
  bool compress;
  bcrypto_ecdsa_t *ec;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 5);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&sig, &sig_len) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[3], &parm) == napi_ok);
  CHECK(napi_get_value_bool(env, argv[4], &compress) == napi_ok);

  JS_ASSERT((parm & 3) == parm, JS_ERR_RECOVERY_PARAM);

  ok = sig_len == ec->sig_size
    && ecdsa_sig_normalize(ec->ctx, tmp, sig)
    && ecdsa_recover(ec->ctx, out, &out_len, msg, msg_len, tmp, parm, compress);

  if (ok)
    CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);
  else
    CHECK(napi_get_null(env, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_ecdsa_recover_der(napi_env env, napi_callback_info info) {
  napi_value argv[5];
  size_t argc = 5;
  uint8_t tmp[ECDSA_MAX_SIG_SIZE];
  uint8_t out[ECDSA_MAX_PUB_SIZE];
  size_t out_len = ECDSA_MAX_PUB_SIZE;
  const uint8_t *msg, *sig;
  size_t msg_len, sig_len;
  uint32_t parm;
  bool compress;
  bcrypto_ecdsa_t *ec;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 5);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&sig, &sig_len) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[3], &parm) == napi_ok);
  CHECK(napi_get_value_bool(env, argv[4], &compress) == napi_ok);

  JS_ASSERT((parm & 3) == parm, JS_ERR_RECOVERY_PARAM);

  ok = ecdsa_sig_import_lax(ec->ctx, tmp, sig, sig_len)
    && ecdsa_sig_normalize(ec->ctx, tmp, tmp)
    && ecdsa_recover(ec->ctx, out, &out_len, msg, msg_len, tmp, parm, compress);

  if (ok)
    CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);
  else
    CHECK(napi_get_null(env, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_ecdsa_derive(napi_env env, napi_callback_info info) {
  napi_value argv[4];
  size_t argc = 4;
  uint8_t out[ECDSA_MAX_PUB_SIZE];
  size_t out_len = ECDSA_MAX_PUB_SIZE;
  const uint8_t *pub, *priv;
  size_t pub_len, priv_len;
  bool compress;
  bcrypto_ecdsa_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 4);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pub, &pub_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&priv,
                             &priv_len) == napi_ok);
  CHECK(napi_get_value_bool(env, argv[3], &compress) == napi_ok);

  JS_ASSERT(priv_len == ec->scalar_size, JS_ERR_PRIVKEY_SIZE);
  JS_ASSERT(ecdsa_derive(ec->ctx, out, &out_len, pub, pub_len, priv, compress),
            JS_ERR_PUBKEY);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_ecdsa_schnorr_sign(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[ECDSA_MAX_SCHNORR_SIZE];
  const uint8_t *msg, *priv;
  size_t msg_len, priv_len;
  bcrypto_ecdsa_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&priv,
                             &priv_len) == napi_ok);

  JS_ASSERT(ecdsa_schnorr_support(ec->ctx), JS_ERR_NO_SCHNORR);
  JS_ASSERT(priv_len == ec->scalar_size, JS_ERR_PRIVKEY_SIZE);
  JS_ASSERT(ecdsa_schnorr_sign(ec->ctx, out, msg, msg_len, priv), JS_ERR_SIGN);

  CHECK(napi_create_buffer_copy(env,
                                ec->schnorr_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_ecdsa_schnorr_verify(napi_env env, napi_callback_info info) {
  napi_value argv[4];
  size_t argc = 4;
  const uint8_t *msg, *sig, *pub;
  size_t msg_len, sig_len, pub_len;
  bcrypto_ecdsa_t *ec;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 4);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&sig, &sig_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[3], (void **)&pub, &pub_len) == napi_ok);

  JS_ASSERT(ecdsa_schnorr_support(ec->ctx), JS_ERR_NO_SCHNORR);

  ok = sig_len == ec->schnorr_size
    && ecdsa_schnorr_verify(ec->ctx, msg, msg_len, sig, pub, pub_len);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_ecdsa_schnorr_verify_batch(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint32_t i, length, item_len;
  const uint8_t **ptrs, **msgs, **pubs, **sigs;
  size_t *lens, *msg_lens, *pub_lens;
  size_t sig_len;
  bcrypto_ecdsa_t *ec;
  napi_value item, result;
  napi_value items[3];
  int ok = 0;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_array_length(env, argv[1], &length) == napi_ok);

  JS_ASSERT(ecdsa_schnorr_support(ec->ctx), JS_ERR_NO_SCHNORR);

  if (length == 0) {
    CHECK(napi_get_boolean(env, true, &result) == napi_ok);
    return result;
  }

  ptrs = (const uint8_t **)safe_malloc(3 * length * sizeof(uint8_t *));
  lens = (size_t *)safe_malloc(2 * length * sizeof(size_t));
  msgs = &ptrs[length * 0];
  pubs = &ptrs[length * 1];
  sigs = &ptrs[length * 2];
  msg_lens = &lens[length * 0];
  pub_lens = &lens[length * 1];

  memset(items, 0, sizeof(items));

  for (i = 0; i < length; i++) {
    CHECK(napi_get_element(env, argv[1], i, &item) == napi_ok);
    CHECK(napi_get_array_length(env, item, &item_len) == napi_ok);
    CHECK(item_len == 3);

    CHECK(napi_get_element(env, item, 0, &items[0]) == napi_ok);
    CHECK(napi_get_element(env, item, 1, &items[1]) == napi_ok);
    CHECK(napi_get_element(env, item, 2, &items[2]) == napi_ok);

    CHECK(napi_get_buffer_info(env, items[0], (void **)&msgs[i],
                               &msg_lens[i]) == napi_ok);

    CHECK(napi_get_buffer_info(env, items[1], (void **)&sigs[i],
                               &sig_len) == napi_ok);

    CHECK(napi_get_buffer_info(env, items[2], (void **)&pubs[i],
                               &pub_lens[i]) == napi_ok);

    if (sig_len != ec->schnorr_size)
      goto fail;
  }

  ok = ecdsa_schnorr_verify_batch(ec->ctx, msgs, msg_lens, sigs,
                                  pubs, pub_lens, length, ec->scratch);

fail:
  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  safe_free(ptrs);
  safe_free(lens);

  return result;
}

/*
 * EdDSA
 */

static void
bcrypto_eddsa_destroy(napi_env env, void *data, void *hint) {
  bcrypto_eddsa_t *ec = (bcrypto_eddsa_t *)data;

  eddsa_scratch_destroy(ec->ctx, ec->scratch);
  eddsa_context_destroy(ec->ctx);
  safe_free(ec);
}

static napi_value
bcrypto_eddsa_create(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  uint32_t type;
  bcrypto_eddsa_t *ec;
  eddsa_t *ctx;
  napi_value handle;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_value_uint32(env, argv[0], &type) == napi_ok);

  JS_ASSERT(ctx = eddsa_context_create(type), JS_ERR_CONTEXT);

  ec = (bcrypto_eddsa_t *)safe_malloc(sizeof(bcrypto_eddsa_t));
  ec->ctx = ctx;
  ec->scratch = eddsa_scratch_create(ec->ctx);
  ec->scalar_size = eddsa_scalar_size(ec->ctx);
  ec->scalar_bits = eddsa_scalar_bits(ec->ctx);
  ec->field_size = eddsa_field_size(ec->ctx);
  ec->field_bits = eddsa_field_bits(ec->ctx);
  ec->priv_size = eddsa_privkey_size(ec->ctx);
  ec->pub_size = eddsa_pubkey_size(ec->ctx);
  ec->sig_size = eddsa_sig_size(ec->ctx);

  CHECK(ec->scratch != NULL);

  CHECK(napi_create_external(env,
                             ec,
                             bcrypto_eddsa_destroy,
                             NULL,
                             &handle) == napi_ok);

  return handle;
}

static napi_value
bcrypto_eddsa_size(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  bcrypto_eddsa_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_create_uint32(env, ec->pub_size, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_eddsa_bits(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  bcrypto_eddsa_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_create_uint32(env, ec->field_bits, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_eddsa_randomize(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t *entropy;
  size_t entropy_len;
  bcrypto_eddsa_t *ec;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&entropy,
                             &entropy_len) == napi_ok);

  JS_ASSERT(entropy_len == ENTROPY_SIZE, JS_ERR_ENTROPY_SIZE);

  eddsa_context_randomize(ec->ctx, entropy);

  cleanse(entropy, entropy_len);

  return argv[0];
}

static napi_value
bcrypto_eddsa_privkey_generate(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t *entropy;
  size_t entropy_len;
  uint8_t out[EDDSA_MAX_PRIV_SIZE];
  bcrypto_eddsa_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&entropy,
                             &entropy_len) == napi_ok);

  JS_ASSERT(entropy_len == ENTROPY_SIZE, JS_ERR_ENTROPY_SIZE);

  eddsa_privkey_generate(ec->ctx, out, entropy);

  cleanse(entropy, entropy_len);

  CHECK(napi_create_buffer_copy(env,
                                ec->priv_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_eddsa_privkey_verify(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  const uint8_t *priv;
  size_t priv_len;
  bcrypto_eddsa_t *ec;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&priv,
                             &priv_len) == napi_ok);

  ok = priv_len == ec->priv_size && eddsa_privkey_verify(ec->ctx, priv);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_eddsa_privkey_export(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t out[EDDSA_MAX_PRIV_SIZE];
  const uint8_t *priv;
  size_t priv_len;
  bcrypto_eddsa_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&priv,
                             &priv_len) == napi_ok);

  JS_ASSERT(priv_len == ec->priv_size, JS_ERR_PRIVKEY_SIZE);
  JS_ASSERT(eddsa_privkey_export(ec->ctx, out, priv), JS_ERR_PRIVKEY);

  CHECK(napi_create_buffer_copy(env,
                                ec->priv_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_eddsa_privkey_import(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t out[EDDSA_MAX_PRIV_SIZE];
  const uint8_t *priv;
  size_t priv_len;
  bcrypto_eddsa_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&priv,
                             &priv_len) == napi_ok);

  JS_ASSERT(eddsa_privkey_import(ec->ctx, out, priv, priv_len), JS_ERR_PRIVKEY);

  CHECK(napi_create_buffer_copy(env,
                                ec->priv_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_eddsa_privkey_expand(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t scalar[EDDSA_MAX_SCALAR_SIZE];
  uint8_t prefix[EDDSA_MAX_PREFIX_SIZE];
  const uint8_t *priv;
  size_t priv_len;
  bcrypto_eddsa_t *ec;
  napi_value scalarval, prefixval, result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&priv,
                             &priv_len) == napi_ok);

  JS_ASSERT(priv_len == ec->priv_size, JS_ERR_PRIVKEY_SIZE);

  eddsa_privkey_expand(ec->ctx, scalar, prefix, priv);

  CHECK(napi_create_buffer_copy(env,
                                ec->scalar_size,
                                scalar,
                                NULL,
                                &scalarval) == napi_ok);

  CHECK(napi_create_buffer_copy(env,
                                ec->pub_size,
                                prefix,
                                NULL,
                                &prefixval) == napi_ok);

  CHECK(napi_create_array_with_length(env, 2, &result) == napi_ok);
  CHECK(napi_set_element(env, result, 0, scalarval) == napi_ok);
  CHECK(napi_set_element(env, result, 1, prefixval) == napi_ok);

  return result;
}

static napi_value
bcrypto_eddsa_privkey_convert(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t out[EDDSA_MAX_SCALAR_SIZE];
  const uint8_t *priv;
  size_t priv_len;
  bcrypto_eddsa_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&priv,
                             &priv_len) == napi_ok);

  JS_ASSERT(priv_len == ec->priv_size, JS_ERR_PRIVKEY_SIZE);

  eddsa_privkey_convert(ec->ctx, out, priv);

  CHECK(napi_create_buffer_copy(env,
                                ec->scalar_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_eddsa_scalar_generate(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t out[EDDSA_MAX_SCALAR_SIZE];
  uint8_t *entropy;
  size_t entropy_len;
  bcrypto_eddsa_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&entropy,
                             &entropy_len) == napi_ok);

  JS_ASSERT(entropy_len == ENTROPY_SIZE, JS_ERR_ENTROPY_SIZE);

  eddsa_scalar_generate(ec->ctx, out, entropy);

  cleanse(entropy, entropy_len);

  CHECK(napi_create_buffer_copy(env,
                                ec->scalar_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_eddsa_scalar_verify(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  const uint8_t *scalar;
  size_t scalar_len;
  bcrypto_eddsa_t *ec;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&scalar,
                             &scalar_len) == napi_ok);

  ok = scalar_len == ec->scalar_size && eddsa_scalar_verify(ec->ctx, scalar);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_eddsa_scalar_clamp(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t out[EDDSA_MAX_SCALAR_SIZE];
  const uint8_t *scalar;
  size_t scalar_len;
  bcrypto_eddsa_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&scalar,
                             &scalar_len) == napi_ok);

  JS_ASSERT(scalar_len == ec->scalar_size, JS_ERR_SCALAR_SIZE);

  eddsa_scalar_clamp(ec->ctx, out, scalar);

  CHECK(napi_create_buffer_copy(env,
                                ec->scalar_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_eddsa_scalar_is_zero(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  const uint8_t *scalar;
  size_t scalar_len;
  bcrypto_eddsa_t *ec;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&scalar,
                             &scalar_len) == napi_ok);

  ok = scalar_len == ec->scalar_size && eddsa_scalar_is_zero(ec->ctx, scalar);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_eddsa_scalar_tweak_add(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[EDDSA_MAX_SCALAR_SIZE];
  const uint8_t *scalar, *tweak;
  size_t scalar_len, tweak_len;
  bcrypto_eddsa_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&scalar,
                             &scalar_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&tweak,
                             &tweak_len) == napi_ok);

  JS_ASSERT(scalar_len == ec->scalar_size, JS_ERR_SCALAR_SIZE);
  JS_ASSERT(tweak_len == ec->scalar_size, JS_ERR_SCALAR_SIZE);

  eddsa_scalar_tweak_add(ec->ctx, out, scalar, tweak);

  CHECK(napi_create_buffer_copy(env,
                                ec->scalar_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_eddsa_scalar_tweak_mul(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[EDDSA_MAX_SCALAR_SIZE];
  const uint8_t *scalar, *tweak;
  size_t scalar_len, tweak_len;
  bcrypto_eddsa_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&scalar,
                             &scalar_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&tweak,
                             &tweak_len) == napi_ok);

  JS_ASSERT(scalar_len == ec->scalar_size, JS_ERR_SCALAR_SIZE);
  JS_ASSERT(tweak_len == ec->scalar_size, JS_ERR_SCALAR_SIZE);

  eddsa_scalar_tweak_mul(ec->ctx, out, scalar, tweak);

  CHECK(napi_create_buffer_copy(env,
                                ec->scalar_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_eddsa_scalar_reduce(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t out[EDDSA_MAX_SCALAR_SIZE];
  const uint8_t *scalar;
  size_t scalar_len;
  bcrypto_eddsa_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&scalar,
                             &scalar_len) == napi_ok);

  eddsa_scalar_reduce(ec->ctx, out, scalar, scalar_len);

  CHECK(napi_create_buffer_copy(env,
                                ec->scalar_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_eddsa_scalar_negate(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t out[EDDSA_MAX_SCALAR_SIZE];
  const uint8_t *scalar;
  size_t scalar_len;
  bcrypto_eddsa_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&scalar,
                             &scalar_len) == napi_ok);

  JS_ASSERT(scalar_len == ec->scalar_size, JS_ERR_SCALAR_SIZE);

  eddsa_scalar_negate(ec->ctx, out, scalar);

  CHECK(napi_create_buffer_copy(env,
                                ec->scalar_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_eddsa_scalar_invert(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t out[EDDSA_MAX_SCALAR_SIZE];
  const uint8_t *scalar;
  size_t scalar_len;
  bcrypto_eddsa_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&scalar,
                             &scalar_len) == napi_ok);

  JS_ASSERT(scalar_len == ec->scalar_size, JS_ERR_SCALAR_SIZE);

  eddsa_scalar_invert(ec->ctx, out, scalar);

  CHECK(napi_create_buffer_copy(env,
                                ec->scalar_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_eddsa_pubkey_create(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t out[EDDSA_MAX_PUB_SIZE];
  const uint8_t *priv;
  size_t priv_len;
  bcrypto_eddsa_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&priv,
                             &priv_len) == napi_ok);

  JS_ASSERT(priv_len == ec->priv_size, JS_ERR_PRIVKEY_SIZE);

  eddsa_pubkey_create(ec->ctx, out, priv);

  CHECK(napi_create_buffer_copy(env,
                                ec->pub_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_eddsa_pubkey_from_scalar(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t out[EDDSA_MAX_PUB_SIZE];
  const uint8_t *scalar;
  size_t scalar_len;
  bcrypto_eddsa_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&scalar,
                             &scalar_len) == napi_ok);

  JS_ASSERT(scalar_len == ec->scalar_size, JS_ERR_SCALAR_SIZE);

  eddsa_pubkey_from_scalar(ec->ctx, out, scalar);

  CHECK(napi_create_buffer_copy(env,
                                ec->pub_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_eddsa_pubkey_convert(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t out[ECDH_MAX_PUB_SIZE];
  const uint8_t *pub;
  size_t pub_len;
  bcrypto_eddsa_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pub,
                             &pub_len) == napi_ok);

  JS_ASSERT(pub_len == ec->pub_size, JS_ERR_PUBKEY_SIZE);
  JS_ASSERT(eddsa_pubkey_convert(ec->ctx, out, pub), JS_ERR_PUBKEY);

  CHECK(napi_create_buffer_copy(env,
                                ec->field_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_eddsa_pubkey_from_uniform(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t out[EDDSA_MAX_PUB_SIZE];
  const uint8_t *data;
  size_t data_len;
  bcrypto_eddsa_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&data,
                             &data_len) == napi_ok);

  JS_ASSERT(data_len == ec->field_size, JS_ERR_PREIMAGE_SIZE);

  eddsa_pubkey_from_uniform(ec->ctx, out, data);

  CHECK(napi_create_buffer_copy(env,
                                ec->pub_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_eddsa_pubkey_to_uniform(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[EDDSA_MAX_FIELD_SIZE];
  const uint8_t *pub;
  size_t pub_len;
  uint32_t hint;
  bcrypto_eddsa_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pub,
                             &pub_len) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[2], &hint) == napi_ok);

  JS_ASSERT(pub_len == ec->pub_size, JS_ERR_PUBKEY_SIZE);
  JS_ASSERT(eddsa_pubkey_to_uniform(ec->ctx, out, pub, hint), JS_ERR_PUBKEY);

  CHECK(napi_create_buffer_copy(env, ec->field_size,
                                out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_eddsa_pubkey_from_hash(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[EDDSA_MAX_PUB_SIZE];
  const uint8_t *data;
  size_t data_len;
  bool pake;
  bcrypto_eddsa_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&data,
                             &data_len) == napi_ok);
  CHECK(napi_get_value_bool(env, argv[2], &pake) == napi_ok);

  JS_ASSERT(data_len == ec->field_size * 2, JS_ERR_PREIMAGE_SIZE);

  eddsa_pubkey_from_hash(ec->ctx, out, data, pake);

  CHECK(napi_create_buffer_copy(env,
                                ec->pub_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_eddsa_pubkey_to_hash(napi_env env, napi_callback_info info) {
  napi_value argv[4];
  size_t argc = 4;
  uint8_t out[EDDSA_MAX_FIELD_SIZE * 2];
  const uint8_t *pub;
  uint32_t subgroup;
  uint8_t *entropy;
  size_t pub_len, entropy_len;
  bcrypto_eddsa_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 4);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pub,
                             &pub_len) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[2], &subgroup) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[3], (void **)&entropy,
                             &entropy_len) == napi_ok);

  JS_ASSERT(pub_len == ec->pub_size, JS_ERR_PUBKEY_SIZE);
  JS_ASSERT(entropy_len == ENTROPY_SIZE, JS_ERR_ENTROPY_SIZE);
  JS_ASSERT(eddsa_pubkey_to_hash(ec->ctx, out, pub, subgroup, entropy),
            JS_ERR_PUBKEY);

  cleanse(entropy, entropy_len);

  CHECK(napi_create_buffer_copy(env, ec->field_size * 2,
                                out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_eddsa_pubkey_verify(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  const uint8_t *pub;
  size_t pub_len;
  bcrypto_eddsa_t *ec;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pub,
                             &pub_len) == napi_ok);

  ok = pub_len == ec->pub_size && eddsa_pubkey_verify(ec->ctx, pub);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_eddsa_pubkey_export(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t x[EDDSA_MAX_FIELD_SIZE];
  uint8_t y[EDDSA_MAX_FIELD_SIZE];
  const uint8_t *pub;
  size_t pub_len;
  bcrypto_eddsa_t *ec;
  napi_value bx, by, result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pub,
                             &pub_len) == napi_ok);

  JS_ASSERT(pub_len == ec->pub_size, JS_ERR_PUBKEY_SIZE);
  JS_ASSERT(eddsa_pubkey_export(ec->ctx, x, y, pub), JS_ERR_PUBKEY);

  CHECK(napi_create_buffer_copy(env, ec->field_size, x, NULL, &bx) == napi_ok);
  CHECK(napi_create_buffer_copy(env, ec->field_size, y, NULL, &by) == napi_ok);

  CHECK(napi_create_array_with_length(env, 2, &result) == napi_ok);
  CHECK(napi_set_element(env, result, 0, bx) == napi_ok);
  CHECK(napi_set_element(env, result, 1, by) == napi_ok);

  return result;
}

static napi_value
bcrypto_eddsa_pubkey_import(napi_env env, napi_callback_info info) {
  napi_value argv[4];
  size_t argc = 4;
  uint8_t out[EDDSA_MAX_PUB_SIZE];
  const uint8_t *x, *y;
  size_t x_len, y_len;
  int32_t sign;
  bcrypto_eddsa_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 4);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&x, &x_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&y, &y_len) == napi_ok);
  CHECK(napi_get_value_int32(env, argv[3], &sign) == napi_ok);

  JS_ASSERT(eddsa_pubkey_import(ec->ctx, out, x, x_len, y, y_len, sign),
            JS_ERR_PUBKEY);

  CHECK(napi_create_buffer_copy(env,
                                ec->pub_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_eddsa_pubkey_is_infinity(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  const uint8_t *pub;
  size_t pub_len;
  bcrypto_eddsa_t *ec;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pub,
                             &pub_len) == napi_ok);

  ok = pub_len == ec->pub_size && eddsa_pubkey_is_infinity(ec->ctx, pub);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_eddsa_pubkey_is_small(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  const uint8_t *pub;
  size_t pub_len;
  bcrypto_eddsa_t *ec;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pub,
                             &pub_len) == napi_ok);

  ok = pub_len == ec->pub_size && eddsa_pubkey_is_small(ec->ctx, pub);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_eddsa_pubkey_has_torsion(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  const uint8_t *pub;
  size_t pub_len;
  bcrypto_eddsa_t *ec;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pub,
                             &pub_len) == napi_ok);

  ok = pub_len == ec->pub_size && eddsa_pubkey_has_torsion(ec->ctx, pub);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_eddsa_pubkey_tweak_add(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[EDDSA_MAX_PUB_SIZE];
  const uint8_t *pub, *tweak;
  size_t pub_len, tweak_len;
  bcrypto_eddsa_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pub,
                             &pub_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&tweak,
                             &tweak_len) == napi_ok);

  JS_ASSERT(pub_len == ec->pub_size, JS_ERR_PUBKEY_SIZE);
  JS_ASSERT(tweak_len == ec->scalar_size, JS_ERR_SCALAR_SIZE);
  JS_ASSERT(eddsa_pubkey_tweak_add(ec->ctx, out, pub, tweak), JS_ERR_PUBKEY);

  CHECK(napi_create_buffer_copy(env,
                                ec->pub_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_eddsa_pubkey_tweak_mul(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[EDDSA_MAX_PUB_SIZE];
  const uint8_t *pub, *tweak;
  size_t pub_len, tweak_len;
  bcrypto_eddsa_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pub,
                             &pub_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&tweak,
                             &tweak_len) == napi_ok);

  JS_ASSERT(pub_len == ec->pub_size, JS_ERR_PUBKEY_SIZE);
  JS_ASSERT(tweak_len == ec->scalar_size, JS_ERR_SCALAR_SIZE);
  JS_ASSERT(eddsa_pubkey_tweak_mul(ec->ctx, out, pub, tweak), JS_ERR_PUBKEY);

  CHECK(napi_create_buffer_copy(env,
                                ec->pub_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_eddsa_pubkey_combine(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t out[EDDSA_MAX_PUB_SIZE];
  uint32_t i, length;
  const uint8_t **pubs;
  size_t pub_len;
  bcrypto_eddsa_t *ec;
  napi_value item, result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_array_length(env, argv[1], &length) == napi_ok);

  pubs = (const uint8_t **)safe_malloc(length * sizeof(uint8_t *));

  for (i = 0; i < length; i++) {
    CHECK(napi_get_element(env, argv[1], i, &item) == napi_ok);
    CHECK(napi_get_buffer_info(env, item, (void **)&pubs[i],
                               &pub_len) == napi_ok);

    if (pub_len != ec->pub_size) {
      safe_free(pubs);
      JS_THROW(JS_ERR_PUBKEY_SIZE);
    }
  }

  ok = eddsa_pubkey_combine(ec->ctx, out, pubs, length);

  safe_free(pubs);

  JS_ASSERT(ok, JS_ERR_PUBKEY);

  CHECK(napi_create_buffer_copy(env,
                                ec->pub_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_eddsa_pubkey_negate(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t out[EDDSA_MAX_PUB_SIZE];
  const uint8_t *pub;
  size_t pub_len;
  bcrypto_eddsa_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pub,
                             &pub_len) == napi_ok);

  JS_ASSERT(pub_len == ec->pub_size, JS_ERR_PUBKEY_SIZE);
  JS_ASSERT(eddsa_pubkey_negate(ec->ctx, out, pub), JS_ERR_PUBKEY);

  CHECK(napi_create_buffer_copy(env,
                                ec->pub_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_eddsa_sign(napi_env env, napi_callback_info info) {
  napi_value argv[5];
  size_t argc = 5;
  uint8_t out[EDDSA_MAX_SIG_SIZE];
  const uint8_t *msg, *priv, *ctx;
  size_t msg_len, priv_len, ctx_len;
  int32_t ph;
  bcrypto_eddsa_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 5);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&priv,
                             &priv_len) == napi_ok);
  CHECK(napi_get_value_int32(env, argv[3], &ph) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[4], (void **)&ctx, &ctx_len) == napi_ok);

  JS_ASSERT(priv_len == ec->priv_size, JS_ERR_PRIVKEY_SIZE);

  eddsa_sign(ec->ctx, out, msg, msg_len, priv, ph, ctx, ctx_len);

  CHECK(napi_create_buffer_copy(env,
                                ec->sig_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_eddsa_sign_with_scalar(napi_env env, napi_callback_info info) {
  napi_value argv[6];
  size_t argc = 6;
  uint8_t out[EDDSA_MAX_SIG_SIZE];
  const uint8_t *msg, *scalar, *prefix, *ctx;
  size_t msg_len, scalar_len, prefix_len, ctx_len;
  int32_t ph;
  bcrypto_eddsa_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 6);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&scalar,
                             &scalar_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[3], (void **)&prefix,
                             &prefix_len) == napi_ok);
  CHECK(napi_get_value_int32(env, argv[4], &ph) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[5], (void **)&ctx, &ctx_len) == napi_ok);

  JS_ASSERT(scalar_len == ec->scalar_size, JS_ERR_SCALAR_SIZE);
  JS_ASSERT(prefix_len == ec->pub_size, JS_ERR_PREFIX_SIZE);

  eddsa_sign_with_scalar(ec->ctx, out, msg, msg_len,
                         scalar, prefix, ph, ctx, ctx_len);

  CHECK(napi_create_buffer_copy(env,
                                ec->sig_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_eddsa_sign_tweak_add(napi_env env, napi_callback_info info) {
  napi_value argv[6];
  size_t argc = 6;
  uint8_t out[EDDSA_MAX_SIG_SIZE];
  const uint8_t *msg, *priv, *tweak, *ctx;
  size_t msg_len, priv_len, tweak_len, ctx_len;
  int32_t ph;
  bcrypto_eddsa_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 6);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&priv,
                             &priv_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[3], (void **)&tweak,
                             &tweak_len) == napi_ok);
  CHECK(napi_get_value_int32(env, argv[4], &ph) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[5], (void **)&ctx, &ctx_len) == napi_ok);

  JS_ASSERT(priv_len == ec->priv_size, JS_ERR_PRIVKEY_SIZE);
  JS_ASSERT(tweak_len == ec->scalar_size, JS_ERR_SCALAR_SIZE);

  eddsa_sign_tweak_add(ec->ctx, out, msg, msg_len,
                       priv, tweak, ph, ctx, ctx_len);

  CHECK(napi_create_buffer_copy(env,
                                ec->sig_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_eddsa_sign_tweak_mul(napi_env env, napi_callback_info info) {
  napi_value argv[6];
  size_t argc = 6;
  uint8_t out[EDDSA_MAX_SIG_SIZE];
  const uint8_t *msg, *priv, *tweak, *ctx;
  size_t msg_len, priv_len, tweak_len, ctx_len;
  int32_t ph;
  bcrypto_eddsa_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 6);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&priv,
                             &priv_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[3], (void **)&tweak,
                             &tweak_len) == napi_ok);
  CHECK(napi_get_value_int32(env, argv[4], &ph) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[5], (void **)&ctx, &ctx_len) == napi_ok);

  JS_ASSERT(priv_len == ec->priv_size, JS_ERR_PRIVKEY_SIZE);
  JS_ASSERT(tweak_len == ec->scalar_size, JS_ERR_SCALAR_SIZE);

  eddsa_sign_tweak_mul(ec->ctx, out, msg, msg_len,
                       priv, tweak, ph, ctx, ctx_len);

  CHECK(napi_create_buffer_copy(env,
                                ec->sig_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_eddsa_verify(napi_env env, napi_callback_info info) {
  napi_value argv[6];
  size_t argc = 6;
  const uint8_t *msg, *sig, *pub, *ctx;
  size_t msg_len, sig_len, pub_len, ctx_len;
  int32_t ph;
  bcrypto_eddsa_t *ec;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 6);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&sig, &sig_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[3], (void **)&pub, &pub_len) == napi_ok);
  CHECK(napi_get_value_int32(env, argv[4], &ph) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[5], (void **)&ctx, &ctx_len) == napi_ok);

  ok = sig_len == ec->sig_size
    && pub_len == ec->pub_size
    && eddsa_verify(ec->ctx, msg, msg_len, sig, pub, ph, ctx, ctx_len);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_eddsa_verify_single(napi_env env, napi_callback_info info) {
  napi_value argv[6];
  size_t argc = 6;
  const uint8_t *msg, *sig, *pub, *ctx;
  size_t msg_len, sig_len, pub_len, ctx_len;
  int32_t ph;
  bcrypto_eddsa_t *ec;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 6);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&sig, &sig_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[3], (void **)&pub, &pub_len) == napi_ok);
  CHECK(napi_get_value_int32(env, argv[4], &ph) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[5], (void **)&ctx, &ctx_len) == napi_ok);

  ok = sig_len == ec->sig_size
    && pub_len == ec->pub_size
    && eddsa_verify_single(ec->ctx, msg, msg_len, sig, pub, ph, ctx, ctx_len);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_eddsa_verify_batch(napi_env env, napi_callback_info info) {
  napi_value argv[4];
  size_t argc = 4;
  uint32_t i, length, item_len;
  const uint8_t *ctx;
  const uint8_t **ptrs, **msgs, **pubs, **sigs;
  size_t *lens, *msg_lens;
  size_t sig_len, pub_len, ctx_len;
  int32_t ph;
  bcrypto_eddsa_t *ec;
  napi_value item, result;
  napi_value items[3];
  int ok = 0;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 4);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_array_length(env, argv[1], &length) == napi_ok);
  CHECK(napi_get_value_int32(env, argv[2], &ph) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[3], (void **)&ctx, &ctx_len) == napi_ok);

  if (length == 0) {
    CHECK(napi_get_boolean(env, true, &result) == napi_ok);
    return result;
  }

  ptrs = (const uint8_t **)safe_malloc(3 * length * sizeof(uint8_t *));
  lens = (size_t *)safe_malloc(1 * length * sizeof(size_t));
  msgs = &ptrs[length * 0];
  pubs = &ptrs[length * 1];
  sigs = &ptrs[length * 2];
  msg_lens = &lens[length * 0];

  memset(items, 0, sizeof(items));

  for (i = 0; i < length; i++) {
    CHECK(napi_get_element(env, argv[1], i, &item) == napi_ok);
    CHECK(napi_get_array_length(env, item, &item_len) == napi_ok);
    CHECK(item_len == 3);

    CHECK(napi_get_element(env, item, 0, &items[0]) == napi_ok);
    CHECK(napi_get_element(env, item, 1, &items[1]) == napi_ok);
    CHECK(napi_get_element(env, item, 2, &items[2]) == napi_ok);

    CHECK(napi_get_buffer_info(env, items[0], (void **)&msgs[i],
                               &msg_lens[i]) == napi_ok);

    CHECK(napi_get_buffer_info(env, items[1], (void **)&sigs[i],
                               &sig_len) == napi_ok);

    CHECK(napi_get_buffer_info(env, items[2], (void **)&pubs[i],
                               &pub_len) == napi_ok);

    if (sig_len != ec->sig_size || pub_len != ec->pub_size)
      goto fail;
  }

  ok = eddsa_verify_batch(ec->ctx, msgs, msg_lens, sigs,
                          pubs, length, ph, ctx, ctx_len,
                          ec->scratch);

fail:
  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  safe_free(ptrs);
  safe_free(lens);

  return result;
}

static napi_value
bcrypto_eddsa_derive(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[EDDSA_MAX_PUB_SIZE];
  const uint8_t *pub, *priv;
  size_t pub_len, priv_len;
  bcrypto_eddsa_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pub, &pub_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&priv,
                             &priv_len) == napi_ok);

  JS_ASSERT(pub_len == ec->pub_size, JS_ERR_PUBKEY_SIZE);
  JS_ASSERT(priv_len == ec->priv_size, JS_ERR_PRIVKEY_SIZE);
  JS_ASSERT(eddsa_derive(ec->ctx, out, pub, priv), JS_ERR_PUBKEY);

  CHECK(napi_create_buffer_copy(env,
                                ec->pub_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_eddsa_derive_with_scalar(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[EDDSA_MAX_PUB_SIZE];
  const uint8_t *pub, *scalar;
  size_t pub_len, scalar_len;
  bcrypto_eddsa_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pub, &pub_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&scalar,
                             &scalar_len) == napi_ok);

  JS_ASSERT(pub_len == ec->pub_size, JS_ERR_PUBKEY_SIZE);
  JS_ASSERT(scalar_len == ec->scalar_size, JS_ERR_SCALAR_SIZE);
  JS_ASSERT(eddsa_derive_with_scalar(ec->ctx, out, pub, scalar), JS_ERR_PUBKEY);

  CHECK(napi_create_buffer_copy(env,
                                ec->pub_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

/*
 * Hash
 */

static void
bcrypto_hash_destroy(napi_env env, void *data, void *hint) {
  cleanse(data, sizeof(bcrypto_hash_t));
  safe_free(data);
}

static napi_value
bcrypto_hash_create(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  uint32_t type;
  bcrypto_hash_t *hash;
  napi_value handle;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_value_uint32(env, argv[0], &type) == napi_ok);

  JS_ASSERT(hash_has_backend(type), JS_ERR_INIT);

  hash = (bcrypto_hash_t *)safe_malloc(sizeof(bcrypto_hash_t));
  hash->type = type;
  hash->started = 0;

  CHECK(napi_create_external(env,
                             hash,
                             bcrypto_hash_destroy,
                             NULL,
                             &handle) == napi_ok);

  return handle;
}

static napi_value
bcrypto_hash_init(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  bcrypto_hash_t *hash;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_value_external(env, argv[0], (void **)&hash) == napi_ok);

  hash_init(&hash->ctx, hash->type);
  hash->started = 1;

  return argv[0];
}

static napi_value
bcrypto_hash_update(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  const uint8_t *in;
  size_t in_len;
  bcrypto_hash_t *hash;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&hash) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&in, &in_len) == napi_ok);

  JS_ASSERT(hash->started, JS_ERR_INIT);

  hash_update(&hash->ctx, in, in_len);

  return argv[0];
}

static napi_value
bcrypto_hash_final(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  uint8_t out[HASH_MAX_OUTPUT_SIZE];
  size_t out_len;
  bcrypto_hash_t *hash;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_value_external(env, argv[0], (void **)&hash) == napi_ok);

  JS_ASSERT(hash->started, JS_ERR_INIT);

  out_len = hash_output_size(hash->type);

  hash_final(&hash->ctx, out, out_len);
  hash->started = 0;

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_hash_digest(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t out[HASH_MAX_OUTPUT_SIZE];
  size_t out_len;
  uint32_t type;
  const uint8_t *in;
  size_t in_len;
  hash_t ctx;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_uint32(env, argv[0], &type) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&in, &in_len) == napi_ok);

  JS_ASSERT(hash_has_backend(type), JS_ERR_INIT);

  out_len = hash_output_size(type);

  hash_init(&ctx, type);
  hash_update(&ctx, in, in_len);
  hash_final(&ctx, out, out_len);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_hash_root(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[HASH_MAX_OUTPUT_SIZE];
  size_t out_len;
  uint32_t type;
  const uint8_t *left, *right;
  size_t left_len, right_len;
  hash_t ctx;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_uint32(env, argv[0], &type) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&left,
                             &left_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&right,
                             &right_len) == napi_ok);

  JS_ASSERT(hash_has_backend(type), JS_ERR_INIT);

  out_len = hash_output_size(type);

  JS_ASSERT(left_len == out_len && right_len == out_len, JS_ERR_NODE_SIZE);

  hash_init(&ctx, type);
  hash_update(&ctx, left, left_len);
  hash_update(&ctx, right, right_len);
  hash_final(&ctx, out, out_len);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_hash_multi(napi_env env, napi_callback_info info) {
  napi_value argv[4];
  size_t argc = 4;
  uint8_t out[HASH_MAX_OUTPUT_SIZE];
  size_t out_len;
  uint32_t type;
  const uint8_t *x, *y, *z;
  size_t x_len, y_len, z_len;
  hash_t ctx;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 4);
  CHECK(napi_get_value_uint32(env, argv[0], &type) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&x, &x_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&y, &y_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[3], (void **)&z, &z_len) == napi_ok);

  JS_ASSERT(hash_has_backend(type), JS_ERR_INIT);

  out_len = hash_output_size(type);

  hash_init(&ctx, type);
  hash_update(&ctx, x, x_len);
  hash_update(&ctx, y, y_len);
  hash_update(&ctx, z, z_len);
  hash_final(&ctx, out, out_len);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  return result;
}

/*
 * HMAC
 */

static void
bcrypto_hmac_destroy(napi_env env, void *data, void *hint) {
  cleanse(data, sizeof(bcrypto_hmac_t));
  safe_free(data);
}

static napi_value
bcrypto_hmac_create(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  uint32_t type;
  bcrypto_hmac_t *hmac;
  napi_value handle;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_value_uint32(env, argv[0], &type) == napi_ok);

  JS_ASSERT(hash_has_backend(type), JS_ERR_INIT);

  hmac = (bcrypto_hmac_t *)safe_malloc(sizeof(bcrypto_hmac_t));
  hmac->type = type;
  hmac->started = 0;

  CHECK(napi_create_external(env,
                             hmac,
                             bcrypto_hmac_destroy,
                             NULL,
                             &handle) == napi_ok);

  return handle;
}

static napi_value
bcrypto_hmac_init(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  const uint8_t *key;
  size_t key_len;
  bcrypto_hmac_t *hmac;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&hmac) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&key, &key_len) == napi_ok);

  hmac_init(&hmac->ctx, hmac->type, key, key_len);
  hmac->started = 1;

  return argv[0];
}

static napi_value
bcrypto_hmac_update(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  const uint8_t *in;
  size_t in_len;
  bcrypto_hmac_t *hmac;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&hmac) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&in, &in_len) == napi_ok);

  JS_ASSERT(hmac->started, JS_ERR_INIT);

  hmac_update(&hmac->ctx, in, in_len);

  return argv[0];
}

static napi_value
bcrypto_hmac_final(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  uint8_t out[HASH_MAX_OUTPUT_SIZE];
  size_t out_len;
  bcrypto_hmac_t *hmac;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_value_external(env, argv[0], (void **)&hmac) == napi_ok);

  JS_ASSERT(hmac->started, JS_ERR_INIT);

  out_len = hash_output_size(hmac->type);

  hmac_final(&hmac->ctx, out);
  hmac->started = 0;

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_hmac_digest(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[HASH_MAX_OUTPUT_SIZE];
  size_t out_len;
  uint32_t type;
  const uint8_t *in, *key;
  size_t in_len, key_len;
  hmac_t ctx;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_uint32(env, argv[0], &type) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&in, &in_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&key, &key_len) == napi_ok);

  JS_ASSERT(hash_has_backend(type), JS_ERR_INIT);

  out_len = hash_output_size(type);

  hmac_init(&ctx, type, key, key_len);
  hmac_update(&ctx, in, in_len);
  hmac_final(&ctx, out);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  return result;
}

/*
 * Keccak
 */

static void
bcrypto_keccak_destroy(napi_env env, void *data, void *hint) {
  cleanse(data, sizeof(bcrypto_keccak_t));
  safe_free(data);
}

static napi_value
bcrypto_keccak_create(napi_env env, napi_callback_info info) {
  bcrypto_keccak_t *keccak =
    (bcrypto_keccak_t *)safe_malloc(sizeof(bcrypto_keccak_t));
  napi_value handle;

  keccak->started = 0;

  CHECK(napi_create_external(env,
                             keccak,
                             bcrypto_keccak_destroy,
                             NULL,
                             &handle) == napi_ok);

  return handle;
}

static napi_value
bcrypto_keccak_init(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint32_t bits, rate;
  bcrypto_keccak_t *keccak;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&keccak) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[1], &bits) == napi_ok);

  rate = 1600 - bits * 2;

  JS_ASSERT(bits >= 128 && bits <= 512 && (rate & 63) == 0, JS_ERR_OUTPUT_SIZE);

  keccak_init(&keccak->ctx, bits);
  keccak->started = 1;

  return argv[0];
}

static napi_value
bcrypto_keccak_update(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  const uint8_t *in;
  size_t in_len;
  bcrypto_keccak_t *keccak;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&keccak) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&in, &in_len) == napi_ok);

  JS_ASSERT(keccak->started, JS_ERR_INIT);

  keccak_update(&keccak->ctx, in, in_len);

  return argv[0];
}

static napi_value
bcrypto_keccak_final(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[200];
  uint32_t pad, out_len;
  bcrypto_keccak_t *keccak;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&keccak) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[1], &pad) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[2], &out_len) == napi_ok);

  if (out_len == 0)
    out_len = 100 - (keccak->ctx.bs >> 1);

  JS_ASSERT(keccak->started, JS_ERR_INIT);
  JS_ASSERT(out_len < keccak->ctx.bs, JS_ERR_OUTPUT_SIZE);

  keccak_final(&keccak->ctx, out, pad, out_len);
  keccak->started = 0;

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_keccak_digest(napi_env env, napi_callback_info info) {
  napi_value argv[4];
  size_t argc = 4;
  uint8_t out[200];
  const uint8_t *in;
  size_t in_len;
  uint32_t bits, pad, out_len, rate, bs;
  keccak_t ctx;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 4);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&in, &in_len) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[1], &bits) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[2], &pad) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[3], &out_len) == napi_ok);

  rate = 1600 - bits * 2;
  bs = rate >> 3;

  if (out_len == 0)
    out_len = 100 - (bs >> 1);

  JS_ASSERT(bits >= 128 && bits <= 512 && (rate & 63) == 0, JS_ERR_OUTPUT_SIZE);
  JS_ASSERT(out_len < bs, JS_ERR_OUTPUT_SIZE);

  keccak_init(&ctx, bits);
  keccak_update(&ctx, in, in_len);
  keccak_final(&ctx, out, pad, out_len);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_keccak_root(napi_env env, napi_callback_info info) {
  napi_value argv[5];
  size_t argc = 5;
  uint8_t out[200];
  const uint8_t *left, *right;
  size_t left_len, right_len;
  uint32_t bits, pad, out_len, rate, bs;
  keccak_t ctx;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 5);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&left,
                             &left_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&right,
                             &right_len) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[2], &bits) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[3], &pad) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[4], &out_len) == napi_ok);

  rate = 1600 - bits * 2;
  bs = rate >> 3;

  if (out_len == 0)
    out_len = 100 - (bs >> 1);

  JS_ASSERT(bits >= 128 && bits <= 512 && (rate & 63) == 0, JS_ERR_OUTPUT_SIZE);
  JS_ASSERT(out_len < bs, JS_ERR_OUTPUT_SIZE);
  JS_ASSERT(left_len == out_len && right_len == out_len, JS_ERR_NODE_SIZE);

  keccak_init(&ctx, bits);
  keccak_update(&ctx, left, left_len);
  keccak_update(&ctx, right, right_len);
  keccak_final(&ctx, out, pad, out_len);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_keccak_multi(napi_env env, napi_callback_info info) {
  napi_value argv[6];
  size_t argc = 6;
  uint8_t out[200];
  const uint8_t *x, *y, *z;
  size_t x_len, y_len, z_len;
  uint32_t bits, pad, out_len, rate, bs;
  keccak_t ctx;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 6);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&x, &x_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&y, &y_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&z, &z_len) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[3], &bits) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[4], &pad) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[5], &out_len) == napi_ok);

  rate = 1600 - bits * 2;
  bs = rate >> 3;

  if (out_len == 0)
    out_len = 100 - (bs >> 1);

  JS_ASSERT(bits >= 128 && bits <= 512 && (rate & 63) == 0, JS_ERR_OUTPUT_SIZE);
  JS_ASSERT(out_len < bs, JS_ERR_OUTPUT_SIZE);

  keccak_init(&ctx, bits);
  keccak_update(&ctx, x, x_len);
  keccak_update(&ctx, y, y_len);
  keccak_update(&ctx, z, z_len);
  keccak_final(&ctx, out, pad, out_len);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  return result;
}

/*
 * Murmur3
 */

static napi_value
bcrypto_murmur3_sum(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint32_t out;
  const uint8_t *msg;
  size_t msg_len;
  uint32_t seed;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[1], &seed) == napi_ok);

  out = murmur3_sum(msg, msg_len, seed);

  CHECK(napi_create_uint32(env, out, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_murmur3_tweak(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint32_t out;
  const uint8_t *msg;
  size_t msg_len;
  uint32_t n, tweak;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[1], &n) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[2], &tweak) == napi_ok);

  out = murmur3_tweak(msg, msg_len, n, tweak);

  CHECK(napi_create_uint32(env, out, &result) == napi_ok);

  return result;
}

/*
 * PBKDF2
 */

static napi_value
bcrypto_pbkdf2_derive(napi_env env, napi_callback_info info) {
  napi_value argv[5];
  size_t argc = 5;
  uint8_t *out;
  uint32_t type, iter, out_len;
  const uint8_t *pass, *salt;
  size_t pass_len, salt_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 5);
  CHECK(napi_get_value_uint32(env, argv[0], &type) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pass,
                             &pass_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&salt,
                             &salt_len) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[3], &iter) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[4], &out_len) == napi_ok);

  out = (uint8_t *)safe_malloc(out_len);

  if (!pbkdf2_derive(out, type, pass, pass_len,
                     salt, salt_len, iter, out_len)) {
    safe_free(out);
    JS_THROW(JS_ERR_DERIVE);
  }

  CHECK(create_external_buffer(env, out_len, out, &result) == napi_ok);

  return result;
}

typedef struct bcrypto_pbkdf2_worker_s {
  uint32_t type;
  uint8_t *pass;
  size_t pass_len;
  uint8_t *salt;
  size_t salt_len;
  uint32_t iter;
  uint8_t *out;
  uint32_t out_len;
  const char *error;
  napi_async_work work;
  napi_deferred deferred;
} bcrypto_pbkdf2_worker_t;

static void
bcrypto_pbkdf2_execute_(napi_env env, void *data) {
  bcrypto_pbkdf2_worker_t *w = (bcrypto_pbkdf2_worker_t *)data;

  if (!pbkdf2_derive(w->out, w->type, w->pass, w->pass_len,
                     w->salt, w->salt_len, w->iter, w->out_len)) {
    w->error = JS_ERR_DERIVE;
  }

  cleanse(w->pass, w->pass_len);
  cleanse(w->salt, w->salt_len);
}

static void
bcrypto_pbkdf2_complete_(napi_env env, napi_status status, void *data) {
  bcrypto_pbkdf2_worker_t *w = (bcrypto_pbkdf2_worker_t *)data;
  napi_value result, strval;

  if (status != napi_ok)
    w->error = JS_ERR_DERIVE;

  if (w->error == NULL) {
    CHECK(create_external_buffer(env, w->out_len, w->out, &result) == napi_ok);
    CHECK(napi_resolve_deferred(env, w->deferred, result) == napi_ok);
  } else {
    CHECK(napi_create_string_utf8(env, w->error,
                                  NAPI_AUTO_LENGTH, &strval) == napi_ok);
    CHECK(napi_create_error(env, NULL, strval, &result) == napi_ok);
    CHECK(napi_reject_deferred(env, w->deferred, result) == napi_ok);
    safe_free(w->out);
  }

  CHECK(napi_delete_async_work(env, w->work) == napi_ok);

  safe_free(w->pass);
  safe_free(w->salt);
  safe_free(w);
}

static napi_value
bcrypto_pbkdf2_derive_async(napi_env env, napi_callback_info info) {
  bcrypto_pbkdf2_worker_t *worker =
    (bcrypto_pbkdf2_worker_t *)safe_malloc(sizeof(bcrypto_pbkdf2_worker_t));
  napi_value argv[5];
  size_t argc = 5;
  uint32_t type, iter, out_len;
  const uint8_t *pass, *salt;
  size_t pass_len, salt_len;
  napi_value name, result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 5);
  CHECK(napi_get_value_uint32(env, argv[0], &type) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pass,
                             &pass_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&salt,
                             &salt_len) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[3], &iter) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[4], &out_len) == napi_ok);

  worker->type = type;
  worker->pass = (uint8_t *)safe_malloc(pass_len);
  worker->pass_len = pass_len;
  worker->salt = (uint8_t *)safe_malloc(salt_len);
  worker->salt_len = salt_len;
  worker->iter = iter;
  worker->out = (uint8_t *)safe_malloc(out_len);
  worker->out_len = out_len;
  worker->error = NULL;

  memcpy(worker->pass, pass, pass_len);
  memcpy(worker->salt, salt, salt_len);

  CHECK(napi_create_string_utf8(env, "bcrypto:pbkdf2_derive",
                                NAPI_AUTO_LENGTH, &name) == napi_ok);

  CHECK(napi_create_promise(env, &worker->deferred, &result) == napi_ok);

  CHECK(napi_create_async_work(env,
                               NULL,
                               name,
                               bcrypto_pbkdf2_execute_,
                               bcrypto_pbkdf2_complete_,
                               worker,
                               &worker->work) == napi_ok);

  CHECK(napi_queue_async_work(env, worker->work) == napi_ok);

  return result;
}

/*
 * Poly1305
 */

static void
bcrypto_poly1305_destroy_(napi_env env, void *data, void *hint) {
  cleanse(data, sizeof(bcrypto_poly1305_t));
  safe_free(data);
}

static napi_value
bcrypto_poly1305_create(napi_env env, napi_callback_info info) {
  bcrypto_poly1305_t *poly =
    (bcrypto_poly1305_t *)safe_malloc(sizeof(bcrypto_poly1305_t));
  napi_value handle;

  poly->started = 0;

  CHECK(napi_create_external(env,
                             poly,
                             bcrypto_poly1305_destroy_,
                             NULL,
                             &handle) == napi_ok);

  return handle;
}

static napi_value
bcrypto_poly1305_init(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  const uint8_t *key;
  size_t key_len;
  bcrypto_poly1305_t *poly;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&poly) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&key, &key_len) == napi_ok);

  JS_ASSERT(key_len == 32, JS_ERR_KEY_SIZE);

  poly1305_init(&poly->ctx, key);
  poly->started = 1;

  return argv[0];
}

static napi_value
bcrypto_poly1305_update(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t *msg;
  size_t msg_len;
  bcrypto_poly1305_t *poly;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&poly) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&msg, &msg_len) == napi_ok);

  JS_ASSERT(poly->started, JS_ERR_INIT);

  poly1305_update(&poly->ctx, msg, msg_len);

  return argv[0];
}

static napi_value
bcrypto_poly1305_final(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  uint8_t out[16];
  bcrypto_poly1305_t *poly;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_value_external(env, argv[0], (void **)&poly) == napi_ok);

  JS_ASSERT(poly->started, JS_ERR_INIT);

  poly1305_final(&poly->ctx, out);
  poly->started = 0;

  CHECK(napi_create_buffer_copy(env, 16, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_poly1305_destroy(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  bcrypto_poly1305_t *poly;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_value_external(env, argv[0], (void **)&poly) == napi_ok);

  poly->started = 0;

  return argv[0];
}

static napi_value
bcrypto_poly1305_verify(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t mac[16];
  const uint8_t *tag;
  size_t tag_len;
  bcrypto_poly1305_t *poly;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(napi_get_value_external(env, argv[0], (void **)&poly) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&tag, &tag_len) == napi_ok);

  JS_ASSERT(tag_len == 16, JS_ERR_TAG_SIZE);
  JS_ASSERT(poly->started, JS_ERR_INIT);

  poly1305_final(&poly->ctx, mac);
  poly->started = 0;

  ok = poly1305_verify(mac, tag);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

/*
 * RSA
 */

static napi_value
bcrypto_rsa_privkey_generate(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t *out;
  size_t out_len;
  uint32_t bits;
  int64_t exp;
  uint8_t *entropy;
  size_t entropy_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_uint32(env, argv[0], &bits) == napi_ok);
  CHECK(napi_get_value_int64(env, argv[1], &exp) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&entropy,
                             &entropy_len) == napi_ok);

  JS_ASSERT(entropy_len == ENTROPY_SIZE, JS_ERR_ENTROPY_SIZE);

  out = (uint8_t *)safe_malloc(RSA_MAX_PRIV_SIZE);
  out_len = RSA_MAX_PRIV_SIZE;

  if (!rsa_privkey_generate(out, &out_len, bits, exp, entropy)) {
    safe_free(out);
    JS_THROW(JS_ERR_GENERATE);
  }

  cleanse(entropy, entropy_len);

  out = (uint8_t *)safe_realloc(out, out_len);

  CHECK(create_external_buffer(env, out_len, out, &result) == napi_ok);

  return result;
}

typedef struct bcrypto_rsa_worker_s {
  uint32_t bits;
  int64_t exp;
  uint8_t entropy[ENTROPY_SIZE];
  uint8_t *out;
  size_t out_len;
  const char *error;
  napi_async_work work;
  napi_deferred deferred;
} bcrypto_rsa_worker_t;

static void
bcrypto_rsa_execute_(napi_env env, void *data) {
  bcrypto_rsa_worker_t *w = (bcrypto_rsa_worker_t *)data;

  if (!rsa_privkey_generate(w->out, &w->out_len, w->bits, w->exp, w->entropy)) {
    w->error = JS_ERR_GENERATE;
    return;
  }

  cleanse(w->entropy, ENTROPY_SIZE);

  w->out = (uint8_t *)safe_realloc(w->out, w->out_len);
}

static void
bcrypto_rsa_complete_(napi_env env, napi_status status, void *data) {
  bcrypto_rsa_worker_t *w = (bcrypto_rsa_worker_t *)data;
  napi_value result, strval;

  if (status != napi_ok)
    w->error = JS_ERR_GENERATE;

  if (w->error == NULL) {
    CHECK(create_external_buffer(env, w->out_len, w->out, &result) == napi_ok);
    CHECK(napi_resolve_deferred(env, w->deferred, result) == napi_ok);
  } else {
    CHECK(napi_create_string_utf8(env, w->error,
                                  NAPI_AUTO_LENGTH, &strval) == napi_ok);
    CHECK(napi_create_error(env, NULL, strval, &result) == napi_ok);
    CHECK(napi_reject_deferred(env, w->deferred, result) == napi_ok);
    safe_free(w->out);
  }

  CHECK(napi_delete_async_work(env, w->work) == napi_ok);

  safe_free(w);
}

static napi_value
bcrypto_rsa_privkey_generate_async(napi_env env, napi_callback_info info) {
  bcrypto_rsa_worker_t *worker;
  napi_value argv[3];
  size_t argc = 3;
  uint32_t bits;
  int64_t exp;
  uint8_t *entropy;
  size_t entropy_len;
  napi_value name, result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_uint32(env, argv[0], &bits) == napi_ok);
  CHECK(napi_get_value_int64(env, argv[1], &exp) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&entropy,
                             &entropy_len) == napi_ok);

  JS_ASSERT(entropy_len == ENTROPY_SIZE, JS_ERR_ENTROPY_SIZE);

  worker = (bcrypto_rsa_worker_t *)safe_malloc(sizeof(bcrypto_rsa_worker_t));
  worker->bits = bits;
  worker->exp = exp;
  worker->out = (uint8_t *)safe_malloc(RSA_MAX_PRIV_SIZE);
  worker->out_len = RSA_MAX_PRIV_SIZE;
  worker->error = NULL;

  memcpy(worker->entropy, entropy, ENTROPY_SIZE);

  cleanse(entropy, entropy_len);

  CHECK(napi_create_string_utf8(env, "bcrypto:rsa_privkey_generate",
                                NAPI_AUTO_LENGTH, &name) == napi_ok);

  CHECK(napi_create_promise(env, &worker->deferred, &result) == napi_ok);

  CHECK(napi_create_async_work(env,
                               NULL,
                               name,
                               bcrypto_rsa_execute_,
                               bcrypto_rsa_complete_,
                               worker,
                               &worker->work) == napi_ok);

  CHECK(napi_queue_async_work(env, worker->work) == napi_ok);

  return result;
}

static napi_value
bcrypto_rsa_privkey_bits(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  size_t bits;
  const uint8_t *key;
  size_t key_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&key, &key_len) == napi_ok);

  bits = rsa_privkey_bits(key, key_len);

  JS_ASSERT(bits != 0, JS_ERR_PRIVKEY);

  CHECK(napi_create_uint32(env, bits, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_rsa_privkey_verify(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  const uint8_t *key;
  size_t key_len;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&key, &key_len) == napi_ok);

  ok = rsa_privkey_verify(key, key_len);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_rsa_privkey_import(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t *out;
  size_t out_len;
  const uint8_t *key;
  size_t key_len;
  uint8_t *entropy;
  size_t entropy_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&key, &key_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&entropy,
                             &entropy_len) == napi_ok);

  JS_ASSERT(entropy_len == ENTROPY_SIZE, JS_ERR_ENTROPY_SIZE);

  out = (uint8_t *)safe_malloc(RSA_MAX_PRIV_SIZE);
  out_len = RSA_MAX_PRIV_SIZE;

  if (!rsa_privkey_import(out, &out_len, key, key_len, entropy)) {
    safe_free(out);
    JS_THROW(JS_ERR_PRIVKEY);
  }

  cleanse(entropy, entropy_len);

  out = (uint8_t *)safe_realloc(out, out_len);

  CHECK(create_external_buffer(env, out_len, out, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_rsa_privkey_export(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  uint8_t *out;
  size_t out_len;
  const uint8_t *key;
  size_t key_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&key, &key_len) == napi_ok);

  out = (uint8_t *)safe_malloc(RSA_MAX_PRIV_SIZE);
  out_len = RSA_MAX_PRIV_SIZE;

  if (!rsa_privkey_export(out, &out_len, key, key_len)) {
    safe_free(out);
    JS_THROW(JS_ERR_PRIVKEY);
  }

  out = (uint8_t *)safe_realloc(out, out_len);

  CHECK(create_external_buffer(env, out_len, out, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_rsa_pubkey_create(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  uint8_t *out;
  size_t out_len;
  const uint8_t *key;
  size_t key_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&key, &key_len) == napi_ok);

  out = (uint8_t *)safe_malloc(RSA_MAX_PUB_SIZE);
  out_len = RSA_MAX_PUB_SIZE;

  if (!rsa_pubkey_create(out, &out_len, key, key_len)) {
    safe_free(out);
    JS_THROW(JS_ERR_PRIVKEY);
  }

  out = (uint8_t *)safe_realloc(out, out_len);

  CHECK(create_external_buffer(env, out_len, out, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_rsa_pubkey_bits(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  size_t bits;
  const uint8_t *key;
  size_t key_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&key, &key_len) == napi_ok);

  bits = rsa_pubkey_bits(key, key_len);

  JS_ASSERT(bits != 0, JS_ERR_PRIVKEY);

  CHECK(napi_create_uint32(env, bits, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_rsa_pubkey_verify(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  const uint8_t *key;
  size_t key_len;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&key, &key_len) == napi_ok);

  ok = rsa_pubkey_verify(key, key_len);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_rsa_pubkey_import(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  uint8_t *out;
  size_t out_len;
  const uint8_t *key;
  size_t key_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&key, &key_len) == napi_ok);

  out = (uint8_t *)safe_malloc(RSA_MAX_PUB_SIZE);
  out_len = RSA_MAX_PUB_SIZE;

  if (!rsa_pubkey_import(out, &out_len, key, key_len)) {
    safe_free(out);
    JS_THROW(JS_ERR_PUBKEY);
  }

  out = (uint8_t *)safe_realloc(out, out_len);

  CHECK(create_external_buffer(env, out_len, out, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_rsa_pubkey_export(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  uint8_t *out;
  size_t out_len;
  const uint8_t *key;
  size_t key_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&key, &key_len) == napi_ok);

  out = (uint8_t *)safe_malloc(RSA_MAX_PUB_SIZE);
  out_len = RSA_MAX_PUB_SIZE;

  if (!rsa_pubkey_export(out, &out_len, key, key_len)) {
    safe_free(out);
    JS_THROW(JS_ERR_PUBKEY);
  }

  out = (uint8_t *)safe_realloc(out, out_len);

  CHECK(create_external_buffer(env, out_len, out, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_rsa_sign(napi_env env, napi_callback_info info) {
  napi_value argv[4];
  size_t argc = 4;
  uint8_t *out;
  size_t out_len;
  uint32_t type;
  const uint8_t *msg, *key;
  size_t msg_len, key_len;
  uint8_t *entropy;
  size_t entropy_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 4);
  CHECK(napi_get_value_uint32(env, argv[0], &type) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&key, &key_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[3], (void **)&entropy,
                             &entropy_len) == napi_ok);

  JS_ASSERT(entropy_len == ENTROPY_SIZE, JS_ERR_ENTROPY_SIZE);

  out = (uint8_t *)safe_malloc(RSA_MAX_MOD_SIZE);
  out_len = RSA_MAX_MOD_SIZE;

  if (!rsa_sign(out, &out_len, type, msg, msg_len, key, key_len, entropy)) {
    safe_free(out);
    JS_THROW(JS_ERR_SIGN);
  }

  cleanse(entropy, entropy_len);

  out = (uint8_t *)safe_realloc(out, out_len);

  CHECK(create_external_buffer(env, out_len, out, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_rsa_verify(napi_env env, napi_callback_info info) {
  napi_value argv[4];
  size_t argc = 4;
  uint32_t type;
  const uint8_t *msg, *sig, *key;
  size_t msg_len, sig_len, key_len;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 4);
  CHECK(napi_get_value_uint32(env, argv[0], &type) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&sig, &sig_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[3], (void **)&key, &key_len) == napi_ok);

  ok = rsa_verify(type, msg, msg_len, sig, sig_len, key, key_len);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_rsa_encrypt(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t *out;
  size_t out_len;
  const uint8_t *msg, *key;
  size_t msg_len, key_len;
  uint8_t *entropy;
  size_t entropy_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&key, &key_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&entropy,
                             &entropy_len) == napi_ok);

  JS_ASSERT(entropy_len == ENTROPY_SIZE, JS_ERR_ENTROPY_SIZE);

  out = (uint8_t *)safe_malloc(RSA_MAX_MOD_SIZE);
  out_len = RSA_MAX_MOD_SIZE;

  if (!rsa_encrypt(out, &out_len, msg, msg_len, key, key_len, entropy)) {
    safe_free(out);
    JS_THROW(JS_ERR_ENCRYPT);
  }

  cleanse(entropy, entropy_len);

  out = (uint8_t *)safe_realloc(out, out_len);

  CHECK(create_external_buffer(env, out_len, out, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_rsa_decrypt(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t *out;
  size_t out_len;
  const uint8_t *msg, *key;
  size_t msg_len, key_len;
  uint8_t *entropy;
  size_t entropy_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&key, &key_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&entropy,
                             &entropy_len) == napi_ok);

  JS_ASSERT(entropy_len == ENTROPY_SIZE, JS_ERR_ENTROPY_SIZE);

  out = (uint8_t *)safe_malloc(RSA_MAX_MOD_SIZE);
  out_len = RSA_MAX_MOD_SIZE;

  if (!rsa_decrypt(out, &out_len, msg, msg_len, key, key_len, entropy)) {
    safe_free(out);
    JS_THROW(JS_ERR_ENCRYPT);
  }

  cleanse(entropy, entropy_len);

  out = (uint8_t *)safe_realloc(out, out_len);

  CHECK(create_external_buffer(env, out_len, out, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_rsa_sign_pss(napi_env env, napi_callback_info info) {
  napi_value argv[5];
  size_t argc = 5;
  uint8_t *out;
  size_t out_len;
  uint32_t type;
  const uint8_t *msg, *key;
  size_t msg_len, key_len;
  int32_t salt_len;
  uint8_t *entropy;
  size_t entropy_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 5);
  CHECK(napi_get_value_uint32(env, argv[0], &type) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&key, &key_len) == napi_ok);
  CHECK(napi_get_value_int32(env, argv[3], &salt_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[4], (void **)&entropy,
                             &entropy_len) == napi_ok);

  JS_ASSERT(entropy_len == ENTROPY_SIZE, JS_ERR_ENTROPY_SIZE);

  out = (uint8_t *)safe_malloc(RSA_MAX_MOD_SIZE);
  out_len = RSA_MAX_MOD_SIZE;

  if (!rsa_sign_pss(out, &out_len, type, msg, msg_len,
                    key, key_len, salt_len, entropy)) {
    safe_free(out);
    JS_THROW(JS_ERR_SIGN);
  }

  cleanse(entropy, entropy_len);

  out = (uint8_t *)safe_realloc(out, out_len);

  CHECK(create_external_buffer(env, out_len, out, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_rsa_verify_pss(napi_env env, napi_callback_info info) {
  napi_value argv[5];
  size_t argc = 5;
  uint32_t type;
  const uint8_t *msg, *sig, *key;
  size_t msg_len, sig_len, key_len;
  int32_t salt_len;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 5);
  CHECK(napi_get_value_uint32(env, argv[0], &type) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&sig, &sig_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[3], (void **)&key, &key_len) == napi_ok);
  CHECK(napi_get_value_int32(env, argv[4], &salt_len) == napi_ok);

  ok = rsa_verify_pss(type, msg, msg_len, sig, sig_len, key, key_len, salt_len);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_rsa_encrypt_oaep(napi_env env, napi_callback_info info) {
  napi_value argv[5];
  size_t argc = 5;
  uint8_t *out;
  size_t out_len;
  uint32_t type;
  const uint8_t *msg, *key, *label;
  size_t msg_len, key_len, label_len;
  uint8_t *entropy;
  size_t entropy_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 5);
  CHECK(napi_get_value_uint32(env, argv[0], &type) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&key, &key_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[3], (void **)&label,
                             &label_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[4], (void **)&entropy,
                             &entropy_len) == napi_ok);

  JS_ASSERT(entropy_len == ENTROPY_SIZE, JS_ERR_ENTROPY_SIZE);

  out = (uint8_t *)safe_malloc(RSA_MAX_MOD_SIZE);
  out_len = RSA_MAX_MOD_SIZE;

  if (!rsa_encrypt_oaep(out, &out_len, type, msg, msg_len,
                        key, key_len, label, label_len, entropy)) {
    safe_free(out);
    JS_THROW(JS_ERR_ENCRYPT);
  }

  cleanse(entropy, entropy_len);

  out = (uint8_t *)safe_realloc(out, out_len);

  CHECK(create_external_buffer(env, out_len, out, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_rsa_decrypt_oaep(napi_env env, napi_callback_info info) {
  napi_value argv[5];
  size_t argc = 5;
  uint8_t *out;
  size_t out_len;
  uint32_t type;
  const uint8_t *msg, *key, *label;
  size_t msg_len, key_len, label_len;
  uint8_t *entropy;
  size_t entropy_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 5);
  CHECK(napi_get_value_uint32(env, argv[0], &type) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&key, &key_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[3], (void **)&label,
                             &label_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[4], (void **)&entropy,
                             &entropy_len) == napi_ok);

  JS_ASSERT(entropy_len == ENTROPY_SIZE, JS_ERR_ENTROPY_SIZE);

  out = (uint8_t *)safe_malloc(RSA_MAX_MOD_SIZE);
  out_len = RSA_MAX_MOD_SIZE;

  if (!rsa_decrypt_oaep(out, &out_len, type, msg, msg_len,
                        key, key_len, label, label_len, entropy)) {
    safe_free(out);
    JS_THROW(JS_ERR_ENCRYPT);
  }

  cleanse(entropy, entropy_len);

  out = (uint8_t *)safe_realloc(out, out_len);

  CHECK(create_external_buffer(env, out_len, out, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_rsa_veil(napi_env env, napi_callback_info info) {
  napi_value argv[4];
  size_t argc = 4;
  uint8_t *out;
  size_t out_len;
  uint32_t bits;
  const uint8_t *msg, *key;
  size_t msg_len, key_len;
  uint8_t *entropy;
  size_t entropy_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 4);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[1], &bits) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&key, &key_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[3], (void **)&entropy,
                             &entropy_len) == napi_ok);

  JS_ASSERT(entropy_len == ENTROPY_SIZE, JS_ERR_ENTROPY_SIZE);

  out_len = (bits + 7) / 8;
  out = (uint8_t *)safe_malloc(out_len);

  if (!rsa_veil(out, &out_len, msg, msg_len, bits, key, key_len, entropy)) {
    safe_free(out);
    JS_THROW(JS_ERR_VEIL);
  }

  cleanse(entropy, entropy_len);

  out = (uint8_t *)safe_realloc(out, out_len);

  CHECK(create_external_buffer(env, out_len, out, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_rsa_unveil(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t *out;
  size_t out_len;
  uint32_t bits;
  const uint8_t *msg, *key;
  size_t msg_len, key_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[1], &bits) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&key, &key_len) == napi_ok);

  out = (uint8_t *)safe_malloc(RSA_MAX_MOD_SIZE);
  out_len = RSA_MAX_MOD_SIZE;

  if (!rsa_unveil(out, &out_len, msg, msg_len, bits, key, key_len)) {
    safe_free(out);
    JS_THROW(JS_ERR_VEIL);
  }

  out = (uint8_t *)safe_realloc(out, out_len);

  CHECK(create_external_buffer(env, out_len, out, &result) == napi_ok);

  return result;
}

/*
 * Salsa20
 */

static void
bcrypto_salsa20_destroy_(napi_env env, void *data, void *hint) {
  cleanse(data, sizeof(bcrypto_salsa20_t));
  safe_free(data);
}

static napi_value
bcrypto_salsa20_create(napi_env env, napi_callback_info info) {
  bcrypto_salsa20_t *salsa =
    (bcrypto_salsa20_t *)safe_malloc(sizeof(bcrypto_salsa20_t));
  napi_value handle;

  salsa->started = 0;

  CHECK(napi_create_external(env,
                             salsa,
                             bcrypto_salsa20_destroy_,
                             NULL,
                             &handle) == napi_ok);

  return handle;
}

static napi_value
bcrypto_salsa20_init(napi_env env, napi_callback_info info) {
  napi_value argv[4];
  size_t argc = 4;
  const uint8_t *key, *nonce;
  size_t key_len, nonce_len;
  int64_t ctr;
  bcrypto_salsa20_t *salsa;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 4);
  CHECK(napi_get_value_external(env, argv[0], (void **)&salsa) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&key, &key_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&nonce,
                             &nonce_len) == napi_ok);
  CHECK(napi_get_value_int64(env, argv[3], &ctr) == napi_ok);

  JS_ASSERT(key_len == 16 || key_len == 32, JS_ERR_KEY_SIZE);
  JS_ASSERT(nonce_len == 8 || nonce_len == 12
         || nonce_len == 16 || nonce_len == 24
         || nonce_len == 28 || nonce_len == 32, JS_ERR_NONCE_SIZE);

  salsa20_init(&salsa->ctx, key, key_len, nonce, nonce_len, ctr);
  salsa->started = 1;

  return argv[0];
}

static napi_value
bcrypto_salsa20_encrypt(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t *msg;
  size_t msg_len;
  bcrypto_salsa20_t *salsa;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&salsa) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&msg, &msg_len) == napi_ok);

  JS_ASSERT(salsa->started, JS_ERR_INIT);

  salsa20_encrypt(&salsa->ctx, msg, msg, msg_len);

  return argv[1];
}

static napi_value
bcrypto_salsa20_destroy(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  bcrypto_salsa20_t *salsa;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_value_external(env, argv[0], (void **)&salsa) == napi_ok);

  salsa->started = 0;

  return argv[0];
}

static napi_value
bcrypto_salsa20_derive(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t out[32];
  const uint8_t *key, *nonce;
  size_t key_len, nonce_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&key, &key_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&nonce,
                             &nonce_len) == napi_ok);

  JS_ASSERT(key_len == 16 || key_len == 32, JS_ERR_KEY_SIZE);
  JS_ASSERT(nonce_len == 16, JS_ERR_NONCE_SIZE);

  salsa20_derive(out, key, key_len, nonce);

  CHECK(napi_create_buffer_copy(env, 32, out, NULL, &result) == napi_ok);

  return result;
}

/*
 * Schnorr
 */

static void
bcrypto_schnorr_destroy(napi_env env, void *data, void *hint) {
  bcrypto_schnorr_t *ec = (bcrypto_schnorr_t *)data;

  schnorr_scratch_destroy(ec->ctx, ec->scratch);
  schnorr_context_destroy(ec->ctx);
  safe_free(ec);
}

static napi_value
bcrypto_schnorr_create(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  uint32_t type;
  bcrypto_schnorr_t *ec;
  schnorr_t *ctx;
  napi_value handle;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_value_uint32(env, argv[0], &type) == napi_ok);

  JS_ASSERT(ctx = schnorr_context_create(type), JS_ERR_CONTEXT);

  ec = (bcrypto_schnorr_t *)safe_malloc(sizeof(bcrypto_schnorr_t));
  ec->ctx = ctx;
  ec->scratch = schnorr_scratch_create(ec->ctx);
  ec->scalar_size = schnorr_scalar_size(ec->ctx);
  ec->scalar_bits = schnorr_scalar_bits(ec->ctx);
  ec->field_size = schnorr_field_size(ec->ctx);
  ec->field_bits = schnorr_field_bits(ec->ctx);
  ec->sig_size = schnorr_sig_size(ec->ctx);

  CHECK(ec->scratch != NULL);

  CHECK(napi_create_external(env,
                             ec,
                             bcrypto_schnorr_destroy,
                             NULL,
                             &handle) == napi_ok);

  return handle;
}

static napi_value
bcrypto_schnorr_size(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  bcrypto_schnorr_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_create_uint32(env, ec->field_size, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_schnorr_bits(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  bcrypto_schnorr_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_create_uint32(env, ec->field_bits, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_schnorr_randomize(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t *entropy;
  size_t entropy_len;
  bcrypto_schnorr_t *ec;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&entropy,
                             &entropy_len) == napi_ok);

  JS_ASSERT(entropy_len == ENTROPY_SIZE, JS_ERR_ENTROPY_SIZE);

  schnorr_context_randomize(ec->ctx, entropy);

  cleanse(entropy, entropy_len);

  return argv[0];
}

static napi_value
bcrypto_schnorr_privkey_generate(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t *entropy;
  size_t entropy_len;
  uint8_t out[SCHNORR_MAX_PRIV_SIZE];
  bcrypto_schnorr_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&entropy,
                             &entropy_len) == napi_ok);

  JS_ASSERT(entropy_len == ENTROPY_SIZE, JS_ERR_ENTROPY_SIZE);

  schnorr_privkey_generate(ec->ctx, out, entropy);

  cleanse(entropy, entropy_len);

  CHECK(napi_create_buffer_copy(env,
                                ec->scalar_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_schnorr_privkey_verify(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  const uint8_t *priv;
  size_t priv_len;
  bcrypto_schnorr_t *ec;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&priv,
                             &priv_len) == napi_ok);

  ok = priv_len == ec->scalar_size && schnorr_privkey_verify(ec->ctx, priv);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_schnorr_privkey_export(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t d[SCHNORR_MAX_PRIV_SIZE];
  uint8_t x[SCHNORR_MAX_FIELD_SIZE];
  uint8_t y[SCHNORR_MAX_FIELD_SIZE];
  const uint8_t *priv;
  size_t priv_len;
  bcrypto_schnorr_t *ec;
  napi_value bd, bx, by, result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&priv,
                             &priv_len) == napi_ok);

  JS_ASSERT(priv_len == ec->scalar_size, JS_ERR_PRIVKEY_SIZE);
  JS_ASSERT(schnorr_privkey_export(ec->ctx, d, x, y, priv), JS_ERR_PRIVKEY);

  CHECK(napi_create_buffer_copy(env, ec->scalar_size, d, NULL, &bd) == napi_ok);
  CHECK(napi_create_buffer_copy(env, ec->field_size, x, NULL, &bx) == napi_ok);
  CHECK(napi_create_buffer_copy(env, ec->field_size, y, NULL, &by) == napi_ok);

  CHECK(napi_create_array_with_length(env, 3, &result) == napi_ok);
  CHECK(napi_set_element(env, result, 0, bd) == napi_ok);
  CHECK(napi_set_element(env, result, 1, bx) == napi_ok);
  CHECK(napi_set_element(env, result, 2, by) == napi_ok);

  return result;
}

static napi_value
bcrypto_schnorr_privkey_import(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t out[SCHNORR_MAX_PRIV_SIZE];
  const uint8_t *priv;
  size_t priv_len;
  bcrypto_schnorr_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&priv,
                             &priv_len) == napi_ok);

  JS_ASSERT(schnorr_privkey_import(ec->ctx, out, priv, priv_len),
            JS_ERR_PRIVKEY);

  CHECK(napi_create_buffer_copy(env,
                                ec->scalar_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_schnorr_privkey_tweak_add(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[SCHNORR_MAX_PRIV_SIZE];
  const uint8_t *priv, *tweak;
  size_t priv_len, tweak_len;
  bcrypto_schnorr_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&priv,
                             &priv_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&tweak,
                             &tweak_len) == napi_ok);

  JS_ASSERT(priv_len == ec->scalar_size, JS_ERR_PRIVKEY_SIZE);
  JS_ASSERT(tweak_len == ec->scalar_size, JS_ERR_SCALAR_SIZE);
  JS_ASSERT(schnorr_privkey_tweak_add(ec->ctx, out, priv, tweak),
            JS_ERR_PRIVKEY);

  CHECK(napi_create_buffer_copy(env,
                                ec->scalar_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_schnorr_privkey_tweak_mul(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[SCHNORR_MAX_PRIV_SIZE];
  const uint8_t *priv, *tweak;
  size_t priv_len, tweak_len;
  bcrypto_schnorr_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&priv,
                             &priv_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&tweak,
                             &tweak_len) == napi_ok);

  JS_ASSERT(priv_len == ec->scalar_size, JS_ERR_PRIVKEY_SIZE);
  JS_ASSERT(tweak_len == ec->scalar_size, JS_ERR_SCALAR_SIZE);
  JS_ASSERT(schnorr_privkey_tweak_mul(ec->ctx, out, priv, tweak),
            JS_ERR_PRIVKEY);

  CHECK(napi_create_buffer_copy(env,
                                ec->scalar_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_schnorr_privkey_reduce(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t out[SCHNORR_MAX_PRIV_SIZE];
  const uint8_t *priv;
  size_t priv_len;
  bcrypto_schnorr_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&priv,
                             &priv_len) == napi_ok);

  JS_ASSERT(schnorr_privkey_reduce(ec->ctx, out, priv, priv_len),
            JS_ERR_PRIVKEY);

  CHECK(napi_create_buffer_copy(env,
                                ec->scalar_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_schnorr_privkey_invert(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t out[SCHNORR_MAX_PRIV_SIZE];
  const uint8_t *priv;
  size_t priv_len;
  bcrypto_schnorr_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&priv,
                             &priv_len) == napi_ok);

  JS_ASSERT(priv_len == ec->scalar_size, JS_ERR_PRIVKEY_SIZE);
  JS_ASSERT(schnorr_privkey_invert(ec->ctx, out, priv), JS_ERR_PRIVKEY);

  CHECK(napi_create_buffer_copy(env,
                                ec->scalar_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_schnorr_pubkey_create(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t out[SCHNORR_MAX_PUB_SIZE];
  const uint8_t *priv;
  size_t priv_len;
  bcrypto_schnorr_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&priv,
                             &priv_len) == napi_ok);

  JS_ASSERT(priv_len == ec->scalar_size, JS_ERR_PRIVKEY_SIZE);
  JS_ASSERT(schnorr_pubkey_create(ec->ctx, out, priv), JS_ERR_PRIVKEY);

  CHECK(napi_create_buffer_copy(env,
                                ec->field_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_schnorr_pubkey_from_uniform(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t out[SCHNORR_MAX_PUB_SIZE];
  const uint8_t *data;
  size_t data_len;
  bcrypto_schnorr_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&data,
                             &data_len) == napi_ok);

  JS_ASSERT(data_len == ec->field_size, JS_ERR_PREIMAGE_SIZE);

  schnorr_pubkey_from_uniform(ec->ctx, out, data);

  CHECK(napi_create_buffer_copy(env,
                                ec->field_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_schnorr_pubkey_to_uniform(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[SCHNORR_MAX_FIELD_SIZE];
  const uint8_t *pub;
  size_t pub_len;
  uint32_t hint;
  bcrypto_schnorr_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pub,
                             &pub_len) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[2], &hint) == napi_ok);

  JS_ASSERT(pub_len == ec->field_size, JS_ERR_PUBKEY_SIZE);
  JS_ASSERT(schnorr_pubkey_to_uniform(ec->ctx, out, pub, hint), JS_ERR_PUBKEY);

  CHECK(napi_create_buffer_copy(env, ec->field_size,
                                out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_schnorr_pubkey_from_hash(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t out[SCHNORR_MAX_PUB_SIZE];
  const uint8_t *data;
  size_t data_len;
  bcrypto_schnorr_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&data,
                             &data_len) == napi_ok);

  JS_ASSERT(data_len == ec->field_size * 2, JS_ERR_PREIMAGE_SIZE);
  JS_ASSERT(schnorr_pubkey_from_hash(ec->ctx, out, data), JS_ERR_PREIMAGE);

  CHECK(napi_create_buffer_copy(env,
                                ec->field_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_schnorr_pubkey_to_hash(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[SCHNORR_MAX_FIELD_SIZE * 2];
  const uint8_t *pub;
  uint8_t *entropy;
  size_t pub_len, entropy_len;
  bcrypto_schnorr_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pub,
                             &pub_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&entropy,
                             &entropy_len) == napi_ok);

  JS_ASSERT(pub_len == ec->field_size, JS_ERR_PUBKEY_SIZE);
  JS_ASSERT(entropy_len == ENTROPY_SIZE, JS_ERR_ENTROPY_SIZE);
  JS_ASSERT(schnorr_pubkey_to_hash(ec->ctx, out, pub, 0, entropy),
            JS_ERR_PUBKEY);

  cleanse(entropy, entropy_len);

  CHECK(napi_create_buffer_copy(env, ec->field_size * 2,
                                out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_schnorr_pubkey_verify(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  const uint8_t *pub;
  size_t pub_len;
  bcrypto_schnorr_t *ec;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pub,
                             &pub_len) == napi_ok);

  ok = pub_len == ec->field_size && schnorr_pubkey_verify(ec->ctx, pub);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_schnorr_pubkey_export(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t x[SCHNORR_MAX_FIELD_SIZE];
  uint8_t y[SCHNORR_MAX_FIELD_SIZE];
  const uint8_t *pub;
  size_t pub_len;
  bcrypto_schnorr_t *ec;
  napi_value bx, by, result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pub,
                             &pub_len) == napi_ok);

  JS_ASSERT(pub_len == ec->field_size, JS_ERR_PUBKEY_SIZE);
  JS_ASSERT(schnorr_pubkey_export(ec->ctx, x, y, pub), JS_ERR_PUBKEY);

  CHECK(napi_create_buffer_copy(env, ec->field_size, x, NULL, &bx) == napi_ok);
  CHECK(napi_create_buffer_copy(env, ec->field_size, y, NULL, &by) == napi_ok);

  CHECK(napi_create_array_with_length(env, 2, &result) == napi_ok);
  CHECK(napi_set_element(env, result, 0, bx) == napi_ok);
  CHECK(napi_set_element(env, result, 1, by) == napi_ok);

  return result;
}

static napi_value
bcrypto_schnorr_pubkey_import(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t out[SCHNORR_MAX_PUB_SIZE];
  const uint8_t *x;
  size_t x_len;
  bcrypto_schnorr_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&x, &x_len) == napi_ok);

  JS_ASSERT(schnorr_pubkey_import(ec->ctx, out, x, x_len), JS_ERR_PUBKEY);

  CHECK(napi_create_buffer_copy(env,
                                ec->field_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_schnorr_pubkey_tweak_add(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[SCHNORR_MAX_PUB_SIZE];
  const uint8_t *pub, *tweak;
  size_t pub_len, tweak_len;
  bcrypto_schnorr_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pub,
                             &pub_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&tweak,
                             &tweak_len) == napi_ok);

  JS_ASSERT(pub_len == ec->field_size, JS_ERR_PUBKEY_SIZE);
  JS_ASSERT(tweak_len == ec->scalar_size, JS_ERR_SCALAR_SIZE);
  JS_ASSERT(schnorr_pubkey_tweak_add(ec->ctx, out, NULL, pub, tweak),
            JS_ERR_PUBKEY);

  CHECK(napi_create_buffer_copy(env,
                                ec->field_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_schnorr_pubkey_tweak_mul(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[SCHNORR_MAX_PUB_SIZE];
  const uint8_t *pub, *tweak;
  size_t pub_len, tweak_len;
  bcrypto_schnorr_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pub,
                             &pub_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&tweak,
                             &tweak_len) == napi_ok);

  JS_ASSERT(pub_len == ec->field_size, JS_ERR_PUBKEY_SIZE);
  JS_ASSERT(tweak_len == ec->scalar_size, JS_ERR_SCALAR_SIZE);
  JS_ASSERT(schnorr_pubkey_tweak_mul(ec->ctx, out, NULL, pub, tweak),
            JS_ERR_PUBKEY);

  CHECK(napi_create_buffer_copy(env,
                                ec->field_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_schnorr_pubkey_tweak_sum(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[SCHNORR_MAX_PUB_SIZE];
  int negated;
  const uint8_t *pub, *tweak;
  size_t pub_len, tweak_len;
  bcrypto_schnorr_t *ec;
  napi_value outval, negval, result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pub,
                             &pub_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&tweak,
                             &tweak_len) == napi_ok);

  JS_ASSERT(pub_len == ec->field_size, JS_ERR_PUBKEY_SIZE);
  JS_ASSERT(tweak_len == ec->scalar_size, JS_ERR_SCALAR_SIZE);
  JS_ASSERT(schnorr_pubkey_tweak_add(ec->ctx, out, &negated, pub, tweak),
            JS_ERR_PUBKEY);

  CHECK(napi_create_buffer_copy(env,
                                ec->field_size,
                                out,
                                NULL,
                                &outval) == napi_ok);

  CHECK(napi_get_boolean(env, negated, &negval) == napi_ok);

  CHECK(napi_create_array_with_length(env, 2, &result) == napi_ok);
  CHECK(napi_set_element(env, result, 0, outval) == napi_ok);
  CHECK(napi_set_element(env, result, 1, negval) == napi_ok);

  return result;
}

static napi_value
bcrypto_schnorr_pubkey_tweak_test(napi_env env, napi_callback_info info) {
  napi_value argv[5];
  size_t argc = 5;
  const uint8_t *pub, *tweak, *expect;
  size_t pub_len, tweak_len, expect_len;
  bool negated;
  bcrypto_schnorr_t *ec;
  napi_value result;
  int ok = 0;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 5);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pub,
                             &pub_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&tweak,
                             &tweak_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[3], (void **)&expect,
                             &expect_len) == napi_ok);
  CHECK(napi_get_value_bool(env, argv[4], &negated) == napi_ok);

  if (pub_len != ec->field_size
      || tweak_len != ec->scalar_size
      || expect_len != ec->field_size) {
    goto fail;
  }

  schnorr_pubkey_tweak_test(ec->ctx, &ok, pub, tweak, expect, negated);

fail:
  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_schnorr_pubkey_combine(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t out[SCHNORR_MAX_PUB_SIZE];
  uint32_t i, length;
  const uint8_t **pubs;
  size_t pub_len;
  bcrypto_schnorr_t *ec;
  napi_value item, result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_array_length(env, argv[1], &length) == napi_ok);

  pubs = (const uint8_t **)safe_malloc(length * sizeof(uint8_t *));

  for (i = 0; i < length; i++) {
    CHECK(napi_get_element(env, argv[1], i, &item) == napi_ok);
    CHECK(napi_get_buffer_info(env, item, (void **)&pubs[i],
                               &pub_len) == napi_ok);

    if (pub_len != ec->field_size) {
      safe_free(pubs);
      JS_THROW(JS_ERR_PUBKEY_SIZE);
    }
  }

  ok = schnorr_pubkey_combine(ec->ctx, out, pubs, length);

  safe_free(pubs);

  JS_ASSERT(ok, JS_ERR_PUBKEY);

  CHECK(napi_create_buffer_copy(env,
                                ec->field_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_schnorr_sign(napi_env env, napi_callback_info info) {
  napi_value argv[4];
  size_t argc = 4;
  uint8_t out[SCHNORR_MAX_SIG_SIZE];
  const uint8_t *msg, *priv, *aux;
  size_t msg_len, priv_len, aux_len;
  bcrypto_schnorr_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 4);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&priv,
                             &priv_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[3], (void **)&aux, &aux_len) == napi_ok);

  JS_ASSERT(priv_len == ec->scalar_size, JS_ERR_PRIVKEY_SIZE);
  JS_ASSERT(aux_len == 32, JS_ERR_PRIVKEY_SIZE);
  JS_ASSERT(schnorr_sign(ec->ctx, out, msg, msg_len, priv, aux), JS_ERR_SIGN);

  CHECK(napi_create_buffer_copy(env,
                                ec->sig_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_schnorr_verify(napi_env env, napi_callback_info info) {
  napi_value argv[4];
  size_t argc = 4;
  const uint8_t *msg, *sig, *pub;
  size_t msg_len, sig_len, pub_len;
  bcrypto_schnorr_t *ec;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 4);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&sig, &sig_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[3], (void **)&pub, &pub_len) == napi_ok);

  ok = sig_len == ec->sig_size
    && pub_len == ec->field_size
    && schnorr_verify(ec->ctx, msg, msg_len, sig, pub);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_schnorr_verify_batch(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint32_t i, length, item_len;
  const uint8_t **ptrs, **msgs, **pubs, **sigs;
  size_t *lens, *msg_lens;
  size_t sig_len, pub_len;
  bcrypto_schnorr_t *ec;
  napi_value item, result;
  napi_value items[3];
  int ok = 0;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_array_length(env, argv[1], &length) == napi_ok);

  if (length == 0) {
    CHECK(napi_get_boolean(env, true, &result) == napi_ok);
    return result;
  }

  ptrs = (const uint8_t **)safe_malloc(3 * length * sizeof(uint8_t *));
  lens = (size_t *)safe_malloc(1 * length * sizeof(size_t));
  msgs = &ptrs[length * 0];
  pubs = &ptrs[length * 1];
  sigs = &ptrs[length * 2];
  msg_lens = &lens[length * 0];

  memset(items, 0, sizeof(items));

  for (i = 0; i < length; i++) {
    CHECK(napi_get_element(env, argv[1], i, &item) == napi_ok);
    CHECK(napi_get_array_length(env, item, &item_len) == napi_ok);
    CHECK(item_len == 3);

    CHECK(napi_get_element(env, item, 0, &items[0]) == napi_ok);
    CHECK(napi_get_element(env, item, 1, &items[1]) == napi_ok);
    CHECK(napi_get_element(env, item, 2, &items[2]) == napi_ok);

    CHECK(napi_get_buffer_info(env, items[0], (void **)&msgs[i],
                               &msg_lens[i]) == napi_ok);

    CHECK(napi_get_buffer_info(env, items[1], (void **)&sigs[i],
                               &sig_len) == napi_ok);

    CHECK(napi_get_buffer_info(env, items[2], (void **)&pubs[i],
                               &pub_len) == napi_ok);

    if (sig_len != ec->sig_size || pub_len != ec->field_size)
      goto fail;
  }

  ok = schnorr_verify_batch(ec->ctx, msgs, msg_lens, sigs,
                            pubs, length, ec->scratch);

fail:
  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  safe_free(ptrs);
  safe_free(lens);

  return result;
}

static napi_value
bcrypto_schnorr_derive(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[SCHNORR_MAX_PUB_SIZE];
  const uint8_t *pub, *priv;
  size_t pub_len, priv_len;
  bcrypto_schnorr_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 4);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pub, &pub_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&priv,
                             &priv_len) == napi_ok);

  JS_ASSERT(pub_len == ec->field_size, JS_ERR_PUBKEY_SIZE);
  JS_ASSERT(priv_len == ec->scalar_size, JS_ERR_PRIVKEY_SIZE);
  JS_ASSERT(schnorr_derive(ec->ctx, out, pub, priv), JS_ERR_PUBKEY);

  CHECK(napi_create_buffer_copy(env,
                                ec->field_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

/*
 * Scrypt
 */

static napi_value
bcrypto_scrypt_derive(napi_env env, napi_callback_info info) {
  napi_value argv[6];
  size_t argc = 6;
  uint8_t *out;
  uint32_t out_len;
  const uint8_t *pass, *salt;
  size_t pass_len, salt_len;
  int64_t N;
  uint32_t r, p;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 6);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&pass,
                             &pass_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&salt,
                             &salt_len) == napi_ok);
  CHECK(napi_get_value_int64(env, argv[2], &N) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[3], &r) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[4], &p) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[5], &out_len) == napi_ok);

  out = (uint8_t *)safe_malloc(out_len);

  if (!scrypt_derive(out, pass, pass_len,
                     salt, salt_len, N, r, p, out_len)) {
    safe_free(out);
    JS_THROW(JS_ERR_DERIVE);
  }

  CHECK(create_external_buffer(env, out_len, out, &result) == napi_ok);

  return result;
}

typedef struct bcrypto_scrypt_worker_s {
  uint8_t *pass;
  size_t pass_len;
  uint8_t *salt;
  size_t salt_len;
  int64_t N;
  uint32_t r;
  uint32_t p;
  uint8_t *out;
  uint32_t out_len;
  const char *error;
  napi_async_work work;
  napi_deferred deferred;
} bcrypto_scrypt_worker_t;

static void
bcrypto_scrypt_execute_(napi_env env, void *data) {
  bcrypto_scrypt_worker_t *w = (bcrypto_scrypt_worker_t *)data;

  if (!scrypt_derive(w->out, w->pass, w->pass_len,
                     w->salt, w->salt_len, w->N, w->r, w->p, w->out_len)) {
    w->error = JS_ERR_DERIVE;
  }

  cleanse(w->pass, w->pass_len);
  cleanse(w->salt, w->salt_len);
}

static void
bcrypto_scrypt_complete_(napi_env env, napi_status status, void *data) {
  bcrypto_scrypt_worker_t *w = (bcrypto_scrypt_worker_t *)data;
  napi_value result, strval;

  if (status != napi_ok)
    w->error = JS_ERR_DERIVE;

  if (w->error == NULL) {
    CHECK(create_external_buffer(env, w->out_len, w->out, &result) == napi_ok);
    CHECK(napi_resolve_deferred(env, w->deferred, result) == napi_ok);
  } else {
    CHECK(napi_create_string_utf8(env, w->error,
                                  NAPI_AUTO_LENGTH, &strval) == napi_ok);
    CHECK(napi_create_error(env, NULL, strval, &result) == napi_ok);
    CHECK(napi_reject_deferred(env, w->deferred, result) == napi_ok);
    safe_free(w->out);
  }

  CHECK(napi_delete_async_work(env, w->work) == napi_ok);

  safe_free(w->pass);
  safe_free(w->salt);
  safe_free(w);
}

static napi_value
bcrypto_scrypt_derive_async(napi_env env, napi_callback_info info) {
  bcrypto_scrypt_worker_t *worker =
    (bcrypto_scrypt_worker_t *)safe_malloc(sizeof(bcrypto_scrypt_worker_t));
  napi_value argv[6];
  size_t argc = 6;
  uint32_t out_len;
  const uint8_t *pass, *salt;
  size_t pass_len, salt_len;
  int64_t N;
  uint32_t r, p;
  napi_value name, result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 6);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&pass,
                             &pass_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&salt,
                             &salt_len) == napi_ok);
  CHECK(napi_get_value_int64(env, argv[2], &N) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[3], &r) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[4], &p) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[5], &out_len) == napi_ok);

  worker->pass = (uint8_t *)safe_malloc(pass_len);
  worker->pass_len = pass_len;
  worker->salt = (uint8_t *)safe_malloc(salt_len);
  worker->salt_len = salt_len;
  worker->N = N;
  worker->r = r;
  worker->p = p;
  worker->out = (uint8_t *)safe_malloc(out_len);
  worker->out_len = out_len;
  worker->error = NULL;

  memcpy(worker->pass, pass, pass_len);
  memcpy(worker->salt, salt, salt_len);

  CHECK(napi_create_string_utf8(env, "bcrypto:scrypt_derive",
                                NAPI_AUTO_LENGTH, &name) == napi_ok);

  CHECK(napi_create_promise(env, &worker->deferred, &result) == napi_ok);

  CHECK(napi_create_async_work(env,
                               NULL,
                               name,
                               bcrypto_scrypt_execute_,
                               bcrypto_scrypt_complete_,
                               worker,
                               &worker->work) == napi_ok);

  CHECK(napi_queue_async_work(env, worker->work) == napi_ok);

  return result;
}

/*
 * Secp256k1
 */

#ifdef BCRYPTO_USE_SECP256K1
static void
bcrypto_secp256k1_destroy(napi_env env, void *data, void *hint) {
  bcrypto_secp256k1_t *ec = (bcrypto_secp256k1_t *)data;

#ifdef BCRYPTO_USE_SECP256K1_LATEST
  secp256k1_scratch_space_destroy(ec->ctx, ec->scratch);
#else
  secp256k1_scratch_space_destroy(ec->scratch);
#endif
  secp256k1_context_destroy(ec->ctx);
  safe_free(ec);
}

static napi_value
bcrypto_secp256k1_create(napi_env env, napi_callback_info info) {
  static const int flags = SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY;
  bcrypto_secp256k1_t *ec;
  secp256k1_context *ctx;
  napi_value handle;

  JS_ASSERT(ctx = secp256k1_context_create(flags), JS_ERR_CONTEXT);

  ec = (bcrypto_secp256k1_t *)safe_malloc(sizeof(bcrypto_secp256k1_t));
  ec->ctx = ctx;

  /* See:
   *   https://github.com/ElementsProject/secp256k1-zkp/issues/69
   *   https://github.com/bitcoin-core/secp256k1/pull/638
   */
  ec->scratch = secp256k1_scratch_space_create(ec->ctx, 1024 * 1024);

  CHECK(ec->scratch != NULL);

  CHECK(napi_create_external(env,
                             ec,
                             bcrypto_secp256k1_destroy,
                             NULL,
                             &handle) == napi_ok);

  return handle;
}

static napi_value
bcrypto_secp256k1_randomize(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t *entropy;
  size_t entropy_len;
  bcrypto_secp256k1_t *ec;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&entropy,
                             &entropy_len) == napi_ok);

  JS_ASSERT(entropy_len == 32, JS_ERR_ENTROPY_SIZE);
  JS_ASSERT(secp256k1_context_randomize(ec->ctx, entropy), JS_ERR_RANDOM);

  cleanse(entropy, entropy_len);

  return argv[0];
}

static napi_value
bcrypto_secp256k1_privkey_generate(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t *entropy;
  size_t entropy_len;
  uint8_t out[32];
  bcrypto_secp256k1_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&entropy,
                             &entropy_len) == napi_ok);

  JS_ASSERT(entropy_len == ENTROPY_SIZE, JS_ERR_ENTROPY_SIZE);

  CHECK(secp256k1_ec_privkey_generate(ec->ctx, out, entropy));

  cleanse(entropy, entropy_len);

  CHECK(napi_create_buffer_copy(env, 32, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_privkey_verify(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  const uint8_t *priv;
  size_t priv_len;
  bcrypto_secp256k1_t *ec;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&priv,
                             &priv_len) == napi_ok);

  ok = priv_len == 32 && secp256k1_ec_seckey_verify(ec->ctx, priv);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_privkey_export(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t out[32];
  const uint8_t *priv;
  size_t priv_len;
  bcrypto_secp256k1_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&priv,
                             &priv_len) == napi_ok);

  JS_ASSERT(priv_len == 32, JS_ERR_PRIVKEY_SIZE);
  JS_ASSERT(secp256k1_ec_privkey_export(ec->ctx, out, priv), JS_ERR_PRIVKEY);

  CHECK(napi_create_buffer_copy(env, 32, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_privkey_import(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t out[32];
  const uint8_t *priv;
  size_t priv_len;
  bcrypto_secp256k1_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&priv,
                             &priv_len) == napi_ok);

  JS_ASSERT(secp256k1_ec_privkey_import(ec->ctx, out, priv, priv_len),
            JS_ERR_PRIVKEY);

  CHECK(napi_create_buffer_copy(env, 32, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_privkey_tweak_add(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[32];
  const uint8_t *priv, *tweak;
  size_t priv_len, tweak_len;
  bcrypto_secp256k1_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&priv,
                             &priv_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&tweak,
                             &tweak_len) == napi_ok);

  JS_ASSERT(priv_len == 32, JS_ERR_PRIVKEY_SIZE);
  JS_ASSERT(tweak_len == 32, JS_ERR_SCALAR_SIZE);

  memcpy(out, priv, 32);

  JS_ASSERT(secp256k1_ec_privkey_tweak_add(ec->ctx, out, tweak),
            JS_ERR_PRIVKEY);

  CHECK(napi_create_buffer_copy(env, 32, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_privkey_tweak_mul(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[32];
  const uint8_t *priv, *tweak;
  size_t priv_len, tweak_len;
  bcrypto_secp256k1_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&priv,
                             &priv_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&tweak,
                             &tweak_len) == napi_ok);

  JS_ASSERT(priv_len == 32, JS_ERR_PRIVKEY_SIZE);
  JS_ASSERT(tweak_len == 32, JS_ERR_SCALAR_SIZE);

  memcpy(out, priv, 32);

  JS_ASSERT(secp256k1_ec_privkey_tweak_mul(ec->ctx, out, tweak),
            JS_ERR_PRIVKEY);

  CHECK(napi_create_buffer_copy(env, 32, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_privkey_reduce(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t out[32];
  const uint8_t *priv;
  size_t priv_len;
  bcrypto_secp256k1_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&priv,
                             &priv_len) == napi_ok);

  JS_ASSERT(secp256k1_ec_privkey_reduce(ec->ctx, out, priv, priv_len),
            JS_ERR_PRIVKEY);

  CHECK(napi_create_buffer_copy(env, 32, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_privkey_negate(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t out[32];
  const uint8_t *priv;
  size_t priv_len;
  bcrypto_secp256k1_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&priv,
                             &priv_len) == napi_ok);

  JS_ASSERT(priv_len == 32, JS_ERR_PRIVKEY_SIZE);

  memcpy(out, priv, 32);

  JS_ASSERT(secp256k1_ec_privkey_negate_safe(ec->ctx, out), JS_ERR_PRIVKEY);

  CHECK(napi_create_buffer_copy(env, 32, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_privkey_invert(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t out[32];
  const uint8_t *priv;
  size_t priv_len;
  bcrypto_secp256k1_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&priv,
                             &priv_len) == napi_ok);

  JS_ASSERT(priv_len == 32, JS_ERR_PRIVKEY_SIZE);

  memcpy(out, priv, 32);

  JS_ASSERT(secp256k1_ec_privkey_invert(ec->ctx, out), JS_ERR_PRIVKEY);

  CHECK(napi_create_buffer_copy(env, 32, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_pubkey_create(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[65];
  size_t out_len = 65;
  secp256k1_pubkey pubkey;
  const uint8_t *priv;
  size_t priv_len;
  bool compress;
  bcrypto_secp256k1_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&priv,
                             &priv_len) == napi_ok);
  CHECK(napi_get_value_bool(env, argv[2], &compress) == napi_ok);

  JS_ASSERT(priv_len == 32, JS_ERR_PRIVKEY_SIZE);
  JS_ASSERT(secp256k1_ec_pubkey_create(ec->ctx, &pubkey, priv), JS_ERR_PRIVKEY);

  secp256k1_ec_pubkey_serialize(ec->ctx, out, &out_len, &pubkey,
    compress ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_pubkey_convert(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[65];
  size_t out_len = 65;
  secp256k1_pubkey pubkey;
  const uint8_t *pub;
  size_t pub_len;
  bool compress;
  bcrypto_secp256k1_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pub,
                             &pub_len) == napi_ok);
  CHECK(napi_get_value_bool(env, argv[2], &compress) == napi_ok);

  JS_ASSERT(secp256k1_ec_pubkey_parse(ec->ctx, &pubkey, pub, pub_len),
            JS_ERR_PUBKEY);

  secp256k1_ec_pubkey_serialize(ec->ctx, out, &out_len, &pubkey,
    compress ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_pubkey_from_uniform(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[65];
  size_t out_len = 65;
  secp256k1_pubkey pubkey;
  const uint8_t *data;
  size_t data_len;
  bool compress;
  bcrypto_secp256k1_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&data,
                             &data_len) == napi_ok);
  CHECK(napi_get_value_bool(env, argv[2], &compress) == napi_ok);

  JS_ASSERT(data_len == 32, JS_ERR_PREIMAGE_SIZE);

  CHECK(secp256k1_ec_pubkey_from_uniform(ec->ctx, &pubkey, data));

  secp256k1_ec_pubkey_serialize(ec->ctx, out, &out_len, &pubkey,
    compress ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_pubkey_to_uniform(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[32];
  const uint8_t *pub;
  size_t pub_len;
  secp256k1_pubkey pubkey;
  uint32_t hint;
  bcrypto_secp256k1_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pub,
                             &pub_len) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[2], &hint) == napi_ok);

  JS_ASSERT(secp256k1_ec_pubkey_parse(ec->ctx, &pubkey, pub, pub_len),
            JS_ERR_PUBKEY);

  JS_ASSERT(secp256k1_ec_pubkey_to_uniform(ec->ctx, out, &pubkey, hint),
            JS_ERR_PUBKEY);

  CHECK(napi_create_buffer_copy(env, 32, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_pubkey_from_hash(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[65];
  size_t out_len = 65;
  secp256k1_pubkey pubkey;
  const uint8_t *data;
  size_t data_len;
  bool compress;
  bcrypto_secp256k1_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&data,
                             &data_len) == napi_ok);
  CHECK(napi_get_value_bool(env, argv[2], &compress) == napi_ok);

  JS_ASSERT(data_len == 64, JS_ERR_PREIMAGE_SIZE);
  JS_ASSERT(secp256k1_ec_pubkey_from_hash(ec->ctx, &pubkey, data),
            JS_ERR_PREIMAGE);

  secp256k1_ec_pubkey_serialize(ec->ctx, out, &out_len, &pubkey,
    compress ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_pubkey_to_hash(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[64];
  const uint8_t *pub;
  secp256k1_pubkey pubkey;
  uint8_t *entropy;
  size_t pub_len, entropy_len;
  bcrypto_secp256k1_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pub,
                             &pub_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&entropy,
                             &entropy_len) == napi_ok);

  JS_ASSERT(entropy_len == ENTROPY_SIZE, JS_ERR_ENTROPY_SIZE);

  JS_ASSERT(secp256k1_ec_pubkey_parse(ec->ctx, &pubkey, pub, pub_len),
            JS_ERR_PUBKEY);

  JS_ASSERT(secp256k1_ec_pubkey_to_hash(ec->ctx, out, &pubkey, entropy),
            JS_ERR_PUBKEY);

  cleanse(entropy, entropy_len);

  CHECK(napi_create_buffer_copy(env, 64, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_pubkey_verify(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  const uint8_t *pub;
  size_t pub_len;
  secp256k1_pubkey pubkey;
  bcrypto_secp256k1_t *ec;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pub,
                             &pub_len) == napi_ok);

  ok = secp256k1_ec_pubkey_parse(ec->ctx, &pubkey, pub, pub_len);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_pubkey_export(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t x[32];
  uint8_t y[32];
  const uint8_t *pub;
  size_t pub_len;
  secp256k1_pubkey pubkey;
  bcrypto_secp256k1_t *ec;
  napi_value bx, by, result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pub,
                             &pub_len) == napi_ok);

  JS_ASSERT(secp256k1_ec_pubkey_parse(ec->ctx, &pubkey, pub, pub_len),
            JS_ERR_PUBKEY);

  JS_ASSERT(secp256k1_ec_pubkey_export(ec->ctx, x, y, &pubkey),
            JS_ERR_PUBKEY);

  CHECK(napi_create_buffer_copy(env, 32, x, NULL, &bx) == napi_ok);
  CHECK(napi_create_buffer_copy(env, 32, y, NULL, &by) == napi_ok);

  CHECK(napi_create_array_with_length(env, 2, &result) == napi_ok);
  CHECK(napi_set_element(env, result, 0, bx) == napi_ok);
  CHECK(napi_set_element(env, result, 1, by) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_pubkey_import(napi_env env, napi_callback_info info) {
  napi_value argv[5];
  size_t argc = 5;
  uint8_t out[65];
  size_t out_len = 65;
  secp256k1_pubkey pubkey;
  const uint8_t *x, *y;
  size_t x_len, y_len;
  int32_t sign;
  bool compress;
  bcrypto_secp256k1_t *ec;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 5);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&x, &x_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&y, &y_len) == napi_ok);
  CHECK(napi_get_value_int32(env, argv[3], &sign) == napi_ok);
  CHECK(napi_get_value_bool(env, argv[4], &compress) == napi_ok);

  ok = secp256k1_ec_pubkey_import(ec->ctx, &pubkey, x, x_len, y, y_len, sign);

  JS_ASSERT(ok, JS_ERR_PUBKEY);

  secp256k1_ec_pubkey_serialize(ec->ctx, out, &out_len, &pubkey,
    compress ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_pubkey_tweak_add(napi_env env, napi_callback_info info) {
  napi_value argv[4];
  size_t argc = 4;
  uint8_t out[65];
  size_t out_len = 65;
  secp256k1_pubkey pubkey;
  const uint8_t *pub, *tweak;
  size_t pub_len, tweak_len;
  bool compress;
  bcrypto_secp256k1_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 4);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pub,
                             &pub_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&tweak,
                             &tweak_len) == napi_ok);
  CHECK(napi_get_value_bool(env, argv[3], &compress) == napi_ok);

  JS_ASSERT(tweak_len == 32, JS_ERR_SCALAR_SIZE);

  JS_ASSERT(secp256k1_ec_pubkey_parse(ec->ctx, &pubkey, pub, pub_len),
            JS_ERR_PUBKEY);

  JS_ASSERT(secp256k1_ec_pubkey_tweak_add(ec->ctx, &pubkey, tweak),
            JS_ERR_PUBKEY);

  secp256k1_ec_pubkey_serialize(ec->ctx, out, &out_len, &pubkey,
    compress ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_pubkey_tweak_mul(napi_env env, napi_callback_info info) {
  napi_value argv[4];
  size_t argc = 4;
  uint8_t out[65];
  size_t out_len = 65;
  secp256k1_pubkey pubkey;
  const uint8_t *pub, *tweak;
  size_t pub_len, tweak_len;
  bool compress;
  bcrypto_secp256k1_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 4);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pub,
                             &pub_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&tweak,
                             &tweak_len) == napi_ok);
  CHECK(napi_get_value_bool(env, argv[3], &compress) == napi_ok);

  JS_ASSERT(tweak_len == 32, JS_ERR_SCALAR_SIZE);

  JS_ASSERT(secp256k1_ec_pubkey_parse(ec->ctx, &pubkey, pub, pub_len),
            JS_ERR_PUBKEY);

  JS_ASSERT(secp256k1_ec_pubkey_tweak_mul(ec->ctx, &pubkey, tweak),
            JS_ERR_PUBKEY);

  secp256k1_ec_pubkey_serialize(ec->ctx, out, &out_len, &pubkey,
    compress ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_pubkey_combine(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[65];
  size_t out_len = 65;
  secp256k1_pubkey pubkey;
  uint32_t i, length;
  secp256k1_pubkey **pubkeys;
  secp256k1_pubkey *pubkey_data;
  const uint8_t *pub;
  size_t pub_len;
  bool compress;
  bcrypto_secp256k1_t *ec;
  napi_value item, result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_array_length(env, argv[1], &length) == napi_ok);
  CHECK(napi_get_value_bool(env, argv[2], &compress) == napi_ok);

  JS_ASSERT(length != 0, JS_ERR_PUBKEY);

  pubkeys =
    (secp256k1_pubkey **)safe_malloc(length * sizeof(secp256k1_pubkey *));

  pubkey_data =
    (secp256k1_pubkey *)safe_malloc(length * sizeof(secp256k1_pubkey));

  for (i = 0; i < length; i++) {
    CHECK(napi_get_element(env, argv[1], i, &item) == napi_ok);
    CHECK(napi_get_buffer_info(env, item, (void **)&pub,
                               &pub_len) == napi_ok);

    if (!secp256k1_ec_pubkey_parse(ec->ctx, &pubkey_data[i], pub, pub_len)) {
      safe_free(pubkeys);
      safe_free(pubkey_data);
      JS_THROW(JS_ERR_PUBKEY);
    }

    pubkeys[i] = &pubkey_data[i];
  }

  ok = secp256k1_ec_pubkey_combine(ec->ctx, &pubkey,
                                   (const secp256k1_pubkey *const *)pubkeys,
                                   length);

  safe_free(pubkeys);
  safe_free(pubkey_data);

  JS_ASSERT(ok, JS_ERR_PUBKEY);

  secp256k1_ec_pubkey_serialize(ec->ctx, out, &out_len, &pubkey,
    compress ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_pubkey_negate(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[65];
  size_t out_len = 65;
  secp256k1_pubkey pubkey;
  const uint8_t *pub;
  size_t pub_len;
  bool compress;
  bcrypto_secp256k1_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pub,
                             &pub_len) == napi_ok);
  CHECK(napi_get_value_bool(env, argv[2], &compress) == napi_ok);

  JS_ASSERT(secp256k1_ec_pubkey_parse(ec->ctx, &pubkey, pub, pub_len),
            JS_ERR_PUBKEY);

  JS_ASSERT(secp256k1_ec_pubkey_negate(ec->ctx, &pubkey), JS_ERR_PUBKEY);

  secp256k1_ec_pubkey_serialize(ec->ctx, out, &out_len, &pubkey,
    compress ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_signature_normalize(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t out[64];
  const uint8_t *sig;
  size_t sig_len;
  secp256k1_ecdsa_signature sigin;
  secp256k1_ecdsa_signature sigout;
  bcrypto_secp256k1_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&sig,
                             &sig_len) == napi_ok);

  JS_ASSERT(sig_len == 64, JS_ERR_SIGNATURE_SIZE);

  JS_ASSERT(secp256k1_ecdsa_signature_parse_compact(ec->ctx, &sigin, sig),
            JS_ERR_SIGNATURE);

  secp256k1_ecdsa_signature_normalize(ec->ctx, &sigout, &sigin);
  secp256k1_ecdsa_signature_serialize_compact(ec->ctx, out, &sigout);

  CHECK(napi_create_buffer_copy(env, 64, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_signature_normalize_der(napi_env env,
                                          napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t out[72];
  size_t out_len = 72;
  const uint8_t *sig;
  size_t sig_len;
  secp256k1_ecdsa_signature sigin;
  secp256k1_ecdsa_signature sigout;
  bcrypto_secp256k1_t *ec;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&sig,
                             &sig_len) == napi_ok);

  ok = ecdsa_signature_parse_der_lax(ec->ctx, &sigin, sig, sig_len);
  JS_ASSERT(ok, JS_ERR_SIGNATURE);

  secp256k1_ecdsa_signature_normalize(ec->ctx, &sigout, &sigin);

  ok = secp256k1_ecdsa_signature_serialize_der(ec->ctx, out, &out_len, &sigout);
  JS_ASSERT(ok, JS_ERR_SIGNATURE);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_signature_export(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t out[72];
  size_t out_len = 72;
  secp256k1_ecdsa_signature sigin;
  const uint8_t *sig;
  size_t sig_len;
  bcrypto_secp256k1_t *ec;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&sig,
                             &sig_len) == napi_ok);

  JS_ASSERT(sig_len == 64, JS_ERR_SIGNATURE_SIZE);

  ok = secp256k1_ecdsa_signature_parse_compact(ec->ctx, &sigin, sig)
    && secp256k1_ecdsa_signature_serialize_der(ec->ctx, out, &out_len, &sigin);

  JS_ASSERT(ok, JS_ERR_SIGNATURE);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_signature_import(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t out[64];
  const uint8_t *sig;
  size_t sig_len;
  secp256k1_ecdsa_signature sigin;
  bcrypto_secp256k1_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&sig,
                             &sig_len) == napi_ok);

  JS_ASSERT(ecdsa_signature_parse_der_lax(ec->ctx, &sigin, sig, sig_len),
            JS_ERR_SIGNATURE);

  secp256k1_ecdsa_signature_serialize_compact(ec->ctx, out, &sigin);

  CHECK(napi_create_buffer_copy(env, 64, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_is_low_s(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  const uint8_t *sig;
  size_t sig_len;
  secp256k1_ecdsa_signature sigin;
  bcrypto_secp256k1_t *ec;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&sig,
                             &sig_len) == napi_ok);

  ok = sig_len == 64
    && secp256k1_ecdsa_signature_parse_compact(ec->ctx, &sigin, sig)
    && !secp256k1_ecdsa_signature_normalize(ec->ctx, NULL, &sigin);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_is_low_der(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  const uint8_t *sig;
  size_t sig_len;
  secp256k1_ecdsa_signature sigin;
  bcrypto_secp256k1_t *ec;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&sig,
                             &sig_len) == napi_ok);

  ok = ecdsa_signature_parse_der_lax(ec->ctx, &sigin, sig, sig_len)
    && !secp256k1_ecdsa_signature_normalize(ec->ctx, NULL, &sigin);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_sign(napi_env env, napi_callback_info info) {
  secp256k1_nonce_function noncefn = secp256k1_nonce_function_rfc6979;
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[64];
  secp256k1_ecdsa_signature sigout;
  unsigned char msg32[32];
  const uint8_t *msg, *priv;
  size_t msg_len, priv_len;
  bcrypto_secp256k1_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&priv,
                             &priv_len) == napi_ok);

  JS_ASSERT(priv_len == 32, JS_ERR_PRIVKEY_SIZE);

  secp256k1_ecdsa_reduce(ec->ctx, msg32, msg, msg_len);

  JS_ASSERT(secp256k1_ecdsa_sign(ec->ctx, &sigout, msg32, priv, noncefn, NULL),
            JS_ERR_SIGN);

  secp256k1_ecdsa_signature_serialize_compact(ec->ctx, out, &sigout);

  CHECK(napi_create_buffer_copy(env, 64, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_sign_recoverable(napi_env env, napi_callback_info info) {
  secp256k1_nonce_function noncefn = secp256k1_nonce_function_rfc6979;
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[64];
  secp256k1_ecdsa_recoverable_signature sigout;
  unsigned char msg32[32];
  int param;
  const uint8_t *msg, *priv;
  size_t msg_len, priv_len;
  bcrypto_secp256k1_t *ec;
  napi_value sigval, paramval, result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&priv,
                             &priv_len) == napi_ok);

  JS_ASSERT(priv_len == 32, JS_ERR_PRIVKEY_SIZE);

  secp256k1_ecdsa_reduce(ec->ctx, msg32, msg, msg_len);

  ok = secp256k1_ecdsa_sign_recoverable(ec->ctx, &sigout, msg32,
                                        priv, noncefn, NULL);
  JS_ASSERT(ok, JS_ERR_SIGN);

  secp256k1_ecdsa_recoverable_signature_serialize_compact(ec->ctx, out,
                                                          &param, &sigout);

  CHECK(napi_create_buffer_copy(env, 64, out, NULL, &sigval) == napi_ok);
  CHECK(napi_create_uint32(env, param, &paramval) == napi_ok);

  CHECK(napi_create_array_with_length(env, 2, &result) == napi_ok);
  CHECK(napi_set_element(env, result, 0, sigval) == napi_ok);
  CHECK(napi_set_element(env, result, 1, paramval) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_sign_der(napi_env env, napi_callback_info info) {
  secp256k1_nonce_function noncefn = secp256k1_nonce_function_rfc6979;
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[72];
  size_t out_len = 72;
  secp256k1_ecdsa_signature sigout;
  unsigned char msg32[32];
  const uint8_t *msg, *priv;
  size_t msg_len, priv_len;
  bcrypto_secp256k1_t *ec;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&priv,
                             &priv_len) == napi_ok);

  JS_ASSERT(priv_len == 32, JS_ERR_PRIVKEY_SIZE);

  secp256k1_ecdsa_reduce(ec->ctx, msg32, msg, msg_len);

  ok = secp256k1_ecdsa_sign(ec->ctx, &sigout, msg32, priv, noncefn, NULL)
    && secp256k1_ecdsa_signature_serialize_der(ec->ctx, out, &out_len, &sigout);

  JS_ASSERT(ok, JS_ERR_SIGN);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_sign_recoverable_der(napi_env env, napi_callback_info info) {
  secp256k1_nonce_function noncefn = secp256k1_nonce_function_rfc6979;
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[72];
  size_t out_len = 72;
  secp256k1_ecdsa_recoverable_signature sigout;
  secp256k1_ecdsa_signature cmpct;
  unsigned char msg32[32];
  int param;
  const uint8_t *msg, *priv;
  size_t msg_len, priv_len;
  bcrypto_secp256k1_t *ec;
  napi_value sigval, paramval, result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&priv,
                             &priv_len) == napi_ok);

  JS_ASSERT(priv_len == 32, JS_ERR_PRIVKEY_SIZE);

  secp256k1_ecdsa_reduce(ec->ctx, msg32, msg, msg_len);

  ok = secp256k1_ecdsa_sign_recoverable(ec->ctx, &sigout, msg32,
                                        priv, noncefn, NULL);
  JS_ASSERT(ok, JS_ERR_SIGN);

  secp256k1_ecdsa_recoverable_signature_serialize_compact(ec->ctx, out,
                                                          &param, &sigout);

  ok = secp256k1_ecdsa_signature_parse_compact(ec->ctx, &cmpct, out)
    && secp256k1_ecdsa_signature_serialize_der(ec->ctx, out, &out_len, &cmpct);

  JS_ASSERT(ok, JS_ERR_SIGN);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &sigval) == napi_ok);
  CHECK(napi_create_uint32(env, param, &paramval) == napi_ok);

  CHECK(napi_create_array_with_length(env, 2, &result) == napi_ok);
  CHECK(napi_set_element(env, result, 0, sigval) == napi_ok);
  CHECK(napi_set_element(env, result, 1, paramval) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_verify(napi_env env, napi_callback_info info) {
  napi_value argv[4];
  size_t argc = 4;
  secp256k1_ecdsa_signature sigin;
  secp256k1_pubkey pubkey;
  unsigned char msg32[32];
  const uint8_t *msg, *sig, *pub;
  size_t msg_len, sig_len, pub_len;
  bcrypto_secp256k1_t *ec;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 4);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&sig, &sig_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[3], (void **)&pub, &pub_len) == napi_ok);

  ok = sig_len == 64
    && secp256k1_ecdsa_signature_parse_compact(ec->ctx, &sigin, sig)
    && secp256k1_ec_pubkey_parse(ec->ctx, &pubkey, pub, pub_len);

  if (ok) {
    secp256k1_ecdsa_signature_normalize(ec->ctx, &sigin, &sigin);
    secp256k1_ecdsa_reduce(ec->ctx, msg32, msg, msg_len);

    ok = secp256k1_ecdsa_verify(ec->ctx, &sigin, msg32, &pubkey);
  }

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_verify_der(napi_env env, napi_callback_info info) {
  napi_value argv[4];
  size_t argc = 4;
  secp256k1_ecdsa_signature sigin;
  secp256k1_pubkey pubkey;
  unsigned char msg32[32];
  const uint8_t *msg, *sig, *pub;
  size_t msg_len, sig_len, pub_len;
  bcrypto_secp256k1_t *ec;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 4);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&sig, &sig_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[3], (void **)&pub, &pub_len) == napi_ok);

  ok = ecdsa_signature_parse_der_lax(ec->ctx, &sigin, sig, sig_len)
    && secp256k1_ec_pubkey_parse(ec->ctx, &pubkey, pub, pub_len);

  if (ok) {
    secp256k1_ecdsa_signature_normalize(ec->ctx, &sigin, &sigin);
    secp256k1_ecdsa_reduce(ec->ctx, msg32, msg, msg_len);

    ok = secp256k1_ecdsa_verify(ec->ctx, &sigin, msg32, &pubkey);
  }

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_recover(napi_env env, napi_callback_info info) {
  napi_value argv[5];
  size_t argc = 5;
  uint8_t out[65];
  size_t out_len = 65;
  secp256k1_ecdsa_recoverable_signature sigin;
  secp256k1_pubkey pubkey;
  unsigned char msg32[32];
  const uint8_t *msg, *sig;
  size_t msg_len, sig_len;
  uint32_t parm;
  bool compress;
  bcrypto_secp256k1_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 5);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&sig, &sig_len) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[3], &parm) == napi_ok);
  CHECK(napi_get_value_bool(env, argv[4], &compress) == napi_ok);

  JS_ASSERT((parm & 3) == parm, JS_ERR_RECOVERY_PARAM);

  if (sig_len != 64)
    goto fail;

  if (!secp256k1_ecdsa_recoverable_signature_parse_compact(ec->ctx,
                                                           &sigin,
                                                           sig,
                                                           parm)) {
    goto fail;
  }

  secp256k1_ecdsa_reduce(ec->ctx, msg32, msg, msg_len);

  if (!secp256k1_ecdsa_recover(ec->ctx, &pubkey, &sigin, msg32))
    goto fail;

  secp256k1_ec_pubkey_serialize(ec->ctx, out, &out_len, &pubkey,
    compress ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  return result;
fail:
  CHECK(napi_get_null(env, &result) == napi_ok);
  return result;
}

static napi_value
bcrypto_secp256k1_recover_der(napi_env env, napi_callback_info info) {
  napi_value argv[5];
  size_t argc = 5;
  secp256k1_ecdsa_recoverable_signature sigin;
  secp256k1_pubkey pubkey;
  secp256k1_ecdsa_signature orig;
  unsigned char tmp[64];
  uint8_t out[65];
  size_t out_len = 65;
  unsigned char msg32[32];
  const uint8_t *msg, *sig;
  size_t msg_len, sig_len;
  uint32_t parm;
  bool compress;
  bcrypto_secp256k1_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 5);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&sig, &sig_len) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[3], &parm) == napi_ok);
  CHECK(napi_get_value_bool(env, argv[4], &compress) == napi_ok);

  JS_ASSERT((parm & 3) == parm, JS_ERR_RECOVERY_PARAM);

  if (!ecdsa_signature_parse_der_lax(ec->ctx, &orig, sig, sig_len))
    goto fail;

  secp256k1_ecdsa_signature_serialize_compact(ec->ctx, tmp, &orig);

  if (!secp256k1_ecdsa_recoverable_signature_parse_compact(ec->ctx,
                                                           &sigin,
                                                           tmp,
                                                           parm)) {
    goto fail;
  }

  secp256k1_ecdsa_reduce(ec->ctx, msg32, msg, msg_len);

  if (!secp256k1_ecdsa_recover(ec->ctx, &pubkey, &sigin, msg32))
    goto fail;

  secp256k1_ec_pubkey_serialize(ec->ctx, out, &out_len, &pubkey,
    compress ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  return result;
fail:
  CHECK(napi_get_null(env, &result) == napi_ok);
  return result;
}

static int
ecdh_hash_function_raw(unsigned char *out,
                       const unsigned char *x,
                       const unsigned char *y,
                       void *data) {
  bool compress = *((bool *)data);

  if (compress) {
    out[0] = 0x02 | (y[31] & 1);
    memcpy(out + 1, x, 32);
  } else {
    out[0] = 0x04;
    memcpy(out + 1, x, 32);
    memcpy(out + 33, y, 32);
  }

  return 1;
}

static napi_value
bcrypto_secp256k1_derive(napi_env env, napi_callback_info info) {
  secp256k1_ecdh_hash_function hashfp = ecdh_hash_function_raw;
  napi_value argv[4];
  size_t argc = 4;
  secp256k1_pubkey pubkey;
  uint8_t out[65];
  size_t out_len = 65;
  const uint8_t *pub, *priv;
  size_t pub_len, priv_len;
  bool compress;
  bcrypto_secp256k1_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 4);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pub, &pub_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&priv,
                             &priv_len) == napi_ok);
  CHECK(napi_get_value_bool(env, argv[3], &compress) == napi_ok);

  JS_ASSERT(priv_len == 32, JS_ERR_PRIVKEY_SIZE);

  JS_ASSERT(secp256k1_ec_pubkey_parse(ec->ctx, &pubkey, pub, pub_len),
            JS_ERR_PUBKEY);

  JS_ASSERT(secp256k1_ecdh(ec->ctx, out, &pubkey, priv, hashfp, &compress),
            JS_ERR_PUBKEY);

  if (compress)
    out_len = 33;

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_schnorr_legacy_sign(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  secp256k1_schnorrleg sigout;
  uint8_t out[64];
  const uint8_t *msg, *priv;
  size_t msg_len, priv_len;
  bcrypto_secp256k1_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&priv,
                             &priv_len) == napi_ok);

  JS_ASSERT(priv_len == 32, JS_ERR_PRIVKEY_SIZE);
  JS_ASSERT(secp256k1_schnorrleg_sign(ec->ctx, &sigout, msg, msg_len, priv),
            JS_ERR_SIGN);

  secp256k1_schnorrleg_serialize(ec->ctx, out, &sigout);

  CHECK(napi_create_buffer_copy(env, 64, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_schnorr_legacy_verify(napi_env env, napi_callback_info info) {
  napi_value argv[4];
  size_t argc = 4;
  const uint8_t *msg, *sig, *pub;
  size_t msg_len, sig_len, pub_len;
  secp256k1_schnorrleg sigin;
  secp256k1_pubkey pubkey;
  bcrypto_secp256k1_t *ec;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 4);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&sig, &sig_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[3], (void **)&pub, &pub_len) == napi_ok);

  ok = sig_len == 64
    && secp256k1_schnorrleg_parse(ec->ctx, &sigin, sig)
    && secp256k1_ec_pubkey_parse(ec->ctx, &pubkey, pub, pub_len)
    && secp256k1_schnorrleg_verify(ec->ctx, &sigin, msg, msg_len, &pubkey);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_schnorr_legacy_verify_batch(napi_env env,
                                              napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint32_t i, length, item_len;
  const uint8_t *sig, *pub;
  size_t sig_len, pub_len;
  const uint8_t **msgs;
  size_t *msg_lens;
  secp256k1_schnorrleg **sigs;
  secp256k1_schnorrleg *sig_data;
  secp256k1_pubkey **pubkeys;
  secp256k1_pubkey *pubkey_data;
  bcrypto_secp256k1_t *ec;
  napi_value item, result;
  napi_value items[3];
  int ok = 0;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_array_length(env, argv[1], &length) == napi_ok);

  if (length == 0) {
    CHECK(napi_get_boolean(env, true, &result) == napi_ok);
    return result;
  }

  msgs = (const unsigned char **)safe_malloc(length * sizeof(unsigned char *));
  msg_lens = (size_t *)safe_malloc(length * sizeof(size_t));

  sigs =
    (secp256k1_schnorrleg **)safe_malloc(length * sizeof(secp256k1_schnorrleg *));

  sig_data =
    (secp256k1_schnorrleg *)safe_malloc(length * sizeof(secp256k1_schnorrleg));

  pubkeys =
    (secp256k1_pubkey **)safe_malloc(length * sizeof(secp256k1_pubkey *));

  pubkey_data =
    (secp256k1_pubkey *)safe_malloc(length * sizeof(secp256k1_pubkey));

  memset(items, 0, sizeof(items));

  for (i = 0; i < length; i++) {
    CHECK(napi_get_element(env, argv[1], i, &item) == napi_ok);
    CHECK(napi_get_array_length(env, item, &item_len) == napi_ok);
    CHECK(item_len == 3);

    CHECK(napi_get_element(env, item, 0, &items[0]) == napi_ok);
    CHECK(napi_get_element(env, item, 1, &items[1]) == napi_ok);
    CHECK(napi_get_element(env, item, 2, &items[2]) == napi_ok);

    CHECK(napi_get_buffer_info(env, items[0], (void **)&msgs[i],
                               &msg_lens[i]) == napi_ok);

    CHECK(napi_get_buffer_info(env, items[1], (void **)&sig,
                               &sig_len) == napi_ok);

    CHECK(napi_get_buffer_info(env, items[2], (void **)&pub,
                               &pub_len) == napi_ok);

    if (sig_len != 64)
      goto fail;

    if (!secp256k1_schnorrleg_parse(ec->ctx, &sig_data[i], sig))
      goto fail;

    if (!secp256k1_ec_pubkey_parse(ec->ctx, &pubkey_data[i], pub, pub_len))
      goto fail;

    sigs[i] = &sig_data[i];
    pubkeys[i] = &pubkey_data[i];
  }

  ok = secp256k1_schnorrleg_verify_batch(
    ec->ctx,
    ec->scratch,
    (const secp256k1_schnorrleg *const *)sigs,
    msgs,
    msg_lens,
    (const secp256k1_pubkey *const *)pubkeys,
    length
  );

fail:
  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  safe_free(msgs);
  safe_free(msg_lens);
  safe_free(sigs);
  safe_free(sig_data);
  safe_free(pubkeys);
  safe_free(pubkey_data);

  return result;
}

#ifdef BCRYPTO_USE_SECP256K1_LATEST
static napi_value
bcrypto_secp256k1_xonly_privkey_export(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t d[32], x[32], y[32];
  const uint8_t *priv;
  size_t priv_len;
  secp256k1_pubkey pubkey;
  secp256k1_xonly_pubkey xonly;
  int negated;
  bcrypto_secp256k1_t *ec;
  napi_value bd, bx, by, result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&priv,
                             &priv_len) == napi_ok);

  JS_ASSERT(priv_len == 32, JS_ERR_PRIVKEY_SIZE);
  JS_ASSERT(secp256k1_ec_privkey_export(ec->ctx, d, priv), JS_ERR_PRIVKEY);
  JS_ASSERT(secp256k1_ec_pubkey_create(ec->ctx, &pubkey, priv), JS_ERR_PRIVKEY);

  CHECK(secp256k1_xonly_pubkey_from_pubkey(ec->ctx, &xonly, &negated, &pubkey));

  if (negated)
    CHECK(secp256k1_ec_privkey_negate(ec->ctx, d));

  CHECK(secp256k1_xonly_pubkey_export(ec->ctx, x, y, &xonly));

  CHECK(napi_create_buffer_copy(env, 32, d, NULL, &bd) == napi_ok);
  CHECK(napi_create_buffer_copy(env, 32, x, NULL, &bx) == napi_ok);
  CHECK(napi_create_buffer_copy(env, 32, y, NULL, &by) == napi_ok);

  CHECK(napi_create_array_with_length(env, 3, &result) == napi_ok);
  CHECK(napi_set_element(env, result, 0, bd) == napi_ok);
  CHECK(napi_set_element(env, result, 1, bx) == napi_ok);
  CHECK(napi_set_element(env, result, 2, by) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_xonly_privkey_tweak_add(napi_env env,
                                          napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[32];
  const uint8_t *priv, *tweak;
  size_t priv_len, tweak_len;
  bcrypto_secp256k1_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&priv,
                             &priv_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&tweak,
                             &tweak_len) == napi_ok);

  JS_ASSERT(priv_len == 32, JS_ERR_PRIVKEY_SIZE);
  JS_ASSERT(tweak_len == 32, JS_ERR_SCALAR_SIZE);

  memcpy(out, priv, 32);

  JS_ASSERT(secp256k1_xonly_seckey_tweak_add(ec->ctx, out, tweak),
            JS_ERR_PRIVKEY);

  CHECK(napi_create_buffer_copy(env, 32, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_xonly_create(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t out[32];
  secp256k1_xonly_pubkey pubkey;
  const uint8_t *priv;
  size_t priv_len;
  bcrypto_secp256k1_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&priv,
                             &priv_len) == napi_ok);

  JS_ASSERT(priv_len == 32, JS_ERR_PRIVKEY_SIZE);
  JS_ASSERT(secp256k1_xonly_pubkey_create(ec->ctx, &pubkey, priv),
            JS_ERR_PRIVKEY);

  secp256k1_xonly_pubkey_serialize(ec->ctx, out, &pubkey);

  CHECK(napi_create_buffer_copy(env, 32, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_xonly_from_uniform(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t out[32];
  secp256k1_xonly_pubkey pubkey;
  const uint8_t *data;
  size_t data_len;
  bcrypto_secp256k1_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&data,
                             &data_len) == napi_ok);

  JS_ASSERT(data_len == 32, JS_ERR_PREIMAGE_SIZE);

  CHECK(secp256k1_xonly_pubkey_from_uniform(ec->ctx, &pubkey, data));

  secp256k1_xonly_pubkey_serialize(ec->ctx, out, &pubkey);

  CHECK(napi_create_buffer_copy(env, 32, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_xonly_to_uniform(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[32];
  const uint8_t *pub;
  size_t pub_len;
  secp256k1_xonly_pubkey pubkey;
  uint32_t hint;
  bcrypto_secp256k1_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pub,
                             &pub_len) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[2], &hint) == napi_ok);

  JS_ASSERT(pub_len == 32, JS_ERR_PUBKEY_SIZE);

  JS_ASSERT(secp256k1_xonly_pubkey_parse(ec->ctx, &pubkey, pub), JS_ERR_PUBKEY);

  JS_ASSERT(secp256k1_xonly_pubkey_to_uniform(ec->ctx, out, &pubkey, hint),
            JS_ERR_PUBKEY);

  CHECK(napi_create_buffer_copy(env, 32, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_xonly_from_hash(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t out[32];
  secp256k1_xonly_pubkey pubkey;
  const uint8_t *data;
  size_t data_len;
  bcrypto_secp256k1_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&data,
                             &data_len) == napi_ok);

  JS_ASSERT(data_len == 64, JS_ERR_PREIMAGE_SIZE);
  JS_ASSERT(secp256k1_xonly_pubkey_from_hash(ec->ctx, &pubkey, data),
            JS_ERR_PREIMAGE);

  secp256k1_xonly_pubkey_serialize(ec->ctx, out, &pubkey);

  CHECK(napi_create_buffer_copy(env, 32, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_xonly_to_hash(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[64];
  const uint8_t *pub;
  secp256k1_xonly_pubkey pubkey;
  uint8_t *entropy;
  size_t pub_len, entropy_len;
  bcrypto_secp256k1_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pub,
                             &pub_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&entropy,
                             &entropy_len) == napi_ok);

  JS_ASSERT(pub_len == 32, JS_ERR_PUBKEY_SIZE);
  JS_ASSERT(entropy_len == ENTROPY_SIZE, JS_ERR_ENTROPY_SIZE);

  JS_ASSERT(secp256k1_xonly_pubkey_parse(ec->ctx, &pubkey, pub), JS_ERR_PUBKEY);

  JS_ASSERT(secp256k1_xonly_pubkey_to_hash(ec->ctx, out, &pubkey, entropy),
            JS_ERR_PUBKEY);

  cleanse(entropy, entropy_len);

  CHECK(napi_create_buffer_copy(env, 64, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_xonly_verify(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  const uint8_t *pub;
  size_t pub_len;
  secp256k1_xonly_pubkey pubkey;
  bcrypto_secp256k1_t *ec;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pub,
                             &pub_len) == napi_ok);

  ok = pub_len == 32 && secp256k1_xonly_pubkey_parse(ec->ctx, &pubkey, pub);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_xonly_export(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t x[32];
  uint8_t y[32];
  const uint8_t *pub;
  size_t pub_len;
  secp256k1_xonly_pubkey pubkey;
  bcrypto_secp256k1_t *ec;
  napi_value bx, by, result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pub,
                             &pub_len) == napi_ok);

  JS_ASSERT(pub_len == 32, JS_ERR_PUBKEY_SIZE);

  JS_ASSERT(secp256k1_xonly_pubkey_parse(ec->ctx, &pubkey, pub), JS_ERR_PUBKEY);

  JS_ASSERT(secp256k1_xonly_pubkey_export(ec->ctx, x, y, &pubkey),
            JS_ERR_PUBKEY);

  CHECK(napi_create_buffer_copy(env, 32, x, NULL, &bx) == napi_ok);
  CHECK(napi_create_buffer_copy(env, 32, y, NULL, &by) == napi_ok);

  CHECK(napi_create_array_with_length(env, 2, &result) == napi_ok);
  CHECK(napi_set_element(env, result, 0, bx) == napi_ok);
  CHECK(napi_set_element(env, result, 1, by) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_xonly_import(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[32];
  secp256k1_xonly_pubkey pubkey;
  const uint8_t *x, *y;
  size_t x_len, y_len;
  bcrypto_secp256k1_t *ec;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&x, &x_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&y, &y_len) == napi_ok);

  ok = secp256k1_xonly_pubkey_import(ec->ctx, &pubkey,
                                     x, x_len, y, y_len);

  JS_ASSERT(ok, JS_ERR_PUBKEY);

  secp256k1_xonly_pubkey_serialize(ec->ctx, out, &pubkey);

  CHECK(napi_create_buffer_copy(env, 32, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_xonly_tweak_add(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[32];
  int negated;
  secp256k1_xonly_pubkey pubkey;
  const uint8_t *pub, *tweak;
  size_t pub_len, tweak_len;
  bcrypto_secp256k1_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pub,
                             &pub_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&tweak,
                             &tweak_len) == napi_ok);

  JS_ASSERT(pub_len == 32, JS_ERR_PUBKEY_SIZE);
  JS_ASSERT(tweak_len == 32, JS_ERR_SCALAR_SIZE);

  JS_ASSERT(secp256k1_xonly_pubkey_parse(ec->ctx, &pubkey, pub), JS_ERR_PUBKEY);

  JS_ASSERT(secp256k1_xonly_pubkey_tweak_add(ec->ctx, &pubkey, &negated, tweak),
            JS_ERR_PUBKEY);

  secp256k1_xonly_pubkey_serialize(ec->ctx, out, &pubkey);

  CHECK(napi_create_buffer_copy(env, 32, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_xonly_tweak_mul(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[32];
  secp256k1_xonly_pubkey pubkey;
  const uint8_t *pub, *tweak;
  size_t pub_len, tweak_len;
  bcrypto_secp256k1_t *ec;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pub,
                             &pub_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&tweak,
                             &tweak_len) == napi_ok);

  JS_ASSERT(pub_len == 32, JS_ERR_PUBKEY_SIZE);
  JS_ASSERT(tweak_len == 32, JS_ERR_SCALAR_SIZE);

  JS_ASSERT(secp256k1_xonly_pubkey_parse(ec->ctx, &pubkey, pub), JS_ERR_PUBKEY);

  ok = secp256k1_ec_pubkey_tweak_mul(ec->ctx,
                                     (secp256k1_pubkey *)&pubkey,
                                     tweak);

  JS_ASSERT(ok, JS_ERR_PUBKEY);

  secp256k1_xonly_pubkey_serialize(ec->ctx, out, &pubkey);

  CHECK(napi_create_buffer_copy(env, 32, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_xonly_tweak_sum(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[32];
  int negated;
  secp256k1_xonly_pubkey pubkey;
  const uint8_t *pub, *tweak;
  size_t pub_len, tweak_len;
  bcrypto_secp256k1_t *ec;
  napi_value outval, negval, result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pub,
                             &pub_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&tweak,
                             &tweak_len) == napi_ok);

  JS_ASSERT(pub_len == 32, JS_ERR_PUBKEY_SIZE);
  JS_ASSERT(tweak_len == 32, JS_ERR_SCALAR_SIZE);

  JS_ASSERT(secp256k1_xonly_pubkey_parse(ec->ctx, &pubkey, pub), JS_ERR_PUBKEY);

  JS_ASSERT(secp256k1_xonly_pubkey_tweak_add(ec->ctx, &pubkey, &negated, tweak),
            JS_ERR_PUBKEY);

  secp256k1_xonly_pubkey_serialize(ec->ctx, out, &pubkey);

  CHECK(napi_create_buffer_copy(env, 32, out, NULL, &outval) == napi_ok);
  CHECK(napi_get_boolean(env, negated, &negval) == napi_ok);

  CHECK(napi_create_array_with_length(env, 2, &result) == napi_ok);
  CHECK(napi_set_element(env, result, 0, outval) == napi_ok);
  CHECK(napi_set_element(env, result, 1, negval) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_xonly_tweak_test(napi_env env, napi_callback_info info) {
  napi_value argv[5];
  size_t argc = 5;
  secp256k1_xonly_pubkey pubkey;
  const uint8_t *pub, *tweak, *expect;
  size_t pub_len, tweak_len, expect_len;
  bool negated;
  bcrypto_secp256k1_t *ec;
  napi_value result;
  int ok = 0;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 5);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pub,
                             &pub_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&tweak,
                             &tweak_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[3], (void **)&expect,
                             &expect_len) == napi_ok);
  CHECK(napi_get_value_bool(env, argv[4], &negated) == napi_ok);

  if (pub_len != 32 || tweak_len != 32 || expect_len != 32)
    goto fail;

  if (!secp256k1_xonly_pubkey_parse(ec->ctx, &pubkey, pub))
    goto fail;

  ok = secp256k1_xonly_pubkey_tweak_test(ec->ctx,
                                         expect,
                                         negated,
                                         &pubkey,
                                         tweak);

fail:
  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_xonly_combine(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t out[32];
  secp256k1_xonly_pubkey pubkey;
  uint32_t i, length;
  secp256k1_xonly_pubkey **pubkeys;
  secp256k1_xonly_pubkey *pubkey_data;
  const uint8_t *pub;
  size_t pub_len;
  bcrypto_secp256k1_t *ec;
  napi_value item, result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_array_length(env, argv[1], &length) == napi_ok);

  JS_ASSERT(length != 0, JS_ERR_PUBKEY);

  pubkeys =
    (secp256k1_xonly_pubkey **)safe_malloc(length * sizeof(secp256k1_xonly_pubkey *));

  pubkey_data =
    (secp256k1_xonly_pubkey *)safe_malloc(length * sizeof(secp256k1_xonly_pubkey));

  for (i = 0; i < length; i++) {
    CHECK(napi_get_element(env, argv[1], i, &item) == napi_ok);
    CHECK(napi_get_buffer_info(env, item, (void **)&pub,
                               &pub_len) == napi_ok);

    if (pub_len != 32)
      goto fail;

    if (!secp256k1_xonly_pubkey_parse(ec->ctx, &pubkey_data[i], pub))
      goto fail;

    pubkeys[i] = &pubkey_data[i];
  }

  ok = secp256k1_ec_pubkey_combine(ec->ctx, (secp256k1_pubkey *)&pubkey,
                                   (const secp256k1_pubkey *const *)pubkeys,
                                   length);

  safe_free(pubkeys);
  safe_free(pubkey_data);

  JS_ASSERT(ok, JS_ERR_PUBKEY);

  secp256k1_xonly_pubkey_serialize(ec->ctx, out, &pubkey);

  CHECK(napi_create_buffer_copy(env, 32, out, NULL, &result) == napi_ok);

  return result;
fail:
  safe_free(pubkeys);
  safe_free(pubkey_data);
  JS_THROW(JS_ERR_PUBKEY);
}

static napi_value
bcrypto_secp256k1_schnorr_sign(napi_env env, napi_callback_info info) {
  napi_value argv[4];
  size_t argc = 4;
  secp256k1_schnorrsig sigout;
  uint8_t out[64];
  const uint8_t *msg, *priv, *aux;
  size_t msg_len, priv_len, aux_len;
  bcrypto_secp256k1_t *ec;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 4);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&priv,
                             &priv_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[3], (void **)&aux,
                             &aux_len) == napi_ok);

  JS_ASSERT(msg_len == 32, JS_ERR_MSG_SIZE);
  JS_ASSERT(priv_len == 32, JS_ERR_PRIVKEY_SIZE);
  JS_ASSERT(aux_len == 32, JS_ERR_ENTROPY_SIZE);

  ok = secp256k1_schnorrsig_sign(ec->ctx,
                                 &sigout,
                                 msg,
                                 priv,
                                 NULL,
                                 (void *)aux);

  JS_ASSERT(ok, JS_ERR_SIGN);

  secp256k1_schnorrsig_serialize(ec->ctx, out, &sigout);

  CHECK(napi_create_buffer_copy(env, 64, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_schnorr_verify(napi_env env, napi_callback_info info) {
  napi_value argv[4];
  size_t argc = 4;
  const uint8_t *msg, *sig, *pub;
  size_t msg_len, sig_len, pub_len;
  secp256k1_schnorrsig sigin;
  secp256k1_xonly_pubkey pubkey;
  bcrypto_secp256k1_t *ec;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 4);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&sig, &sig_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[3], (void **)&pub, &pub_len) == napi_ok);

  ok = msg_len == 32 && sig_len == 64 && pub_len == 32
    && secp256k1_schnorrsig_parse(ec->ctx, &sigin, sig)
    && secp256k1_xonly_pubkey_parse(ec->ctx, &pubkey, pub)
    && secp256k1_schnorrsig_verify(ec->ctx, &sigin, msg, &pubkey);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_schnorr_verify_batch(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint32_t i, length, item_len;
  const uint8_t *sig, *pub;
  size_t msg_len, sig_len, pub_len;
  const uint8_t **msgs;
  secp256k1_schnorrsig **sigs;
  secp256k1_schnorrsig *sig_data;
  secp256k1_xonly_pubkey **pubkeys;
  secp256k1_xonly_pubkey *pubkey_data;
  bcrypto_secp256k1_t *ec;
  napi_value item, result;
  napi_value items[3];
  int ok = 0;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_array_length(env, argv[1], &length) == napi_ok);

  if (length == 0) {
    CHECK(napi_get_boolean(env, true, &result) == napi_ok);
    return result;
  }

  msgs = (const unsigned char **)safe_malloc(length * sizeof(unsigned char *));

  sigs =
    (secp256k1_schnorrsig **)safe_malloc(length * sizeof(secp256k1_schnorrsig *));

  sig_data =
    (secp256k1_schnorrsig *)safe_malloc(length * sizeof(secp256k1_schnorrsig));

  pubkeys =
    (secp256k1_xonly_pubkey **)safe_malloc(length * sizeof(secp256k1_xonly_pubkey *));

  pubkey_data =
    (secp256k1_xonly_pubkey *)safe_malloc(length * sizeof(secp256k1_xonly_pubkey));

  memset(items, 0, sizeof(items));

  for (i = 0; i < length; i++) {
    CHECK(napi_get_element(env, argv[1], i, &item) == napi_ok);
    CHECK(napi_get_array_length(env, item, &item_len) == napi_ok);
    CHECK(item_len == 3);

    CHECK(napi_get_element(env, item, 0, &items[0]) == napi_ok);
    CHECK(napi_get_element(env, item, 1, &items[1]) == napi_ok);
    CHECK(napi_get_element(env, item, 2, &items[2]) == napi_ok);

    CHECK(napi_get_buffer_info(env, items[0], (void **)&msgs[i],
                               &msg_len) == napi_ok);

    CHECK(napi_get_buffer_info(env, items[1], (void **)&sig,
                               &sig_len) == napi_ok);

    CHECK(napi_get_buffer_info(env, items[2], (void **)&pub,
                               &pub_len) == napi_ok);

    if (msg_len != 32 || sig_len != 64 || pub_len != 32)
      goto fail;

    if (!secp256k1_schnorrsig_parse(ec->ctx, &sig_data[i], sig))
      goto fail;

    if (!secp256k1_xonly_pubkey_parse(ec->ctx, &pubkey_data[i], pub))
      goto fail;

    sigs[i] = &sig_data[i];
    pubkeys[i] = &pubkey_data[i];
  }

  ok = secp256k1_schnorrsig_verify_batch(
    ec->ctx,
    ec->scratch,
    (const secp256k1_schnorrsig *const *)sigs,
    msgs,
    (const secp256k1_xonly_pubkey *const *)pubkeys,
    length
  );

fail:
  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  safe_free(msgs);
  safe_free(sigs);
  safe_free(sig_data);
  safe_free(pubkeys);
  safe_free(pubkey_data);

  return result;
}

static int
ecdh_hash_function_xonly(unsigned char *out,
                         const unsigned char *x,
                         const unsigned char *y,
                         void *data) {
  memcpy(out, x, 32);
  return 1;
}

static napi_value
bcrypto_secp256k1_xonly_derive(napi_env env, napi_callback_info info) {
  secp256k1_ecdh_hash_function hashfp = ecdh_hash_function_xonly;
  napi_value argv[3];
  size_t argc = 3;
  secp256k1_xonly_pubkey pubkey;
  uint8_t out[32];
  const uint8_t *pub, *priv;
  size_t pub_len, priv_len;
  bcrypto_secp256k1_t *ec;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pub, &pub_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&priv,
                             &priv_len) == napi_ok);

  JS_ASSERT(pub_len == 32, JS_ERR_PUBKEY_SIZE);
  JS_ASSERT(priv_len == 32, JS_ERR_PRIVKEY_SIZE);

  JS_ASSERT(secp256k1_xonly_pubkey_parse(ec->ctx, &pubkey, pub), JS_ERR_PUBKEY);

  ok = secp256k1_ecdh(ec->ctx,
                      out,
                      (secp256k1_pubkey *)&pubkey,
                      priv,
                      hashfp,
                      NULL);

  JS_ASSERT(ok, JS_ERR_PUBKEY);

  CHECK(napi_create_buffer_copy(env, 32, out, NULL, &result) == napi_ok);

  return result;
}
#endif /* BCRYPTO_USE_SECP256K1_LATEST */
#endif /* BCRYPTO_USE_SECP256K1 */

/*
 * Siphash
 */

static napi_value
bcrypto_siphash(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint64_t out;
  const uint8_t *msg, *key;
  size_t msg_len, key_len;
  napi_value hival, loval, result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&key, &key_len) == napi_ok);

  JS_ASSERT(key_len >= 16, JS_ERR_KEY_SIZE);

  out = siphash(msg, msg_len, key);

  CHECK(napi_create_uint32(env, out >> 32, &hival) == napi_ok);
  CHECK(napi_create_uint32(env, out, &loval) == napi_ok);

  CHECK(napi_create_array_with_length(env, 2, &result) == napi_ok);
  CHECK(napi_set_element(env, result, 0, hival) == napi_ok);
  CHECK(napi_set_element(env, result, 1, loval) == napi_ok);

  return result;
}

static napi_value
bcrypto_siphash32(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint32_t out, num;
  const uint8_t *key;
  size_t key_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_uint32(env, argv[0], &num) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&key, &key_len) == napi_ok);

  JS_ASSERT(key_len >= 16, JS_ERR_KEY_SIZE);

  out = siphash32(num, key);

  CHECK(napi_create_uint32(env, out, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_siphash64(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint64_t out, num;
  uint32_t hi, lo;
  const uint8_t *key;
  size_t key_len;
  napi_value hival, loval, result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_uint32(env, argv[0], &hi) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[1], &lo) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&key, &key_len) == napi_ok);

  JS_ASSERT(key_len >= 16, JS_ERR_KEY_SIZE);

  num = ((uint64_t)hi << 32) | lo;
  out = siphash64(num, key);

  CHECK(napi_create_uint32(env, out >> 32, &hival) == napi_ok);
  CHECK(napi_create_uint32(env, out, &loval) == napi_ok);

  CHECK(napi_create_array_with_length(env, 2, &result) == napi_ok);
  CHECK(napi_set_element(env, result, 0, hival) == napi_ok);
  CHECK(napi_set_element(env, result, 1, loval) == napi_ok);

  return result;
}

static napi_value
bcrypto_siphash32k256(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint32_t out, num;
  const uint8_t *key;
  size_t key_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_uint32(env, argv[0], &num) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&key, &key_len) == napi_ok);

  JS_ASSERT(key_len >= 32, JS_ERR_KEY_SIZE);

  out = siphash32k256(num, key);

  CHECK(napi_create_uint32(env, out, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_siphash64k256(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint64_t out, num;
  uint32_t hi, lo;
  const uint8_t *key;
  size_t key_len;
  napi_value hival, loval, result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_uint32(env, argv[0], &hi) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[1], &lo) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&key, &key_len) == napi_ok);

  JS_ASSERT(key_len >= 32, JS_ERR_KEY_SIZE);

  num = ((uint64_t)hi << 32) | lo;
  out = siphash64k256(num, key);

  CHECK(napi_create_uint32(env, out >> 32, &hival) == napi_ok);
  CHECK(napi_create_uint32(env, out, &loval) == napi_ok);

  CHECK(napi_create_array_with_length(env, 2, &result) == napi_ok);
  CHECK(napi_set_element(env, result, 0, hival) == napi_ok);
  CHECK(napi_set_element(env, result, 1, loval) == napi_ok);

  return result;
}

static napi_value
bcrypto_sipmod(napi_env env, napi_callback_info info) {
  napi_value argv[4];
  size_t argc = 4;
  uint64_t out, mod;
  uint32_t mhi, mlo;
  const uint8_t *msg, *key;
  size_t msg_len, key_len;
  napi_value hival, loval, result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 4);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&key, &key_len) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[2], &mhi) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[3], &mlo) == napi_ok);

  JS_ASSERT(key_len >= 16, JS_ERR_KEY_SIZE);

  mod = ((uint64_t)mhi << 32) | mlo;
  out = sipmod(msg, msg_len, key, mod);

  CHECK(napi_create_uint32(env, out >> 32, &hival) == napi_ok);
  CHECK(napi_create_uint32(env, out, &loval) == napi_ok);

  CHECK(napi_create_array_with_length(env, 2, &result) == napi_ok);
  CHECK(napi_set_element(env, result, 0, hival) == napi_ok);
  CHECK(napi_set_element(env, result, 1, loval) == napi_ok);

  return result;
}

/*
 * Module
 */

napi_value
bcrypto_init(napi_env env, napi_value exports) {
  size_t i;

  static struct {
    const char *name;
    napi_callback callback;
  } funcs[] = {
    /* AEAD */
    { "aead_create", bcrypto_aead_create },
    { "aead_init", bcrypto_aead_init },
    { "aead_aad", bcrypto_aead_aad },
    { "aead_encrypt", bcrypto_aead_encrypt },
    { "aead_decrypt", bcrypto_aead_decrypt },
    { "aead_auth", bcrypto_aead_auth },
    { "aead_final", bcrypto_aead_final },
    { "aead_destroy", bcrypto_aead_destroy },
    { "aead_verify", bcrypto_aead_verify },
    { "aead_static_encrypt", bcrypto_aead_static_encrypt },
    { "aead_static_decrypt", bcrypto_aead_static_decrypt },
    { "aead_static_auth", bcrypto_aead_static_auth },

    /* Base58 */
    { "base58_encode", bcrypto_base58_encode },
    { "base58_decode", bcrypto_base58_decode },
    { "base58_test", bcrypto_base58_test },

    /* Bech32 */
    { "bech32_serialize", bcrypto_bech32_serialize },
    { "bech32_deserialize", bcrypto_bech32_deserialize },
    { "bech32_is", bcrypto_bech32_is },
    { "bech32_convert_bits", bcrypto_bech32_convert_bits },
    { "bech32_encode", bcrypto_bech32_encode },
    { "bech32_decode", bcrypto_bech32_decode },
    { "bech32_test", bcrypto_bech32_test },

    /* BLAKE2b */
    { "blake2b_create", bcrypto_blake2b_create },
    { "blake2b_init", bcrypto_blake2b_init },
    { "blake2b_update", bcrypto_blake2b_update },
    { "blake2b_final", bcrypto_blake2b_final },
    { "blake2b_digest", bcrypto_blake2b_digest },
    { "blake2b_root", bcrypto_blake2b_root },
    { "blake2b_multi", bcrypto_blake2b_multi },

    /* BLAKE2s */
    { "blake2s_create", bcrypto_blake2s_create },
    { "blake2s_init", bcrypto_blake2s_init },
    { "blake2s_update", bcrypto_blake2s_update },
    { "blake2s_final", bcrypto_blake2s_final },
    { "blake2s_digest", bcrypto_blake2s_digest },
    { "blake2s_root", bcrypto_blake2s_root },
    { "blake2s_multi", bcrypto_blake2s_multi },

    /* Cash32 */
    { "cash32_serialize", bcrypto_cash32_serialize },
    { "cash32_deserialize", bcrypto_cash32_deserialize },
    { "cash32_is", bcrypto_cash32_is },
    { "cash32_convert_bits", bcrypto_cash32_convert_bits },
    { "cash32_encode", bcrypto_cash32_encode },
    { "cash32_decode", bcrypto_cash32_decode },
    { "cash32_test", bcrypto_cash32_test },

    /* ChaCha20 */
    { "chacha20_create", bcrypto_chacha20_create },
    { "chacha20_init", bcrypto_chacha20_init },
    { "chacha20_encrypt", bcrypto_chacha20_encrypt },
    { "chacha20_destroy", bcrypto_chacha20_destroy },
    { "chacha20_derive", bcrypto_chacha20_derive },

    /* Cleanse */
    { "cleanse", bcrypto_cleanse },

    /* DSA */
    { "dsa_params_create", bcrypto_dsa_params_create },
    { "dsa_params_generate", bcrypto_dsa_params_generate },
    { "dsa_params_generate_async", bcrypto_dsa_params_generate_async },
    { "dsa_params_bits", bcrypto_dsa_params_bits },
    { "dsa_params_verify", bcrypto_dsa_params_verify },
    { "dsa_params_import", bcrypto_dsa_params_import },
    { "dsa_params_export", bcrypto_dsa_params_export },
    { "dsa_privkey_create", bcrypto_dsa_privkey_create },
    { "dsa_privkey_bits", bcrypto_dsa_privkey_bits },
    { "dsa_privkey_verify", bcrypto_dsa_privkey_verify },
    { "dsa_privkey_import", bcrypto_dsa_privkey_import },
    { "dsa_privkey_export", bcrypto_dsa_privkey_export },
    { "dsa_pubkey_create", bcrypto_dsa_pubkey_create },
    { "dsa_pubkey_bits", bcrypto_dsa_pubkey_bits },
    { "dsa_pubkey_verify", bcrypto_dsa_pubkey_verify },
    { "dsa_pubkey_import", bcrypto_dsa_pubkey_import },
    { "dsa_pubkey_export", bcrypto_dsa_pubkey_export },
    { "dsa_signature_export", bcrypto_dsa_signature_export },
    { "dsa_signature_import", bcrypto_dsa_signature_import },
    { "dsa_sign", bcrypto_dsa_sign },
    { "dsa_sign_der", bcrypto_dsa_sign_der },
    { "dsa_verify", bcrypto_dsa_verify },
    { "dsa_verify_der", bcrypto_dsa_verify_der },
    { "dsa_derive", bcrypto_dsa_derive },

    /* ECDH */
    { "ecdh_create", bcrypto_ecdh_create },
    { "ecdh_size", bcrypto_ecdh_size },
    { "ecdh_bits", bcrypto_ecdh_bits },
    { "ecdh_privkey_generate", bcrypto_ecdh_privkey_generate },
    { "ecdh_privkey_verify", bcrypto_ecdh_privkey_verify },
    { "ecdh_privkey_export", bcrypto_ecdh_privkey_export },
    { "ecdh_privkey_import", bcrypto_ecdh_privkey_import },
    { "ecdh_pubkey_create", bcrypto_ecdh_pubkey_create },
    { "ecdh_pubkey_convert", bcrypto_ecdh_pubkey_convert },
    { "ecdh_pubkey_from_uniform", bcrypto_ecdh_pubkey_from_uniform },
    { "ecdh_pubkey_to_uniform", bcrypto_ecdh_pubkey_to_uniform },
    { "ecdh_pubkey_from_hash", bcrypto_ecdh_pubkey_from_hash },
    { "ecdh_pubkey_to_hash", bcrypto_ecdh_pubkey_to_hash },
    { "ecdh_pubkey_verify", bcrypto_ecdh_pubkey_verify },
    { "ecdh_pubkey_export", bcrypto_ecdh_pubkey_export },
    { "ecdh_pubkey_import", bcrypto_ecdh_pubkey_import },
    { "ecdh_pubkey_is_small", bcrypto_ecdh_pubkey_is_small },
    { "ecdh_pubkey_has_torsion", bcrypto_ecdh_pubkey_has_torsion },
    { "ecdh_derive", bcrypto_ecdh_derive },

    /* ECDSA */
    { "ecdsa_create", bcrypto_ecdsa_create },
    { "ecdsa_size", bcrypto_ecdsa_size },
    { "ecdsa_bits", bcrypto_ecdsa_bits },
    { "ecdsa_randomize", bcrypto_ecdsa_randomize },
    { "ecdsa_privkey_generate", bcrypto_ecdsa_privkey_generate },
    { "ecdsa_privkey_verify", bcrypto_ecdsa_privkey_verify },
    { "ecdsa_privkey_export", bcrypto_ecdsa_privkey_export },
    { "ecdsa_privkey_import", bcrypto_ecdsa_privkey_import },
    { "ecdsa_privkey_tweak_add", bcrypto_ecdsa_privkey_tweak_add },
    { "ecdsa_privkey_tweak_mul", bcrypto_ecdsa_privkey_tweak_mul },
    { "ecdsa_privkey_reduce", bcrypto_ecdsa_privkey_reduce },
    { "ecdsa_privkey_negate", bcrypto_ecdsa_privkey_negate },
    { "ecdsa_privkey_invert", bcrypto_ecdsa_privkey_invert },
    { "ecdsa_pubkey_create", bcrypto_ecdsa_pubkey_create },
    { "ecdsa_pubkey_convert", bcrypto_ecdsa_pubkey_convert },
    { "ecdsa_pubkey_from_uniform", bcrypto_ecdsa_pubkey_from_uniform },
    { "ecdsa_pubkey_to_uniform", bcrypto_ecdsa_pubkey_to_uniform },
    { "ecdsa_pubkey_from_hash", bcrypto_ecdsa_pubkey_from_hash },
    { "ecdsa_pubkey_to_hash", bcrypto_ecdsa_pubkey_to_hash },
    { "ecdsa_pubkey_verify", bcrypto_ecdsa_pubkey_verify },
    { "ecdsa_pubkey_export", bcrypto_ecdsa_pubkey_export },
    { "ecdsa_pubkey_import", bcrypto_ecdsa_pubkey_import },
    { "ecdsa_pubkey_tweak_add", bcrypto_ecdsa_pubkey_tweak_add },
    { "ecdsa_pubkey_tweak_mul", bcrypto_ecdsa_pubkey_tweak_mul },
    { "ecdsa_pubkey_combine", bcrypto_ecdsa_pubkey_combine },
    { "ecdsa_pubkey_negate", bcrypto_ecdsa_pubkey_negate },
    { "ecdsa_signature_normalize", bcrypto_ecdsa_signature_normalize },
    { "ecdsa_signature_normalize_der", bcrypto_ecdsa_signature_normalize_der },
    { "ecdsa_signature_export", bcrypto_ecdsa_signature_export },
    { "ecdsa_signature_import", bcrypto_ecdsa_signature_import },
    { "ecdsa_is_low_s", bcrypto_ecdsa_is_low_s },
    { "ecdsa_is_low_der", bcrypto_ecdsa_is_low_der },
    { "ecdsa_sign", bcrypto_ecdsa_sign },
    { "ecdsa_sign_recoverable", bcrypto_ecdsa_sign_recoverable },
    { "ecdsa_sign_der", bcrypto_ecdsa_sign_der },
    { "ecdsa_sign_recoverable_der", bcrypto_ecdsa_sign_recoverable_der },
    { "ecdsa_verify", bcrypto_ecdsa_verify },
    { "ecdsa_verify_der", bcrypto_ecdsa_verify_der },
    { "ecdsa_recover", bcrypto_ecdsa_recover },
    { "ecdsa_recover_der", bcrypto_ecdsa_recover_der },
    { "ecdsa_derive", bcrypto_ecdsa_derive },
    { "ecdsa_schnorr_sign", bcrypto_ecdsa_schnorr_sign },
    { "ecdsa_schnorr_verify", bcrypto_ecdsa_schnorr_verify },
    { "ecdsa_schnorr_verify_batch", bcrypto_ecdsa_schnorr_verify_batch },

    /* EdDSA */
    { "eddsa_create", bcrypto_eddsa_create },
    { "eddsa_size", bcrypto_eddsa_size },
    { "eddsa_bits", bcrypto_eddsa_bits },
    { "eddsa_randomize", bcrypto_eddsa_randomize },
    { "eddsa_privkey_generate", bcrypto_eddsa_privkey_generate },
    { "eddsa_privkey_verify", bcrypto_eddsa_privkey_verify },
    { "eddsa_privkey_export", bcrypto_eddsa_privkey_export },
    { "eddsa_privkey_import", bcrypto_eddsa_privkey_import },
    { "eddsa_privkey_expand", bcrypto_eddsa_privkey_expand },
    { "eddsa_privkey_convert", bcrypto_eddsa_privkey_convert },
    { "eddsa_scalar_generate", bcrypto_eddsa_scalar_generate },
    { "eddsa_scalar_verify", bcrypto_eddsa_scalar_verify },
    { "eddsa_scalar_clamp", bcrypto_eddsa_scalar_clamp },
    { "eddsa_scalar_is_zero", bcrypto_eddsa_scalar_is_zero },
    { "eddsa_scalar_tweak_add", bcrypto_eddsa_scalar_tweak_add },
    { "eddsa_scalar_tweak_mul", bcrypto_eddsa_scalar_tweak_mul },
    { "eddsa_scalar_reduce", bcrypto_eddsa_scalar_reduce },
    { "eddsa_scalar_negate", bcrypto_eddsa_scalar_negate },
    { "eddsa_scalar_invert", bcrypto_eddsa_scalar_invert },
    { "eddsa_pubkey_create", bcrypto_eddsa_pubkey_create },
    { "eddsa_pubkey_from_scalar", bcrypto_eddsa_pubkey_from_scalar },
    { "eddsa_pubkey_convert", bcrypto_eddsa_pubkey_convert },
    { "eddsa_pubkey_from_uniform", bcrypto_eddsa_pubkey_from_uniform },
    { "eddsa_pubkey_to_uniform", bcrypto_eddsa_pubkey_to_uniform },
    { "eddsa_pubkey_from_hash", bcrypto_eddsa_pubkey_from_hash },
    { "eddsa_pubkey_to_hash", bcrypto_eddsa_pubkey_to_hash },
    { "eddsa_pubkey_verify", bcrypto_eddsa_pubkey_verify },
    { "eddsa_pubkey_export", bcrypto_eddsa_pubkey_export },
    { "eddsa_pubkey_import", bcrypto_eddsa_pubkey_import },
    { "eddsa_pubkey_is_infinity", bcrypto_eddsa_pubkey_is_infinity },
    { "eddsa_pubkey_is_small", bcrypto_eddsa_pubkey_is_small },
    { "eddsa_pubkey_has_torsion", bcrypto_eddsa_pubkey_has_torsion },
    { "eddsa_pubkey_tweak_add", bcrypto_eddsa_pubkey_tweak_add },
    { "eddsa_pubkey_tweak_mul", bcrypto_eddsa_pubkey_tweak_mul },
    { "eddsa_pubkey_combine", bcrypto_eddsa_pubkey_combine },
    { "eddsa_pubkey_negate", bcrypto_eddsa_pubkey_negate },
    { "eddsa_sign", bcrypto_eddsa_sign },
    { "eddsa_sign_with_scalar", bcrypto_eddsa_sign_with_scalar },
    { "eddsa_sign_tweak_add", bcrypto_eddsa_sign_tweak_add },
    { "eddsa_sign_tweak_mul", bcrypto_eddsa_sign_tweak_mul },
    { "eddsa_verify", bcrypto_eddsa_verify },
    { "eddsa_verify_single", bcrypto_eddsa_verify_single },
    { "eddsa_verify_batch", bcrypto_eddsa_verify_batch },
    { "eddsa_derive", bcrypto_eddsa_derive },
    { "eddsa_derive_with_scalar", bcrypto_eddsa_derive_with_scalar },

    /* Hash */
    { "hash_create", bcrypto_hash_create },
    { "hash_init", bcrypto_hash_init },
    { "hash_update", bcrypto_hash_update },
    { "hash_final", bcrypto_hash_final },
    { "hash_digest", bcrypto_hash_digest },
    { "hash_root", bcrypto_hash_root },
    { "hash_multi", bcrypto_hash_multi },

    /* HMAC */
    { "hmac_create", bcrypto_hmac_create },
    { "hmac_init", bcrypto_hmac_init },
    { "hmac_update", bcrypto_hmac_update },
    { "hmac_final", bcrypto_hmac_final },
    { "hmac_digest", bcrypto_hmac_digest },

    /* Keccak */
    { "keccak_create", bcrypto_keccak_create },
    { "keccak_init", bcrypto_keccak_init },
    { "keccak_update", bcrypto_keccak_update },
    { "keccak_final", bcrypto_keccak_final },
    { "keccak_digest", bcrypto_keccak_digest },
    { "keccak_root", bcrypto_keccak_root },
    { "keccak_multi", bcrypto_keccak_multi },

    /* Murmur3 */
    { "murmur3_sum", bcrypto_murmur3_sum },
    { "murmur3_tweak", bcrypto_murmur3_tweak },

    /* PBKDF2 */
    { "pbkdf2_derive", bcrypto_pbkdf2_derive },
    { "pbkdf2_derive_async", bcrypto_pbkdf2_derive_async },

    /* Poly1305 */
    { "poly1305_create", bcrypto_poly1305_create },
    { "poly1305_init", bcrypto_poly1305_init },
    { "poly1305_update", bcrypto_poly1305_update },
    { "poly1305_final", bcrypto_poly1305_final },
    { "poly1305_destroy", bcrypto_poly1305_destroy },
    { "poly1305_verify", bcrypto_poly1305_verify },

    /* RSA */
    { "rsa_privkey_generate", bcrypto_rsa_privkey_generate },
    { "rsa_privkey_generate_async", bcrypto_rsa_privkey_generate_async },
    { "rsa_privkey_bits", bcrypto_rsa_privkey_bits },
    { "rsa_privkey_verify", bcrypto_rsa_privkey_verify },
    { "rsa_privkey_import", bcrypto_rsa_privkey_import },
    { "rsa_privkey_export", bcrypto_rsa_privkey_export },
    { "rsa_pubkey_create", bcrypto_rsa_pubkey_create },
    { "rsa_pubkey_bits", bcrypto_rsa_pubkey_bits },
    { "rsa_pubkey_verify", bcrypto_rsa_pubkey_verify },
    { "rsa_pubkey_import", bcrypto_rsa_pubkey_import },
    { "rsa_pubkey_export", bcrypto_rsa_pubkey_export },
    { "rsa_sign", bcrypto_rsa_sign },
    { "rsa_verify", bcrypto_rsa_verify },
    { "rsa_encrypt", bcrypto_rsa_encrypt },
    { "rsa_decrypt", bcrypto_rsa_decrypt },
    { "rsa_sign_pss", bcrypto_rsa_sign_pss },
    { "rsa_verify_pss", bcrypto_rsa_verify_pss },
    { "rsa_encrypt_oaep", bcrypto_rsa_encrypt_oaep },
    { "rsa_decrypt_oaep", bcrypto_rsa_decrypt_oaep },
    { "rsa_veil", bcrypto_rsa_veil },
    { "rsa_unveil", bcrypto_rsa_unveil },

    /* Salsa20 */
    { "salsa20_create", bcrypto_salsa20_create },
    { "salsa20_init", bcrypto_salsa20_init },
    { "salsa20_encrypt", bcrypto_salsa20_encrypt },
    { "salsa20_destroy", bcrypto_salsa20_destroy },
    { "salsa20_derive", bcrypto_salsa20_derive },

    /* Schnorr */
    { "schnorr_create", bcrypto_schnorr_create },
    { "schnorr_size", bcrypto_schnorr_size },
    { "schnorr_bits", bcrypto_schnorr_bits },
    { "schnorr_randomize", bcrypto_schnorr_randomize },
    { "schnorr_privkey_generate", bcrypto_schnorr_privkey_generate },
    { "schnorr_privkey_verify", bcrypto_schnorr_privkey_verify },
    { "schnorr_privkey_export", bcrypto_schnorr_privkey_export },
    { "schnorr_privkey_import", bcrypto_schnorr_privkey_import },
    { "schnorr_privkey_tweak_add", bcrypto_schnorr_privkey_tweak_add },
    { "schnorr_privkey_tweak_mul", bcrypto_schnorr_privkey_tweak_mul },
    { "schnorr_privkey_reduce", bcrypto_schnorr_privkey_reduce },
    { "schnorr_privkey_invert", bcrypto_schnorr_privkey_invert },
    { "schnorr_pubkey_create", bcrypto_schnorr_pubkey_create },
    { "schnorr_pubkey_from_uniform", bcrypto_schnorr_pubkey_from_uniform },
    { "schnorr_pubkey_to_uniform", bcrypto_schnorr_pubkey_to_uniform },
    { "schnorr_pubkey_from_hash", bcrypto_schnorr_pubkey_from_hash },
    { "schnorr_pubkey_to_hash", bcrypto_schnorr_pubkey_to_hash },
    { "schnorr_pubkey_verify", bcrypto_schnorr_pubkey_verify },
    { "schnorr_pubkey_export", bcrypto_schnorr_pubkey_export },
    { "schnorr_pubkey_import", bcrypto_schnorr_pubkey_import },
    { "schnorr_pubkey_tweak_add", bcrypto_schnorr_pubkey_tweak_add },
    { "schnorr_pubkey_tweak_mul", bcrypto_schnorr_pubkey_tweak_mul },
    { "schnorr_pubkey_tweak_sum", bcrypto_schnorr_pubkey_tweak_sum },
    { "schnorr_pubkey_tweak_test", bcrypto_schnorr_pubkey_tweak_test },
    { "schnorr_pubkey_combine", bcrypto_schnorr_pubkey_combine },
    { "schnorr_sign", bcrypto_schnorr_sign },
    { "schnorr_verify", bcrypto_schnorr_verify },
    { "schnorr_verify_batch", bcrypto_schnorr_verify_batch },
    { "schnorr_derive", bcrypto_schnorr_derive },

    /* Scrypt */
    { "scrypt_derive", bcrypto_scrypt_derive },
    { "scrypt_derive_async", bcrypto_scrypt_derive_async },

#ifdef BCRYPTO_USE_SECP256K1
    /* Secp256k1 */
    { "secp256k1_create", bcrypto_secp256k1_create },
    { "secp256k1_randomize", bcrypto_secp256k1_randomize },
    { "secp256k1_privkey_generate", bcrypto_secp256k1_privkey_generate },
    { "secp256k1_privkey_verify", bcrypto_secp256k1_privkey_verify },
    { "secp256k1_privkey_export", bcrypto_secp256k1_privkey_export },
    { "secp256k1_privkey_import", bcrypto_secp256k1_privkey_import },
    { "secp256k1_privkey_tweak_add", bcrypto_secp256k1_privkey_tweak_add },
    { "secp256k1_privkey_tweak_mul", bcrypto_secp256k1_privkey_tweak_mul },
    { "secp256k1_privkey_reduce", bcrypto_secp256k1_privkey_reduce },
    { "secp256k1_privkey_negate", bcrypto_secp256k1_privkey_negate },
    { "secp256k1_privkey_invert", bcrypto_secp256k1_privkey_invert },
    { "secp256k1_pubkey_create", bcrypto_secp256k1_pubkey_create },
    { "secp256k1_pubkey_convert", bcrypto_secp256k1_pubkey_convert },
    { "secp256k1_pubkey_from_uniform", bcrypto_secp256k1_pubkey_from_uniform },
    { "secp256k1_pubkey_to_uniform", bcrypto_secp256k1_pubkey_to_uniform },
    { "secp256k1_pubkey_from_hash", bcrypto_secp256k1_pubkey_from_hash },
    { "secp256k1_pubkey_to_hash", bcrypto_secp256k1_pubkey_to_hash },
    { "secp256k1_pubkey_verify", bcrypto_secp256k1_pubkey_verify },
    { "secp256k1_pubkey_export", bcrypto_secp256k1_pubkey_export },
    { "secp256k1_pubkey_import", bcrypto_secp256k1_pubkey_import },
    { "secp256k1_pubkey_tweak_add", bcrypto_secp256k1_pubkey_tweak_add },
    { "secp256k1_pubkey_tweak_mul", bcrypto_secp256k1_pubkey_tweak_mul },
    { "secp256k1_pubkey_combine", bcrypto_secp256k1_pubkey_combine },
    { "secp256k1_pubkey_negate", bcrypto_secp256k1_pubkey_negate },
    { "secp256k1_signature_normalize", bcrypto_secp256k1_signature_normalize },
    { "secp256k1_signature_normalize_der", bcrypto_secp256k1_signature_normalize_der },
    { "secp256k1_signature_export", bcrypto_secp256k1_signature_export },
    { "secp256k1_signature_import", bcrypto_secp256k1_signature_import },
    { "secp256k1_is_low_s", bcrypto_secp256k1_is_low_s },
    { "secp256k1_is_low_der", bcrypto_secp256k1_is_low_der },
    { "secp256k1_sign", bcrypto_secp256k1_sign },
    { "secp256k1_sign_recoverable", bcrypto_secp256k1_sign_recoverable },
    { "secp256k1_sign_der", bcrypto_secp256k1_sign_der },
    { "secp256k1_sign_recoverable_der", bcrypto_secp256k1_sign_recoverable_der },
    { "secp256k1_verify", bcrypto_secp256k1_verify },
    { "secp256k1_verify_der", bcrypto_secp256k1_verify_der },
    { "secp256k1_recover", bcrypto_secp256k1_recover },
    { "secp256k1_recover_der", bcrypto_secp256k1_recover_der },
    { "secp256k1_derive", bcrypto_secp256k1_derive },
    { "secp256k1_schnorr_legacy_sign", bcrypto_secp256k1_schnorr_legacy_sign },
    { "secp256k1_schnorr_legacy_verify", bcrypto_secp256k1_schnorr_legacy_verify },
    { "secp256k1_schnorr_legacy_verify_batch", bcrypto_secp256k1_schnorr_legacy_verify_batch },
#ifdef BCRYPTO_USE_SECP256K1_LATEST
    { "secp256k1_xonly_privkey_export", bcrypto_secp256k1_xonly_privkey_export },
    { "secp256k1_xonly_privkey_tweak_add", bcrypto_secp256k1_xonly_privkey_tweak_add },
    { "secp256k1_xonly_create", bcrypto_secp256k1_xonly_create },
    { "secp256k1_xonly_from_uniform", bcrypto_secp256k1_xonly_from_uniform },
    { "secp256k1_xonly_to_uniform", bcrypto_secp256k1_xonly_to_uniform },
    { "secp256k1_xonly_from_hash", bcrypto_secp256k1_xonly_from_hash },
    { "secp256k1_xonly_to_hash", bcrypto_secp256k1_xonly_to_hash },
    { "secp256k1_xonly_verify", bcrypto_secp256k1_xonly_verify },
    { "secp256k1_xonly_export", bcrypto_secp256k1_xonly_export },
    { "secp256k1_xonly_import", bcrypto_secp256k1_xonly_import },
    { "secp256k1_xonly_tweak_add", bcrypto_secp256k1_xonly_tweak_add },
    { "secp256k1_xonly_tweak_mul", bcrypto_secp256k1_xonly_tweak_mul },
    { "secp256k1_xonly_tweak_sum", bcrypto_secp256k1_xonly_tweak_sum },
    { "secp256k1_xonly_tweak_test", bcrypto_secp256k1_xonly_tweak_test },
    { "secp256k1_xonly_combine", bcrypto_secp256k1_xonly_combine },
    { "secp256k1_schnorr_sign", bcrypto_secp256k1_schnorr_sign },
    { "secp256k1_schnorr_verify", bcrypto_secp256k1_schnorr_verify },
    { "secp256k1_schnorr_verify_batch", bcrypto_secp256k1_schnorr_verify_batch },
    { "secp256k1_xonly_derive", bcrypto_secp256k1_xonly_derive },
#endif
#endif

    /* Siphash */
    { "siphash", bcrypto_siphash },
    { "siphash32", bcrypto_siphash32 },
    { "siphash64", bcrypto_siphash64 },
    { "siphash32k256", bcrypto_siphash32k256 },
    { "siphash64k256", bcrypto_siphash64k256 },
    { "sipmod", bcrypto_sipmod }
  };

  static struct {
    const char *name;
    int value;
  } flags[] = {
#ifdef BCRYPTO_USE_SECP256K1
    { "USE_SECP256K1", 1 },
#else
    { "USE_SECP256K1", 0 },
#endif
#ifdef BCRYPTO_USE_SECP256K1_LATEST
    { "USE_SECP256K1_LATEST", 1 },
#else
    { "USE_SECP256K1_LATEST", 0 },
#endif
    { "ENTROPY_SIZE", ENTROPY_SIZE }
  };

  for (i = 0; i < sizeof(funcs) / sizeof(funcs[0]); i++) {
    const char *name = funcs[i].name;
    napi_callback callback = funcs[i].callback;
    napi_value fn;

    CHECK(napi_create_function(env,
                               name,
                               NAPI_AUTO_LENGTH,
                               callback,
                               NULL,
                               &fn) == napi_ok);

    CHECK(napi_set_named_property(env, exports, name, fn) == napi_ok);
  }

  for (i = 0; i < sizeof(flags) / sizeof(flags[0]); i++) {
    const char *name = flags[i].name;
    int value = flags[i].value;
    napi_value val;

    CHECK(napi_create_int32(env, value, &val) == napi_ok);
    CHECK(napi_set_named_property(env, exports, name, val) == napi_ok);
  }

  return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, bcrypto_init)
