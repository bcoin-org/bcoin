/**
 * bcrypto.cc - fast native bindings to crypto functions
 * Copyright (c) 2016-2020, Christopher Jeffrey (MIT License)
 * https://github.com/bcoin-org/bcrypto
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <node_api.h>

#include <torsion/aead.h>
#include <torsion/cipher.h>
#include <torsion/drbg.h>
#include <torsion/dsa.h>
#include <torsion/ecc.h>
#include <torsion/encoding.h>
#include <torsion/hash.h>
#include <torsion/ies.h>
#include <torsion/kdf.h>
#include <torsion/mac.h>
#include <torsion/rand.h>
#include <torsion/rsa.h>
#include <torsion/stream.h>
#include <torsion/util.h>

#ifdef BCRYPTO_USE_SECP256K1
#include <secp256k1.h>
#include <secp256k1_ecdh.h>
#include <secp256k1_elligator.h>
#include <secp256k1_extra.h>
#include <secp256k1_recovery.h>
#include <secp256k1_schnorrleg.h>
#include <secp256k1_schnorrsig.h>
#include <lax_der_parsing.h>
#endif

#define CHECK(expr) do {                            \
  if (!(expr))                                      \
    bcrypto_assert_fail(__FILE__, __LINE__, #expr); \
} while (0)

#define ENTROPY_SIZE 32
#define SCRATCH_SIZE 64

#define MAX_BUFFER_LENGTH \
  (sizeof(void *) == 4 ? 0x3ffffffful : 0xfffffffeul)

#define MAX_STRING_LENGTH \
  (sizeof(void *) == 4 ? ((1ul << 28) - 16ul) : ((1ul << 29) - 24ul))

#define JS_ERR_CONTEXT "Could not create context."
#define JS_ERR_FINAL "Could not finalize context."
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
#define JS_ERR_SECRET_SIZE "Invalid secret size."
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
#define JS_ERR_ALLOC "Allocation failed."
#define JS_ERR_ARG "Invalid argument."
#define JS_ERR_OPT "Could not set option."
#define JS_ERR_GET "Could not get value."
#define JS_ERR_CRYPT "Could not encipher."
#define JS_ERR_RNG "RNG failure."

#define JS_THROW(msg) do {                              \
  CHECK(napi_throw_error(env, NULL, (msg)) == napi_ok); \
  return NULL;                                          \
} while (0)

#define JS_ASSERT(cond, msg) if (!(cond)) JS_THROW(msg)

#define JS_CHECK_ALLOC(expr) JS_ASSERT((expr) == napi_ok, JS_ERR_ALLOC)

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

typedef struct bcrypto_cipher_s {
  cipher_stream_t ctx;
  int type;
  int mode;
  int encrypt;
  int started;
  int has_tag;
} bcrypto_cipher_t;

typedef struct bcrypto_ctr_drbg_s {
  ctr_drbg_t ctx;
  uint32_t bits;
  int derivation;
  int started;
} bcrypto_ctr_drbg_t;

typedef struct bcrypto_mont_s {
  mont_curve_t *ctx;
  size_t scalar_size;
  size_t scalar_bits;
  size_t field_size;
  size_t field_bits;
} bcrypto_mont_curve_t;

typedef struct bcrypto_edwards_s {
  edwards_curve_t *ctx;
  edwards_scratch_t *scratch;
  size_t scalar_size;
  size_t scalar_bits;
  size_t field_size;
  size_t field_bits;
  size_t priv_size;
  size_t pub_size;
  size_t sig_size;
} bcrypto_edwards_curve_t;

typedef struct bcrypto_hash_s {
  hash_t ctx;
  int type;
  int started;
} bcrypto_hash_t;

typedef struct bcrypto_hash_drbg_s {
  hash_drbg_t ctx;
  int type;
  int started;
} bcrypto_hash_drbg_t;

typedef struct bcrypto_hmac_s {
  hmac_t ctx;
  int type;
  int started;
} bcrypto_hmac_t;

typedef struct bcrypto_hmac_drbg_s {
  hmac_drbg_t ctx;
  int type;
  int started;
} bcrypto_hmac_drbg_t;

typedef struct bcrypto_keccak_s {
  keccak_t ctx;
  int started;
} bcrypto_keccak_t;

typedef struct bcrypto_poly1305_s {
  poly1305_t ctx;
  int started;
} bcrypto_poly1305_t;

typedef struct bcrypto_arc4_s {
  arc4_t ctx;
  int started;
} bcrypto_arc4_t;

typedef struct bcrypto_salsa20_s {
  salsa20_t ctx;
  int started;
} bcrypto_salsa20_t;

#ifdef BCRYPTO_USE_SECP256K1
typedef struct bcrypto_secp256k1_s {
  secp256k1_context *ctx;
  secp256k1_scratch_space *scratch;
} bcrypto_secp256k1_t;
#endif

typedef struct bcrypto_wei_s {
  wei_curve_t *ctx;
  wei_scratch_t *scratch;
  size_t scalar_size;
  size_t scalar_bits;
  size_t field_size;
  size_t field_bits;
  size_t sig_size;
  size_t legacy_size;
  size_t schnorr_size;
} bcrypto_wei_curve_t;

/*
 * Assertions
 */

static void
bcrypto_assert_fail(const char *file, int line, const char *expr) {
  fprintf(stderr, "%s:%d: Assertion `%s' failed.\n", file, line, expr);
  fflush(stderr);
  abort();
}

/*
 * Allocation
 */

static void *
bcrypto_malloc(size_t size) {
  if (size == 0)
    return NULL;

  return malloc(size);
}

static void
bcrypto_free(void *ptr) {
  if (ptr != NULL)
    free(ptr);
}

static void *
bcrypto_xmalloc(size_t size) {
  void *ptr;

  if (size == 0)
    return NULL;

  ptr = malloc(size);

  CHECK(ptr != NULL);

  return ptr;
}

/*
 * N-API Extras
 */

static napi_status
read_value_string_latin1(napi_env env, napi_value value,
                         char **str, size_t *length) {
  char *buf;
  size_t buflen;
  napi_status status;

  status = napi_get_value_string_latin1(env, value, NULL, 0, &buflen);

  if (status != napi_ok)
    return status;

  buf = bcrypto_malloc(buflen + 1);

  if (buf == NULL)
    return napi_generic_failure;

  status = napi_get_value_string_latin1(env,
                                        value,
                                        buf,
                                        buflen + 1,
                                        length);

  if (status != napi_ok) {
    bcrypto_free(buf);
    return status;
  }

  CHECK(*length == buflen);

  *str = buf;

  return napi_ok;
}

/*
 * AEAD
 */

static void
bcrypto_aead_destroy_(napi_env env, void *data, void *hint) {
  (void)env;
  (void)hint;
  torsion_cleanse(data, sizeof(aead_t));
  bcrypto_free(data);
}

static napi_value
bcrypto_aead_create(napi_env env, napi_callback_info info) {
  aead_t *ctx = bcrypto_xmalloc(sizeof(aead_t));
  napi_value handle;

  (void)info;

  ctx->mode = -1;

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

  aead_init(ctx, key, iv, iv_len);

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

  ok = torsion_memequal(mac, tag, 16);

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

  aead_init(&ctx, key, iv, iv_len);
  aead_aad(&ctx, aad, aad_len);
  aead_encrypt(&ctx, msg, msg, msg_len);
  aead_final(&ctx, out);

  torsion_cleanse(&ctx, sizeof(aead_t));

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

  aead_init(&ctx, key, iv, iv_len);
  aead_aad(&ctx, aad, aad_len);
  aead_decrypt(&ctx, msg, msg, msg_len);
  aead_final(&ctx, mac);

  torsion_cleanse(&ctx, sizeof(aead_t));

  ok = torsion_memequal(mac, tag, 16);

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

  aead_init(&ctx, key, iv, iv_len);
  aead_aad(&ctx, aad, aad_len);
  aead_auth(&ctx, msg, msg_len);
  aead_final(&ctx, mac);

  torsion_cleanse(&ctx, sizeof(aead_t));

  ok = torsion_memequal(mac, tag, 16);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

/*
 * ARC4
 */

static void
bcrypto_arc4_destroy_(napi_env env, void *data, void *hint) {
  (void)env;
  (void)hint;
  torsion_cleanse(data, sizeof(bcrypto_arc4_t));
  bcrypto_free(data);
}

static napi_value
bcrypto_arc4_create(napi_env env, napi_callback_info info) {
  bcrypto_arc4_t *arc4 = bcrypto_xmalloc(sizeof(bcrypto_arc4_t));
  napi_value handle;

  (void)info;

  arc4->started = 0;

  CHECK(napi_create_external(env,
                             arc4,
                             bcrypto_arc4_destroy_,
                             NULL,
                             &handle) == napi_ok);

  return handle;
}

static napi_value
bcrypto_arc4_init(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  const uint8_t *key;
  size_t key_len;
  bcrypto_arc4_t *arc4;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&arc4) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&key, &key_len) == napi_ok);

  JS_ASSERT(key_len >= 1 && key_len <= 256, JS_ERR_KEY_SIZE);

  arc4_init(&arc4->ctx, key, key_len);
  arc4->started = 1;

  return argv[0];
}

static napi_value
bcrypto_arc4_crypt(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t *msg;
  size_t msg_len;
  bcrypto_arc4_t *arc4;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&arc4) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&msg, &msg_len) == napi_ok);

  JS_ASSERT(arc4->started, JS_ERR_INIT);

  arc4_crypt(&arc4->ctx, msg, msg, msg_len);

  return argv[1];
}

static napi_value
bcrypto_arc4_destroy(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  bcrypto_arc4_t *arc4;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_value_external(env, argv[0], (void **)&arc4) == napi_ok);

  arc4->started = 0;

  return argv[0];
}

/*
 * Base16
 */

static napi_value
bcrypto_base16_encode(napi_env env, napi_callback_info info) {
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

  JS_ASSERT(data_len <= 0x7fffffff, JS_ERR_ENCODE);

  out_len = base16_encode_size(data_len);

  JS_ASSERT(out_len <= MAX_STRING_LENGTH, JS_ERR_ALLOC);

  out = bcrypto_malloc(out_len + 1);

  JS_ASSERT(out != NULL, JS_ERR_ALLOC);

  base16_encode(out, &out_len, data, data_len);

  if (napi_create_string_latin1(env, out, out_len, &result) != napi_ok)
    goto fail;

  bcrypto_free(out);

  return result;
fail:
  bcrypto_free(out);
  JS_THROW(JS_ERR_ENCODE);
}

static napi_value
bcrypto_base16_decode(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  uint8_t *out;
  size_t out_len;
  char *str;
  size_t str_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);

  JS_CHECK_ALLOC(read_value_string_latin1(env, argv[0], &str, &str_len));

  out_len = base16_decode_size(str_len);

  if (out_len > MAX_BUFFER_LENGTH)
    goto fail;

  if (napi_create_buffer(env, out_len, (void **)&out, &result) != napi_ok)
    goto fail;

  if (!base16_decode(out, &out_len, str, str_len))
    goto fail;

  bcrypto_free(str);

  return result;
fail:
  bcrypto_free(str);
  JS_THROW(JS_ERR_DECODE);
}

static napi_value
bcrypto_base16_test(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  char *str;
  size_t str_len;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);

  JS_CHECK_ALLOC(read_value_string_latin1(env, argv[0], &str, &str_len));

  ok = base16_test(str, str_len);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  bcrypto_free(str);

  return result;
}

/*
 * Base16 (Little Endian)
 */

static napi_value
bcrypto_base16le_encode(napi_env env, napi_callback_info info) {
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

  JS_ASSERT(data_len <= 0x7fffffff, JS_ERR_ENCODE);

  out_len = base16le_encode_size(data_len);

  JS_ASSERT(out_len <= MAX_STRING_LENGTH, JS_ERR_ALLOC);

  out = bcrypto_malloc(out_len + 1);

  JS_ASSERT(out != NULL, JS_ERR_ALLOC);

  base16le_encode(out, &out_len, data, data_len);

  if (napi_create_string_latin1(env, out, out_len, &result) != napi_ok)
    goto fail;

  bcrypto_free(out);

  return result;
fail:
  bcrypto_free(out);
  JS_THROW(JS_ERR_ENCODE);
}

static napi_value
bcrypto_base16le_decode(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  uint8_t *out;
  size_t out_len;
  char *str;
  size_t str_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);

  JS_CHECK_ALLOC(read_value_string_latin1(env, argv[0], &str, &str_len));

  out_len = base16le_decode_size(str_len);

  if (out_len > MAX_BUFFER_LENGTH)
    goto fail;

  if (napi_create_buffer(env, out_len, (void **)&out, &result) != napi_ok)
    goto fail;

  if (!base16le_decode(out, &out_len, str, str_len))
    goto fail;

  bcrypto_free(str);

  return result;
fail:
  bcrypto_free(str);
  JS_THROW(JS_ERR_DECODE);
}

static napi_value
bcrypto_base16le_test(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  char *str;
  size_t str_len;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);

  JS_CHECK_ALLOC(read_value_string_latin1(env, argv[0], &str, &str_len));

  ok = base16le_test(str, str_len);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  bcrypto_free(str);

  return result;
}

/*
 * Base32
 */

static napi_value
bcrypto_base32_encode(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  char *out;
  size_t out_len;
  const uint8_t *data;
  size_t data_len;
  bool pad;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&data,
                             &data_len) == napi_ok);
  CHECK(napi_get_value_bool(env, argv[1], &pad) == napi_ok);

  JS_ASSERT(data_len <= 0x7fffffff, JS_ERR_ENCODE);

  out_len = base32_encode_size(data_len, pad);

  JS_ASSERT(out_len <= MAX_STRING_LENGTH, JS_ERR_ALLOC);

  out = bcrypto_malloc(out_len + 1);

  JS_ASSERT(out != NULL, JS_ERR_ALLOC);

  base32_encode(out, &out_len, data, data_len, pad);

  if (napi_create_string_latin1(env, out, out_len, &result) != napi_ok)
    goto fail;

  bcrypto_free(out);

  return result;
fail:
  bcrypto_free(out);
  JS_THROW(JS_ERR_ENCODE);
}

static napi_value
bcrypto_base32_decode(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t *out;
  size_t out_len;
  char *str;
  size_t str_len;
  bool unpad;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);

  JS_CHECK_ALLOC(read_value_string_latin1(env, argv[0], &str, &str_len));

  CHECK(napi_get_value_bool(env, argv[1], &unpad) == napi_ok);

  out_len = base32_decode_size(str, str_len);

  if (out_len > MAX_BUFFER_LENGTH)
    goto fail;

  if (napi_create_buffer(env, out_len, (void **)&out, &result) != napi_ok)
    goto fail;

  if (!base32_decode(out, &out_len, str, str_len, unpad))
    goto fail;

  bcrypto_free(str);

  return result;
fail:
  bcrypto_free(str);
  JS_THROW(JS_ERR_DECODE);
}

static napi_value
bcrypto_base32_test(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  char *str;
  size_t str_len;
  bool unpad;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);

  JS_CHECK_ALLOC(read_value_string_latin1(env, argv[0], &str, &str_len));

  CHECK(napi_get_value_bool(env, argv[1], &unpad) == napi_ok);

  ok = base32_test(str, str_len, unpad);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  bcrypto_free(str);

  return result;
}

/*
 * Base32-Hex
 */

static napi_value
bcrypto_base32hex_encode(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  char *out;
  size_t out_len;
  const uint8_t *data;
  size_t data_len;
  bool pad;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&data,
                             &data_len) == napi_ok);
  CHECK(napi_get_value_bool(env, argv[1], &pad) == napi_ok);

  JS_ASSERT(data_len <= 0x7fffffff, JS_ERR_ENCODE);

  out_len = base32hex_encode_size(data_len, pad);

  JS_ASSERT(out_len <= MAX_STRING_LENGTH, JS_ERR_ALLOC);

  out = bcrypto_malloc(out_len + 1);

  JS_ASSERT(out != NULL, JS_ERR_ALLOC);

  base32hex_encode(out, &out_len, data, data_len, pad);

  if (napi_create_string_latin1(env, out, out_len, &result) != napi_ok)
    goto fail;

  bcrypto_free(out);

  return result;
fail:
  bcrypto_free(out);
  JS_THROW(JS_ERR_ENCODE);
}

static napi_value
bcrypto_base32hex_decode(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t *out;
  size_t out_len;
  char *str;
  size_t str_len;
  bool unpad;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);

  JS_CHECK_ALLOC(read_value_string_latin1(env, argv[0], &str, &str_len));

  CHECK(napi_get_value_bool(env, argv[1], &unpad) == napi_ok);

  out_len = base32hex_decode_size(str, str_len);

  if (out_len > MAX_BUFFER_LENGTH)
    goto fail;

  if (napi_create_buffer(env, out_len, (void **)&out, &result) != napi_ok)
    goto fail;

  if (!base32hex_decode(out, &out_len, str, str_len, unpad))
    goto fail;

  bcrypto_free(str);

  return result;
fail:
  bcrypto_free(str);
  JS_THROW(JS_ERR_DECODE);
}

static napi_value
bcrypto_base32hex_test(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  char *str;
  size_t str_len;
  bool unpad;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);

  JS_CHECK_ALLOC(read_value_string_latin1(env, argv[0], &str, &str_len));

  CHECK(napi_get_value_bool(env, argv[1], &unpad) == napi_ok);

  ok = base32hex_test(str, str_len, unpad);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  bcrypto_free(str);

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

  JS_ASSERT(data_len <= 0x7fffffff, JS_ERR_ENCODE);

  out_len = BASE58_ENCODE_SIZE(data_len);

  JS_ASSERT(out_len <= MAX_STRING_LENGTH, JS_ERR_ALLOC);

  out = bcrypto_malloc(out_len + 1);

  JS_ASSERT(out != NULL, JS_ERR_ALLOC);

  if (!base58_encode(out, &out_len, data, data_len))
    goto fail;

  if (napi_create_string_latin1(env, out, out_len, &result) != napi_ok)
    goto fail;

  bcrypto_free(out);

  return result;
fail:
  bcrypto_free(out);
  JS_THROW(JS_ERR_ENCODE);
}

static napi_value
bcrypto_base58_decode(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  uint8_t *out;
  size_t out_len;
  char *str;
  size_t str_len;
  napi_value ab, result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);

  JS_CHECK_ALLOC(read_value_string_latin1(env, argv[0], &str, &str_len));

  if (str_len > 0xffffffff)
    goto fail;

  out_len = BASE58_DECODE_SIZE(str_len);

  if (out_len > MAX_BUFFER_LENGTH)
    goto fail;

  if (napi_create_arraybuffer(env, out_len, (void **)&out, &ab) != napi_ok)
    goto fail;

  if (!base58_decode(out, &out_len, str, str_len))
    goto fail;

  CHECK(napi_create_typedarray(env, napi_uint8_array, out_len,
                               ab, 0, &result) == napi_ok);

  bcrypto_free(str);

  return result;
fail:
  bcrypto_free(str);
  JS_THROW(JS_ERR_DECODE);
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

  JS_CHECK_ALLOC(read_value_string_latin1(env, argv[0], &str, &str_len));

  ok = base58_test(str, str_len);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  bcrypto_free(str);

  return result;
}

/*
 * Base64
 */

static napi_value
bcrypto_base64_encode(napi_env env, napi_callback_info info) {
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

  JS_ASSERT(data_len <= 0x7fffffff, JS_ERR_ENCODE);

  out_len = base64_encode_size(data_len);

  JS_ASSERT(out_len <= MAX_STRING_LENGTH, JS_ERR_ALLOC);

  out = bcrypto_malloc(out_len + 1);

  JS_ASSERT(out != NULL, JS_ERR_ALLOC);

  base64_encode(out, &out_len, data, data_len);

  if (napi_create_string_latin1(env, out, out_len, &result) != napi_ok)
    goto fail;

  bcrypto_free(out);

  return result;
fail:
  bcrypto_free(out);
  JS_THROW(JS_ERR_ENCODE);
}

static napi_value
bcrypto_base64_decode(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  uint8_t *out;
  size_t out_len;
  char *str;
  size_t str_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);

  JS_CHECK_ALLOC(read_value_string_latin1(env, argv[0], &str, &str_len));

  out_len = base64_decode_size(str, str_len);

  if (out_len > MAX_BUFFER_LENGTH)
    goto fail;

  if (napi_create_buffer(env, out_len, (void **)&out, &result) != napi_ok)
    goto fail;

  if (!base64_decode(out, &out_len, str, str_len))
    goto fail;

  bcrypto_free(str);

  return result;
fail:
  bcrypto_free(str);
  JS_THROW(JS_ERR_DECODE);
}

static napi_value
bcrypto_base64_test(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  char *str;
  size_t str_len;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);

  JS_CHECK_ALLOC(read_value_string_latin1(env, argv[0], &str, &str_len));

  ok = base64_test(str, str_len);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  bcrypto_free(str);

  return result;
}

/*
 * Base64-URL
 */

static napi_value
bcrypto_base64url_encode(napi_env env, napi_callback_info info) {
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

  JS_ASSERT(data_len <= 0x7fffffff, JS_ERR_ENCODE);

  out_len = base64url_encode_size(data_len);

  JS_ASSERT(out_len <= MAX_STRING_LENGTH, JS_ERR_ALLOC);

  out = bcrypto_malloc(out_len + 1);

  JS_ASSERT(out != NULL, JS_ERR_ALLOC);

  base64url_encode(out, &out_len, data, data_len);

  if (napi_create_string_latin1(env, out, out_len, &result) != napi_ok)
    goto fail;

  bcrypto_free(out);

  return result;
fail:
  bcrypto_free(out);
  JS_THROW(JS_ERR_ENCODE);
}

static napi_value
bcrypto_base64url_decode(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  uint8_t *out;
  size_t out_len;
  char *str;
  size_t str_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);

  JS_CHECK_ALLOC(read_value_string_latin1(env, argv[0], &str, &str_len));

  out_len = base64url_decode_size(str, str_len);

  if (out_len > MAX_BUFFER_LENGTH)
    goto fail;

  if (napi_create_buffer(env, out_len, (void **)&out, &result) != napi_ok)
    goto fail;

  if (!base64url_decode(out, &out_len, str, str_len))
    goto fail;

  bcrypto_free(str);

  return result;
fail:
  bcrypto_free(str);
  JS_THROW(JS_ERR_DECODE);
}

static napi_value
bcrypto_base64url_test(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  char *str;
  size_t str_len;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);

  JS_CHECK_ALLOC(read_value_string_latin1(env, argv[0], &str, &str_len));

  ok = base64url_test(str, str_len);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  bcrypto_free(str);

  return result;
}

/*
 * Bcrypt
 */

static napi_value
bcrypto_bcrypt_hash192(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[24];
  uint32_t rounds;
  const uint8_t *pass, *salt;
  size_t pass_len, salt_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&pass,
                             &pass_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&salt,
                             &salt_len) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[2], &rounds) == napi_ok);

  JS_ASSERT(rounds >= 4 && rounds <= 31, JS_ERR_DERIVE);

  bcrypt_hash192(out, pass, pass_len, salt, salt_len, rounds);

  CHECK(napi_create_buffer_copy(env, 24, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_bcrypt_hash256(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[32];
  uint32_t rounds;
  const uint8_t *pass, *salt;
  size_t pass_len, salt_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&pass,
                             &pass_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&salt,
                             &salt_len) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[2], &rounds) == napi_ok);

  JS_ASSERT(rounds >= 4 && rounds <= 31, JS_ERR_DERIVE);

  bcrypt_hash256(out, pass, pass_len, salt, salt_len, rounds);

  CHECK(napi_create_buffer_copy(env, 32, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_bcrypt_pbkdf(napi_env env, napi_callback_info info) {
  napi_value argv[4];
  size_t argc = 4;
  uint8_t *out;
  uint32_t rounds, out_len;
  const uint8_t *pass, *salt;
  size_t pass_len, salt_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 4);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&pass,
                             &pass_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&salt,
                             &salt_len) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[2], &rounds) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[3], &out_len) == napi_ok);

  JS_ASSERT(out_len <= MAX_BUFFER_LENGTH, JS_ERR_ALLOC);

  JS_CHECK_ALLOC(napi_create_buffer(env, out_len, (void **)&out, &result));

  JS_ASSERT(bcrypt_pbkdf(out, pass, pass_len, salt, salt_len, rounds, out_len),
            JS_ERR_DERIVE);

  return result;
}

typedef struct bcrypto_bcrypt_worker_s {
  uint8_t *pass;
  size_t pass_len;
  uint8_t *salt;
  size_t salt_len;
  uint32_t rounds;
  uint8_t *out;
  uint32_t out_len;
  const char *error;
  napi_async_work work;
  napi_deferred deferred;
} bcrypto_bcrypt_worker_t;

static void
bcrypto_bcrypt_execute_(napi_env env, void *data) {
  bcrypto_bcrypt_worker_t *w = (bcrypto_bcrypt_worker_t *)data;

  (void)env;

  if (!bcrypt_pbkdf(w->out, w->pass, w->pass_len,
                            w->salt, w->salt_len,
                            w->rounds, w->out_len)) {
    w->error = JS_ERR_DERIVE;
  }

  torsion_cleanse(w->pass, w->pass_len);
  torsion_cleanse(w->salt, w->salt_len);
}

static void
bcrypto_bcrypt_complete_(napi_env env, napi_status status, void *data) {
  bcrypto_bcrypt_worker_t *w = (bcrypto_bcrypt_worker_t *)data;
  napi_value result, strval, errval;

  if (w->error == NULL && status == napi_ok)
    status = napi_create_buffer_copy(env, w->out_len, w->out, NULL, &result);

  if (status != napi_ok)
    w->error = JS_ERR_DERIVE;

  if (w->error == NULL) {
    CHECK(napi_resolve_deferred(env, w->deferred, result) == napi_ok);
  } else {
    CHECK(napi_create_string_latin1(env, w->error, NAPI_AUTO_LENGTH,
                                    &strval) == napi_ok);
    CHECK(napi_create_error(env, NULL, strval, &errval) == napi_ok);
    CHECK(napi_reject_deferred(env, w->deferred, errval) == napi_ok);
  }

  CHECK(napi_delete_async_work(env, w->work) == napi_ok);

  bcrypto_free(w->pass);
  bcrypto_free(w->salt);
  bcrypto_free(w->out);
  bcrypto_free(w);
}

static napi_value
bcrypto_bcrypt_pbkdf_async(napi_env env, napi_callback_info info) {
  bcrypto_bcrypt_worker_t *worker;
  napi_value argv[4];
  size_t argc = 4;
  uint8_t *out;
  uint32_t rounds, out_len;
  const uint8_t *pass, *salt;
  size_t pass_len, salt_len;
  napi_value workname, result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 4);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&pass,
                             &pass_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&salt,
                             &salt_len) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[2], &rounds) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[3], &out_len) == napi_ok);

  JS_ASSERT(out_len <= MAX_BUFFER_LENGTH, JS_ERR_ALLOC);

  out = bcrypto_malloc(out_len);

  JS_ASSERT(out != NULL || out_len == 0, JS_ERR_ALLOC);

  worker = bcrypto_xmalloc(sizeof(bcrypto_bcrypt_worker_t));
  worker->pass = bcrypto_malloc(pass_len);
  worker->pass_len = pass_len;
  worker->salt = bcrypto_malloc(salt_len);
  worker->salt_len = salt_len;
  worker->rounds = rounds;
  worker->out = out;
  worker->out_len = out_len;
  worker->error = NULL;

  if ((worker->pass == NULL && pass_len != 0)
      || (worker->salt == NULL && salt_len != 0)) {
    bcrypto_free(worker->pass);
    bcrypto_free(worker->salt);
    bcrypto_free(worker->out);
    bcrypto_free(worker);
    JS_THROW(JS_ERR_DERIVE);
  }

  if (pass_len > 0)
    memcpy(worker->pass, pass, pass_len);

  if (salt_len > 0)
    memcpy(worker->salt, salt, salt_len);

  CHECK(napi_create_string_latin1(env, "bcrypto:bcrypt_pbkdf",
                                  NAPI_AUTO_LENGTH, &workname) == napi_ok);

  CHECK(napi_create_promise(env, &worker->deferred, &result) == napi_ok);

  CHECK(napi_create_async_work(env,
                               NULL,
                               workname,
                               bcrypto_bcrypt_execute_,
                               bcrypto_bcrypt_complete_,
                               worker,
                               &worker->work) == napi_ok);

  CHECK(napi_queue_async_work(env, worker->work) == napi_ok);

  return result;
}

static napi_value
bcrypto_bcrypt_derive(napi_env env, napi_callback_info info) {
  napi_value argv[4];
  size_t argc = 4;
  uint8_t out[31];
  uint32_t rounds, minor;
  const uint8_t *pass, *salt;
  size_t pass_len, salt_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 4);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&pass,
                             &pass_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&salt,
                             &salt_len) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[2], &rounds) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[3], &minor) == napi_ok);

  JS_ASSERT(bcrypt_derive(out, pass, pass_len, salt, salt_len, rounds, minor),
            JS_ERR_DERIVE);

  CHECK(napi_create_buffer_copy(env, 31, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_bcrypt_generate(napi_env env, napi_callback_info info) {
  napi_value argv[4];
  size_t argc = 4;
  char out[62];
  uint32_t rounds, minor;
  const uint8_t *pass, *salt;
  size_t pass_len, salt_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 4);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&pass,
                             &pass_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&salt,
                             &salt_len) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[2], &rounds) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[3], &minor) == napi_ok);

  JS_ASSERT(bcrypt_generate(out, pass, pass_len, salt, salt_len, rounds, minor),
            JS_ERR_DERIVE);

  CHECK(napi_create_string_latin1(env, out, NAPI_AUTO_LENGTH,
                                  &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_bcrypt_generate_with_salt64(napi_env env, napi_callback_info info) {
  napi_value argv[4];
  size_t argc = 4;
  char out[62];
  uint32_t rounds, minor;
  const uint8_t *pass;
  char salt[23 + 1];
  size_t pass_len, salt_len;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 4);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&pass,
                             &pass_len) == napi_ok);
  CHECK(napi_get_value_string_latin1(env, argv[1], salt, sizeof(salt),
                                     &salt_len) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[2], &rounds) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[3], &minor) == napi_ok);

  JS_ASSERT(salt_len != sizeof(salt) - 1, JS_ERR_DERIVE);

  ok = bcrypt_generate_with_salt64(out, pass, pass_len, salt, rounds, minor);

  JS_ASSERT(ok, JS_ERR_DERIVE);

  CHECK(napi_create_string_latin1(env, out, NAPI_AUTO_LENGTH,
                                  &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_bcrypt_verify(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  const uint8_t *pass;
  char record[62 + 1];
  size_t pass_len, record_len;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&pass,
                             &pass_len) == napi_ok);
  CHECK(napi_get_value_string_latin1(env, argv[1], record, sizeof(record),
                                     &record_len) == napi_ok);

  ok = record_len != sizeof(record) - 1
    && bcrypt_verify(pass, pass_len, record);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

/*
 * Bech32
 */

static napi_value
bcrypto_bech32_serialize(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  char str[BECH32_MAX_SERIALIZE_SIZE + 1];
  char hrp[BECH32_MAX_HRP_SIZE + 2];
  const uint8_t *data;
  size_t hrp_len, data_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_string_latin1(env, argv[0], hrp, sizeof(hrp),
                                     &hrp_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&data,
                             &data_len) == napi_ok);

  JS_ASSERT(hrp_len != sizeof(hrp) - 1, JS_ERR_ENCODE);
  JS_ASSERT(hrp_len == strlen(hrp), JS_ERR_ENCODE);
  JS_ASSERT(bech32_serialize(str, hrp, data, data_len), JS_ERR_ENCODE);

  CHECK(napi_create_string_latin1(env, str, NAPI_AUTO_LENGTH,
                                  &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_bech32_deserialize(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  char hrp[BECH32_MAX_HRP_SIZE + 1];
  uint8_t data[BECH32_MAX_DESERIALIZE_SIZE];
  char str[BECH32_MAX_SERIALIZE_SIZE + 2];
  size_t data_len, str_len;
  napi_value hrpval, dataval, result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_value_string_latin1(env, argv[0], str, sizeof(str),
                                     &str_len) == napi_ok);

  JS_ASSERT(str_len != sizeof(str) - 1, JS_ERR_ENCODE);
  JS_ASSERT(str_len == strlen(str), JS_ERR_ENCODE);
  JS_ASSERT(bech32_deserialize(hrp, data, &data_len, str), JS_ERR_ENCODE);

  CHECK(napi_create_string_latin1(env, hrp, NAPI_AUTO_LENGTH,
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
  char str[BECH32_MAX_SERIALIZE_SIZE + 2];
  size_t str_len;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_value_string_latin1(env, argv[0], str, sizeof(str),
                                     &str_len) == napi_ok);

  ok = str_len != sizeof(str) - 1
    && str_len == strlen(str)
    && bech32_is(str);

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
  uint32_t srcbits, dstbits;
  bool pad;
  napi_value result;
  size_t tmp_len = 0;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 4);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&data,
                             &data_len) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[1], &srcbits) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[2], &dstbits) == napi_ok);
  CHECK(napi_get_value_bool(env, argv[3], &pad) == napi_ok);

  JS_ASSERT(data_len < ((size_t)1 << 28), JS_ERR_ENCODE);
  JS_ASSERT(srcbits >= 1 && srcbits <= 8, JS_ERR_ENCODE);
  JS_ASSERT(dstbits >= 1 && dstbits <= 8, JS_ERR_ENCODE);

  out_len = BECH32_CONVERT_SIZE(data_len, srcbits, dstbits, (size_t)pad);

  JS_ASSERT(out_len <= MAX_BUFFER_LENGTH, JS_ERR_ALLOC);

  JS_CHECK_ALLOC(napi_create_buffer(env, out_len, (void **)&out, &result));

  ok = bech32_convert_bits(out, &tmp_len, dstbits,
                           data, data_len, srcbits, pad);

  JS_ASSERT(ok, JS_ERR_ENCODE);

  CHECK(tmp_len == out_len);

  return result;
}

static napi_value
bcrypto_bech32_encode(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  char addr[BECH32_MAX_ENCODE_SIZE + 1];
  char hrp[BECH32_MAX_HRP_SIZE + 2];
  size_t hrp_len;
  uint32_t version;
  const uint8_t *data;
  size_t data_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_string_latin1(env, argv[0], hrp, sizeof(hrp),
                                     &hrp_len) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[1], &version) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&data,
                             &data_len) == napi_ok);

  JS_ASSERT(hrp_len != sizeof(hrp) - 1, JS_ERR_ENCODE);
  JS_ASSERT(hrp_len == strlen(hrp), JS_ERR_ENCODE);
  JS_ASSERT(bech32_encode(addr, hrp, version, data, data_len), JS_ERR_ENCODE);

  CHECK(napi_create_string_latin1(env, addr, NAPI_AUTO_LENGTH,
                                  &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_bech32_decode(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  char hrp[BECH32_MAX_HRP_SIZE + 1];
  unsigned int version;
  uint8_t data[BECH32_MAX_DECODE_SIZE];
  char addr[BECH32_MAX_ENCODE_SIZE + 2];
  size_t data_len, addr_len;
  napi_value hrpval, versionval, dataval, result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_value_string_latin1(env, argv[0], addr, sizeof(addr),
                                     &addr_len) == napi_ok);

  JS_ASSERT(addr_len != sizeof(addr) - 1, JS_ERR_ENCODE);
  JS_ASSERT(addr_len == strlen(addr), JS_ERR_ENCODE);

  JS_ASSERT(bech32_decode(hrp, &version, data, &data_len, addr), JS_ERR_ENCODE);

  CHECK(napi_create_string_latin1(env, hrp, NAPI_AUTO_LENGTH,
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
  char addr[BECH32_MAX_ENCODE_SIZE + 2];
  size_t addr_len;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_value_string_latin1(env, argv[0], addr, sizeof(addr),
                                     &addr_len) == napi_ok);

  ok = addr_len != sizeof(addr) - 1
    && addr_len == strlen(addr)
    && bech32_test(addr);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

/*
 * BLAKE2b
 */

static void
bcrypto_blake2b_destroy(napi_env env, void *data, void *hint) {
  (void)env;
  (void)hint;
  torsion_cleanse(data, sizeof(bcrypto_blake2b_t));
  bcrypto_free(data);
}

static napi_value
bcrypto_blake2b_create(napi_env env, napi_callback_info info) {
  bcrypto_blake2b_t *blake = bcrypto_xmalloc(sizeof(bcrypto_blake2b_t));
  napi_value handle;

  (void)info;

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

  out_len = blake->ctx.len;

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
  (void)env;
  (void)hint;
  torsion_cleanse(data, sizeof(bcrypto_blake2s_t));
  bcrypto_free(data);
}

static napi_value
bcrypto_blake2s_create(napi_env env, napi_callback_info info) {
  bcrypto_blake2s_t *blake = bcrypto_xmalloc(sizeof(bcrypto_blake2s_t));
  napi_value handle;

  (void)info;

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

  out_len = blake->ctx.len;

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
  char str[CASH32_MAX_SERIALIZE_SIZE + 1];
  char prefix[CASH32_MAX_PREFIX_SIZE + 2];
  size_t prefix_len;
  const uint8_t *data;
  size_t data_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_string_latin1(env, argv[0], prefix, sizeof(prefix),
                                     &prefix_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&data,
                             &data_len) == napi_ok);

  JS_ASSERT(prefix_len != sizeof(prefix) - 1, JS_ERR_ENCODE);
  JS_ASSERT(prefix_len == strlen(prefix), JS_ERR_ENCODE);

  JS_ASSERT(cash32_serialize(str, prefix, data, data_len), JS_ERR_ENCODE);

  CHECK(napi_create_string_latin1(env, str, NAPI_AUTO_LENGTH,
                                  &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_cash32_deserialize(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  char prefix[CASH32_MAX_PREFIX_SIZE + 1];
  uint8_t data[CASH32_MAX_DESERIALIZE_SIZE];
  char str[CASH32_MAX_SERIALIZE_SIZE + 2];
  char fallback[CASH32_MAX_PREFIX_SIZE + 2];
  size_t data_len, str_len, fallback_len;
  napi_value preval, dataval, result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_string_latin1(env, argv[0], str, sizeof(str),
                                     &str_len) == napi_ok);
  CHECK(napi_get_value_string_latin1(env, argv[1], fallback, sizeof(fallback),
                                     &fallback_len) == napi_ok);

  JS_ASSERT(str_len != sizeof(str) - 1, JS_ERR_ENCODE);
  JS_ASSERT(str_len == strlen(str), JS_ERR_ENCODE);
  JS_ASSERT(fallback_len != sizeof(fallback) - 1, JS_ERR_ENCODE);
  JS_ASSERT(fallback_len == strlen(fallback), JS_ERR_ENCODE);

  JS_ASSERT(cash32_deserialize(prefix, data, &data_len, str, fallback),
            JS_ERR_ENCODE);

  CHECK(napi_create_string_latin1(env, prefix, NAPI_AUTO_LENGTH,
                                  &preval) == napi_ok);

  CHECK(napi_create_buffer_copy(env, data_len, data, NULL,
                                &dataval) == napi_ok);

  CHECK(napi_create_array_with_length(env, 2, &result) == napi_ok);
  CHECK(napi_set_element(env, result, 0, preval) == napi_ok);
  CHECK(napi_set_element(env, result, 1, dataval) == napi_ok);

  return result;
}

static napi_value
bcrypto_cash32_is(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  char str[CASH32_MAX_SERIALIZE_SIZE + 2];
  char fallback[CASH32_MAX_PREFIX_SIZE + 2];
  size_t str_len, fallback_len;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_string_latin1(env, argv[0], str, sizeof(str),
                                     &str_len) == napi_ok);
  CHECK(napi_get_value_string_latin1(env, argv[1], fallback, sizeof(fallback),
                                     &fallback_len) == napi_ok);

  ok = str_len != sizeof(str) - 1
    && str_len == strlen(str)
    && fallback_len != sizeof(fallback) - 1
    && fallback_len == strlen(fallback)
    && cash32_is(str, fallback);

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
  uint32_t srcbits, dstbits;
  bool pad;
  napi_value result;
  size_t tmp_len = 0;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 4);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&data,
                             &data_len) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[1], &srcbits) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[2], &dstbits) == napi_ok);
  CHECK(napi_get_value_bool(env, argv[3], &pad) == napi_ok);

  JS_ASSERT(data_len < ((size_t)1 << 28), JS_ERR_ENCODE);
  JS_ASSERT(srcbits >= 1 && srcbits <= 8, JS_ERR_ENCODE);
  JS_ASSERT(dstbits >= 1 && dstbits <= 8, JS_ERR_ENCODE);

  out_len = CASH32_CONVERT_SIZE(data_len, srcbits, dstbits, (size_t)pad);

  JS_ASSERT(out_len <= MAX_BUFFER_LENGTH, JS_ERR_ALLOC);

  JS_CHECK_ALLOC(napi_create_buffer(env, out_len, (void **)&out, &result));

  ok = cash32_convert_bits(out, &tmp_len, dstbits,
                           data, data_len, srcbits, pad);

  JS_ASSERT(ok, JS_ERR_ENCODE);

  CHECK(tmp_len == out_len);

  return result;
}

static napi_value
bcrypto_cash32_encode(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  char addr[CASH32_MAX_ENCODE_SIZE + 1];
  char prefix[CASH32_MAX_PREFIX_SIZE + 2];
  size_t prefix_len;
  uint32_t type;
  const uint8_t *data;
  size_t data_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_string_latin1(env, argv[0], prefix, sizeof(prefix),
                                     &prefix_len) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[1], &type) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&data,
                             &data_len) == napi_ok);

  JS_ASSERT(prefix_len != sizeof(prefix) - 1, JS_ERR_ENCODE);
  JS_ASSERT(prefix_len == strlen(prefix), JS_ERR_ENCODE);

  JS_ASSERT(cash32_encode(addr, prefix, type, data, data_len), JS_ERR_ENCODE);

  CHECK(napi_create_string_latin1(env, addr, NAPI_AUTO_LENGTH,
                                  &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_cash32_decode(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  unsigned int type;
  uint8_t data[CASH32_MAX_DECODE_SIZE];
  char addr[CASH32_MAX_ENCODE_SIZE + 2];
  char expect[CASH32_MAX_PREFIX_SIZE + 2];
  size_t data_len, addr_len, expect_len;
  napi_value typeval, dataval, result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_string_latin1(env, argv[0], addr, sizeof(addr),
                                     &addr_len) == napi_ok);
  CHECK(napi_get_value_string_latin1(env, argv[1], expect, sizeof(expect),
                                     &expect_len) == napi_ok);

  JS_ASSERT(addr_len != sizeof(addr) - 1, JS_ERR_ENCODE);
  JS_ASSERT(addr_len == strlen(addr), JS_ERR_ENCODE);
  JS_ASSERT(expect_len != sizeof(expect) - 1, JS_ERR_ENCODE);
  JS_ASSERT(expect_len == strlen(expect), JS_ERR_ENCODE);

  JS_ASSERT(cash32_decode(&type, data, &data_len, addr, expect), JS_ERR_ENCODE);

  CHECK(napi_create_uint32(env, type, &typeval) == napi_ok);

  CHECK(napi_create_buffer_copy(env, data_len, data, NULL,
                                &dataval) == napi_ok);

  CHECK(napi_create_array_with_length(env, 2, &result) == napi_ok);
  CHECK(napi_set_element(env, result, 0, typeval) == napi_ok);
  CHECK(napi_set_element(env, result, 1, dataval) == napi_ok);

  return result;
}

static napi_value
bcrypto_cash32_test(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  char addr[CASH32_MAX_ENCODE_SIZE + 2];
  char expect[CASH32_MAX_PREFIX_SIZE + 2];
  size_t addr_len, expect_len;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_string_latin1(env, argv[0], addr, sizeof(addr),
                                     &addr_len) == napi_ok);
  CHECK(napi_get_value_string_latin1(env, argv[1], expect, sizeof(expect),
                                     &expect_len) == napi_ok);

  ok = addr_len != sizeof(addr) - 1
    && addr_len == strlen(addr)
    && expect_len != sizeof(expect) - 1
    && expect_len == strlen(expect)
    && cash32_test(addr, expect);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

/*
 * ChaCha20
 */

static void
bcrypto_chacha20_destroy_(napi_env env, void *data, void *hint) {
  (void)env;
  (void)hint;
  torsion_cleanse(data, sizeof(bcrypto_chacha20_t));
  bcrypto_free(data);
}

static napi_value
bcrypto_chacha20_create(napi_env env, napi_callback_info info) {
  bcrypto_chacha20_t *chacha = bcrypto_xmalloc(sizeof(bcrypto_chacha20_t));
  napi_value handle;

  (void)info;

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
bcrypto_chacha20_crypt(napi_env env, napi_callback_info info) {
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

  chacha20_crypt(&chacha->ctx, msg, msg, msg_len);

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
 * Cipher
 */

static void
bcrypto_cipher_destroy_(napi_env env, void *data, void *hint) {
  (void)env;
  (void)hint;
  torsion_cleanse(data, sizeof(bcrypto_cipher_t));
  bcrypto_free(data);
}

static napi_value
bcrypto_cipher_create(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint32_t type, mode;
  bool encrypt;
  bcrypto_cipher_t *cipher;
  napi_value handle;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_uint32(env, argv[0], &type) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[1], &mode) == napi_ok);
  CHECK(napi_get_value_bool(env, argv[2], &encrypt) == napi_ok);

  JS_ASSERT(type <= CIPHER_MAX, JS_ERR_CONTEXT);
  JS_ASSERT(mode <= CIPHER_MODE_MAX, JS_ERR_CONTEXT);

  cipher = bcrypto_xmalloc(sizeof(bcrypto_cipher_t));
  cipher->type = type;
  cipher->mode = mode;
  cipher->encrypt = encrypt;
  cipher->started = 0;
  cipher->has_tag = 0;

  CHECK(napi_create_external(env,
                             cipher,
                             bcrypto_cipher_destroy_,
                             NULL,
                             &handle) == napi_ok);

  return handle;
}

static napi_value
bcrypto_cipher_init(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  const uint8_t *key, *iv;
  size_t key_len, iv_len;
  bcrypto_cipher_t *cipher;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&cipher) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&key, &key_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&iv, &iv_len) == napi_ok);

  ok = cipher_stream_init(&cipher->ctx,
                          cipher->type,
                          cipher->mode,
                          cipher->encrypt,
                          key, key_len,
                          iv, iv_len);

  JS_ASSERT(ok, JS_ERR_CONTEXT);

  cipher->started = 1;
  cipher->has_tag = 0;

  return argv[0];
}

static napi_value
bcrypto_cipher_set_padding(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  bool padding;
  bcrypto_cipher_t *cipher;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&cipher) == napi_ok);
  CHECK(napi_get_value_bool(env, argv[1], &padding) == napi_ok);

  JS_ASSERT(cipher->started, JS_ERR_INIT);
  JS_ASSERT(cipher_stream_set_padding(&cipher->ctx, padding), JS_ERR_OPT);

  return argv[0];
}

static napi_value
bcrypto_cipher_set_aad(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  const uint8_t *aad;
  size_t aad_len;
  bcrypto_cipher_t *cipher;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&cipher) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&aad, &aad_len) == napi_ok);

  JS_ASSERT(cipher->started, JS_ERR_INIT);
  JS_ASSERT(cipher_stream_set_aad(&cipher->ctx, aad, aad_len), JS_ERR_OPT);

  return argv[0];
}

static napi_value
bcrypto_cipher_set_ccm(napi_env env, napi_callback_info info) {
  napi_value argv[4];
  size_t argc = 4;
  const uint8_t *aad;
  size_t aad_len;
  uint32_t msg_len, tag_len;
  bcrypto_cipher_t *cipher;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 4);
  CHECK(napi_get_value_external(env, argv[0], (void **)&cipher) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[1], &msg_len) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[2], &tag_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[3], (void **)&aad, &aad_len) == napi_ok);

  JS_ASSERT(cipher->started, JS_ERR_INIT);

  ok = cipher_stream_set_ccm(&cipher->ctx, msg_len, tag_len, aad, aad_len);

  JS_ASSERT(ok, JS_ERR_OPT);

  cipher->started = 1;

  return argv[0];
}


static napi_value
bcrypto_cipher_set_tag(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  const uint8_t *tag;
  size_t tag_len;
  bcrypto_cipher_t *cipher;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&cipher) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&tag, &tag_len) == napi_ok);

  JS_ASSERT(cipher->started, JS_ERR_INIT);
  JS_ASSERT(cipher_stream_set_tag(&cipher->ctx, tag, tag_len), JS_ERR_OPT);

  return argv[0];
}

static napi_value
bcrypto_cipher_get_tag(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  uint8_t out[16];
  size_t out_len;
  bcrypto_cipher_t *cipher;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_value_external(env, argv[0], (void **)&cipher) == napi_ok);

  JS_ASSERT(cipher->has_tag, JS_ERR_INIT);
  JS_ASSERT(cipher_stream_get_tag(&cipher->ctx, out, &out_len), JS_ERR_GET);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_cipher_update(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t *out;
  size_t out_len;
  const uint8_t *in;
  size_t in_len;
  bcrypto_cipher_t *cipher;
  napi_value ab, result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&cipher) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&in, &in_len) == napi_ok);

  JS_ASSERT(cipher->started, JS_ERR_INIT);

  out_len = cipher_stream_update_size(&cipher->ctx, in_len);

  JS_ASSERT(out_len <= MAX_BUFFER_LENGTH, JS_ERR_ALLOC);

  JS_CHECK_ALLOC(napi_create_arraybuffer(env, out_len, (void **)&out, &ab));

  cipher_stream_update(&cipher->ctx, out, &out_len, in, in_len);

  CHECK(napi_create_typedarray(env, napi_uint8_array, out_len,
                               ab, 0, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_cipher_crypt(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t *out;
  const uint8_t *in;
  size_t out_len, in_len;
  bcrypto_cipher_t *cipher;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&cipher) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&out, &out_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&in, &in_len) == napi_ok);

  JS_ASSERT(cipher->started, JS_ERR_INIT);
  JS_ASSERT(out_len == in_len, JS_ERR_CRYPT);

  ok = cipher_stream_crypt(&cipher->ctx, out, in, in_len);

  JS_ASSERT(ok, JS_ERR_CRYPT);

  return argv[1];
}

static napi_value
bcrypto_cipher_final(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  uint8_t out[CIPHER_MAX_FINAL_SIZE];
  size_t out_len;
  bcrypto_cipher_t *cipher;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_value_external(env, argv[0], (void **)&cipher) == napi_ok);

  JS_ASSERT(cipher->started, JS_ERR_INIT);
  JS_ASSERT(cipher_stream_final(&cipher->ctx, out, &out_len), JS_ERR_FINAL);

  cipher->started = 0;
  cipher->has_tag = 1;

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_cipher_destroy(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  bcrypto_cipher_t *cipher;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_value_external(env, argv[0], (void **)&cipher) == napi_ok);

  cipher->started = 0;

  return argv[0];
}

static napi_value
bcrypto_cipher_encrypt(napi_env env, napi_callback_info info) {
  napi_value argv[5];
  size_t argc = 5;
  uint8_t *out;
  size_t out_len;
  uint32_t type, mode;
  const uint8_t *key, *iv, *in;
  size_t key_len, iv_len, in_len;
  napi_value ab, result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 5);
  CHECK(napi_get_value_uint32(env, argv[0], &type) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[1], &mode) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&key, &key_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[3], (void **)&iv, &iv_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[4], (void **)&in, &in_len) == napi_ok);

  JS_ASSERT(type <= CIPHER_MAX, JS_ERR_CONTEXT);
  JS_ASSERT(mode <= CIPHER_MODE_MAX, JS_ERR_CONTEXT);

  out_len = CIPHER_MAX_ENCRYPT_SIZE(in_len);

  JS_ASSERT(out_len <= MAX_BUFFER_LENGTH, JS_ERR_ALLOC);

  JS_CHECK_ALLOC(napi_create_arraybuffer(env, out_len, (void **)&out, &ab));

  ok = cipher_static_encrypt(out, &out_len,
                             type, mode,
                             key, key_len,
                             iv, iv_len,
                             in, in_len);

  JS_ASSERT(ok, JS_ERR_ENCRYPT);

  CHECK(napi_create_typedarray(env, napi_uint8_array, out_len,
                               ab, 0, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_cipher_decrypt(napi_env env, napi_callback_info info) {
  napi_value argv[5];
  size_t argc = 5;
  uint8_t *out;
  size_t out_len;
  uint32_t type, mode;
  const uint8_t *key, *iv, *in;
  size_t key_len, iv_len, in_len;
  napi_value ab, result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 5);
  CHECK(napi_get_value_uint32(env, argv[0], &type) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[1], &mode) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&key, &key_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[3], (void **)&iv, &iv_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[4], (void **)&in, &in_len) == napi_ok);

  JS_ASSERT(type <= CIPHER_MAX, JS_ERR_CONTEXT);
  JS_ASSERT(mode <= CIPHER_MODE_MAX, JS_ERR_CONTEXT);

  out_len = CIPHER_MAX_DECRYPT_SIZE(in_len);

  JS_ASSERT(out_len <= MAX_BUFFER_LENGTH, JS_ERR_ALLOC);

  JS_CHECK_ALLOC(napi_create_arraybuffer(env, out_len, (void **)&out, &ab));

  ok = cipher_static_decrypt(out, &out_len,
                             type, mode,
                             key, key_len,
                             iv, iv_len,
                             in, in_len);

  JS_ASSERT(ok, JS_ERR_DECRYPT);

  CHECK(napi_create_typedarray(env, napi_uint8_array, out_len,
                               ab, 0, &result) == napi_ok);

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

  torsion_cleanse(buf, buf_len);

  return argv[0];
}

/*
 * CTR-DRBG
 */

static void
bcrypto_ctr_drbg_destroy(napi_env env, void *data, void *hint) {
  (void)env;
  (void)hint;
  torsion_cleanse(data, sizeof(bcrypto_ctr_drbg_t));
  bcrypto_free(data);
}

static napi_value
bcrypto_ctr_drbg_create(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint32_t bits;
  bool derivation;
  bcrypto_ctr_drbg_t *drbg;
  napi_value handle;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_uint32(env, argv[0], &bits) == napi_ok);
  CHECK(napi_get_value_bool(env, argv[1], &derivation) == napi_ok);

  JS_ASSERT(bits == 128 || bits == 192 || bits == 256, JS_ERR_ARG);

  drbg = bcrypto_xmalloc(sizeof(bcrypto_ctr_drbg_t));
  drbg->bits = bits;
  drbg->derivation = derivation;
  drbg->started = 0;

  CHECK(napi_create_external(env,
                             drbg,
                             bcrypto_ctr_drbg_destroy,
                             NULL,
                             &handle) == napi_ok);

  return handle;
}

static napi_value
bcrypto_ctr_drbg_init(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t *nonce, *pers;
  size_t nonce_len, pers_len;
  bcrypto_ctr_drbg_t *drbg;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&drbg) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&nonce,
                             &nonce_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&pers,
                             &pers_len) == napi_ok);

  ctr_drbg_init(&drbg->ctx, drbg->bits, drbg->derivation,
                nonce, nonce_len, pers, pers_len);

  drbg->started = 1;

  return argv[0];
}

static napi_value
bcrypto_ctr_drbg_reseed(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t *nonce, *add;
  size_t nonce_len, add_len;
  bcrypto_ctr_drbg_t *drbg;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&drbg) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&nonce,
                             &nonce_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&add, &add_len) == napi_ok);

  JS_ASSERT(drbg->started, JS_ERR_INIT);

  ctr_drbg_reseed(&drbg->ctx, nonce, nonce_len, add, add_len);

  return argv[0];
}

static napi_value
bcrypto_ctr_drbg_generate(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t *out;
  uint32_t out_len;
  const uint8_t *add;
  size_t add_len;
  bcrypto_ctr_drbg_t *drbg;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&drbg) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[1], &out_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&add, &add_len) == napi_ok);

  JS_ASSERT(drbg->started, JS_ERR_INIT);
  JS_ASSERT(out_len <= MAX_BUFFER_LENGTH, JS_ERR_ALLOC);

  JS_CHECK_ALLOC(napi_create_buffer(env, out_len, (void **)&out, &result));

  ctr_drbg_generate(&drbg->ctx, out, out_len, add, add_len);

  return result;
}

/*
 * DSA
 */

static napi_value
bcrypto_dsa_params_create(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  uint8_t out[DSA_MAX_PARAMS_SIZE];
  size_t out_len = DSA_MAX_PARAMS_SIZE;
  const uint8_t *key;
  size_t key_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&key, &key_len) == napi_ok);

  JS_ASSERT(dsa_params_create(out, &out_len, key, key_len), JS_ERR_KEY);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_dsa_params_generate(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t out[DSA_MAX_PARAMS_SIZE];
  size_t out_len = DSA_MAX_PARAMS_SIZE;
  uint32_t bits;
  const uint8_t *entropy;
  size_t entropy_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_uint32(env, argv[0], &bits) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&entropy,
                             &entropy_len) == napi_ok);

  JS_ASSERT(entropy_len == ENTROPY_SIZE, JS_ERR_ENTROPY_SIZE);
  JS_ASSERT(dsa_params_generate(out, &out_len, bits, entropy), JS_ERR_GENERATE);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  torsion_cleanse((void *)entropy, entropy_len);

  return result;
}

typedef struct bcrypto_dsa_worker_s {
  uint32_t bits;
  uint8_t entropy[ENTROPY_SIZE];
  uint8_t out[DSA_MAX_PARAMS_SIZE];
  size_t out_len;
  const char *error;
  napi_async_work work;
  napi_deferred deferred;
} bcrypto_dsa_worker_t;

static void
bcrypto_dsa_execute_(napi_env env, void *data) {
  bcrypto_dsa_worker_t *w = (bcrypto_dsa_worker_t *)data;

  (void)env;

  if (!dsa_params_generate(w->out, &w->out_len, w->bits, w->entropy))
    w->error = JS_ERR_GENERATE;

  torsion_cleanse(w->entropy, ENTROPY_SIZE);
}

static void
bcrypto_dsa_complete_(napi_env env, napi_status status, void *data) {
  bcrypto_dsa_worker_t *w = (bcrypto_dsa_worker_t *)data;
  napi_value result, strval, errval;

  if (w->error == NULL && status == napi_ok)
    status = napi_create_buffer_copy(env, w->out_len, w->out, NULL, &result);

  if (status != napi_ok)
    w->error = JS_ERR_GENERATE;

  if (w->error == NULL) {
    CHECK(napi_resolve_deferred(env, w->deferred, result) == napi_ok);
  } else {
    CHECK(napi_create_string_latin1(env, w->error, NAPI_AUTO_LENGTH,
                                    &strval) == napi_ok);
    CHECK(napi_create_error(env, NULL, strval, &errval) == napi_ok);
    CHECK(napi_reject_deferred(env, w->deferred, errval) == napi_ok);
  }

  CHECK(napi_delete_async_work(env, w->work) == napi_ok);

  bcrypto_free(w);
}

static napi_value
bcrypto_dsa_params_generate_async(napi_env env, napi_callback_info info) {
  bcrypto_dsa_worker_t *worker;
  napi_value argv[2];
  size_t argc = 2;
  uint32_t bits;
  const uint8_t *entropy;
  size_t entropy_len;
  napi_value workname, result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_uint32(env, argv[0], &bits) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&entropy,
                             &entropy_len) == napi_ok);

  JS_ASSERT(entropy_len == ENTROPY_SIZE, JS_ERR_ENTROPY_SIZE);

  worker = bcrypto_xmalloc(sizeof(bcrypto_dsa_worker_t));
  worker->bits = bits;
  worker->out_len = DSA_MAX_PARAMS_SIZE;
  worker->error = NULL;

  memcpy(worker->entropy, entropy, ENTROPY_SIZE);

  CHECK(napi_create_string_latin1(env, "bcrypto:dsa_params_generate",
                                  NAPI_AUTO_LENGTH, &workname) == napi_ok);

  CHECK(napi_create_promise(env, &worker->deferred, &result) == napi_ok);

  CHECK(napi_create_async_work(env,
                               NULL,
                               workname,
                               bcrypto_dsa_execute_,
                               bcrypto_dsa_complete_,
                               worker,
                               &worker->work) == napi_ok);

  CHECK(napi_queue_async_work(env, worker->work) == napi_ok);

  torsion_cleanse((void *)entropy, entropy_len);

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
bcrypto_dsa_params_qbits(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  size_t bits;
  const uint8_t *key;
  size_t key_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&key, &key_len) == napi_ok);

  bits = dsa_params_qbits(key, key_len);

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
  uint8_t out[DSA_MAX_PARAMS_SIZE];
  size_t out_len = DSA_MAX_PARAMS_SIZE;
  const uint8_t *key;
  size_t key_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&key, &key_len) == napi_ok);

  JS_ASSERT(dsa_params_import(out, &out_len, key, key_len), JS_ERR_PARAMS);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  torsion_cleanse((void *)key, key_len);

  return result;
}

static napi_value
bcrypto_dsa_params_export(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  uint8_t out[DSA_MAX_PARAMS_SIZE];
  size_t out_len = DSA_MAX_PARAMS_SIZE;
  const uint8_t *key;
  size_t key_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&key, &key_len) == napi_ok);

  JS_ASSERT(dsa_params_export(out, &out_len, key, key_len), JS_ERR_PARAMS);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_dsa_privkey_create(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t out[DSA_MAX_PRIV_SIZE];
  size_t out_len = DSA_MAX_PRIV_SIZE;
  const uint8_t *key, *entropy;
  size_t key_len, entropy_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&key, &key_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&entropy,
                             &entropy_len) == napi_ok);

  JS_ASSERT(entropy_len == ENTROPY_SIZE, JS_ERR_ENTROPY_SIZE);
  JS_ASSERT(dsa_privkey_create(out, &out_len, key, key_len, entropy),
            JS_ERR_PARAMS);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  torsion_cleanse((void *)entropy, entropy_len);
  torsion_cleanse(out, out_len);

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
bcrypto_dsa_privkey_qbits(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  size_t bits;
  const uint8_t *key;
  size_t key_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&key, &key_len) == napi_ok);

  bits = dsa_privkey_qbits(key, key_len);

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
  uint8_t out[DSA_MAX_PRIV_SIZE];
  size_t out_len = DSA_MAX_PRIV_SIZE;
  const uint8_t *key;
  size_t key_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&key, &key_len) == napi_ok);

  JS_ASSERT(dsa_privkey_import(out, &out_len, key, key_len), JS_ERR_PRIVKEY);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  torsion_cleanse((void *)key, key_len);
  torsion_cleanse(out, out_len);

  return result;
}

static napi_value
bcrypto_dsa_privkey_export(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  uint8_t out[DSA_MAX_PRIV_SIZE];
  size_t out_len = DSA_MAX_PRIV_SIZE;
  const uint8_t *key;
  size_t key_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&key, &key_len) == napi_ok);

  JS_ASSERT(dsa_privkey_export(out, &out_len, key, key_len), JS_ERR_PRIVKEY);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  torsion_cleanse(out, out_len);

  return result;
}

static napi_value
bcrypto_dsa_pubkey_create(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  uint8_t out[DSA_MAX_PUB_SIZE];
  size_t out_len = DSA_MAX_PUB_SIZE;
  const uint8_t *key;
  size_t key_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&key, &key_len) == napi_ok);

  JS_ASSERT(dsa_pubkey_create(out, &out_len, key, key_len), JS_ERR_PRIVKEY);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

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
bcrypto_dsa_pubkey_qbits(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  size_t bits;
  const uint8_t *key;
  size_t key_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&key, &key_len) == napi_ok);

  bits = dsa_pubkey_qbits(key, key_len);

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
  uint8_t out[DSA_MAX_PUB_SIZE];
  size_t out_len = DSA_MAX_PUB_SIZE;
  const uint8_t *key;
  size_t key_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&key, &key_len) == napi_ok);

  JS_ASSERT(dsa_pubkey_import(out, &out_len, key, key_len), JS_ERR_PUBKEY);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  torsion_cleanse((void *)key, key_len);

  return result;
}

static napi_value
bcrypto_dsa_pubkey_export(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  uint8_t out[DSA_MAX_PUB_SIZE];
  size_t out_len = DSA_MAX_PUB_SIZE;
  const uint8_t *key;
  size_t key_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&key, &key_len) == napi_ok);

  JS_ASSERT(dsa_pubkey_export(out, &out_len, key, key_len), JS_ERR_PUBKEY);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

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
  const uint8_t *msg, *key, *entropy;
  size_t msg_len, key_len, entropy_len;
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

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  torsion_cleanse((void *)entropy, entropy_len);

  return result;
}

static napi_value
bcrypto_dsa_sign_der(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[DSA_MAX_DER_SIZE];
  size_t out_len = DSA_MAX_DER_SIZE;
  const uint8_t *msg, *key, *entropy;
  size_t msg_len, key_len, entropy_len;
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

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  torsion_cleanse((void *)entropy, entropy_len);

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
  uint8_t out[DSA_MAX_SIZE];
  size_t out_len = DSA_MAX_SIZE;
  const uint8_t *pub, *priv;
  size_t pub_len, priv_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&pub, &pub_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&priv,
                             &priv_len) == napi_ok);

  JS_ASSERT(dsa_derive(out, &out_len, pub, pub_len, priv, priv_len),
            JS_ERR_PUBKEY);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  torsion_cleanse(out, out_len);

  return result;
}

/*
 * EB2K
 */

static napi_value
bcrypto_eb2k_derive(napi_env env, napi_callback_info info) {
  napi_value argv[5];
  size_t argc = 5;
  uint8_t *key, *iv;
  uint32_t type, key_len, iv_len;
  const uint8_t *pass, *salt;
  size_t pass_len, salt_len;
  napi_value keyval, ivval, result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 5);
  CHECK(napi_get_value_uint32(env, argv[0], &type) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pass,
                             &pass_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&salt,
                             &salt_len) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[3], &key_len) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[4], &iv_len) == napi_ok);

  JS_ASSERT(key_len <= MAX_BUFFER_LENGTH, JS_ERR_ALLOC);
  JS_ASSERT(iv_len <= MAX_BUFFER_LENGTH, JS_ERR_ALLOC);

  JS_CHECK_ALLOC(napi_create_buffer(env, key_len, (void **)&key, &keyval));
  JS_CHECK_ALLOC(napi_create_buffer(env, iv_len, (void **)&iv, &ivval));

  if (!eb2k_derive(key, iv, type, pass, pass_len,
                   salt, salt_len, key_len, iv_len)) {
    goto fail;
  }

  CHECK(napi_create_array_with_length(env, 2, &result) == napi_ok);
  CHECK(napi_set_element(env, result, 0, keyval) == napi_ok);
  CHECK(napi_set_element(env, result, 1, ivval) == napi_ok);

  return result;
fail:
  bcrypto_free(key);
  bcrypto_free(iv);
  JS_THROW(JS_ERR_DERIVE);
}

/*
 * ECDH
 */

static napi_value
bcrypto_ecdh_privkey_generate(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  const uint8_t *entropy;
  size_t entropy_len;
  uint8_t out[ECDH_MAX_PRIV_SIZE];
  bcrypto_mont_curve_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&entropy,
                             &entropy_len) == napi_ok);

  JS_ASSERT(entropy_len == ENTROPY_SIZE, JS_ERR_ENTROPY_SIZE);

  ecdh_privkey_generate(ec->ctx, out, entropy);

  CHECK(napi_create_buffer_copy(env,
                                ec->scalar_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  torsion_cleanse((void *)entropy, entropy_len);

  return result;
}

static napi_value
bcrypto_ecdh_privkey_verify(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  const uint8_t *priv;
  size_t priv_len;
  bcrypto_mont_curve_t *ec;
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
  bcrypto_mont_curve_t *ec;
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
  bcrypto_mont_curve_t *ec;
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
  bcrypto_mont_curve_t *ec;
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
  bcrypto_mont_curve_t *ec;
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
  bcrypto_mont_curve_t *ec;
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
  uint8_t out[MONT_MAX_FIELD_SIZE];
  const uint8_t *pub;
  size_t pub_len;
  uint32_t hint;
  bcrypto_mont_curve_t *ec;
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
  bcrypto_mont_curve_t *ec;
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
  uint8_t out[MONT_MAX_FIELD_SIZE * 2];
  const uint8_t *pub, *entropy;
  size_t pub_len, entropy_len;
  uint32_t subgroup;
  bcrypto_mont_curve_t *ec;
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

  CHECK(napi_create_buffer_copy(env, ec->field_size * 2,
                                out, NULL, &result) == napi_ok);

  torsion_cleanse((void *)entropy, entropy_len);

  return result;
}

static napi_value
bcrypto_ecdh_pubkey_verify(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  const uint8_t *pub;
  size_t pub_len;
  bcrypto_mont_curve_t *ec;
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
  uint8_t x[MONT_MAX_FIELD_SIZE];
  uint8_t y[MONT_MAX_FIELD_SIZE];
  const uint8_t *pub;
  size_t pub_len;
  int32_t sign;
  bcrypto_mont_curve_t *ec;
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
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[ECDH_MAX_PUB_SIZE];
  const uint8_t *x, *y;
  size_t x_len, y_len;
  bcrypto_mont_curve_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&x, &x_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&y, &y_len) == napi_ok);

  JS_ASSERT(ecdh_pubkey_import(ec->ctx, out, x, x_len, y, y_len),
            JS_ERR_PUBKEY);

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
  bcrypto_mont_curve_t *ec;
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
  bcrypto_mont_curve_t *ec;
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
  bcrypto_mont_curve_t *ec;
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

static napi_value
bcrypto_ecdsa_privkey_generate(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  const uint8_t *entropy;
  size_t entropy_len;
  uint8_t out[ECDSA_MAX_PRIV_SIZE];
  bcrypto_wei_curve_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&entropy,
                             &entropy_len) == napi_ok);

  JS_ASSERT(entropy_len == ENTROPY_SIZE, JS_ERR_ENTROPY_SIZE);

  ecdsa_privkey_generate(ec->ctx, out, entropy);

  CHECK(napi_create_buffer_copy(env,
                                ec->scalar_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  torsion_cleanse((void *)entropy, entropy_len);

  return result;
}

static napi_value
bcrypto_ecdsa_privkey_verify(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  const uint8_t *priv;
  size_t priv_len;
  bcrypto_wei_curve_t *ec;
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
  bcrypto_wei_curve_t *ec;
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
  bcrypto_wei_curve_t *ec;
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
  bcrypto_wei_curve_t *ec;
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
  bcrypto_wei_curve_t *ec;
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
bcrypto_ecdsa_privkey_negate(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t out[ECDSA_MAX_PRIV_SIZE];
  const uint8_t *priv;
  size_t priv_len;
  bcrypto_wei_curve_t *ec;
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
  bcrypto_wei_curve_t *ec;
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
  bcrypto_wei_curve_t *ec;
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
  bcrypto_wei_curve_t *ec;
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
  bcrypto_wei_curve_t *ec;
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
  uint8_t out[WEI_MAX_FIELD_SIZE];
  const uint8_t *pub;
  size_t pub_len;
  uint32_t hint;
  bcrypto_wei_curve_t *ec;
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
  bcrypto_wei_curve_t *ec;
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
  uint8_t out[WEI_MAX_FIELD_SIZE * 2];
  const uint8_t *pub, *entropy;
  size_t pub_len, entropy_len;
  bcrypto_wei_curve_t *ec;
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

  CHECK(napi_create_buffer_copy(env, ec->field_size * 2,
                                out, NULL, &result) == napi_ok);

  torsion_cleanse((void *)entropy, entropy_len);

  return result;
}

static napi_value
bcrypto_ecdsa_pubkey_verify(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  const uint8_t *pub;
  size_t pub_len;
  bcrypto_wei_curve_t *ec;
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
  uint8_t x[WEI_MAX_FIELD_SIZE];
  uint8_t y[WEI_MAX_FIELD_SIZE];
  const uint8_t *pub;
  size_t pub_len;
  bcrypto_wei_curve_t *ec;
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
  bcrypto_wei_curve_t *ec;
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
  bcrypto_wei_curve_t *ec;
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
  bcrypto_wei_curve_t *ec;
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
  bcrypto_wei_curve_t *ec;
  napi_value item, result;
  int ok = 0;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_array_length(env, argv[1], &length) == napi_ok);
  CHECK(napi_get_value_bool(env, argv[2], &compress) == napi_ok);

  JS_ASSERT(length != 0, JS_ERR_PUBKEY);

  pubs = bcrypto_malloc(length * sizeof(uint8_t *));
  pub_lens = bcrypto_malloc(length * sizeof(size_t));

  if (pubs == NULL || pub_lens == NULL)
    goto fail;

  for (i = 0; i < length; i++) {
    CHECK(napi_get_element(env, argv[1], i, &item) == napi_ok);
    CHECK(napi_get_buffer_info(env, item, (void **)&pubs[i],
                               &pub_lens[i]) == napi_ok);
  }

  ok = ecdsa_pubkey_combine(ec->ctx, out, &out_len,
                            pubs, pub_lens, length,
                            compress);

fail:
  bcrypto_free((void *)pubs);
  bcrypto_free(pub_lens);

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
  bcrypto_wei_curve_t *ec;
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
  bcrypto_wei_curve_t *ec;
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
  bcrypto_wei_curve_t *ec;
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
  bcrypto_wei_curve_t *ec;
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
  bcrypto_wei_curve_t *ec;
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
  bcrypto_wei_curve_t *ec;
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
  bcrypto_wei_curve_t *ec;
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
  bcrypto_wei_curve_t *ec;
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
  bcrypto_wei_curve_t *ec;
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
  bcrypto_wei_curve_t *ec;
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
  bcrypto_wei_curve_t *ec;
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
  bcrypto_wei_curve_t *ec;
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
  bcrypto_wei_curve_t *ec;
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
  bcrypto_wei_curve_t *ec;
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
  bcrypto_wei_curve_t *ec;
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
  bcrypto_wei_curve_t *ec;
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

/*
 * EdDSA
 */

static napi_value
bcrypto_eddsa_pubkey_size(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  bcrypto_edwards_curve_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_create_uint32(env, ec->pub_size, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_eddsa_privkey_generate(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  const uint8_t *entropy;
  size_t entropy_len;
  uint8_t out[EDDSA_MAX_PRIV_SIZE];
  bcrypto_edwards_curve_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&entropy,
                             &entropy_len) == napi_ok);

  JS_ASSERT(entropy_len == ENTROPY_SIZE, JS_ERR_ENTROPY_SIZE);

  eddsa_privkey_generate(ec->ctx, out, entropy);

  CHECK(napi_create_buffer_copy(env,
                                ec->priv_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  torsion_cleanse((void *)entropy, entropy_len);

  return result;
}

static napi_value
bcrypto_eddsa_privkey_verify(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  const uint8_t *priv;
  size_t priv_len;
  bcrypto_edwards_curve_t *ec;
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
  bcrypto_edwards_curve_t *ec;
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
  bcrypto_edwards_curve_t *ec;
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
  uint8_t scalar[EDWARDS_MAX_SCALAR_SIZE];
  uint8_t prefix[EDDSA_MAX_PREFIX_SIZE];
  const uint8_t *priv;
  size_t priv_len;
  bcrypto_edwards_curve_t *ec;
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
  uint8_t out[EDWARDS_MAX_SCALAR_SIZE];
  const uint8_t *priv;
  size_t priv_len;
  bcrypto_edwards_curve_t *ec;
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
  uint8_t out[EDWARDS_MAX_SCALAR_SIZE];
  const uint8_t *entropy;
  size_t entropy_len;
  bcrypto_edwards_curve_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&entropy,
                             &entropy_len) == napi_ok);

  JS_ASSERT(entropy_len == ENTROPY_SIZE, JS_ERR_ENTROPY_SIZE);

  eddsa_scalar_generate(ec->ctx, out, entropy);

  CHECK(napi_create_buffer_copy(env,
                                ec->scalar_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  torsion_cleanse((void *)entropy, entropy_len);

  return result;
}

static napi_value
bcrypto_eddsa_scalar_verify(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  const uint8_t *scalar;
  size_t scalar_len;
  bcrypto_edwards_curve_t *ec;
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
  uint8_t out[EDWARDS_MAX_SCALAR_SIZE];
  const uint8_t *scalar;
  size_t scalar_len;
  bcrypto_edwards_curve_t *ec;
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
  bcrypto_edwards_curve_t *ec;
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
  uint8_t out[EDWARDS_MAX_SCALAR_SIZE];
  const uint8_t *scalar, *tweak;
  size_t scalar_len, tweak_len;
  bcrypto_edwards_curve_t *ec;
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
  uint8_t out[EDWARDS_MAX_SCALAR_SIZE];
  const uint8_t *scalar, *tweak;
  size_t scalar_len, tweak_len;
  bcrypto_edwards_curve_t *ec;
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
  uint8_t out[EDWARDS_MAX_SCALAR_SIZE];
  const uint8_t *scalar;
  size_t scalar_len;
  bcrypto_edwards_curve_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&scalar,
                             &scalar_len) == napi_ok);

  JS_ASSERT(scalar_len == ec->scalar_size, JS_ERR_SCALAR_SIZE);

  eddsa_scalar_reduce(ec->ctx, out, scalar);

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
  uint8_t out[EDWARDS_MAX_SCALAR_SIZE];
  const uint8_t *scalar;
  size_t scalar_len;
  bcrypto_edwards_curve_t *ec;
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
  uint8_t out[EDWARDS_MAX_SCALAR_SIZE];
  const uint8_t *scalar;
  size_t scalar_len;
  bcrypto_edwards_curve_t *ec;
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
  bcrypto_edwards_curve_t *ec;
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
  bcrypto_edwards_curve_t *ec;
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
  bcrypto_edwards_curve_t *ec;
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
  bcrypto_edwards_curve_t *ec;
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
  uint8_t out[EDWARDS_MAX_FIELD_SIZE];
  const uint8_t *pub;
  size_t pub_len;
  uint32_t hint;
  bcrypto_edwards_curve_t *ec;
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
  bcrypto_edwards_curve_t *ec;
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
  uint8_t out[EDWARDS_MAX_FIELD_SIZE * 2];
  const uint8_t *pub, *entropy;
  size_t pub_len, entropy_len;
  uint32_t subgroup;
  bcrypto_edwards_curve_t *ec;
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

  CHECK(napi_create_buffer_copy(env, ec->field_size * 2,
                                out, NULL, &result) == napi_ok);

  torsion_cleanse((void *)entropy, entropy_len);

  return result;
}

static napi_value
bcrypto_eddsa_pubkey_verify(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  const uint8_t *pub;
  size_t pub_len;
  bcrypto_edwards_curve_t *ec;
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
  uint8_t x[EDWARDS_MAX_FIELD_SIZE];
  uint8_t y[EDWARDS_MAX_FIELD_SIZE];
  const uint8_t *pub;
  size_t pub_len;
  bcrypto_edwards_curve_t *ec;
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
  bcrypto_edwards_curve_t *ec;
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
  bcrypto_edwards_curve_t *ec;
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
  bcrypto_edwards_curve_t *ec;
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
  bcrypto_edwards_curve_t *ec;
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
  bcrypto_edwards_curve_t *ec;
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
  bcrypto_edwards_curve_t *ec;
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
  bcrypto_edwards_curve_t *ec;
  napi_value item, result;
  int ok = 0;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_array_length(env, argv[1], &length) == napi_ok);

  pubs = bcrypto_malloc(length * sizeof(uint8_t *));

  if (pubs == NULL && length != 0)
    goto fail;

  for (i = 0; i < length; i++) {
    CHECK(napi_get_element(env, argv[1], i, &item) == napi_ok);
    CHECK(napi_get_buffer_info(env, item, (void **)&pubs[i],
                               &pub_len) == napi_ok);

    if (pub_len != ec->pub_size)
      goto fail;
  }

  ok = eddsa_pubkey_combine(ec->ctx, out, pubs, length);

fail:
  bcrypto_free((void *)pubs);

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
  bcrypto_edwards_curve_t *ec;
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
  bcrypto_edwards_curve_t *ec;
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
  bcrypto_edwards_curve_t *ec;
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
  bcrypto_edwards_curve_t *ec;
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
  bcrypto_edwards_curve_t *ec;
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
  bcrypto_edwards_curve_t *ec;
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
  bcrypto_edwards_curve_t *ec;
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
  bcrypto_edwards_curve_t *ec;
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

  ptrs = bcrypto_malloc(3 * length * sizeof(uint8_t *));
  lens = bcrypto_malloc(1 * length * sizeof(size_t));

  if (ptrs == NULL || lens == NULL)
    goto fail;

  msgs = &ptrs[length * 0];
  pubs = &ptrs[length * 1];
  sigs = &ptrs[length * 2];
  msg_lens = &lens[length * 0];

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

  if (ec->scratch == NULL)
    ec->scratch = edwards_scratch_create(ec->ctx, SCRATCH_SIZE);

  CHECK(ec->scratch != NULL);

  ok = eddsa_verify_batch(ec->ctx, msgs, msg_lens, sigs,
                          pubs, length, ph, ctx, ctx_len,
                          ec->scratch);

fail:
  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  bcrypto_free((void *)ptrs);
  bcrypto_free(lens);

  return result;
}

static napi_value
bcrypto_eddsa_derive(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[EDDSA_MAX_PUB_SIZE];
  const uint8_t *pub, *priv;
  size_t pub_len, priv_len;
  bcrypto_edwards_curve_t *ec;
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
  bcrypto_edwards_curve_t *ec;
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
 * Edwards Curve
 */

static void
bcrypto_edwards_curve_destroy(napi_env env, void *data, void *hint) {
  bcrypto_edwards_curve_t *ec = (bcrypto_edwards_curve_t *)data;

  (void)env;
  (void)hint;

  if (ec->scratch != NULL)
    edwards_scratch_destroy(ec->ctx, ec->scratch);

  edwards_curve_destroy(ec->ctx);
  bcrypto_free(ec);
}

static napi_value
bcrypto_edwards_curve_create(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  uint32_t type;
  bcrypto_edwards_curve_t *ec;
  edwards_curve_t *ctx;
  napi_value handle;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_value_uint32(env, argv[0], &type) == napi_ok);

  JS_ASSERT(ctx = edwards_curve_create(type), JS_ERR_CONTEXT);

  ec = bcrypto_xmalloc(sizeof(bcrypto_edwards_curve_t));
  ec->ctx = ctx;
  ec->scratch = NULL;
  ec->scalar_size = edwards_curve_scalar_size(ec->ctx);
  ec->scalar_bits = edwards_curve_scalar_bits(ec->ctx);
  ec->field_size = edwards_curve_field_size(ec->ctx);
  ec->field_bits = edwards_curve_field_bits(ec->ctx);
  ec->priv_size = eddsa_privkey_size(ec->ctx);
  ec->pub_size = eddsa_pubkey_size(ec->ctx);
  ec->sig_size = eddsa_sig_size(ec->ctx);

  CHECK(napi_create_external(env,
                             ec,
                             bcrypto_edwards_curve_destroy,
                             NULL,
                             &handle) == napi_ok);

  return handle;
}

static napi_value
bcrypto_edwards_curve_field_size(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  bcrypto_edwards_curve_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_create_uint32(env, ec->field_size, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_edwards_curve_field_bits(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  bcrypto_edwards_curve_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_create_uint32(env, ec->field_bits, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_edwards_curve_randomize(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  const uint8_t *entropy;
  size_t entropy_len;
  bcrypto_edwards_curve_t *ec;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&entropy,
                             &entropy_len) == napi_ok);

  JS_ASSERT(entropy_len == ENTROPY_SIZE, JS_ERR_ENTROPY_SIZE);

  edwards_curve_randomize(ec->ctx, entropy);

  torsion_cleanse((void *)entropy, entropy_len);

  return argv[0];
}

/*
 * Hash
 */

static void
bcrypto_hash_destroy(napi_env env, void *data, void *hint) {
  (void)env;
  (void)hint;
  torsion_cleanse(data, sizeof(bcrypto_hash_t));
  bcrypto_free(data);
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

  hash = bcrypto_xmalloc(sizeof(bcrypto_hash_t));
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

  JS_ASSERT(hash_has_backend(type), JS_ERR_ARG);

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

  JS_ASSERT(hash_has_backend(type), JS_ERR_ARG);

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

  JS_ASSERT(hash_has_backend(type), JS_ERR_ARG);

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
 * Hash-DRBG
 */

static void
bcrypto_hash_drbg_destroy(napi_env env, void *data, void *hint) {
  (void)env;
  (void)hint;
  torsion_cleanse(data, sizeof(bcrypto_hash_drbg_t));
  bcrypto_free(data);
}

static napi_value
bcrypto_hash_drbg_create(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  uint32_t type;
  bcrypto_hash_drbg_t *drbg;
  napi_value handle;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_value_uint32(env, argv[0], &type) == napi_ok);

  JS_ASSERT(hash_has_backend(type), JS_ERR_ARG);

  drbg = bcrypto_xmalloc(sizeof(bcrypto_hash_drbg_t));
  drbg->type = type;
  drbg->started = 0;

  CHECK(napi_create_external(env,
                             drbg,
                             bcrypto_hash_drbg_destroy,
                             NULL,
                             &handle) == napi_ok);

  return handle;
}

static napi_value
bcrypto_hash_drbg_init(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t *seed;
  size_t seed_len;
  bcrypto_hash_drbg_t *drbg;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&drbg) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&seed,
                             &seed_len) == napi_ok);

  hash_drbg_init(&drbg->ctx, drbg->type, seed, seed_len);
  drbg->started = 1;

  return argv[0];
}

static napi_value
bcrypto_hash_drbg_reseed(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t *seed;
  size_t seed_len;
  bcrypto_hash_drbg_t *drbg;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&drbg) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&seed,
                             &seed_len) == napi_ok);

  JS_ASSERT(drbg->started, JS_ERR_INIT);

  hash_drbg_reseed(&drbg->ctx, seed, seed_len);

  return argv[0];
}

static napi_value
bcrypto_hash_drbg_generate(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t *out;
  uint32_t out_len;
  const uint8_t *add;
  size_t add_len;
  bcrypto_hash_drbg_t *drbg;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&drbg) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[1], &out_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&add, &add_len) == napi_ok);

  JS_ASSERT(drbg->started, JS_ERR_INIT);
  JS_ASSERT(out_len <= MAX_BUFFER_LENGTH, JS_ERR_ALLOC);

  JS_CHECK_ALLOC(napi_create_buffer(env, out_len, (void **)&out, &result));

  hash_drbg_generate(&drbg->ctx, out, out_len, add, add_len);

  return result;
}

/*
 * HKDF
 */

static napi_value
bcrypto_hkdf_extract(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[HASH_MAX_OUTPUT_SIZE];
  uint32_t type, out_len;
  const uint8_t *ikm, *salt;
  size_t ikm_len, salt_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_uint32(env, argv[0], &type) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&ikm,
                             &ikm_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&salt,
                             &salt_len) == napi_ok);

  JS_ASSERT(hkdf_extract(out, type, ikm, ikm_len, salt, salt_len),
            JS_ERR_DERIVE);

  out_len = hash_output_size(type);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_hkdf_expand(napi_env env, napi_callback_info info) {
  napi_value argv[4];
  size_t argc = 4;
  uint8_t *out;
  uint32_t type, out_len;
  const uint8_t *prk, *info_;
  size_t prk_len, info_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 4);
  CHECK(napi_get_value_uint32(env, argv[0], &type) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&prk,
                             &prk_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&info_,
                             &info_len) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[3], &out_len) == napi_ok);

  JS_ASSERT(hash_has_backend(type), JS_ERR_DERIVE);
  JS_ASSERT(prk_len == hash_output_size(type), JS_ERR_DERIVE);
  JS_ASSERT(out_len <= MAX_BUFFER_LENGTH, JS_ERR_ALLOC);

  JS_CHECK_ALLOC(napi_create_buffer(env, out_len, (void **)&out, &result));

  JS_ASSERT(hkdf_expand(out, type, prk, info_, info_len, out_len),
            JS_ERR_DERIVE);

  return result;
}

/*
 * HMAC
 */

static void
bcrypto_hmac_destroy(napi_env env, void *data, void *hint) {
  (void)env;
  (void)hint;
  torsion_cleanse(data, sizeof(bcrypto_hmac_t));
  bcrypto_free(data);
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

  JS_ASSERT(hash_has_backend(type), JS_ERR_ARG);

  hmac = bcrypto_xmalloc(sizeof(bcrypto_hmac_t));
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

  JS_ASSERT(hash_has_backend(type), JS_ERR_ARG);

  out_len = hash_output_size(type);

  hmac_init(&ctx, type, key, key_len);
  hmac_update(&ctx, in, in_len);
  hmac_final(&ctx, out);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  return result;
}

/*
 * HMAC-DRBG
 */

static void
bcrypto_hmac_drbg_destroy(napi_env env, void *data, void *hint) {
  (void)env;
  (void)hint;
  torsion_cleanse(data, sizeof(bcrypto_hmac_drbg_t));
  bcrypto_free(data);
}

static napi_value
bcrypto_hmac_drbg_create(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  uint32_t type;
  bcrypto_hmac_drbg_t *drbg;
  napi_value handle;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_value_uint32(env, argv[0], &type) == napi_ok);

  JS_ASSERT(hash_has_backend(type), JS_ERR_ARG);

  drbg = bcrypto_xmalloc(sizeof(bcrypto_hmac_drbg_t));
  drbg->type = type;
  drbg->started = 0;

  CHECK(napi_create_external(env,
                             drbg,
                             bcrypto_hmac_drbg_destroy,
                             NULL,
                             &handle) == napi_ok);

  return handle;
}

static napi_value
bcrypto_hmac_drbg_init(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t *seed;
  size_t seed_len;
  bcrypto_hmac_drbg_t *drbg;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&drbg) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&seed,
                             &seed_len) == napi_ok);

  hmac_drbg_init(&drbg->ctx, drbg->type, seed, seed_len);
  drbg->started = 1;

  return argv[0];
}

static napi_value
bcrypto_hmac_drbg_reseed(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t *seed;
  size_t seed_len;
  bcrypto_hmac_drbg_t *drbg;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&drbg) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&seed,
                             &seed_len) == napi_ok);

  JS_ASSERT(drbg->started, JS_ERR_INIT);

  hmac_drbg_reseed(&drbg->ctx, seed, seed_len);

  return argv[0];
}

static napi_value
bcrypto_hmac_drbg_generate(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t *out;
  uint32_t out_len;
  const uint8_t *add;
  size_t add_len;
  bcrypto_hmac_drbg_t *drbg;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&drbg) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[1], &out_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&add, &add_len) == napi_ok);

  JS_ASSERT(drbg->started, JS_ERR_INIT);
  JS_ASSERT(out_len <= MAX_BUFFER_LENGTH, JS_ERR_ALLOC);

  JS_CHECK_ALLOC(napi_create_buffer(env, out_len, (void **)&out, &result));

  hmac_drbg_generate(&drbg->ctx, out, out_len, add, add_len);

  return result;
}

/*
 * Keccak
 */

static void
bcrypto_keccak_destroy(napi_env env, void *data, void *hint) {
  (void)env;
  (void)hint;
  torsion_cleanse(data, sizeof(bcrypto_keccak_t));
  bcrypto_free(data);
}

static napi_value
bcrypto_keccak_create(napi_env env, napi_callback_info info) {
  bcrypto_keccak_t *keccak = bcrypto_xmalloc(sizeof(bcrypto_keccak_t));
  napi_value handle;

  (void)info;

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
  JS_ASSERT(out_len <= keccak->ctx.bs, JS_ERR_OUTPUT_SIZE);

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
  JS_ASSERT(out_len <= bs, JS_ERR_OUTPUT_SIZE);

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
  JS_ASSERT(out_len <= bs, JS_ERR_OUTPUT_SIZE);
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
  JS_ASSERT(out_len <= bs, JS_ERR_OUTPUT_SIZE);

  keccak_init(&ctx, bits);
  keccak_update(&ctx, x, x_len);
  keccak_update(&ctx, y, y_len);
  keccak_update(&ctx, z, z_len);
  keccak_final(&ctx, out, pad, out_len);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  return result;
}

/*
 * Montgomery Curve
 */

static void
bcrypto_mont_curve_destroy(napi_env env, void *data, void *hint) {
  bcrypto_mont_curve_t *ec = (bcrypto_mont_curve_t *)data;

  (void)env;
  (void)hint;

  mont_curve_destroy(ec->ctx);
  bcrypto_free(ec);
}

static napi_value
bcrypto_mont_curve_create(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  uint32_t type;
  bcrypto_mont_curve_t *ec;
  mont_curve_t *ctx;
  napi_value handle;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_value_uint32(env, argv[0], &type) == napi_ok);

  JS_ASSERT(ctx = mont_curve_create(type), JS_ERR_CONTEXT);

  ec = bcrypto_xmalloc(sizeof(bcrypto_mont_curve_t));
  ec->ctx = ctx;
  ec->scalar_size = mont_curve_scalar_size(ec->ctx);
  ec->scalar_bits = mont_curve_scalar_bits(ec->ctx);
  ec->field_size = mont_curve_field_size(ec->ctx);
  ec->field_bits = mont_curve_field_bits(ec->ctx);

  CHECK(napi_create_external(env,
                             ec,
                             bcrypto_mont_curve_destroy,
                             NULL,
                             &handle) == napi_ok);

  return handle;
}

static napi_value
bcrypto_mont_curve_field_size(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  bcrypto_mont_curve_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_create_uint32(env, ec->field_size, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_mont_curve_field_bits(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  bcrypto_mont_curve_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_create_uint32(env, ec->field_bits, &result) == napi_ok);

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
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 5);
  CHECK(napi_get_value_uint32(env, argv[0], &type) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pass,
                             &pass_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&salt,
                             &salt_len) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[3], &iter) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[4], &out_len) == napi_ok);

  JS_ASSERT(out_len <= MAX_BUFFER_LENGTH, JS_ERR_ALLOC);

  JS_CHECK_ALLOC(napi_create_buffer(env, out_len, (void **)&out, &result));

  ok = pbkdf2_derive(out, type, pass, pass_len,
                     salt, salt_len, iter, out_len);

  JS_ASSERT(ok, JS_ERR_DERIVE);

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

  (void)env;

  if (!pbkdf2_derive(w->out, w->type, w->pass, w->pass_len,
                     w->salt, w->salt_len, w->iter, w->out_len)) {
    w->error = JS_ERR_DERIVE;
  }

  torsion_cleanse(w->pass, w->pass_len);
  torsion_cleanse(w->salt, w->salt_len);
}

static void
bcrypto_pbkdf2_complete_(napi_env env, napi_status status, void *data) {
  bcrypto_pbkdf2_worker_t *w = (bcrypto_pbkdf2_worker_t *)data;
  napi_value result, strval, errval;

  if (w->error == NULL && status == napi_ok)
    status = napi_create_buffer_copy(env, w->out_len, w->out, NULL, &result);

  if (status != napi_ok)
    w->error = JS_ERR_DERIVE;

  if (w->error == NULL) {
    CHECK(napi_resolve_deferred(env, w->deferred, result) == napi_ok);
  } else {
    CHECK(napi_create_string_latin1(env, w->error, NAPI_AUTO_LENGTH,
                                    &strval) == napi_ok);
    CHECK(napi_create_error(env, NULL, strval, &errval) == napi_ok);
    CHECK(napi_reject_deferred(env, w->deferred, errval) == napi_ok);
  }

  CHECK(napi_delete_async_work(env, w->work) == napi_ok);

  bcrypto_free(w->pass);
  bcrypto_free(w->salt);
  bcrypto_free(w->out);
  bcrypto_free(w);
}

static napi_value
bcrypto_pbkdf2_derive_async(napi_env env, napi_callback_info info) {
  bcrypto_pbkdf2_worker_t *worker;
  napi_value argv[5];
  size_t argc = 5;
  uint8_t *out;
  uint32_t type, iter, out_len;
  const uint8_t *pass, *salt;
  size_t pass_len, salt_len;
  napi_value workname, result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 5);
  CHECK(napi_get_value_uint32(env, argv[0], &type) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pass,
                             &pass_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&salt,
                             &salt_len) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[3], &iter) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[4], &out_len) == napi_ok);

  JS_ASSERT(out_len <= MAX_BUFFER_LENGTH, JS_ERR_ALLOC);

  out = bcrypto_malloc(out_len);

  JS_ASSERT(out != NULL || out_len == 0, JS_ERR_ALLOC);

  worker = bcrypto_xmalloc(sizeof(bcrypto_pbkdf2_worker_t));
  worker->type = type;
  worker->pass = bcrypto_malloc(pass_len);
  worker->pass_len = pass_len;
  worker->salt = bcrypto_malloc(salt_len);
  worker->salt_len = salt_len;
  worker->iter = iter;
  worker->out = out;
  worker->out_len = out_len;
  worker->error = NULL;

  if ((worker->pass == NULL && pass_len != 0)
      || (worker->salt == NULL && salt_len != 0)) {
    bcrypto_free(worker->pass);
    bcrypto_free(worker->salt);
    bcrypto_free(worker->out);
    bcrypto_free(worker);
    JS_THROW(JS_ERR_DERIVE);
  }

  if (pass_len > 0)
    memcpy(worker->pass, pass, pass_len);

  if (salt_len > 0)
    memcpy(worker->salt, salt, salt_len);

  CHECK(napi_create_string_latin1(env, "bcrypto:pbkdf2_derive",
                                  NAPI_AUTO_LENGTH, &workname) == napi_ok);

  CHECK(napi_create_promise(env, &worker->deferred, &result) == napi_ok);

  CHECK(napi_create_async_work(env,
                               NULL,
                               workname,
                               bcrypto_pbkdf2_execute_,
                               bcrypto_pbkdf2_complete_,
                               worker,
                               &worker->work) == napi_ok);

  CHECK(napi_queue_async_work(env, worker->work) == napi_ok);

  return result;
}

/*
 * PGPDF
 */

static napi_value
bcrypto_pgpdf_derive_simple(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t *out;
  uint32_t type, out_len;
  const uint8_t *pass;
  size_t pass_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_uint32(env, argv[0], &type) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pass,
                             &pass_len) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[2], &out_len) == napi_ok);

  JS_ASSERT(out_len <= MAX_BUFFER_LENGTH, JS_ERR_ALLOC);

  JS_CHECK_ALLOC(napi_create_buffer(env, out_len, (void **)&out, &result));

  JS_ASSERT(pgpdf_derive_simple(out, type, pass, pass_len, out_len),
            JS_ERR_DERIVE);

  return result;
}

static napi_value
bcrypto_pgpdf_derive_salted(napi_env env, napi_callback_info info) {
  napi_value argv[4];
  size_t argc = 4;
  uint8_t *out;
  uint32_t type, out_len;
  const uint8_t *pass, *salt;
  size_t pass_len, salt_len;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 4);
  CHECK(napi_get_value_uint32(env, argv[0], &type) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pass,
                             &pass_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&salt,
                             &salt_len) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[3], &out_len) == napi_ok);

  JS_ASSERT(out_len <= MAX_BUFFER_LENGTH, JS_ERR_ALLOC);

  JS_CHECK_ALLOC(napi_create_buffer(env, out_len, (void **)&out, &result));

  ok = pgpdf_derive_salted(out, type, pass, pass_len,
                           salt, salt_len, out_len);

  JS_ASSERT(ok, JS_ERR_DERIVE);

  return result;
}

static napi_value
bcrypto_pgpdf_derive_iterated(napi_env env, napi_callback_info info) {
  napi_value argv[5];
  size_t argc = 5;
  uint8_t *out;
  uint32_t type, count, out_len;
  const uint8_t *pass, *salt;
  size_t pass_len, salt_len;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 5);
  CHECK(napi_get_value_uint32(env, argv[0], &type) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&pass,
                             &pass_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&salt,
                             &salt_len) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[3], &count) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[4], &out_len) == napi_ok);

  JS_ASSERT(out_len <= MAX_BUFFER_LENGTH, JS_ERR_ALLOC);

  JS_CHECK_ALLOC(napi_create_buffer(env, out_len, (void **)&out, &result));

  ok = pgpdf_derive_iterated(out, type, pass, pass_len,
                             salt, salt_len, count, out_len);

  JS_ASSERT(ok, JS_ERR_DERIVE);

  return result;
}

/*
 * Poly1305
 */

static void
bcrypto_poly1305_destroy_(napi_env env, void *data, void *hint) {
  (void)env;
  (void)hint;
  torsion_cleanse(data, sizeof(bcrypto_poly1305_t));
  bcrypto_free(data);
}

static napi_value
bcrypto_poly1305_create(napi_env env, napi_callback_info info) {
  bcrypto_poly1305_t *poly = bcrypto_xmalloc(sizeof(bcrypto_poly1305_t));
  napi_value handle;

  (void)info;

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

  ok = torsion_memequal(mac, tag, 16);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

/*
 * Random
 */

static napi_value
bcrypto_getentropy(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t *out;
  size_t out_len;
  uint32_t off, size;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&out, &out_len) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[1], &off) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[2], &size) == napi_ok);

  JS_ASSERT(off + size >= size, JS_ERR_RNG);
  JS_ASSERT(off + size <= out_len, JS_ERR_RNG);

  if (size > 0)
    JS_ASSERT(torsion_getentropy(out + off, size), JS_ERR_RNG);

  return argv[0];
}

static napi_value
bcrypto_getrandom(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t *out;
  size_t out_len;
  uint32_t off, size;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&out, &out_len) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[1], &off) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[2], &size) == napi_ok);

  JS_ASSERT(off + size >= size, JS_ERR_RNG);
  JS_ASSERT(off + size <= out_len, JS_ERR_RNG);

  if (size > 0)
    JS_ASSERT(torsion_getrandom(out + off, size), JS_ERR_RNG);

  return argv[0];
}

static napi_value
bcrypto_random(napi_env env, napi_callback_info info) {
  uint32_t num = 0;
  napi_value result;

  (void)info;

  JS_ASSERT(torsion_random(&num), JS_ERR_RNG);

  CHECK(napi_create_uint32(env, num, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_uniform(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  uint32_t num = 0;
  uint32_t max;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_value_uint32(env, argv[0], &max) == napi_ok);

  JS_ASSERT(torsion_uniform(&num, max), JS_ERR_RNG);

  CHECK(napi_create_uint32(env, num, &result) == napi_ok);

  return result;
}

/*
 * RSA
 */

static napi_value
bcrypto_rsa_privkey_generate(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[RSA_MAX_PRIV_SIZE];
  size_t out_len = RSA_MAX_PRIV_SIZE;
  uint32_t bits;
  int64_t exp;
  const uint8_t *entropy;
  size_t entropy_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_uint32(env, argv[0], &bits) == napi_ok);
  CHECK(napi_get_value_int64(env, argv[1], &exp) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&entropy,
                             &entropy_len) == napi_ok);

  JS_ASSERT(entropy_len == ENTROPY_SIZE, JS_ERR_ENTROPY_SIZE);
  JS_ASSERT(rsa_privkey_generate(out, &out_len, bits, exp, entropy),
            JS_ERR_GENERATE);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  torsion_cleanse((void *)entropy, entropy_len);
  torsion_cleanse(out, out_len);

  return result;
}

typedef struct bcrypto_rsa_worker_s {
  uint32_t bits;
  int64_t exp;
  uint8_t entropy[ENTROPY_SIZE];
  uint8_t out[RSA_MAX_PRIV_SIZE];
  size_t out_len;
  const char *error;
  napi_async_work work;
  napi_deferred deferred;
} bcrypto_rsa_worker_t;

static void
bcrypto_rsa_execute_(napi_env env, void *data) {
  bcrypto_rsa_worker_t *w = (bcrypto_rsa_worker_t *)data;

  (void)env;

  if (!rsa_privkey_generate(w->out, &w->out_len, w->bits, w->exp, w->entropy))
    w->error = JS_ERR_GENERATE;

  torsion_cleanse(w->entropy, ENTROPY_SIZE);
}

static void
bcrypto_rsa_complete_(napi_env env, napi_status status, void *data) {
  bcrypto_rsa_worker_t *w = (bcrypto_rsa_worker_t *)data;
  napi_value result, strval, errval;

  if (w->error == NULL && status == napi_ok)
    status = napi_create_buffer_copy(env, w->out_len, w->out, NULL, &result);

  if (status != napi_ok)
    w->error = JS_ERR_GENERATE;

  if (w->error == NULL) {
    CHECK(napi_resolve_deferred(env, w->deferred, result) == napi_ok);
  } else {
    CHECK(napi_create_string_latin1(env, w->error, NAPI_AUTO_LENGTH,
                                    &strval) == napi_ok);
    CHECK(napi_create_error(env, NULL, strval, &errval) == napi_ok);
    CHECK(napi_reject_deferred(env, w->deferred, errval) == napi_ok);
  }

  CHECK(napi_delete_async_work(env, w->work) == napi_ok);

  torsion_cleanse(w->out, w->out_len);

  bcrypto_free(w);
}

static napi_value
bcrypto_rsa_privkey_generate_async(napi_env env, napi_callback_info info) {
  bcrypto_rsa_worker_t *worker;
  napi_value argv[3];
  size_t argc = 3;
  uint32_t bits;
  int64_t exp;
  const uint8_t *entropy;
  size_t entropy_len;
  napi_value workname, result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_uint32(env, argv[0], &bits) == napi_ok);
  CHECK(napi_get_value_int64(env, argv[1], &exp) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&entropy,
                             &entropy_len) == napi_ok);

  JS_ASSERT(entropy_len == ENTROPY_SIZE, JS_ERR_ENTROPY_SIZE);

  worker = bcrypto_xmalloc(sizeof(bcrypto_rsa_worker_t));
  worker->bits = bits;
  worker->exp = exp;
  worker->out_len = RSA_MAX_PRIV_SIZE;
  worker->error = NULL;

  memcpy(worker->entropy, entropy, ENTROPY_SIZE);

  CHECK(napi_create_string_latin1(env, "bcrypto:rsa_privkey_generate",
                                  NAPI_AUTO_LENGTH, &workname) == napi_ok);

  CHECK(napi_create_promise(env, &worker->deferred, &result) == napi_ok);

  CHECK(napi_create_async_work(env,
                               NULL,
                               workname,
                               bcrypto_rsa_execute_,
                               bcrypto_rsa_complete_,
                               worker,
                               &worker->work) == napi_ok);

  CHECK(napi_queue_async_work(env, worker->work) == napi_ok);

  torsion_cleanse((void *)entropy, entropy_len);

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
  uint8_t out[RSA_MAX_PRIV_SIZE];
  size_t out_len = RSA_MAX_PRIV_SIZE;
  const uint8_t *key, *entropy;
  size_t key_len, entropy_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&key, &key_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&entropy,
                             &entropy_len) == napi_ok);

  JS_ASSERT(entropy_len == ENTROPY_SIZE, JS_ERR_ENTROPY_SIZE);
  JS_ASSERT(rsa_privkey_import(out, &out_len, key, key_len, entropy),
            JS_ERR_PRIVKEY);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  torsion_cleanse((void *)entropy, entropy_len);
  torsion_cleanse((void *)key, key_len);
  torsion_cleanse(out, out_len);

  return result;
}

static napi_value
bcrypto_rsa_privkey_export(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  uint8_t out[RSA_MAX_PRIV_SIZE];
  size_t out_len = RSA_MAX_PRIV_SIZE;
  const uint8_t *key;
  size_t key_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&key, &key_len) == napi_ok);

  JS_ASSERT(rsa_privkey_export(out, &out_len, key, key_len), JS_ERR_PRIVKEY);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  torsion_cleanse(out, out_len);

  return result;
}

static napi_value
bcrypto_rsa_pubkey_create(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  uint8_t out[RSA_MAX_PUB_SIZE];
  size_t out_len = RSA_MAX_PUB_SIZE;
  const uint8_t *key;
  size_t key_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&key, &key_len) == napi_ok);

  JS_ASSERT(rsa_pubkey_create(out, &out_len, key, key_len), JS_ERR_PRIVKEY);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

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
  uint8_t out[RSA_MAX_PUB_SIZE];
  size_t out_len = RSA_MAX_PUB_SIZE;
  const uint8_t *key;
  size_t key_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&key, &key_len) == napi_ok);

  JS_ASSERT(rsa_pubkey_import(out, &out_len, key, key_len), JS_ERR_PUBKEY);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  torsion_cleanse((void *)key, key_len);

  return result;
}

static napi_value
bcrypto_rsa_pubkey_export(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  uint8_t out[RSA_MAX_PUB_SIZE];
  size_t out_len = RSA_MAX_PUB_SIZE;
  const uint8_t *key;
  size_t key_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&key, &key_len) == napi_ok);

  JS_ASSERT(rsa_pubkey_export(out, &out_len, key, key_len), JS_ERR_PUBKEY);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_rsa_sign(napi_env env, napi_callback_info info) {
  napi_value argv[4];
  size_t argc = 4;
  uint8_t out[RSA_MAX_MOD_SIZE];
  size_t out_len = RSA_MAX_MOD_SIZE;
  uint32_t type;
  const uint8_t *msg, *key, *entropy;
  size_t msg_len, key_len, entropy_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 4);
  CHECK(napi_get_value_uint32(env, argv[0], &type) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&key, &key_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[3], (void **)&entropy,
                             &entropy_len) == napi_ok);

  JS_ASSERT(entropy_len == ENTROPY_SIZE, JS_ERR_ENTROPY_SIZE);
  JS_ASSERT(rsa_sign(out, &out_len, type, msg, msg_len, key, key_len, entropy),
            JS_ERR_SIGN);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  torsion_cleanse((void *)entropy, entropy_len);

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
  uint8_t out[RSA_MAX_MOD_SIZE];
  size_t out_len = RSA_MAX_MOD_SIZE;
  const uint8_t *msg, *key, *entropy;
  size_t msg_len, key_len, entropy_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&key, &key_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&entropy,
                             &entropy_len) == napi_ok);

  JS_ASSERT(entropy_len == ENTROPY_SIZE, JS_ERR_ENTROPY_SIZE);
  JS_ASSERT(rsa_encrypt(out, &out_len, msg, msg_len, key, key_len, entropy),
            JS_ERR_ENCRYPT);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  torsion_cleanse((void *)entropy, entropy_len);

  return result;
}

static napi_value
bcrypto_rsa_decrypt(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[RSA_MAX_MOD_SIZE];
  size_t out_len = RSA_MAX_MOD_SIZE;
  const uint8_t *msg, *key, *entropy;
  size_t msg_len, key_len, entropy_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&key, &key_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&entropy,
                             &entropy_len) == napi_ok);

  JS_ASSERT(entropy_len == ENTROPY_SIZE, JS_ERR_ENTROPY_SIZE);
  JS_ASSERT(rsa_decrypt(out, &out_len, msg, msg_len, key, key_len, entropy),
            JS_ERR_DECRYPT);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  torsion_cleanse((void *)entropy, entropy_len);
  torsion_cleanse(out, out_len);

  return result;
}

static napi_value
bcrypto_rsa_sign_pss(napi_env env, napi_callback_info info) {
  napi_value argv[5];
  size_t argc = 5;
  uint8_t out[RSA_MAX_MOD_SIZE];
  size_t out_len = RSA_MAX_MOD_SIZE;
  uint32_t type;
  const uint8_t *msg, *key, *entropy;
  size_t msg_len, key_len, entropy_len;
  int32_t salt_len;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 5);
  CHECK(napi_get_value_uint32(env, argv[0], &type) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&key, &key_len) == napi_ok);
  CHECK(napi_get_value_int32(env, argv[3], &salt_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[4], (void **)&entropy,
                             &entropy_len) == napi_ok);

  JS_ASSERT(entropy_len == ENTROPY_SIZE, JS_ERR_ENTROPY_SIZE);

  ok = rsa_sign_pss(out, &out_len, type, msg, msg_len,
                    key, key_len, salt_len, entropy);

  JS_ASSERT(ok, JS_ERR_SIGN);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  torsion_cleanse((void *)entropy, entropy_len);

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
  uint8_t out[RSA_MAX_MOD_SIZE];
  size_t out_len = RSA_MAX_MOD_SIZE;
  uint32_t type;
  const uint8_t *msg, *key, *label, *entropy;
  size_t msg_len, key_len, label_len, entropy_len;
  napi_value result;
  int ok;

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

  ok = rsa_encrypt_oaep(out, &out_len, type, msg, msg_len,
                        key, key_len, label, label_len, entropy);

  JS_ASSERT(ok, JS_ERR_ENCRYPT);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  torsion_cleanse((void *)entropy, entropy_len);

  return result;
}

static napi_value
bcrypto_rsa_decrypt_oaep(napi_env env, napi_callback_info info) {
  napi_value argv[5];
  size_t argc = 5;
  uint8_t out[RSA_MAX_MOD_SIZE];
  size_t out_len = RSA_MAX_MOD_SIZE;
  uint32_t type;
  const uint8_t *msg, *key, *label, *entropy;
  size_t msg_len, key_len, label_len, entropy_len;
  napi_value result;
  int ok;

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

  ok = rsa_decrypt_oaep(out, &out_len, type, msg, msg_len,
                        key, key_len, label, label_len, entropy);

  JS_ASSERT(ok, JS_ERR_DECRYPT);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  torsion_cleanse((void *)entropy, entropy_len);

  return result;
}

static napi_value
bcrypto_rsa_veil(napi_env env, napi_callback_info info) {
  napi_value argv[4];
  size_t argc = 4;
  uint8_t out[RSA_MAX_MOD_SIZE + 1];
  size_t out_len = RSA_MAX_MOD_SIZE + 1;
  uint32_t bits;
  const uint8_t *msg, *key, *entropy;
  size_t msg_len, key_len, entropy_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 4);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[1], &bits) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&key, &key_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[3], (void **)&entropy,
                             &entropy_len) == napi_ok);

  JS_ASSERT(entropy_len == ENTROPY_SIZE, JS_ERR_ENTROPY_SIZE);
  JS_ASSERT(bits <= RSA_MAX_MOD_BITS + 8, JS_ERR_VEIL);
  JS_ASSERT((bits + 7) / 8 <= out_len, JS_ERR_VEIL);
  JS_ASSERT(rsa_veil(out, &out_len, msg, msg_len, bits, key, key_len, entropy),
            JS_ERR_VEIL);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  torsion_cleanse((void *)entropy, entropy_len);

  return result;
}

static napi_value
bcrypto_rsa_unveil(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[RSA_MAX_MOD_SIZE];
  size_t out_len = RSA_MAX_MOD_SIZE;
  uint32_t bits;
  const uint8_t *msg, *key;
  size_t msg_len, key_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[1], &bits) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&key, &key_len) == napi_ok);

  JS_ASSERT(rsa_unveil(out, &out_len, msg, msg_len, bits, key, key_len),
            JS_ERR_UNVEIL);

  CHECK(napi_create_buffer_copy(env, out_len, out, NULL, &result) == napi_ok);

  torsion_cleanse(out, out_len);

  return result;
}

/*
 * Salsa20
 */

static void
bcrypto_salsa20_destroy_(napi_env env, void *data, void *hint) {
  (void)env;
  (void)hint;
  torsion_cleanse(data, sizeof(bcrypto_salsa20_t));
  bcrypto_free(data);
}

static napi_value
bcrypto_salsa20_create(napi_env env, napi_callback_info info) {
  bcrypto_salsa20_t *salsa = bcrypto_xmalloc(sizeof(bcrypto_salsa20_t));
  napi_value handle;

  (void)info;

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
bcrypto_salsa20_crypt(napi_env env, napi_callback_info info) {
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

  salsa20_crypt(&salsa->ctx, msg, msg, msg_len);

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

static napi_value
bcrypto_schnorr_privkey_generate(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  const uint8_t *entropy;
  size_t entropy_len;
  uint8_t out[SCHNORR_MAX_PRIV_SIZE];
  bcrypto_wei_curve_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&entropy,
                             &entropy_len) == napi_ok);

  JS_ASSERT(entropy_len == ENTROPY_SIZE, JS_ERR_ENTROPY_SIZE);

  schnorr_privkey_generate(ec->ctx, out, entropy);

  CHECK(napi_create_buffer_copy(env,
                                ec->scalar_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  torsion_cleanse((void *)entropy, entropy_len);

  return result;
}

static napi_value
bcrypto_schnorr_privkey_verify(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  const uint8_t *priv;
  size_t priv_len;
  bcrypto_wei_curve_t *ec;
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
  uint8_t x[WEI_MAX_FIELD_SIZE];
  uint8_t y[WEI_MAX_FIELD_SIZE];
  const uint8_t *priv;
  size_t priv_len;
  bcrypto_wei_curve_t *ec;
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
  bcrypto_wei_curve_t *ec;
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
  bcrypto_wei_curve_t *ec;
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
  bcrypto_wei_curve_t *ec;
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
bcrypto_schnorr_privkey_invert(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t out[SCHNORR_MAX_PRIV_SIZE];
  const uint8_t *priv;
  size_t priv_len;
  bcrypto_wei_curve_t *ec;
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
  bcrypto_wei_curve_t *ec;
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
  bcrypto_wei_curve_t *ec;
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
  uint8_t out[WEI_MAX_FIELD_SIZE];
  const uint8_t *pub;
  size_t pub_len;
  uint32_t hint;
  bcrypto_wei_curve_t *ec;
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
  bcrypto_wei_curve_t *ec;
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
  uint8_t out[WEI_MAX_FIELD_SIZE * 2];
  const uint8_t *pub, *entropy;
  size_t pub_len, entropy_len;
  bcrypto_wei_curve_t *ec;
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

  CHECK(napi_create_buffer_copy(env, ec->field_size * 2,
                                out, NULL, &result) == napi_ok);

  torsion_cleanse((void *)entropy, entropy_len);

  return result;
}

static napi_value
bcrypto_schnorr_pubkey_verify(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  const uint8_t *pub;
  size_t pub_len;
  bcrypto_wei_curve_t *ec;
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
  uint8_t x[WEI_MAX_FIELD_SIZE];
  uint8_t y[WEI_MAX_FIELD_SIZE];
  const uint8_t *pub;
  size_t pub_len;
  bcrypto_wei_curve_t *ec;
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
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[SCHNORR_MAX_PUB_SIZE];
  const uint8_t *x, *y;
  size_t x_len, y_len;
  bcrypto_wei_curve_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&x, &x_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&y, &y_len) == napi_ok);

  JS_ASSERT(schnorr_pubkey_import(ec->ctx, out, x, x_len, y, y_len),
            JS_ERR_PUBKEY);

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
  bcrypto_wei_curve_t *ec;
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
  bcrypto_wei_curve_t *ec;
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
  bcrypto_wei_curve_t *ec;
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
bcrypto_schnorr_pubkey_tweak_check(napi_env env, napi_callback_info info) {
  napi_value argv[5];
  size_t argc = 5;
  const uint8_t *pub, *tweak, *expect;
  size_t pub_len, tweak_len, expect_len;
  bool negated;
  bcrypto_wei_curve_t *ec;
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

  ok = schnorr_pubkey_tweak_add_check(ec->ctx, pub, tweak, expect, negated);

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
  bcrypto_wei_curve_t *ec;
  napi_value item, result;
  int ok = 0;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_array_length(env, argv[1], &length) == napi_ok);

  JS_ASSERT(length != 0, JS_ERR_PUBKEY);

  pubs = bcrypto_malloc(length * sizeof(uint8_t *));

  if (pubs == NULL)
    goto fail;

  for (i = 0; i < length; i++) {
    CHECK(napi_get_element(env, argv[1], i, &item) == napi_ok);
    CHECK(napi_get_buffer_info(env, item, (void **)&pubs[i],
                               &pub_len) == napi_ok);

    if (pub_len != ec->field_size)
      goto fail;
  }

  ok = schnorr_pubkey_combine(ec->ctx, out, pubs, length);

fail:
  bcrypto_free((void *)pubs);

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
  bcrypto_wei_curve_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 4);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&priv,
                             &priv_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[3], (void **)&aux, &aux_len) == napi_ok);

  JS_ASSERT(priv_len == ec->scalar_size, JS_ERR_PRIVKEY_SIZE);
  JS_ASSERT(aux_len == 0 || aux_len == 32, JS_ERR_PRIVKEY_SIZE);

  if (aux_len == 0)
    aux = NULL;

  JS_ASSERT(schnorr_sign(ec->ctx, out, msg, msg_len, priv, aux), JS_ERR_SIGN);

  CHECK(napi_create_buffer_copy(env,
                                ec->schnorr_size,
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
  bcrypto_wei_curve_t *ec;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 4);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&sig, &sig_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[3], (void **)&pub, &pub_len) == napi_ok);

  ok = sig_len == ec->schnorr_size
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
  bcrypto_wei_curve_t *ec;
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

  ptrs = bcrypto_malloc(3 * length * sizeof(uint8_t *));
  lens = bcrypto_malloc(1 * length * sizeof(size_t));

  if (ptrs == NULL || lens == NULL)
    goto fail;

  msgs = &ptrs[length * 0];
  pubs = &ptrs[length * 1];
  sigs = &ptrs[length * 2];
  msg_lens = &lens[length * 0];

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

    if (sig_len != ec->schnorr_size || pub_len != ec->field_size)
      goto fail;
  }

  if (ec->scratch == NULL)
    ec->scratch = wei_scratch_create(ec->ctx, SCRATCH_SIZE);

  CHECK(ec->scratch != NULL);

  ok = schnorr_verify_batch(ec->ctx, msgs, msg_lens, sigs,
                            pubs, length, ec->scratch);

fail:
  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  bcrypto_free((void *)ptrs);
  bcrypto_free(lens);

  return result;
}

static napi_value
bcrypto_schnorr_derive(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[SCHNORR_MAX_PUB_SIZE];
  const uint8_t *pub, *priv;
  size_t pub_len, priv_len;
  bcrypto_wei_curve_t *ec;
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
 * Schnorr Legacy
 */

static napi_value
bcrypto_schnorr_legacy_sign(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t out[SCHNORR_LEGACY_MAX_SIG_SIZE];
  const uint8_t *msg, *priv;
  size_t msg_len, priv_len;
  bcrypto_wei_curve_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&priv,
                             &priv_len) == napi_ok);

  JS_ASSERT(schnorr_legacy_support(ec->ctx), JS_ERR_NO_SCHNORR);
  JS_ASSERT(priv_len == ec->scalar_size, JS_ERR_PRIVKEY_SIZE);
  JS_ASSERT(schnorr_legacy_sign(ec->ctx, out, msg, msg_len, priv), JS_ERR_SIGN);

  CHECK(napi_create_buffer_copy(env,
                                ec->legacy_size,
                                out,
                                NULL,
                                &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_schnorr_legacy_verify(napi_env env, napi_callback_info info) {
  napi_value argv[4];
  size_t argc = 4;
  const uint8_t *msg, *sig, *pub;
  size_t msg_len, sig_len, pub_len;
  bcrypto_wei_curve_t *ec;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 4);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&sig, &sig_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[3], (void **)&pub, &pub_len) == napi_ok);

  JS_ASSERT(schnorr_legacy_support(ec->ctx), JS_ERR_NO_SCHNORR);

  ok = sig_len == ec->legacy_size
    && schnorr_legacy_verify(ec->ctx, msg, msg_len, sig, pub, pub_len);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_schnorr_legacy_verify_batch(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint32_t i, length, item_len;
  const uint8_t **ptrs, **msgs, **pubs, **sigs;
  size_t *lens, *msg_lens, *pub_lens;
  size_t sig_len;
  bcrypto_wei_curve_t *ec;
  napi_value item, result;
  napi_value items[3];
  int ok = 0;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_array_length(env, argv[1], &length) == napi_ok);

  JS_ASSERT(schnorr_legacy_support(ec->ctx), JS_ERR_NO_SCHNORR);

  if (length == 0) {
    CHECK(napi_get_boolean(env, true, &result) == napi_ok);
    return result;
  }

  ptrs = bcrypto_malloc(3 * length * sizeof(uint8_t *));
  lens = bcrypto_malloc(2 * length * sizeof(size_t));

  if (ptrs == NULL || lens == NULL)
    goto fail;

  msgs = &ptrs[length * 0];
  pubs = &ptrs[length * 1];
  sigs = &ptrs[length * 2];
  msg_lens = &lens[length * 0];
  pub_lens = &lens[length * 1];

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

    if (sig_len != ec->legacy_size)
      goto fail;
  }

  if (ec->scratch == NULL)
    ec->scratch = wei_scratch_create(ec->ctx, SCRATCH_SIZE);

  CHECK(ec->scratch != NULL);

  ok = schnorr_legacy_verify_batch(ec->ctx, msgs, msg_lens, sigs,
                                   pubs, pub_lens, length, ec->scratch);

fail:
  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  bcrypto_free((void *)ptrs);
  bcrypto_free(lens);

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
  int ok;

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

  JS_ASSERT(out_len <= MAX_BUFFER_LENGTH, JS_ERR_ALLOC);

  JS_CHECK_ALLOC(napi_create_buffer(env, out_len, (void **)&out, &result));

  ok = scrypt_derive(out, pass, pass_len, salt, salt_len, N, r, p, out_len);

  JS_ASSERT(ok, JS_ERR_DERIVE);

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

  (void)env;

  if (!scrypt_derive(w->out, w->pass, w->pass_len,
                     w->salt, w->salt_len, w->N, w->r, w->p, w->out_len)) {
    w->error = JS_ERR_DERIVE;
  }

  torsion_cleanse(w->pass, w->pass_len);
  torsion_cleanse(w->salt, w->salt_len);
}

static void
bcrypto_scrypt_complete_(napi_env env, napi_status status, void *data) {
  bcrypto_scrypt_worker_t *w = (bcrypto_scrypt_worker_t *)data;
  napi_value result, strval, errval;

  if (w->error == NULL && status == napi_ok)
    status = napi_create_buffer_copy(env, w->out_len, w->out, NULL, &result);

  if (status != napi_ok)
    w->error = JS_ERR_DERIVE;

  if (w->error == NULL) {
    CHECK(napi_resolve_deferred(env, w->deferred, result) == napi_ok);
  } else {
    CHECK(napi_create_string_latin1(env, w->error, NAPI_AUTO_LENGTH,
                                    &strval) == napi_ok);
    CHECK(napi_create_error(env, NULL, strval, &errval) == napi_ok);
    CHECK(napi_reject_deferred(env, w->deferred, errval) == napi_ok);
  }

  CHECK(napi_delete_async_work(env, w->work) == napi_ok);

  bcrypto_free(w->pass);
  bcrypto_free(w->salt);
  bcrypto_free(w->out);
  bcrypto_free(w);
}

static napi_value
bcrypto_scrypt_derive_async(napi_env env, napi_callback_info info) {
  bcrypto_scrypt_worker_t *worker;
  napi_value argv[6];
  size_t argc = 6;
  uint8_t *out;
  uint32_t out_len;
  const uint8_t *pass, *salt;
  size_t pass_len, salt_len;
  int64_t N;
  uint32_t r, p;
  napi_value workname, result;

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

  JS_ASSERT(out_len <= MAX_BUFFER_LENGTH, JS_ERR_ALLOC);

  out = bcrypto_malloc(out_len);

  JS_ASSERT(out != NULL || out_len == 0, JS_ERR_ALLOC);

  worker = bcrypto_xmalloc(sizeof(bcrypto_scrypt_worker_t));
  worker->pass = bcrypto_malloc(pass_len);
  worker->pass_len = pass_len;
  worker->salt = bcrypto_malloc(salt_len);
  worker->salt_len = salt_len;
  worker->N = N;
  worker->r = r;
  worker->p = p;
  worker->out = out;
  worker->out_len = out_len;
  worker->error = NULL;

  if ((worker->pass == NULL && pass_len != 0)
      || (worker->salt == NULL && salt_len != 0)) {
    bcrypto_free(worker->pass);
    bcrypto_free(worker->salt);
    bcrypto_free(worker->out);
    bcrypto_free(worker);
    JS_THROW(JS_ERR_DERIVE);
  }

  if (pass_len > 0)
    memcpy(worker->pass, pass, pass_len);

  if (salt_len > 0)
    memcpy(worker->salt, salt, salt_len);

  CHECK(napi_create_string_latin1(env, "bcrypto:scrypt_derive",
                                  NAPI_AUTO_LENGTH, &workname) == napi_ok);

  CHECK(napi_create_promise(env, &worker->deferred, &result) == napi_ok);

  CHECK(napi_create_async_work(env,
                               NULL,
                               workname,
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

  (void)env;
  (void)hint;

  if (ec->scratch != NULL)
    secp256k1_scratch_space_destroy(ec->ctx, ec->scratch);

  secp256k1_context_destroy(ec->ctx);
  bcrypto_free(ec);
}

static napi_value
bcrypto_secp256k1_context_create(napi_env env, napi_callback_info info) {
  static const int flags = SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY;
  bcrypto_secp256k1_t *ec;
  secp256k1_context *ctx;
  napi_value handle;

  (void)info;

  JS_ASSERT(ctx = secp256k1_context_create(flags), JS_ERR_CONTEXT);

  ec = bcrypto_xmalloc(sizeof(bcrypto_secp256k1_t));
  ec->ctx = ctx;
  ec->scratch = NULL;

  CHECK(napi_create_external(env,
                             ec,
                             bcrypto_secp256k1_destroy,
                             NULL,
                             &handle) == napi_ok);

  return handle;
}

static napi_value
bcrypto_secp256k1_context_randomize(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  const uint8_t *entropy;
  size_t entropy_len;
  bcrypto_secp256k1_t *ec;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&entropy,
                             &entropy_len) == napi_ok);

  JS_ASSERT(entropy_len == 32, JS_ERR_ENTROPY_SIZE);
  JS_ASSERT(secp256k1_context_randomize(ec->ctx, entropy), JS_ERR_RANDOM);

  torsion_cleanse((void *)entropy, entropy_len);

  return argv[0];
}

static napi_value
bcrypto_secp256k1_seckey_generate(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  const uint8_t *entropy;
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

  CHECK(secp256k1_ec_seckey_generate(ec->ctx, out, entropy));

  CHECK(napi_create_buffer_copy(env, 32, out, NULL, &result) == napi_ok);

  torsion_cleanse((void *)entropy, entropy_len);

  return result;
}

static napi_value
bcrypto_secp256k1_seckey_verify(napi_env env, napi_callback_info info) {
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
bcrypto_secp256k1_seckey_export(napi_env env, napi_callback_info info) {
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
  JS_ASSERT(secp256k1_ec_seckey_export(ec->ctx, out, priv), JS_ERR_PRIVKEY);

  CHECK(napi_create_buffer_copy(env, 32, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_seckey_import(napi_env env, napi_callback_info info) {
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

  JS_ASSERT(secp256k1_ec_seckey_import(ec->ctx, out, priv, priv_len),
            JS_ERR_PRIVKEY);

  CHECK(napi_create_buffer_copy(env, 32, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_seckey_tweak_add(napi_env env, napi_callback_info info) {
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

  JS_ASSERT(secp256k1_ec_seckey_tweak_add(ec->ctx, out, tweak),
            JS_ERR_PRIVKEY);

  CHECK(napi_create_buffer_copy(env, 32, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_seckey_tweak_mul(napi_env env, napi_callback_info info) {
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

  JS_ASSERT(secp256k1_ec_seckey_tweak_mul(ec->ctx, out, tweak),
            JS_ERR_PRIVKEY);

  CHECK(napi_create_buffer_copy(env, 32, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_seckey_negate(napi_env env, napi_callback_info info) {
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

  JS_ASSERT(secp256k1_ec_seckey_negate(ec->ctx, out), JS_ERR_PRIVKEY);

  CHECK(napi_create_buffer_copy(env, 32, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_seckey_invert(napi_env env, napi_callback_info info) {
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

  JS_ASSERT(secp256k1_ec_seckey_invert(ec->ctx, out), JS_ERR_PRIVKEY);

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

  JS_ASSERT(pub_len > 0, JS_ERR_PUBKEY);
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

  JS_ASSERT(pub_len > 0, JS_ERR_PUBKEY);
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
  const uint8_t *pub, *entropy;
  size_t pub_len, entropy_len;
  secp256k1_pubkey pubkey;
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

  JS_ASSERT(pub_len > 0, JS_ERR_PUBKEY);
  JS_ASSERT(secp256k1_ec_pubkey_parse(ec->ctx, &pubkey, pub, pub_len),
            JS_ERR_PUBKEY);

  JS_ASSERT(secp256k1_ec_pubkey_to_hash(ec->ctx, out, &pubkey, entropy),
            JS_ERR_PUBKEY);

  CHECK(napi_create_buffer_copy(env, 64, out, NULL, &result) == napi_ok);

  torsion_cleanse((void *)entropy, entropy_len);

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

  ok = pub_len > 0 && secp256k1_ec_pubkey_parse(ec->ctx, &pubkey, pub, pub_len);

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

  JS_ASSERT(pub_len > 0, JS_ERR_PUBKEY);
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

  JS_ASSERT(pub_len > 0, JS_ERR_PUBKEY);
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

  JS_ASSERT(pub_len > 0, JS_ERR_PUBKEY);
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
  const secp256k1_pubkey **pubkeys;
  secp256k1_pubkey *pubkey_data;
  const uint8_t *pub;
  size_t pub_len;
  bool compress;
  bcrypto_secp256k1_t *ec;
  napi_value item, result;
  int ok = 0;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_array_length(env, argv[1], &length) == napi_ok);
  CHECK(napi_get_value_bool(env, argv[2], &compress) == napi_ok);

  JS_ASSERT(length != 0, JS_ERR_PUBKEY);

  pubkeys = bcrypto_malloc(length * sizeof(secp256k1_pubkey *));
  pubkey_data = bcrypto_malloc(length * sizeof(secp256k1_pubkey));

  if (pubkeys == NULL || pubkey_data == NULL)
    goto fail;

  for (i = 0; i < length; i++) {
    CHECK(napi_get_element(env, argv[1], i, &item) == napi_ok);
    CHECK(napi_get_buffer_info(env, item, (void **)&pub,
                               &pub_len) == napi_ok);

    if (pub_len == 0)
      goto fail;

    if (!secp256k1_ec_pubkey_parse(ec->ctx, &pubkey_data[i], pub, pub_len))
      goto fail;

    pubkeys[i] = &pubkey_data[i];
  }

  ok = secp256k1_ec_pubkey_combine(ec->ctx, &pubkey, pubkeys, length);

fail:
  bcrypto_free((void *)pubkeys);
  bcrypto_free(pubkey_data);

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

  JS_ASSERT(pub_len > 0, JS_ERR_PUBKEY);
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
  int ok = 0;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&sig,
                             &sig_len) == napi_ok);

  if (sig_len > 0)
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

  JS_ASSERT(sig_len > 0, JS_ERR_SIGNATURE);
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

  ok = sig_len > 0
    && ecdsa_signature_parse_der_lax(ec->ctx, &sigin, sig, sig_len)
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

  ok = sig_len == 64 && pub_len > 0
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

  ok = sig_len > 0 && pub_len > 0
    && ecdsa_signature_parse_der_lax(ec->ctx, &sigin, sig, sig_len)
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

  if (sig_len == 0)
    goto fail;

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

  JS_ASSERT(pub_len > 0, JS_ERR_PUBKEY);
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
  JS_ASSERT(secp256k1_schnorrleg_sign(ec->ctx, out, msg, msg_len, priv),
            JS_ERR_SIGN);

  CHECK(napi_create_buffer_copy(env, 64, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_schnorr_legacy_verify(napi_env env, napi_callback_info info) {
  napi_value argv[4];
  size_t argc = 4;
  const uint8_t *msg, *sig, *pub;
  size_t msg_len, sig_len, pub_len;
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

  ok = sig_len == 64 && pub_len > 0
    && secp256k1_ec_pubkey_parse(ec->ctx, &pubkey, pub, pub_len)
    && secp256k1_schnorrleg_verify(ec->ctx, sig, msg, msg_len, &pubkey);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_schnorr_legacy_verify_batch(napi_env env,
                                              napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint32_t i, length, item_len;
  const uint8_t *pub;
  size_t sig_len, pub_len;
  const uint8_t **msgs;
  size_t *msg_lens;
  const unsigned char **sigs;
  const secp256k1_pubkey **pubkeys;
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

  msgs = bcrypto_malloc(length * sizeof(unsigned char *));
  msg_lens = bcrypto_malloc(length * sizeof(size_t));
  sigs = bcrypto_malloc(length * sizeof(unsigned char *));
  pubkeys = bcrypto_malloc(length * sizeof(secp256k1_pubkey *));
  pubkey_data = bcrypto_malloc(length * sizeof(secp256k1_pubkey));

  if (msgs == NULL || msg_lens == NULL || sigs == NULL
      || pubkeys == NULL || pubkey_data == NULL) {
    goto fail;
  }

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

    CHECK(napi_get_buffer_info(env, items[2], (void **)&pub,
                               &pub_len) == napi_ok);

    if (sig_len != 64)
      goto fail;

    if (pub_len == 0)
      goto fail;

    if (!secp256k1_ec_pubkey_parse(ec->ctx, &pubkey_data[i], pub, pub_len))
      goto fail;

    pubkeys[i] = &pubkey_data[i];
  }

  /* See:
   *   https://github.com/ElementsProject/secp256k1-zkp/issues/69
   *   https://github.com/bitcoin-core/secp256k1/pull/638
   */
  if (ec->scratch == NULL)
    ec->scratch = secp256k1_scratch_space_create(ec->ctx, 1024 * 1024);

  CHECK(ec->scratch != NULL);

  ok = secp256k1_schnorrleg_verify_batch(ec->ctx,
                                         ec->scratch,
                                         sigs,
                                         msgs,
                                         msg_lens,
                                         pubkeys,
                                         length);

fail:
  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  bcrypto_free((void *)msgs);
  bcrypto_free(msg_lens);
  bcrypto_free((void *)sigs);
  bcrypto_free((void *)pubkeys);
  bcrypto_free(pubkey_data);

  return result;
}

static napi_value
bcrypto_secp256k1_xonly_seckey_export(napi_env env, napi_callback_info info) {
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
  JS_ASSERT(secp256k1_ec_seckey_export(ec->ctx, d, priv), JS_ERR_PRIVKEY);
  JS_ASSERT(secp256k1_ec_pubkey_create(ec->ctx, &pubkey, priv), JS_ERR_PRIVKEY);

  CHECK(secp256k1_xonly_pubkey_from_pubkey(ec->ctx, &xonly, &negated, &pubkey));

  if (negated)
    CHECK(secp256k1_ec_seckey_negate(ec->ctx, d));

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
bcrypto_secp256k1_xonly_seckey_tweak_add(napi_env env,
                                         napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  const uint8_t *priv, *tweak;
  size_t priv_len, tweak_len;
  bcrypto_secp256k1_t *ec;
  secp256k1_keypair pair;
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

  JS_ASSERT(secp256k1_keypair_create(ec->ctx, &pair, priv), JS_ERR_PRIVKEY);

  JS_ASSERT(secp256k1_keypair_xonly_tweak_add(ec->ctx, &pair, tweak),
            JS_ERR_PRIVKEY);

  CHECK(napi_create_buffer_copy(env, 32, pair.data, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_xonly_create(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint8_t out[32];
  secp256k1_keypair pair;
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

  JS_ASSERT(secp256k1_keypair_create(ec->ctx, &pair, priv), JS_ERR_PRIVKEY);

  CHECK(secp256k1_keypair_xonly_pub(ec->ctx, &pubkey, NULL, &pair));

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
  const uint8_t *pub, *entropy;
  size_t pub_len, entropy_len;
  secp256k1_xonly_pubkey pubkey;
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

  CHECK(napi_create_buffer_copy(env, 64, out, NULL, &result) == napi_ok);

  torsion_cleanse((void *)entropy, entropy_len);

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
  secp256k1_xonly_pubkey xonly;
  secp256k1_pubkey pubkey;
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

  JS_ASSERT(secp256k1_xonly_pubkey_parse(ec->ctx, &xonly, pub), JS_ERR_PUBKEY);

  JS_ASSERT(secp256k1_xonly_pubkey_tweak_add(ec->ctx, &pubkey, &xonly, tweak),
            JS_ERR_PUBKEY);

  CHECK(secp256k1_xonly_pubkey_from_pubkey(ec->ctx, &xonly, NULL, &pubkey));

  secp256k1_xonly_pubkey_serialize(ec->ctx, out, &xonly);

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
  secp256k1_xonly_pubkey xonly;
  secp256k1_pubkey pubkey;
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

  JS_ASSERT(secp256k1_xonly_pubkey_parse(ec->ctx, &xonly, pub), JS_ERR_PUBKEY);

  JS_ASSERT(secp256k1_xonly_pubkey_tweak_add(ec->ctx, &pubkey, &xonly, tweak),
            JS_ERR_PUBKEY);

  CHECK(secp256k1_xonly_pubkey_from_pubkey(ec->ctx, &xonly, &negated, &pubkey));

  secp256k1_xonly_pubkey_serialize(ec->ctx, out, &xonly);

  CHECK(napi_create_buffer_copy(env, 32, out, NULL, &outval) == napi_ok);
  CHECK(napi_get_boolean(env, negated, &negval) == napi_ok);

  CHECK(napi_create_array_with_length(env, 2, &result) == napi_ok);
  CHECK(napi_set_element(env, result, 0, outval) == napi_ok);
  CHECK(napi_set_element(env, result, 1, negval) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_xonly_tweak_check(napi_env env, napi_callback_info info) {
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

  ok = secp256k1_xonly_pubkey_tweak_add_check(ec->ctx,
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
  secp256k1_xonly_pubkey xonly;
  secp256k1_pubkey pubkey;
  uint32_t i, length;
  const secp256k1_xonly_pubkey **pubkeys;
  secp256k1_xonly_pubkey *pubkey_data;
  const uint8_t *pub;
  size_t pub_len;
  bcrypto_secp256k1_t *ec;
  napi_value item, result;
  int ok = 0;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_array_length(env, argv[1], &length) == napi_ok);

  JS_ASSERT(length != 0, JS_ERR_PUBKEY);

  pubkeys = bcrypto_malloc(length * sizeof(secp256k1_xonly_pubkey *));
  pubkey_data = bcrypto_malloc(length * sizeof(secp256k1_xonly_pubkey));

  if (pubkeys == NULL || pubkey_data == NULL)
    goto fail;

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

  ok = secp256k1_ec_pubkey_combine(ec->ctx, &pubkey,
                                   (const secp256k1_pubkey *const *)pubkeys,
                                   length);
fail:
  bcrypto_free((void *)pubkeys);
  bcrypto_free(pubkey_data);

  JS_ASSERT(ok, JS_ERR_PUBKEY);

  CHECK(secp256k1_xonly_pubkey_from_pubkey(ec->ctx, &xonly, NULL, &pubkey));

  secp256k1_xonly_pubkey_serialize(ec->ctx, out, &xonly);

  CHECK(napi_create_buffer_copy(env, 32, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_schnorr_sign(napi_env env, napi_callback_info info) {
  napi_value argv[4];
  size_t argc = 4;
  uint8_t out[64];
  const uint8_t *msg, *priv, *aux;
  size_t msg_len, priv_len, aux_len;
  bcrypto_secp256k1_t *ec;
  secp256k1_keypair pair;
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
  JS_ASSERT(aux_len == 0 || aux_len == 32, JS_ERR_ENTROPY_SIZE);

  JS_ASSERT(secp256k1_keypair_create(ec->ctx, &pair, priv), JS_ERR_PRIVKEY);

  if (aux_len == 0)
    aux = NULL;

  ok = secp256k1_schnorrsig_sign(ec->ctx, out, msg, &pair, NULL, (void *)aux);

  JS_ASSERT(ok, JS_ERR_SIGN);

  CHECK(napi_create_buffer_copy(env, 64, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_schnorr_verify(napi_env env, napi_callback_info info) {
  napi_value argv[4];
  size_t argc = 4;
  const uint8_t *msg, *sig, *pub;
  size_t msg_len, sig_len, pub_len;
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
    && secp256k1_xonly_pubkey_parse(ec->ctx, &pubkey, pub)
    && secp256k1_schnorrsig_verify(ec->ctx, sig, msg, &pubkey);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_secp256k1_schnorr_verify_batch(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  uint32_t i, length, item_len;
  const uint8_t *pub;
  size_t msg_len, sig_len, pub_len;
  const uint8_t **msgs;
  const uint8_t **sigs;
  const secp256k1_xonly_pubkey **pubkeys;
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

  msgs = bcrypto_malloc(length * sizeof(unsigned char *));
  sigs = bcrypto_malloc(length * sizeof(unsigned char *));
  pubkeys = bcrypto_malloc(length * sizeof(secp256k1_xonly_pubkey *));
  pubkey_data = bcrypto_malloc(length * sizeof(secp256k1_xonly_pubkey));

  if (msgs == NULL || sigs == NULL || pubkeys == NULL || pubkey_data == NULL)
    goto fail;

  for (i = 0; i < length; i++) {
    CHECK(napi_get_element(env, argv[1], i, &item) == napi_ok);
    CHECK(napi_get_array_length(env, item, &item_len) == napi_ok);
    CHECK(item_len == 3);

    CHECK(napi_get_element(env, item, 0, &items[0]) == napi_ok);
    CHECK(napi_get_element(env, item, 1, &items[1]) == napi_ok);
    CHECK(napi_get_element(env, item, 2, &items[2]) == napi_ok);

    CHECK(napi_get_buffer_info(env, items[0], (void **)&msgs[i],
                               &msg_len) == napi_ok);

    CHECK(napi_get_buffer_info(env, items[1], (void **)&sigs[i],
                               &sig_len) == napi_ok);

    CHECK(napi_get_buffer_info(env, items[2], (void **)&pub,
                               &pub_len) == napi_ok);

    if (msg_len != 32 || sig_len != 64 || pub_len != 32)
      goto fail;

    if (!secp256k1_xonly_pubkey_parse(ec->ctx, &pubkey_data[i], pub))
      goto fail;

    pubkeys[i] = &pubkey_data[i];
  }

#if defined(BCRYPTO_SECP256K1_USE_VERIFY_BATCH)
  /* See:
   *   https://github.com/ElementsProject/secp256k1-zkp/issues/69
   *   https://github.com/bitcoin-core/secp256k1/pull/638
   */
  if (ec->scratch == NULL)
    ec->scratch = secp256k1_scratch_space_create(ec->ctx, 1024 * 1024);

  CHECK(ec->scratch != NULL);

  ok = secp256k1_schnorrsig_verify_batch(ec->ctx,
                                         ec->scratch,
                                         sigs,
                                         msgs,
                                         pubkeys,
                                         length);
#else
  for (i = 0; i < length; i++) {
    if (!secp256k1_schnorrsig_verify(ec->ctx, sigs[i], msgs[i], pubkeys[i]))
      goto fail;
  }

  ok = 1;
#endif

fail:
  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  bcrypto_free((void *)msgs);
  bcrypto_free((void *)sigs);
  bcrypto_free((void *)pubkeys);
  bcrypto_free(pubkey_data);

  return result;
}

static int
ecdh_hash_function_xonly(unsigned char *out,
                         const unsigned char *x,
                         const unsigned char *y,
                         void *data) {
  int *negated = data;

  memcpy(out, x, 32);

  if (negated != NULL)
    *negated = (y[31] & 1);

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
                      (const secp256k1_pubkey *)&pubkey,
                      priv,
                      hashfp,
                      NULL);

  JS_ASSERT(ok, JS_ERR_PUBKEY);

  CHECK(napi_create_buffer_copy(env, 32, out, NULL, &result) == napi_ok);

  return result;
}
#endif /* BCRYPTO_USE_SECP256K1 */

/*
 * Secret Box
 */

static napi_value
bcrypto_secretbox_seal(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t *out;
  size_t out_len;
  const uint8_t *msg, *key, *nonce;
  size_t msg_len, key_len, nonce_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&key, &key_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&nonce,
                             &nonce_len) == napi_ok);

  JS_ASSERT(key_len == 32, JS_ERR_KEY_SIZE);
  JS_ASSERT(nonce_len == 24, JS_ERR_NONCE_SIZE);

  out_len = SECRETBOX_SEAL_SIZE(msg_len);

  JS_ASSERT(out_len <= MAX_BUFFER_LENGTH, JS_ERR_ALLOC);

  JS_CHECK_ALLOC(napi_create_buffer(env, out_len, (void **)&out, &result));

  secretbox_seal(out, msg, msg_len, key, nonce);

  return result;
}

static napi_value
bcrypto_secretbox_open(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t *out;
  size_t out_len;
  const uint8_t *sealed, *key, *nonce;
  size_t sealed_len, key_len, nonce_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&sealed,
                             &sealed_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&key, &key_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&nonce,
                             &nonce_len) == napi_ok);

  JS_ASSERT(key_len == 32, JS_ERR_KEY_SIZE);
  JS_ASSERT(nonce_len == 24, JS_ERR_NONCE_SIZE);

  out_len = SECRETBOX_OPEN_SIZE(sealed_len);

  JS_ASSERT(out_len <= MAX_BUFFER_LENGTH, JS_ERR_ALLOC);

  JS_CHECK_ALLOC(napi_create_buffer(env, out_len, (void **)&out, &result));

  JS_ASSERT(secretbox_open(out, sealed, sealed_len, key, nonce),
            JS_ERR_DECRYPT);

  return result;
}

static napi_value
bcrypto_secretbox_derive(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  uint8_t out[32];
  const uint8_t *secret;
  size_t secret_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&secret,
                             &secret_len) == napi_ok);

  JS_ASSERT(secret_len == 32, JS_ERR_SECRET_SIZE);

  secretbox_derive(out, secret);

  CHECK(napi_create_buffer_copy(env, 32, out, NULL, &result) == napi_ok);

  return result;
}

/*
 * Siphash
 */

static napi_value
bcrypto_siphash_sum(napi_env env, napi_callback_info info) {
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

  out = siphash_sum(msg, msg_len, key);

  CHECK(napi_create_uint32(env, out >> 32, &hival) == napi_ok);
  CHECK(napi_create_uint32(env, out, &loval) == napi_ok);

  CHECK(napi_create_array_with_length(env, 2, &result) == napi_ok);
  CHECK(napi_set_element(env, result, 0, hival) == napi_ok);
  CHECK(napi_set_element(env, result, 1, loval) == napi_ok);

  return result;
}

static napi_value
bcrypto_siphash_mod(napi_env env, napi_callback_info info) {
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
  out = siphash_mod(msg, msg_len, key, mod);

  CHECK(napi_create_uint32(env, out >> 32, &hival) == napi_ok);
  CHECK(napi_create_uint32(env, out, &loval) == napi_ok);

  CHECK(napi_create_array_with_length(env, 2, &result) == napi_ok);
  CHECK(napi_set_element(env, result, 0, hival) == napi_ok);
  CHECK(napi_set_element(env, result, 1, loval) == napi_ok);

  return result;
}

static napi_value
bcrypto_siphash128_sum(napi_env env, napi_callback_info info) {
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
  out = siphash128_sum(num, key);

  CHECK(napi_create_uint32(env, out >> 32, &hival) == napi_ok);
  CHECK(napi_create_uint32(env, out, &loval) == napi_ok);

  CHECK(napi_create_array_with_length(env, 2, &result) == napi_ok);
  CHECK(napi_set_element(env, result, 0, hival) == napi_ok);
  CHECK(napi_set_element(env, result, 1, loval) == napi_ok);

  return result;
}

static napi_value
bcrypto_siphash256_sum(napi_env env, napi_callback_info info) {
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
  out = siphash256_sum(num, key);

  CHECK(napi_create_uint32(env, out >> 32, &hival) == napi_ok);
  CHECK(napi_create_uint32(env, out, &loval) == napi_ok);

  CHECK(napi_create_array_with_length(env, 2, &result) == napi_ok);
  CHECK(napi_set_element(env, result, 0, hival) == napi_ok);
  CHECK(napi_set_element(env, result, 1, loval) == napi_ok);

  return result;
}

/*
 * Short Weierstrass Curve
 */

static void
bcrypto_wei_curve_destroy(napi_env env, void *data, void *hint) {
  bcrypto_wei_curve_t *ec = (bcrypto_wei_curve_t *)data;

  (void)env;
  (void)hint;

  if (ec->scratch != NULL)
    wei_scratch_destroy(ec->ctx, ec->scratch);

  wei_curve_destroy(ec->ctx);
  bcrypto_free(ec);
}

static napi_value
bcrypto_wei_curve_create(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  uint32_t type;
  bcrypto_wei_curve_t *ec;
  wei_curve_t *ctx;
  napi_value handle;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_value_uint32(env, argv[0], &type) == napi_ok);

  JS_ASSERT(ctx = wei_curve_create(type), JS_ERR_CONTEXT);

  ec = bcrypto_xmalloc(sizeof(bcrypto_wei_curve_t));
  ec->ctx = ctx;
  ec->scratch = NULL;
  ec->scalar_size = wei_curve_scalar_size(ec->ctx);
  ec->scalar_bits = wei_curve_scalar_bits(ec->ctx);
  ec->field_size = wei_curve_field_size(ec->ctx);
  ec->field_bits = wei_curve_field_bits(ec->ctx);
  ec->sig_size = ecdsa_sig_size(ec->ctx);
  ec->legacy_size = schnorr_legacy_sig_size(ec->ctx);
  ec->schnorr_size = schnorr_sig_size(ec->ctx);

  CHECK(napi_create_external(env,
                             ec,
                             bcrypto_wei_curve_destroy,
                             NULL,
                             &handle) == napi_ok);

  return handle;
}

static napi_value
bcrypto_wei_curve_field_size(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  bcrypto_wei_curve_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_create_uint32(env, ec->field_size, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_wei_curve_field_bits(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  bcrypto_wei_curve_t *ec;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_create_uint32(env, ec->field_bits, &result) == napi_ok);

  return result;
}

static napi_value
bcrypto_wei_curve_randomize(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  const uint8_t *entropy;
  size_t entropy_len;
  bcrypto_wei_curve_t *ec;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 2);
  CHECK(napi_get_value_external(env, argv[0], (void **)&ec) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&entropy,
                             &entropy_len) == napi_ok);

  JS_ASSERT(entropy_len == ENTROPY_SIZE, JS_ERR_ENTROPY_SIZE);

  wei_curve_randomize(ec->ctx, entropy);

  torsion_cleanse((void *)entropy, entropy_len);

  return argv[0];
}

/*
 * Module
 */

#ifndef NAPI_MODULE_INIT
#define NAPI_MODULE_INIT()                                        \
static napi_value bcrypto_init(napi_env env, napi_value exports); \
NAPI_MODULE(NODE_GYP_MODULE_NAME, bcrypto_init)                   \
static napi_value bcrypto_init(napi_env env, napi_value exports)
#endif

NAPI_MODULE_INIT() {
  size_t i;

  static const struct {
    const char *name;
    napi_callback callback;
  } funcs[] = {
#define F(name) { #name, bcrypto_ ## name }
    /* AEAD */
    F(aead_create),
    F(aead_init),
    F(aead_aad),
    F(aead_encrypt),
    F(aead_decrypt),
    F(aead_auth),
    F(aead_final),
    F(aead_destroy),
    F(aead_verify),
    F(aead_static_encrypt),
    F(aead_static_decrypt),
    F(aead_static_auth),

    /* ARC4 */
    F(arc4_create),
    F(arc4_init),
    F(arc4_crypt),
    F(arc4_destroy),

    /* Base16 */
    F(base16_encode),
    F(base16_decode),
    F(base16_test),

    /* Base16 (Little Endian) */
    F(base16le_encode),
    F(base16le_decode),
    F(base16le_test),

    /* Base32 */
    F(base32_encode),
    F(base32_decode),
    F(base32_test),

    /* Base32-Hex */
    F(base32hex_encode),
    F(base32hex_decode),
    F(base32hex_test),

    /* Base58 */
    F(base58_encode),
    F(base58_decode),
    F(base58_test),

    /* Base64 */
    F(base64_encode),
    F(base64_decode),
    F(base64_test),

    /* Base64-URL */
    F(base64url_encode),
    F(base64url_decode),
    F(base64url_test),

    /* Bcrypt */
    F(bcrypt_hash192),
    F(bcrypt_hash256),
    F(bcrypt_pbkdf),
    F(bcrypt_pbkdf_async),
    F(bcrypt_derive),
    F(bcrypt_generate),
    F(bcrypt_generate_with_salt64),
    F(bcrypt_verify),

    /* Bech32 */
    F(bech32_serialize),
    F(bech32_deserialize),
    F(bech32_is),
    F(bech32_convert_bits),
    F(bech32_encode),
    F(bech32_decode),
    F(bech32_test),

    /* BLAKE2b */
    F(blake2b_create),
    F(blake2b_init),
    F(blake2b_update),
    F(blake2b_final),
    F(blake2b_digest),
    F(blake2b_root),
    F(blake2b_multi),

    /* BLAKE2s */
    F(blake2s_create),
    F(blake2s_init),
    F(blake2s_update),
    F(blake2s_final),
    F(blake2s_digest),
    F(blake2s_root),
    F(blake2s_multi),

    /* Cash32 */
    F(cash32_serialize),
    F(cash32_deserialize),
    F(cash32_is),
    F(cash32_convert_bits),
    F(cash32_encode),
    F(cash32_decode),
    F(cash32_test),

    /* ChaCha20 */
    F(chacha20_create),
    F(chacha20_init),
    F(chacha20_crypt),
    F(chacha20_destroy),
    F(chacha20_derive),

    /* Cipher */
    F(cipher_create),
    F(cipher_init),
    F(cipher_set_padding),
    F(cipher_set_aad),
    F(cipher_set_ccm),
    F(cipher_set_tag),
    F(cipher_get_tag),
    F(cipher_update),
    F(cipher_crypt),
    F(cipher_final),
    F(cipher_destroy),
    F(cipher_encrypt),
    F(cipher_decrypt),

    /* Cleanse */
    F(cleanse),

    /* CTR-DRBG */
    F(ctr_drbg_create),
    F(ctr_drbg_init),
    F(ctr_drbg_reseed),
    F(ctr_drbg_generate),

    /* DSA */
    F(dsa_params_create),
    F(dsa_params_generate),
    F(dsa_params_generate_async),
    F(dsa_params_bits),
    F(dsa_params_qbits),
    F(dsa_params_verify),
    F(dsa_params_import),
    F(dsa_params_export),
    F(dsa_privkey_create),
    F(dsa_privkey_bits),
    F(dsa_privkey_qbits),
    F(dsa_privkey_verify),
    F(dsa_privkey_import),
    F(dsa_privkey_export),
    F(dsa_pubkey_create),
    F(dsa_pubkey_bits),
    F(dsa_pubkey_qbits),
    F(dsa_pubkey_verify),
    F(dsa_pubkey_import),
    F(dsa_pubkey_export),
    F(dsa_signature_export),
    F(dsa_signature_import),
    F(dsa_sign),
    F(dsa_sign_der),
    F(dsa_verify),
    F(dsa_verify_der),
    F(dsa_derive),

    /* EB2K */
    F(eb2k_derive),

    /* ECDH */
    F(ecdh_privkey_generate),
    F(ecdh_privkey_verify),
    F(ecdh_privkey_export),
    F(ecdh_privkey_import),
    F(ecdh_pubkey_create),
    F(ecdh_pubkey_convert),
    F(ecdh_pubkey_from_uniform),
    F(ecdh_pubkey_to_uniform),
    F(ecdh_pubkey_from_hash),
    F(ecdh_pubkey_to_hash),
    F(ecdh_pubkey_verify),
    F(ecdh_pubkey_export),
    F(ecdh_pubkey_import),
    F(ecdh_pubkey_is_small),
    F(ecdh_pubkey_has_torsion),
    F(ecdh_derive),

    /* ECDSA */
    F(ecdsa_privkey_generate),
    F(ecdsa_privkey_verify),
    F(ecdsa_privkey_export),
    F(ecdsa_privkey_import),
    F(ecdsa_privkey_tweak_add),
    F(ecdsa_privkey_tweak_mul),
    F(ecdsa_privkey_negate),
    F(ecdsa_privkey_invert),
    F(ecdsa_pubkey_create),
    F(ecdsa_pubkey_convert),
    F(ecdsa_pubkey_from_uniform),
    F(ecdsa_pubkey_to_uniform),
    F(ecdsa_pubkey_from_hash),
    F(ecdsa_pubkey_to_hash),
    F(ecdsa_pubkey_verify),
    F(ecdsa_pubkey_export),
    F(ecdsa_pubkey_import),
    F(ecdsa_pubkey_tweak_add),
    F(ecdsa_pubkey_tweak_mul),
    F(ecdsa_pubkey_combine),
    F(ecdsa_pubkey_negate),
    F(ecdsa_signature_normalize),
    F(ecdsa_signature_normalize_der),
    F(ecdsa_signature_export),
    F(ecdsa_signature_import),
    F(ecdsa_is_low_s),
    F(ecdsa_is_low_der),
    F(ecdsa_sign),
    F(ecdsa_sign_recoverable),
    F(ecdsa_sign_der),
    F(ecdsa_sign_recoverable_der),
    F(ecdsa_verify),
    F(ecdsa_verify_der),
    F(ecdsa_recover),
    F(ecdsa_recover_der),
    F(ecdsa_derive),

    /* EdDSA */
    F(eddsa_pubkey_size),
    F(eddsa_privkey_generate),
    F(eddsa_privkey_verify),
    F(eddsa_privkey_export),
    F(eddsa_privkey_import),
    F(eddsa_privkey_expand),
    F(eddsa_privkey_convert),
    F(eddsa_scalar_generate),
    F(eddsa_scalar_verify),
    F(eddsa_scalar_clamp),
    F(eddsa_scalar_is_zero),
    F(eddsa_scalar_tweak_add),
    F(eddsa_scalar_tweak_mul),
    F(eddsa_scalar_reduce),
    F(eddsa_scalar_negate),
    F(eddsa_scalar_invert),
    F(eddsa_pubkey_create),
    F(eddsa_pubkey_from_scalar),
    F(eddsa_pubkey_convert),
    F(eddsa_pubkey_from_uniform),
    F(eddsa_pubkey_to_uniform),
    F(eddsa_pubkey_from_hash),
    F(eddsa_pubkey_to_hash),
    F(eddsa_pubkey_verify),
    F(eddsa_pubkey_export),
    F(eddsa_pubkey_import),
    F(eddsa_pubkey_is_infinity),
    F(eddsa_pubkey_is_small),
    F(eddsa_pubkey_has_torsion),
    F(eddsa_pubkey_tweak_add),
    F(eddsa_pubkey_tweak_mul),
    F(eddsa_pubkey_combine),
    F(eddsa_pubkey_negate),
    F(eddsa_sign),
    F(eddsa_sign_with_scalar),
    F(eddsa_sign_tweak_add),
    F(eddsa_sign_tweak_mul),
    F(eddsa_verify),
    F(eddsa_verify_single),
    F(eddsa_verify_batch),
    F(eddsa_derive),
    F(eddsa_derive_with_scalar),

    /* Edwards Curve */
    F(edwards_curve_create),
    F(edwards_curve_field_size),
    F(edwards_curve_field_bits),
    F(edwards_curve_randomize),

    /* Hash */
    F(hash_create),
    F(hash_init),
    F(hash_update),
    F(hash_final),
    F(hash_digest),
    F(hash_root),
    F(hash_multi),

    /* Hash-DRBG */
    F(hash_drbg_create),
    F(hash_drbg_init),
    F(hash_drbg_reseed),
    F(hash_drbg_generate),

    /* HKDF */
    F(hkdf_extract),
    F(hkdf_expand),

    /* HMAC */
    F(hmac_create),
    F(hmac_init),
    F(hmac_update),
    F(hmac_final),
    F(hmac_digest),

    /* HMAC-DRBG */
    F(hmac_drbg_create),
    F(hmac_drbg_init),
    F(hmac_drbg_reseed),
    F(hmac_drbg_generate),

    /* Keccak */
    F(keccak_create),
    F(keccak_init),
    F(keccak_update),
    F(keccak_final),
    F(keccak_digest),
    F(keccak_root),
    F(keccak_multi),

    /* Montgomery Curve */
    F(mont_curve_create),
    F(mont_curve_field_size),
    F(mont_curve_field_bits),

    /* Murmur3 */
    F(murmur3_sum),
    F(murmur3_tweak),

    /* PBKDF2 */
    F(pbkdf2_derive),
    F(pbkdf2_derive_async),

    /* PGPDF */
    F(pgpdf_derive_simple),
    F(pgpdf_derive_salted),
    F(pgpdf_derive_iterated),

    /* Poly1305 */
    F(poly1305_create),
    F(poly1305_init),
    F(poly1305_update),
    F(poly1305_final),
    F(poly1305_destroy),
    F(poly1305_verify),

    /* RNG */
    F(getentropy),
    F(getrandom),
    F(random),
    F(uniform),

    /* RSA */
    F(rsa_privkey_generate),
    F(rsa_privkey_generate_async),
    F(rsa_privkey_bits),
    F(rsa_privkey_verify),
    F(rsa_privkey_import),
    F(rsa_privkey_export),
    F(rsa_pubkey_create),
    F(rsa_pubkey_bits),
    F(rsa_pubkey_verify),
    F(rsa_pubkey_import),
    F(rsa_pubkey_export),
    F(rsa_sign),
    F(rsa_verify),
    F(rsa_encrypt),
    F(rsa_decrypt),
    F(rsa_sign_pss),
    F(rsa_verify_pss),
    F(rsa_encrypt_oaep),
    F(rsa_decrypt_oaep),
    F(rsa_veil),
    F(rsa_unveil),

    /* Salsa20 */
    F(salsa20_create),
    F(salsa20_init),
    F(salsa20_crypt),
    F(salsa20_destroy),
    F(salsa20_derive),

    /* Schnorr */
    F(schnorr_privkey_generate),
    F(schnorr_privkey_verify),
    F(schnorr_privkey_export),
    F(schnorr_privkey_import),
    F(schnorr_privkey_tweak_add),
    F(schnorr_privkey_tweak_mul),
    F(schnorr_privkey_invert),
    F(schnorr_pubkey_create),
    F(schnorr_pubkey_from_uniform),
    F(schnorr_pubkey_to_uniform),
    F(schnorr_pubkey_from_hash),
    F(schnorr_pubkey_to_hash),
    F(schnorr_pubkey_verify),
    F(schnorr_pubkey_export),
    F(schnorr_pubkey_import),
    F(schnorr_pubkey_tweak_add),
    F(schnorr_pubkey_tweak_mul),
    F(schnorr_pubkey_tweak_sum),
    F(schnorr_pubkey_tweak_check),
    F(schnorr_pubkey_combine),
    F(schnorr_sign),
    F(schnorr_verify),
    F(schnorr_verify_batch),
    F(schnorr_derive),

    /* Schnorr Legacy */
    F(schnorr_legacy_sign),
    F(schnorr_legacy_verify),
    F(schnorr_legacy_verify_batch),

    /* Scrypt */
    F(scrypt_derive),
    F(scrypt_derive_async),

#ifdef BCRYPTO_USE_SECP256K1
    /* Secp256k1 */
    F(secp256k1_context_create),
    F(secp256k1_context_randomize),
    F(secp256k1_seckey_generate),
    F(secp256k1_seckey_verify),
    F(secp256k1_seckey_export),
    F(secp256k1_seckey_import),
    F(secp256k1_seckey_tweak_add),
    F(secp256k1_seckey_tweak_mul),
    F(secp256k1_seckey_negate),
    F(secp256k1_seckey_invert),
    F(secp256k1_pubkey_create),
    F(secp256k1_pubkey_convert),
    F(secp256k1_pubkey_from_uniform),
    F(secp256k1_pubkey_to_uniform),
    F(secp256k1_pubkey_from_hash),
    F(secp256k1_pubkey_to_hash),
    F(secp256k1_pubkey_verify),
    F(secp256k1_pubkey_export),
    F(secp256k1_pubkey_import),
    F(secp256k1_pubkey_tweak_add),
    F(secp256k1_pubkey_tweak_mul),
    F(secp256k1_pubkey_combine),
    F(secp256k1_pubkey_negate),
    F(secp256k1_signature_normalize),
    F(secp256k1_signature_normalize_der),
    F(secp256k1_signature_export),
    F(secp256k1_signature_import),
    F(secp256k1_is_low_s),
    F(secp256k1_is_low_der),
    F(secp256k1_sign),
    F(secp256k1_sign_recoverable),
    F(secp256k1_sign_der),
    F(secp256k1_sign_recoverable_der),
    F(secp256k1_verify),
    F(secp256k1_verify_der),
    F(secp256k1_recover),
    F(secp256k1_recover_der),
    F(secp256k1_derive),
    F(secp256k1_schnorr_legacy_sign),
    F(secp256k1_schnorr_legacy_verify),
    F(secp256k1_schnorr_legacy_verify_batch),
    F(secp256k1_xonly_seckey_export),
    F(secp256k1_xonly_seckey_tweak_add),
    F(secp256k1_xonly_create),
    F(secp256k1_xonly_from_uniform),
    F(secp256k1_xonly_to_uniform),
    F(secp256k1_xonly_from_hash),
    F(secp256k1_xonly_to_hash),
    F(secp256k1_xonly_verify),
    F(secp256k1_xonly_export),
    F(secp256k1_xonly_import),
    F(secp256k1_xonly_tweak_add),
    F(secp256k1_xonly_tweak_mul),
    F(secp256k1_xonly_tweak_sum),
    F(secp256k1_xonly_tweak_check),
    F(secp256k1_xonly_combine),
    F(secp256k1_schnorr_sign),
    F(secp256k1_schnorr_verify),
    F(secp256k1_schnorr_verify_batch),
    F(secp256k1_xonly_derive),
#endif

    /* Secret Box */
    F(secretbox_seal),
    F(secretbox_open),
    F(secretbox_derive),

    /* Siphash */
    F(siphash_sum),
    F(siphash_mod),
    F(siphash128_sum),
    F(siphash256_sum),

    /* Short Weierstrass Curve */
    F(wei_curve_create),
    F(wei_curve_field_size),
    F(wei_curve_field_bits),
    F(wei_curve_randomize)
#undef F
  };

  static const struct {
    const char *name;
    int value;
  } flags[] = {
#ifdef BCRYPTO_USE_SECP256K1
    { "USE_SECP256K1", 1 },
#else
    { "USE_SECP256K1", 0 },
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
