/*
 * Copyright 2017-2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2015-2016 Cryptography Research, Inc.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Originally written by Mike Hamburg
 */
#include <string.h>
#include "openssl/crypto.h"
#include "curve448_lcl.h"
#include "word.h"
#include "ed448.h"
#include "internal/numbers.h"
#include "../keccak/keccak.h"

#define BCRYPTO_COFACTOR 4

static bcrypto_c448_error_t oneshot_hash(uint8_t *out, size_t outlen,
                 const uint8_t *in, size_t inlen)
{
  bcrypto_keccak_ctx ctx;

  if (!bcrypto_keccak_init(&ctx, 256))
    return BCRYPTO_C448_FAILURE;

  bcrypto_keccak_update(&ctx, in, inlen);

  if (!bcrypto_keccak_final(&ctx, 0x1f, out, outlen, NULL))
    return BCRYPTO_C448_FAILURE;

  return BCRYPTO_C448_SUCCESS;
}

static void clamp(uint8_t secret_scalar_ser[BCRYPTO_EDDSA_448_PRIVATE_BYTES])
{
  secret_scalar_ser[0] &= -BCRYPTO_COFACTOR;
  secret_scalar_ser[BCRYPTO_EDDSA_448_PRIVATE_BYTES - 1] = 0;
  secret_scalar_ser[BCRYPTO_EDDSA_448_PRIVATE_BYTES - 2] |= 0x80;
}

static void half_clamp(uint8_t secret_scalar_ser[BCRYPTO_C448_SCALAR_BYTES])
{
  secret_scalar_ser[0] &= -BCRYPTO_COFACTOR;
  secret_scalar_ser[BCRYPTO_EDDSA_448_PRIVATE_BYTES - 2] |= 0x80;
}

static bcrypto_c448_error_t hash_init_with_dom(bcrypto_keccak_ctx *hashctx,
                     uint8_t prehashed,
                     uint8_t for_prehash,
                     const uint8_t *context,
                     size_t context_len)
{
  const char *dom_s = "SigEd448";
  uint8_t dom[2];

  if (context_len > UINT8_MAX)
    return BCRYPTO_C448_FAILURE;

  dom[0] = (uint8_t)(2 - (prehashed == 0 ? 1 : 0)
             - (for_prehash == 0 ? 1 : 0));
  dom[1] = (uint8_t)context_len;

  if (!bcrypto_keccak_init(hashctx, 256))
    return BCRYPTO_C448_FAILURE;

  bcrypto_keccak_update(hashctx, (void *)dom_s, strlen(dom_s));
  bcrypto_keccak_update(hashctx, dom, sizeof(dom));
  bcrypto_keccak_update(hashctx, context, context_len);

  return BCRYPTO_C448_SUCCESS;
}

/* In this file because it uses the hash */
bcrypto_c448_error_t bcrypto_c448_ed448_convert_private_key_to_x448(
              uint8_t x[BCRYPTO_X448_PRIVATE_BYTES],
              const uint8_t ed [BCRYPTO_EDDSA_448_PRIVATE_BYTES])
{
  /* pass the private key through oneshot_hash function */
  /* and keep the first BCRYPTO_X448_PRIVATE_BYTES bytes */
  bcrypto_c448_error_t ret = oneshot_hash(x, BCRYPTO_X448_PRIVATE_BYTES, ed,
                                          BCRYPTO_EDDSA_448_PRIVATE_BYTES);

  if (ret != BCRYPTO_C448_SUCCESS)
    return ret;

  half_clamp(x);

  return ret;
}

bcrypto_c448_error_t bcrypto_c448_ed448_scalar_tweak_add(
            uint8_t out[BCRYPTO_C448_SCALAR_BYTES],
            const uint8_t scalar[BCRYPTO_C448_SCALAR_BYTES],
            const uint8_t tweak[BCRYPTO_C448_SCALAR_BYTES]) {
  bcrypto_curve448_scalar_t scalar_scalar;
  bcrypto_curve448_scalar_t tweak_scalar;

  bcrypto_curve448_scalar_decode(scalar_scalar, &scalar[0]);
  bcrypto_curve448_scalar_decode(tweak_scalar, &tweak[0]);

  bcrypto_curve448_scalar_add(scalar_scalar, scalar_scalar, tweak_scalar);
  bcrypto_curve448_scalar_encode(out, scalar_scalar);

  bcrypto_curve448_scalar_destroy(scalar_scalar);
  bcrypto_curve448_scalar_destroy(tweak_scalar);

  return BCRYPTO_C448_SUCCESS;
}

bcrypto_c448_error_t bcrypto_c448_ed448_scalar_tweak_mul(
            uint8_t out[BCRYPTO_C448_SCALAR_BYTES],
            const uint8_t scalar[BCRYPTO_C448_SCALAR_BYTES],
            const uint8_t tweak[BCRYPTO_C448_SCALAR_BYTES]) {
  bcrypto_curve448_scalar_t scalar_scalar;
  bcrypto_curve448_scalar_t tweak_scalar;

  bcrypto_curve448_scalar_decode(scalar_scalar, &scalar[0]);
  bcrypto_curve448_scalar_decode(tweak_scalar, &tweak[0]);

  bcrypto_curve448_scalar_mul(scalar_scalar, scalar_scalar, tweak_scalar);
  bcrypto_curve448_scalar_encode(out, scalar_scalar);

  bcrypto_curve448_scalar_destroy(scalar_scalar);
  bcrypto_curve448_scalar_destroy(tweak_scalar);

  return BCRYPTO_C448_SUCCESS;
}

bcrypto_c448_error_t bcrypto_c448_ed448_scalar_negate(
            uint8_t out[BCRYPTO_C448_SCALAR_BYTES],
            const uint8_t scalar[BCRYPTO_C448_SCALAR_BYTES]) {
  bcrypto_curve448_scalar_t scalar_scalar;

  bcrypto_curve448_scalar_decode(scalar_scalar, &scalar[0]);

  bcrypto_curve448_scalar_negate(scalar_scalar, scalar_scalar);
  bcrypto_curve448_scalar_encode(out, scalar_scalar);

  bcrypto_curve448_scalar_destroy(scalar_scalar);

  return BCRYPTO_C448_SUCCESS;
}

bcrypto_c448_error_t bcrypto_c448_ed448_scalar_inverse(
            uint8_t out[BCRYPTO_C448_SCALAR_BYTES],
            const uint8_t scalar[BCRYPTO_C448_SCALAR_BYTES]) {
  bcrypto_curve448_scalar_t scalar_scalar;

  bcrypto_curve448_scalar_decode(scalar_scalar, &scalar[0]);

  bcrypto_c448_error_t error =
    bcrypto_curve448_scalar_invert(scalar_scalar, scalar_scalar);

  if (error == BCRYPTO_C448_SUCCESS)
    bcrypto_curve448_scalar_encode(out, scalar_scalar);

  bcrypto_curve448_scalar_destroy(scalar_scalar);

  return error;
}

bcrypto_c448_error_t bcrypto_c448_ed448_public_key_tweak_add(
            uint8_t out[BCRYPTO_EDDSA_448_PUBLIC_BYTES],
            const uint8_t pubkey[BCRYPTO_EDDSA_448_PUBLIC_BYTES],
            const uint8_t tweak[BCRYPTO_C448_SCALAR_BYTES]) {
  bcrypto_curve448_scalar_t tweak_scalar;
  bcrypto_curve448_point_t pk_point, tweak_point;

  bcrypto_c448_error_t error =
    bcrypto_curve448_point_decode_like_eddsa_and_mul_by_ratio(pk_point, pubkey);

  if (error != BCRYPTO_C448_SUCCESS)
    return error;

  bcrypto_curve448_scalar_decode(tweak_scalar, &tweak[0]);

  bcrypto_curve448_precomputed_scalarmul(tweak_point, bcrypto_curve448_precomputed_base, tweak_scalar);
  bcrypto_curve448_point_add(pk_point, pk_point, tweak_point);

  // We have to divide the new point by the ratio due to decaf's encoding.
  bcrypto_curve448_scalar_t ratio_scalar = {{{BCRYPTO_C448_EDDSA_ENCODE_RATIO}}};
  bcrypto_curve448_scalar_invert(ratio_scalar, ratio_scalar);
  bcrypto_curve448_point_t ratio_point;
  bcrypto_curve448_precomputed_scalarmul(ratio_point, bcrypto_curve448_precomputed_base, ratio_scalar);
  bcrypto_curve448_point_scalarmul(pk_point, pk_point, ratio_scalar);

  bcrypto_curve448_point_mul_by_ratio_and_encode_like_eddsa(out, pk_point);

  bcrypto_curve448_scalar_destroy(tweak_scalar);
  bcrypto_curve448_point_destroy(tweak_point);
  bcrypto_curve448_point_destroy(pk_point);

  return BCRYPTO_C448_SUCCESS;
}

bcrypto_c448_error_t bcrypto_c448_ed448_public_key_tweak_mul(
            uint8_t out[BCRYPTO_EDDSA_448_PUBLIC_BYTES],
            const uint8_t pubkey[BCRYPTO_EDDSA_448_PUBLIC_BYTES],
            const uint8_t tweak[BCRYPTO_C448_SCALAR_BYTES]) {
  bcrypto_curve448_scalar_t tweak_scalar;
  bcrypto_curve448_point_t pk_point;
  unsigned int c;

  bcrypto_c448_error_t error =
    bcrypto_curve448_point_decode_like_eddsa_and_mul_by_ratio(pk_point, pubkey);

  if (error != BCRYPTO_C448_SUCCESS)
    return error;

  bcrypto_curve448_scalar_decode(tweak_scalar, &tweak[0]);

  for (c = 1; c < BCRYPTO_C448_EDDSA_ENCODE_RATIO; c <<= 1)
    bcrypto_curve448_scalar_halve(tweak_scalar, tweak_scalar);

  bcrypto_curve448_point_scalarmul(pk_point, pk_point, tweak_scalar);
  bcrypto_curve448_point_mul_by_ratio_and_encode_like_eddsa(out, pk_point);

  bcrypto_curve448_scalar_destroy(tweak_scalar);
  bcrypto_curve448_point_destroy(pk_point);

  return BCRYPTO_C448_SUCCESS;
}

bcrypto_c448_error_t bcrypto_c448_ed448_public_key_add(
            uint8_t out[BCRYPTO_EDDSA_448_PUBLIC_BYTES],
            const uint8_t pubkey1[BCRYPTO_EDDSA_448_PUBLIC_BYTES],
            const uint8_t pubkey2[BCRYPTO_EDDSA_448_PUBLIC_BYTES]) {
  bcrypto_curve448_point_t pk1_point, pk2_point;

  bcrypto_c448_error_t error1 =
    bcrypto_curve448_point_decode_like_eddsa_and_mul_by_ratio(pk1_point, pubkey1);

  if (error1 != BCRYPTO_C448_SUCCESS)
    return error1;

  bcrypto_c448_error_t error2 =
    bcrypto_curve448_point_decode_like_eddsa_and_mul_by_ratio(pk2_point, pubkey2);

  if (error2 != BCRYPTO_C448_SUCCESS) {
    bcrypto_curve448_point_destroy(pk1_point);
    return error2;
  }

  bcrypto_curve448_point_add(pk1_point, pk1_point, pk2_point);

  // We have to divide the new point by the ratio due to decaf's encoding.
  bcrypto_curve448_scalar_t ratio_scalar = {{{BCRYPTO_C448_EDDSA_ENCODE_RATIO}}};
  bcrypto_curve448_scalar_invert(ratio_scalar, ratio_scalar);
  bcrypto_curve448_point_t ratio_point;
  bcrypto_curve448_precomputed_scalarmul(ratio_point, bcrypto_curve448_precomputed_base, ratio_scalar);
  bcrypto_curve448_point_scalarmul(pk1_point, pk1_point, ratio_scalar);

  bcrypto_curve448_point_mul_by_ratio_and_encode_like_eddsa(out, pk1_point);

  bcrypto_curve448_point_destroy(pk1_point);
  bcrypto_curve448_point_destroy(pk2_point);

  return BCRYPTO_C448_SUCCESS;
}

bcrypto_c448_error_t bcrypto_c448_ed448_public_key_negate(
            uint8_t out[BCRYPTO_EDDSA_448_PUBLIC_BYTES],
            const uint8_t pubkey[BCRYPTO_EDDSA_448_PUBLIC_BYTES]) {
  bcrypto_curve448_point_t pk_point;

  bcrypto_c448_error_t error =
    bcrypto_curve448_point_decode_like_eddsa_and_mul_by_ratio(pk_point, pubkey);

  if (error != BCRYPTO_C448_SUCCESS)
    return error;

  bcrypto_curve448_point_negate(pk_point, pk_point);

  // We have to divide the new point by the ratio due to decaf's encoding.
  bcrypto_curve448_scalar_t ratio_scalar = {{{BCRYPTO_C448_EDDSA_ENCODE_RATIO}}};
  bcrypto_curve448_scalar_invert(ratio_scalar, ratio_scalar);
  bcrypto_curve448_point_t ratio_point;
  bcrypto_curve448_precomputed_scalarmul(ratio_point, bcrypto_curve448_precomputed_base, ratio_scalar);
  bcrypto_curve448_point_scalarmul(pk_point, pk_point, ratio_scalar);

  bcrypto_curve448_point_mul_by_ratio_and_encode_like_eddsa(out, pk_point);

  bcrypto_curve448_point_destroy(pk_point);

  return BCRYPTO_C448_SUCCESS;
}

bcrypto_c448_error_t bcrypto_c448_ed448_derive_public_key_with_scalar(
            uint8_t pubkey[BCRYPTO_EDDSA_448_PUBLIC_BYTES],
            const uint8_t scalar[BCRYPTO_C448_SCALAR_BYTES])
{
  /* only this much used for keygen */
  bcrypto_curve448_scalar_t secret_scalar;
  bcrypto_curve448_point_t p;
  unsigned int c;

  bcrypto_curve448_scalar_decode(secret_scalar, &scalar[0]);

  /*
   * Since we are going to mul_by_cofactor during encoding, divide by it
   * here. However, the EdDSA base point is not the same as the decaf base
   * point if the sigma isogeny is in use: the EdDSA base point is on
   * Etwist_d/(1-d) and the decaf base point is on Etwist_d, and when
   * converted it effectively picks up a factor of 2 from the isogenies.  So
   * we might start at 2 instead of 1.
   */
  for (c = 1; c < BCRYPTO_C448_EDDSA_ENCODE_RATIO; c <<= 1)
    bcrypto_curve448_scalar_halve(secret_scalar, secret_scalar);

  bcrypto_curve448_precomputed_scalarmul(p,
    bcrypto_curve448_precomputed_base, secret_scalar);

  bcrypto_curve448_point_mul_by_ratio_and_encode_like_eddsa(pubkey, p);

  /* Cleanup */
  bcrypto_curve448_scalar_destroy(secret_scalar);
  bcrypto_curve448_point_destroy(p);

  return BCRYPTO_C448_SUCCESS;
}

bcrypto_c448_error_t bcrypto_c448_ed448_derive_public_key(
            uint8_t pubkey[BCRYPTO_EDDSA_448_PUBLIC_BYTES],
            const uint8_t privkey[BCRYPTO_EDDSA_448_PRIVATE_BYTES])
{
  /* only this much used for keygen */
  uint8_t secret_scalar_ser[BCRYPTO_EDDSA_448_PRIVATE_BYTES];

  if (!oneshot_hash(secret_scalar_ser, sizeof(secret_scalar_ser), privkey,
                    BCRYPTO_EDDSA_448_PRIVATE_BYTES)) {
    return BCRYPTO_C448_FAILURE;
  }

  clamp(secret_scalar_ser);

  bcrypto_c448_error_t ret =
    bcrypto_c448_ed448_derive_public_key_with_scalar(pubkey, secret_scalar_ser);

  OPENSSL_cleanse(secret_scalar_ser, sizeof(secret_scalar_ser));

  return ret;
}

bcrypto_c448_error_t bcrypto_c448_ed448_derive_with_scalar(
            uint8_t out[BCRYPTO_EDDSA_448_PUBLIC_BYTES],
            const uint8_t pubkey[BCRYPTO_EDDSA_448_PUBLIC_BYTES],
            const uint8_t scalar[BCRYPTO_C448_SCALAR_BYTES])
{
  bcrypto_curve448_scalar_t secret_scalar;
  bcrypto_curve448_point_t p;
  unsigned int c;

  if (bcrypto_curve448_point_decode_like_eddsa_and_mul_by_ratio(p, pubkey)
      != BCRYPTO_C448_SUCCESS) {
    return BCRYPTO_C448_FAILURE;
  }

  bcrypto_curve448_scalar_decode(secret_scalar, &scalar[0]);

  for (c = 1; c < BCRYPTO_C448_EDDSA_ENCODE_RATIO; c <<= 1)
    bcrypto_curve448_scalar_halve(secret_scalar, secret_scalar);

  bcrypto_curve448_point_scalarmul(p, p, secret_scalar);
  bcrypto_curve448_point_mul_by_ratio_and_encode_like_eddsa(out, p);

  bcrypto_curve448_scalar_destroy(secret_scalar);
  bcrypto_curve448_point_destroy(p);

  return BCRYPTO_C448_SUCCESS;
}

bcrypto_c448_error_t bcrypto_c448_ed448_derive(
            uint8_t out[BCRYPTO_EDDSA_448_PUBLIC_BYTES],
            const uint8_t pubkey[BCRYPTO_EDDSA_448_PUBLIC_BYTES],
            const uint8_t privkey[BCRYPTO_EDDSA_448_PRIVATE_BYTES])
{
  uint8_t secret_scalar_ser[BCRYPTO_EDDSA_448_PRIVATE_BYTES];

  if (!oneshot_hash(secret_scalar_ser, sizeof(secret_scalar_ser), privkey,
                    BCRYPTO_EDDSA_448_PRIVATE_BYTES)) {
    return BCRYPTO_C448_FAILURE;
  }

  clamp(secret_scalar_ser);

  bcrypto_c448_error_t ret =
    bcrypto_c448_ed448_derive_with_scalar(out, pubkey, secret_scalar_ser);

  OPENSSL_cleanse(secret_scalar_ser, sizeof(secret_scalar_ser));

  return ret;
}

bcrypto_c448_error_t bcrypto_c448_ed448_sign_with_scalar(
            uint8_t signature[BCRYPTO_EDDSA_448_SIGNATURE_BYTES],
            const uint8_t raw[BCRYPTO_EDDSA_448_PRIVATE_BYTES * 2],
            const uint8_t pubkey[BCRYPTO_EDDSA_448_PUBLIC_BYTES],
            const uint8_t *message, size_t message_len,
            uint8_t prehashed, const uint8_t *context,
            size_t context_len)
{
  bcrypto_curve448_scalar_t secret_scalar;
  bcrypto_keccak_ctx hashctx;
  bcrypto_c448_error_t ret = BCRYPTO_C448_FAILURE;
  bcrypto_curve448_scalar_t nonce_scalar;
  uint8_t nonce_point[BCRYPTO_EDDSA_448_PUBLIC_BYTES] = { 0 };
  unsigned int c;
  bcrypto_curve448_scalar_t challenge_scalar;

  {
    /*
     * Schedule the secret key, First BCRYPTO_EDDSA_448_PRIVATE_BYTES is serialised
     * secret scalar,next BCRYPTO_EDDSA_448_PRIVATE_BYTES bytes is the seed.
     */
    uint8_t expanded[BCRYPTO_EDDSA_448_PRIVATE_BYTES * 2];

    memcpy(&expanded[0], &raw[0], sizeof(expanded));

    bcrypto_curve448_scalar_decode_long(secret_scalar, expanded,
                  BCRYPTO_EDDSA_448_PRIVATE_BYTES);

    /* Hash to create the nonce */
    if (!hash_init_with_dom(&hashctx, prehashed, 0, context, context_len)) {
      OPENSSL_cleanse(expanded, sizeof(expanded));
      goto err;
    }
    bcrypto_keccak_update(&hashctx, expanded + BCRYPTO_EDDSA_448_PRIVATE_BYTES,
                     BCRYPTO_EDDSA_448_PRIVATE_BYTES);
    bcrypto_keccak_update(&hashctx, message, message_len);
    OPENSSL_cleanse(expanded, sizeof(expanded));
  }

  /* Decode the nonce */
  {
    uint8_t nonce[2 * BCRYPTO_EDDSA_448_PRIVATE_BYTES];

    if (!bcrypto_keccak_final(&hashctx, 0x1f, nonce, sizeof(nonce), NULL))
      return BCRYPTO_C448_FAILURE;
    bcrypto_curve448_scalar_decode_long(nonce_scalar, nonce, sizeof(nonce));
    OPENSSL_cleanse(nonce, sizeof(nonce));
  }

  {
    /* Scalarmul to create the nonce-point */
    bcrypto_curve448_scalar_t nonce_scalar_2;
    bcrypto_curve448_point_t p;

    bcrypto_curve448_scalar_halve(nonce_scalar_2, nonce_scalar);
    for (c = 2; c < BCRYPTO_C448_EDDSA_ENCODE_RATIO; c <<= 1)
      bcrypto_curve448_scalar_halve(nonce_scalar_2, nonce_scalar_2);

    bcrypto_curve448_precomputed_scalarmul(p, bcrypto_curve448_precomputed_base,
                     nonce_scalar_2);
    bcrypto_curve448_point_mul_by_ratio_and_encode_like_eddsa(nonce_point, p);
    bcrypto_curve448_point_destroy(p);
    bcrypto_curve448_scalar_destroy(nonce_scalar_2);
  }

  {
    uint8_t challenge[2 * BCRYPTO_EDDSA_448_PRIVATE_BYTES];

    /* Compute the challenge */
    if (!hash_init_with_dom(&hashctx, prehashed, 0, context, context_len))
      goto err;

    bcrypto_keccak_update(&hashctx, nonce_point, sizeof(nonce_point));
    bcrypto_keccak_update(&hashctx, pubkey, BCRYPTO_EDDSA_448_PUBLIC_BYTES);
    bcrypto_keccak_update(&hashctx, message, message_len);

    if (!bcrypto_keccak_final(&hashctx, 0x1f, challenge,
                              sizeof(challenge), NULL)) {
      goto err;
    }

    bcrypto_curve448_scalar_decode_long(challenge_scalar, challenge,
                  sizeof(challenge));
    OPENSSL_cleanse(challenge, sizeof(challenge));
  }

  bcrypto_curve448_scalar_mul(challenge_scalar, challenge_scalar, secret_scalar);
  bcrypto_curve448_scalar_add(challenge_scalar, challenge_scalar, nonce_scalar);

  OPENSSL_cleanse(signature, BCRYPTO_EDDSA_448_SIGNATURE_BYTES);
  memcpy(signature, nonce_point, sizeof(nonce_point));
  bcrypto_curve448_scalar_encode(&signature[BCRYPTO_EDDSA_448_PUBLIC_BYTES],
               challenge_scalar);

  bcrypto_curve448_scalar_destroy(secret_scalar);
  bcrypto_curve448_scalar_destroy(nonce_scalar);
  bcrypto_curve448_scalar_destroy(challenge_scalar);

  ret = BCRYPTO_C448_SUCCESS;
 err:
  return ret;
}

bcrypto_c448_error_t bcrypto_c448_ed448_sign(
            uint8_t signature[BCRYPTO_EDDSA_448_SIGNATURE_BYTES],
            const uint8_t privkey[BCRYPTO_EDDSA_448_PRIVATE_BYTES],
            const uint8_t pubkey[BCRYPTO_EDDSA_448_PUBLIC_BYTES],
            const uint8_t *message, size_t message_len,
            uint8_t prehashed, const uint8_t *context,
            size_t context_len)
{
  /*
   * Schedule the secret key, First BCRYPTO_EDDSA_448_PRIVATE_BYTES is serialised
   * secret scalar,next BCRYPTO_EDDSA_448_PRIVATE_BYTES bytes is the seed.
   */
  uint8_t expanded[BCRYPTO_EDDSA_448_PRIVATE_BYTES * 2];

  if (!oneshot_hash(expanded, sizeof(expanded), privkey,
                    BCRYPTO_EDDSA_448_PRIVATE_BYTES)) {
    return BCRYPTO_C448_FAILURE;
  }

  clamp(expanded);

  bcrypto_c448_error_t ret = bcrypto_c448_ed448_sign_with_scalar(signature,
    expanded, pubkey, message, message_len,
    prehashed, context, context_len);

  OPENSSL_cleanse(expanded, sizeof(expanded));

  return ret;
}

bcrypto_c448_error_t bcrypto_c448_ed448_sign_tweak_add(
            uint8_t signature[BCRYPTO_EDDSA_448_SIGNATURE_BYTES],
            const uint8_t privkey[BCRYPTO_EDDSA_448_PRIVATE_BYTES],
            const uint8_t pubkey[BCRYPTO_EDDSA_448_PUBLIC_BYTES],
            const uint8_t tweak[BCRYPTO_C448_SCALAR_BYTES],
            const uint8_t *message, size_t message_len,
            uint8_t prehashed, const uint8_t *context,
            size_t context_len)
{
  /*
   * Schedule the secret key, First BCRYPTO_EDDSA_448_PRIVATE_BYTES is serialised
   * secret scalar,next BCRYPTO_EDDSA_448_PRIVATE_BYTES bytes is the seed.
   */
  uint8_t expanded[BCRYPTO_EDDSA_448_PRIVATE_BYTES * 2];
  uint8_t expanded2[BCRYPTO_EDDSA_448_PRIVATE_BYTES * 2];
  uint8_t pubkey2[BCRYPTO_EDDSA_448_PUBLIC_BYTES];
  bcrypto_c448_error_t ret = BCRYPTO_C448_SUCCESS;

  if (!oneshot_hash(expanded, sizeof(expanded), privkey,
                    BCRYPTO_EDDSA_448_PRIVATE_BYTES)) {
    ret = BCRYPTO_C448_FAILURE;
    goto fail;
  }

  clamp(expanded);

  ret = bcrypto_c448_ed448_scalar_tweak_add(expanded, expanded, tweak);

  if (ret != BCRYPTO_C448_SUCCESS)
    goto fail;

  ret = bcrypto_c448_ed448_public_key_tweak_add(pubkey2, pubkey, tweak);

  if (ret != BCRYPTO_C448_SUCCESS)
    goto fail;

  // Preimage:
  memcpy(&expanded2[0], &expanded[BCRYPTO_EDDSA_448_PRIVATE_BYTES], BCRYPTO_EDDSA_448_PRIVATE_BYTES);
  memcpy(&expanded2[BCRYPTO_EDDSA_448_PRIVATE_BYTES], &tweak[0], BCRYPTO_C448_SCALAR_BYTES);
  expanded2[sizeof(expanded2) - 1] = 0;

  if (!oneshot_hash(expanded2, BCRYPTO_EDDSA_448_PRIVATE_BYTES,
                    expanded2, sizeof(expanded2) - 1)) {
    ret = BCRYPTO_C448_FAILURE;
    goto fail;
  }

  memcpy(&expanded[BCRYPTO_EDDSA_448_PRIVATE_BYTES], &expanded2[0], BCRYPTO_EDDSA_448_PRIVATE_BYTES);

  ret = bcrypto_c448_ed448_sign_with_scalar(signature,
    expanded, pubkey2, message, message_len,
    prehashed, context, context_len);

fail:
  OPENSSL_cleanse(expanded, sizeof(expanded));
  OPENSSL_cleanse(expanded2, sizeof(expanded2));
  OPENSSL_cleanse(pubkey2, sizeof(pubkey2));
  return ret;
}

bcrypto_c448_error_t bcrypto_c448_ed448_sign_tweak_mul(
            uint8_t signature[BCRYPTO_EDDSA_448_SIGNATURE_BYTES],
            const uint8_t privkey[BCRYPTO_EDDSA_448_PRIVATE_BYTES],
            const uint8_t pubkey[BCRYPTO_EDDSA_448_PUBLIC_BYTES],
            const uint8_t tweak[BCRYPTO_C448_SCALAR_BYTES],
            const uint8_t *message, size_t message_len,
            uint8_t prehashed, const uint8_t *context,
            size_t context_len)
{
  /*
   * Schedule the secret key, First BCRYPTO_EDDSA_448_PRIVATE_BYTES is serialised
   * secret scalar,next BCRYPTO_EDDSA_448_PRIVATE_BYTES bytes is the seed.
   */
  uint8_t expanded[BCRYPTO_EDDSA_448_PRIVATE_BYTES * 2];
  uint8_t expanded2[BCRYPTO_EDDSA_448_PRIVATE_BYTES * 2];
  uint8_t pubkey2[BCRYPTO_EDDSA_448_PUBLIC_BYTES];
  bcrypto_c448_error_t ret = BCRYPTO_C448_SUCCESS;

  if (!oneshot_hash(expanded, sizeof(expanded), privkey,
                    BCRYPTO_EDDSA_448_PRIVATE_BYTES)) {
    ret = BCRYPTO_C448_FAILURE;
    goto fail;
  }

  clamp(expanded);

  ret = bcrypto_c448_ed448_scalar_tweak_mul(expanded, expanded, tweak);

  if (ret != BCRYPTO_C448_SUCCESS)
    goto fail;

  ret = bcrypto_c448_ed448_public_key_tweak_mul(pubkey2, pubkey, tweak);

  if (ret != BCRYPTO_C448_SUCCESS)
    goto fail;

  // Preimage:
  memcpy(&expanded2[0], &expanded[BCRYPTO_EDDSA_448_PRIVATE_BYTES], BCRYPTO_EDDSA_448_PRIVATE_BYTES);
  memcpy(&expanded2[BCRYPTO_EDDSA_448_PRIVATE_BYTES], &tweak[0], BCRYPTO_C448_SCALAR_BYTES);
  expanded2[sizeof(expanded2) - 1] = 0;

  if (!oneshot_hash(expanded2, BCRYPTO_EDDSA_448_PRIVATE_BYTES,
                    expanded2, sizeof(expanded2) - 1)) {
    ret = BCRYPTO_C448_FAILURE;
    goto fail;
  }

  memcpy(&expanded[BCRYPTO_EDDSA_448_PRIVATE_BYTES], &expanded2[0], BCRYPTO_EDDSA_448_PRIVATE_BYTES);

  ret = bcrypto_c448_ed448_sign_with_scalar(signature,
    expanded, pubkey2, message, message_len,
    prehashed, context, context_len);

fail:
  OPENSSL_cleanse(expanded, sizeof(expanded));
  OPENSSL_cleanse(expanded2, sizeof(expanded2));
  OPENSSL_cleanse(pubkey2, sizeof(pubkey2));
  return ret;
}

bcrypto_c448_error_t bcrypto_c448_ed448_sign_prehash(
            uint8_t signature[BCRYPTO_EDDSA_448_SIGNATURE_BYTES],
            const uint8_t privkey[BCRYPTO_EDDSA_448_PRIVATE_BYTES],
            const uint8_t pubkey[BCRYPTO_EDDSA_448_PUBLIC_BYTES],
            const uint8_t hash[64], const uint8_t *context,
            size_t context_len)
{
  return bcrypto_c448_ed448_sign(signature, privkey, pubkey, hash, 64, 1, context,
               context_len);
}

bcrypto_c448_error_t bcrypto_c448_ed448_verify(
          const uint8_t signature[BCRYPTO_EDDSA_448_SIGNATURE_BYTES],
          const uint8_t pubkey[BCRYPTO_EDDSA_448_PUBLIC_BYTES],
          const uint8_t *message, size_t message_len,
          uint8_t prehashed, const uint8_t *context,
          uint8_t context_len)
{
  bcrypto_curve448_point_t pk_point, r_point;
  bcrypto_c448_error_t error =
    bcrypto_curve448_point_decode_like_eddsa_and_mul_by_ratio(pk_point, pubkey);
  bcrypto_curve448_scalar_t challenge_scalar;
  bcrypto_curve448_scalar_t response_scalar;

  if (BCRYPTO_C448_SUCCESS != error)
    return error;

  error =
    bcrypto_curve448_point_decode_like_eddsa_and_mul_by_ratio(r_point, signature);
  if (BCRYPTO_C448_SUCCESS != error)
    return error;

  {
    /* Compute the challenge */
    bcrypto_keccak_ctx hashctx;
    uint8_t challenge[2 * BCRYPTO_EDDSA_448_PRIVATE_BYTES];

    if (!hash_init_with_dom(&hashctx, prehashed, 0, context, context_len))
      return BCRYPTO_C448_FAILURE;

    bcrypto_keccak_update(&hashctx, signature, BCRYPTO_EDDSA_448_PUBLIC_BYTES);
    bcrypto_keccak_update(&hashctx, pubkey, BCRYPTO_EDDSA_448_PUBLIC_BYTES);
    bcrypto_keccak_update(&hashctx, message, message_len);

    if (!bcrypto_keccak_final(&hashctx, 0x1f, challenge,
                              sizeof(challenge), NULL)) {
      return BCRYPTO_C448_FAILURE;
    }

    bcrypto_curve448_scalar_decode_long(challenge_scalar, challenge,
                  sizeof(challenge));
    OPENSSL_cleanse(challenge, sizeof(challenge));
  }
  bcrypto_curve448_scalar_sub(challenge_scalar, bcrypto_curve448_scalar_zero,
            challenge_scalar);

  bcrypto_curve448_scalar_decode_long(response_scalar,
                &signature[BCRYPTO_EDDSA_448_PUBLIC_BYTES],
                BCRYPTO_EDDSA_448_PRIVATE_BYTES);

  /* pk_point = -c(x(P)) + (cx + k)G = kG */
  bcrypto_curve448_base_double_scalarmul_non_secret(pk_point,
                        response_scalar,
                        pk_point, challenge_scalar);
  return bcrypto_c448_succeed_if(bcrypto_curve448_point_eq(pk_point, r_point));
}

bcrypto_c448_error_t bcrypto_c448_ed448_verify_prehash(
          const uint8_t signature[BCRYPTO_EDDSA_448_SIGNATURE_BYTES],
          const uint8_t pubkey[BCRYPTO_EDDSA_448_PUBLIC_BYTES],
          const uint8_t hash[64], const uint8_t *context,
          uint8_t context_len)
{
  return bcrypto_c448_ed448_verify(signature, pubkey, hash, 64, 1, context,
               context_len);
}

int bcrypto_ed448_sign(uint8_t *out_sig, const uint8_t *message, size_t message_len,
         const uint8_t public_key[57], const uint8_t private_key[57],
         const uint8_t *context, size_t context_len)
{
  return bcrypto_c448_ed448_sign(out_sig, private_key, public_key, message,
               message_len, 0, context, context_len)
    == BCRYPTO_C448_SUCCESS;
}

int bcrypto_ed448_verify(const uint8_t *message, size_t message_len,
         const uint8_t signature[114], const uint8_t public_key[57],
         const uint8_t *context, size_t context_len)
{
  return bcrypto_c448_ed448_verify(signature, public_key, message, message_len, 0,
               context, (uint8_t)context_len) == BCRYPTO_C448_SUCCESS;
}

int bcrypto_ed448ph_sign(uint8_t *out_sig, const uint8_t hash[64],
         const uint8_t public_key[57], const uint8_t private_key[57],
         const uint8_t *context, size_t context_len)
{
  return bcrypto_c448_ed448_sign_prehash(out_sig, private_key, public_key, hash,
                   context, context_len) == BCRYPTO_C448_SUCCESS;

}

int bcrypto_ed448ph_verify(const uint8_t hash[64], const uint8_t signature[114],
           const uint8_t public_key[57], const uint8_t *context,
           size_t context_len)
{
  return bcrypto_c448_ed448_verify_prehash(signature, public_key, hash, context,
                   (uint8_t)context_len) == BCRYPTO_C448_SUCCESS;
}

int bcrypto_ed448_public_from_private(uint8_t out_public_key[57],
                const uint8_t private_key[57])
{
  return bcrypto_c448_ed448_derive_public_key(out_public_key, private_key)
    == BCRYPTO_C448_SUCCESS;
}
