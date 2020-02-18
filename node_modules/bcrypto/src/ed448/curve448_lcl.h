/*
 * Copyright 2017-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#ifndef _BCRYPTO_CURVE448_LCL_H
# define _BCRYPTO_CURVE448_LCL_H

#if defined(__cplusplus)
extern "C" {
#endif

# include "curve448utils.h"

int bcrypto_x448(uint8_t out_shared_key[56], const uint8_t private_key[56],
     const uint8_t peer_public_value[56]);

void bcrypto_x448_public_from_private(uint8_t out_public_value[56],
                const uint8_t private_key[56]);

int bcrypto_ed448_sign(uint8_t *out_sig, const uint8_t *message, size_t message_len,
         const uint8_t public_key[57], const uint8_t private_key[57],
         const uint8_t *context, size_t context_len);

int bcrypto_ed448_verify(const uint8_t *message, size_t message_len,
         const uint8_t signature[114], const uint8_t public_key[57],
         const uint8_t *context, size_t context_len);

int bcrypto_ed448ph_sign(uint8_t *out_sig, const uint8_t hash[64],
         const uint8_t public_key[57], const uint8_t private_key[57],
         const uint8_t *context, size_t context_len);

int bcrypto_ed448ph_verify(const uint8_t hash[64], const uint8_t signature[114],
           const uint8_t public_key[57], const uint8_t *context,
           size_t context_len);

int bcrypto_ed448_public_from_private(uint8_t out_public_key[57],
                const uint8_t private_key[57]);

#if defined(__cplusplus)
}
#endif

#endif        /* _BCRYPTO_CURVE448_LCL_H */
