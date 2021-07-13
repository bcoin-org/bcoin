/**********************************************************************
 * Copyright (c) 2018 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_SCHNORRLEG_H
#define SECP256K1_SCHNORRLEG_H

#include "secp256k1.h"

#ifdef __cplusplus
extern "C" {
#endif

/** This module implements a variant of Schnorr signatures compliant with
 * BIP-schnorr
 * (https://github.com/sipa/bips/blob/d194620/bip-schnorr.mediawiki).
 */

/** Create a Schnorr signature.
 *
 * Returns 1 on success, 0 on failure.
 *  Args:    ctx: pointer to a context object, initialized for signing (cannot be NULL)
 *  Out:     sig: pointer to the returned signature (cannot be NULL)
 *  In:      msg: the message hash being signed
 *       msg_len: message length
 *        seckey: pointer to a 32-byte secret key (cannot be NULL)
 */
SECP256K1_API int
secp256k1_schnorrleg_sign(const secp256k1_context *ctx,
                          unsigned char *sig,
                          const unsigned char *msg,
                          size_t msg_len,
                          const unsigned char *seckey) SECP256K1_ARG_NONNULL(1)
                                                       SECP256K1_ARG_NONNULL(2)
                                                       SECP256K1_ARG_NONNULL(5);

/** Verify a Schnorr signature.
 *
 *  Returns: 1: correct signature
 *           0: incorrect or unparseable signature
 *  Args:    ctx: a secp256k1 context object, initialized for verification.
 *  In:      sig: the signature being verified (cannot be NULL)
 *           msg: the message hash being verified
 *       msg_len: message length
 *        pubkey: pointer to a public key to verify with (cannot be NULL)
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int
secp256k1_schnorrleg_verify(const secp256k1_context *ctx,
                            const unsigned char *sig,
                            const unsigned char *msg,
                            size_t msg_len,
                            const secp256k1_pubkey *pubkey) SECP256K1_ARG_NONNULL(1)
                                                            SECP256K1_ARG_NONNULL(2)
                                                            SECP256K1_ARG_NONNULL(5);

/** Verifies a set of Schnorr signatures.
 *
 * Returns 1 if all succeeded, 0 otherwise. In particular, returns 1 if n_sigs is 0.
 *
 *  Args:    ctx: a secp256k1 context object, initialized for verification.
 *       scratch: scratch space used for the multiexponentiation
 *  In:     sigs: array of signatures, or NULL if there are no signatures
 *          msgs: array of messages, or NULL if there are no signatures
 *      msg_lens: array of message lengths, or NULL if there are no signatures
 *           pks: array of public keys, or NULL if there are no signatures
 *           len: number of signatures in above arrays. Must be smaller than
 *                2^31 and smaller than half the maximum size_t value. Must be 0
 *                if above arrays are NULL.
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int
secp256k1_schnorrleg_verify_batch(const secp256k1_context *ctx,
                                  secp256k1_scratch_space *scratch,
                                  const unsigned char *const *sigs,
                                  const unsigned char *const *msgs,
                                  const size_t *msg_lens,
                                  const secp256k1_pubkey *const *pks,
                                  size_t len) SECP256K1_ARG_NONNULL(1)
                                              SECP256K1_ARG_NONNULL(2);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_SCHNORRLEG_H */
