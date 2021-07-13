#ifndef SECP256K1_ELLIGATOR_H
#define SECP256K1_ELLIGATOR_H

#include "secp256k1.h"
#include "secp256k1_extrakeys.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Hash bytes to a point using the Shallue-van de Woestijne map.
 *
 *  Returns: 1: the byte array was sucessfully mapped.
 *           0: invalid arguments.
 *  Args:    ctx:      pointer to a context object (cannot be NULL).
 *  Out:     pubkey:   pointer to a pubkey object.
 *  In:      bytes32:  pointer to a raw 32-byte field element.
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int
secp256k1_ec_pubkey_from_uniform(const secp256k1_context *ctx,
                                 secp256k1_pubkey *pubkey,
                                 const unsigned char *bytes32) SECP256K1_ARG_NONNULL(1)
                                                               SECP256K1_ARG_NONNULL(2)
                                                               SECP256K1_ARG_NONNULL(3);

/** Convert a point to bytes by inverting the Shallue-van de Woestijne map.
 *  The preimage must be explicitly selected with the `hint` argument.
 *
 *  Returns: 1: the point was sucessfully inverted.
 *           0: no inverse for given preimage index.
 *  Args:    ctx:     pointer to a context object (cannot be NULL).
 *  Out:     bytes32: pointer to a 32-byte array to be filled by the function.
 *  In:      pubkey:  pointer to a secp256k1_pubkey containing an
 *                    initialized public key.
 *           hint:    preimage index (ranges from 0 to 3 inclusive).
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int
secp256k1_ec_pubkey_to_uniform(const secp256k1_context *ctx,
                               unsigned char *bytes32,
                               const secp256k1_pubkey *pubkey,
                               unsigned int hint) SECP256K1_ARG_NONNULL(1)
                                                  SECP256K1_ARG_NONNULL(2)
                                                  SECP256K1_ARG_NONNULL(3);

/** Hash bytes to a point using the Shallue-van de Woestijne map.
 *
 *  Returns: 1: the point was sucessfully created.
 *           0: point is at infinity.
 *  Args:    ctx:      pointer to a context object (cannot be NULL).
 *  Out:     pubkey:   pointer to a pubkey object.
 *  In:      bytes64:  pointer to two raw concatenated 32-byte field elements.
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int
secp256k1_ec_pubkey_from_hash(const secp256k1_context *ctx,
                              secp256k1_pubkey *pubkey,
                              const unsigned char *bytes64) SECP256K1_ARG_NONNULL(1)
                                                            SECP256K1_ARG_NONNULL(2)
                                                            SECP256K1_ARG_NONNULL(3);

/** Convert a point to bytes by inverting the Shallue-van de Woestijne map.
 *
 *  Returns: 1: the point was sucessfully inverted.
 *           0: pubkey is invalid.
 *  Args:    ctx:     pointer to a context object (cannot be NULL).
 *  Out:     bytes64: pointer to a 64-byte array to be filled by the function.
 *  In:      pubkey:  pointer to a secp256k1_pubkey containing an
 *                    initialized public key.
 *           entropy: pointer to a 32-byte random seed.
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int
secp256k1_ec_pubkey_to_hash(const secp256k1_context *ctx,
                            unsigned char *bytes64,
                            const secp256k1_pubkey *pubkey,
                            const unsigned char *entropy) SECP256K1_ARG_NONNULL(1)
                                                          SECP256K1_ARG_NONNULL(2)
                                                          SECP256K1_ARG_NONNULL(3)
                                                          SECP256K1_ARG_NONNULL(4);

/** Hash bytes to a point using the Shallue-van de Woestijne map.
 *
 *  Returns: 1: the byte array was sucessfully mapped.
 *           0: invalid arguments.
 *  Args:    ctx:      pointer to a context object (cannot be NULL).
 *  Out:     pubkey:   pointer to an x-only pubkey object.
 *  In:      bytes32:  pointer to a raw 32-byte field element.
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int
secp256k1_xonly_pubkey_from_uniform(const secp256k1_context *ctx,
                                    secp256k1_xonly_pubkey *pubkey,
                                    const unsigned char *bytes32) SECP256K1_ARG_NONNULL(1)
                                                                  SECP256K1_ARG_NONNULL(2)
                                                                  SECP256K1_ARG_NONNULL(3);

/** Convert a point to bytes by inverting the Shallue-van de Woestijne map.
 *  The preimage must be explicitly selected with the `hint` argument.
 *
 *  Returns: 1: the point was sucessfully inverted.
 *           0: no inverse for given preimage index.
 *  Args:    ctx:     pointer to a context object (cannot be NULL).
 *  Out:     bytes32: pointer to a 32-byte array to be filled by the function.
 *  In:      pubkey:  pointer to a secp256k1_xonly_pubkey containing an
 *                    initialized public key.
 *           hint:    preimage index (ranges from 0 to 3 inclusive).
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int
secp256k1_xonly_pubkey_to_uniform(const secp256k1_context *ctx,
                                  unsigned char *bytes32,
                                  const secp256k1_xonly_pubkey *pubkey,
                                  unsigned int hint) SECP256K1_ARG_NONNULL(1)
                                                     SECP256K1_ARG_NONNULL(2)
                                                     SECP256K1_ARG_NONNULL(3);

/** Hash bytes to a point using the Shallue-van de Woestijne map.
 *
 *  Returns: 1: the point was sucessfully created.
 *           0: point is at infinity.
 *  Args:    ctx:      pointer to a context object (cannot be NULL).
 *  Out:     pubkey:   pointer to an x-only pubkey object.
 *  In:      bytes64:  pointer to two raw concatenated 32-byte field elements.
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int
secp256k1_xonly_pubkey_from_hash(const secp256k1_context *ctx,
                                 secp256k1_xonly_pubkey *pubkey,
                                 const unsigned char *bytes64) SECP256K1_ARG_NONNULL(1)
                                                               SECP256K1_ARG_NONNULL(2)
                                                               SECP256K1_ARG_NONNULL(3);

/** Convert a point to bytes by inverting the Shallue-van de Woestijne map.
 *
 *  Returns: 1: the point was sucessfully inverted.
 *           0: pubkey is invalid.
 *  Args:    ctx:     pointer to a context object (cannot be NULL).
 *  Out:     bytes64: pointer to a 64-byte array to be filled by the function.
 *  In:      pubkey:  pointer to a secp256k1_xonly_pubkey containing an
 *                    initialized public key.
 *           entropy: pointer to a 32-byte random seed.
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int
secp256k1_xonly_pubkey_to_hash(const secp256k1_context *ctx,
                               unsigned char *bytes64,
                               const secp256k1_xonly_pubkey *pubkey,
                               const unsigned char *entropy) SECP256K1_ARG_NONNULL(1)
                                                             SECP256K1_ARG_NONNULL(2)
                                                             SECP256K1_ARG_NONNULL(3)
                                                             SECP256K1_ARG_NONNULL(4);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_ELLIGATOR_H */
