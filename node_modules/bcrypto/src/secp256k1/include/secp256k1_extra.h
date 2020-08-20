#ifndef SECP256K1_EXTRA_H
#define SECP256K1_EXTRA_H

#include "secp256k1.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Generates a private key from entropy.
 *
 *  Returns: 1 if seckey was successfully generated and 0 otherwise
 *  Args:   ctx:        pointer to a context object
 *  Out:    output:     pointer to a 32-byte array to be filled by the function
 *  In:     entropy:    pointer to a 32-byte random seed.
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int
secp256k1_ec_privkey_generate(const secp256k1_context *ctx,
                              unsigned char *output,
                              const unsigned char *entropy) SECP256K1_ARG_NONNULL(1)
                                                            SECP256K1_ARG_NONNULL(2)
                                                            SECP256K1_ARG_NONNULL(3);

/** Negates a private key in place.
 *
 *  Returns: 1 if seckey was successfully negated and 0 otherwise
 *  Args:   ctx:        pointer to a context object
 *  In/Out: seckey:     pointer to the 32-byte private key to be negated. The private
 *                      key should be valid according to secp256k1_ec_seckey_verify
 *                      (cannot be NULL)
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int
secp256k1_ec_privkey_negate_safe(const secp256k1_context *ctx,
                                 unsigned char *seckey) SECP256K1_ARG_NONNULL(1)
                                                        SECP256K1_ARG_NONNULL(2);

/** Inverts a private key in place.
 *
 *  Returns: 1 if seckey was successfully inverted and 0 otherwise
 *  Args:   ctx:        pointer to a context object
 *  In/Out: seckey:     pointer to the 32-byte private key to be inverted. The private
 *                      key should be valid according to secp256k1_ec_seckey_verify
 *                      (cannot be NULL)
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int
secp256k1_ec_privkey_invert(const secp256k1_context *ctx,
                            unsigned char *seckey) SECP256K1_ARG_NONNULL(1)
                                                   SECP256K1_ARG_NONNULL(2);

/** Reduces an arbitrary sized byte array to a private key.
 *
 *  Returns: 1 if bytes were successfully reduced and 0 otherwise
 *  Args:   ctx:        pointer to a context object
 *  Out:    output:     pointer to a 32-byte array to be filled by the function
 *  In:     bytes:      pointer to an arbitrary sized byte array
 *          len:        byte array length
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int
secp256k1_ec_privkey_reduce(const secp256k1_context *ctx,
                            unsigned char *output,
                            const unsigned char *bytes,
                            size_t len) SECP256K1_ARG_NONNULL(1)
                                        SECP256K1_ARG_NONNULL(2);

/** Exports a private key to a byte array.
 *
 *  Returns: 1 if key was successfully exported and 0 otherwise
 *  Args:   ctx:        pointer to a context object
 *  Out:    output:     pointer to a 32-byte array to be filled by the function
 *  In:     seckey:     pointer to a 32-byte array containing a private key
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int
secp256k1_ec_privkey_export(const secp256k1_context *ctx,
                            unsigned char *output,
                            const unsigned char *seckey) SECP256K1_ARG_NONNULL(1)
                                                         SECP256K1_ARG_NONNULL(2)
                                                         SECP256K1_ARG_NONNULL(3);

/** Imports a private key from a byte array.
 *
 *  Returns: 1 if key was successfully imported and 0 otherwise
 *  Args:   ctx:        pointer to a context object
 *  Out:    output:     pointer to a 32-byte array to be filled by the function
 *  In:     bytes:      pointer to an arbitrary sized byte array
 *          len:        byte array length
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int
secp256k1_ec_privkey_import(const secp256k1_context *ctx,
                            unsigned char *output,
                            const unsigned char *bytes,
                            size_t len) SECP256K1_ARG_NONNULL(1)
                                        SECP256K1_ARG_NONNULL(2);

/** Exports a public key to x/y byte arrays.
 *
 *  Returns: 1 if key was successfully exported and 0 otherwise
 *  Args:   ctx:        pointer to a context object
 *  Out:    x:          pointer to a 32-byte array to be filled by the function
 *          y:          pointer to a 32-byte array to be filled by the function
 *  In:     pubkey:     pointer to a pubkey struct
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int
secp256k1_ec_pubkey_export(const secp256k1_context *ctx,
                           unsigned char *x,
                           unsigned char *y,
                           const secp256k1_pubkey *pubkey) SECP256K1_ARG_NONNULL(1)
                                                           SECP256K1_ARG_NONNULL(2)
                                                           SECP256K1_ARG_NONNULL(3)
                                                           SECP256K1_ARG_NONNULL(4);

/** Imports a public key from x/y byte arrays.
 *
 *  Returns: 1 if key was successfully imported and 0 otherwise
 *  Args:   ctx:        pointer to a context object
 *  Out:    pubkey:     pointer to a pubkey struct
 *  In:     x:          pointer to an arbitrary sized byte array
 *          x_len:      byte array length
 *          y:          pointer to an arbitrary sized byte array
 *          y_len:      byte array length
 *          sign:       integer representing oddness of the y-coordinate
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int
secp256k1_ec_pubkey_import(const secp256k1_context *ctx,
                           secp256k1_pubkey *pubkey,
                           const unsigned char *x,
                           size_t x_len,
                           const unsigned char *y,
                           size_t y_len,
                           int sign) SECP256K1_ARG_NONNULL(1)
                                     SECP256K1_ARG_NONNULL(2);

#ifdef BCRYPTO_USE_SECP256K1_LATEST
/** Exports an x-only public key to x/y byte arrays.
 *
 *  Returns: 1 if key was successfully exported and 0 otherwise
 *  Args:   ctx:        pointer to a context object
 *  Out:    x:          pointer to a 32-byte array to be filled by the function
 *          y:          pointer to a 32-byte array to be filled by the function
 *  In:     pubkey:     pointer to an x-only pubkey struct
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int
secp256k1_xonly_pubkey_export(const secp256k1_context *ctx,
                              unsigned char *x,
                              unsigned char *y,
                              const secp256k1_xonly_pubkey *pubkey) SECP256K1_ARG_NONNULL(1)
                                                                    SECP256K1_ARG_NONNULL(2)
                                                                    SECP256K1_ARG_NONNULL(3)
                                                                    SECP256K1_ARG_NONNULL(4);

/** Imports an x-only public key from x/y byte arrays.
 *
 *  Returns: 1 if key was successfully imported and 0 otherwise
 *  Args:   ctx:        pointer to a context object
 *  Out:    pubkey:     pointer to an x-only pubkey struct
 *  In:     x:          pointer to an arbitrary sized byte array
 *          x_len:      byte array length
 *          y:          pointer to an arbitrary sized byte array
 *          y_len:      byte array length
 *          sign:       integer representing oddness of the y-coordinate
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int
secp256k1_xonly_pubkey_import(const secp256k1_context *ctx,
                              secp256k1_xonly_pubkey *pubkey,
                              const unsigned char *x,
                              size_t x_len,
                              const unsigned char *y,
                              size_t y_len) SECP256K1_ARG_NONNULL(1)
                                            SECP256K1_ARG_NONNULL(2);
#endif

/** Truncates an ECDSA message.
 *
 *  Args:   ctx:        pointer to a context object
 *  Out:    output:     pointer to a 32-byte array
 *  In:     msg:        pointer to an arbitrary sized byte array
 *          len:        byte array length
 */
void
secp256k1_ecdsa_reduce(const secp256k1_context *ctx,
                       unsigned char *output,
                       const unsigned char *msg,
                       size_t len) SECP256K1_ARG_NONNULL(1)
                                   SECP256K1_ARG_NONNULL(2);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_EXTRA_H */
