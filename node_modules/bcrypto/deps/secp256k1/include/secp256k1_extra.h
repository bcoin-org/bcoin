#ifndef SECP256K1_EXTRA_H
#define SECP256K1_EXTRA_H

#include "secp256k1.h"
#include "secp256k1_extrakeys.h"

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
secp256k1_ec_seckey_generate(const secp256k1_context *ctx,
                             unsigned char *output,
                             const unsigned char *entropy) SECP256K1_ARG_NONNULL(1)
                                                           SECP256K1_ARG_NONNULL(2)
                                                           SECP256K1_ARG_NONNULL(3);

/** Inverts a private key in place.
 *
 *  Returns: 1 if seckey was successfully inverted and 0 otherwise
 *  Args:   ctx:        pointer to a context object
 *  In/Out: seckey:     pointer to the 32-byte private key to be inverted. The private
 *                      key should be valid according to secp256k1_ec_seckey_verify
 *                      (cannot be NULL)
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int
secp256k1_ec_seckey_invert(const secp256k1_context *ctx,
                           unsigned char *seckey) SECP256K1_ARG_NONNULL(1)
                                                  SECP256K1_ARG_NONNULL(2);

/** Exports a private key to a byte array.
 *
 *  Returns: 1 if key was successfully exported and 0 otherwise
 *  Args:   ctx:        pointer to a context object
 *  Out:    output:     pointer to a 32-byte array to be filled by the function
 *  In:     seckey:     pointer to a 32-byte array containing a private key
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int
secp256k1_ec_seckey_export(const secp256k1_context *ctx,
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
secp256k1_ec_seckey_import(const secp256k1_context *ctx,
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

/** Get the secret key from a keypair.
 *
 *  Returns: 0 if the arguments are invalid. 1 otherwise.
 *  Args:    ctx: pointer to a context object (cannot be NULL)
 *  Out: seckey: pointer to a 32-byte array. If 1 is returned, it is set to
 *               the keypair secret key. If not, it's set to an invalid value.
 *               (cannot be NULL)
 *  In: keypair: pointer to a keypair (cannot be NULL)
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int
secp256k1_keypair_priv(const secp256k1_context* ctx,
                       unsigned char *seckey,
                       const secp256k1_keypair *keypair) SECP256K1_ARG_NONNULL(1)
                                                         SECP256K1_ARG_NONNULL(2);

/** Converts a secp256k1_xonly_pubkey into a secp256k1_pubkey.
 *
 *  Returns: 1 if the public key was successfully converted
 *           0 otherwise
 *
 *  Args:         ctx: pointer to a context object (cannot be NULL)
 *  Out:       pubkey: pointer to a public key object for placing the
 *                     converted public key (cannot be NULL)
 *          pk_parity: pointer to an integer that will be set to 1 if the point
 *                     encoded by xonly_pubkey is the negation of the pubkey and
 *                     set to 0 otherwise. (can be NULL)
 *  In:  xonly_pubkey: pointer to an x-only public key that is converted
 *                     (cannot be NULL)
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int
secp256k1_pubkey_from_xonly_pubkey(const secp256k1_context *ctx,
                                   secp256k1_pubkey *pubkey,
                                   const secp256k1_xonly_pubkey *xonly_pubkey) SECP256K1_ARG_NONNULL(1)
                                                                               SECP256K1_ARG_NONNULL(2)
                                                                               SECP256K1_ARG_NONNULL(3);

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
