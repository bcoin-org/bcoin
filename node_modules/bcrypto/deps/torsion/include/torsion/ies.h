/*!
 * ies.c - ies for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

#ifndef TORSION_IES_H
#define TORSION_IES_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include "common.h"

/*
 * Symbol Aliases
 */

#define secretbox_seal torsion_secretbox_seal
#define secretbox_open torsion_secretbox_open
#define secretbox_derive torsion_secretbox_derive

/*
 * Macros
 */

#define SECRETBOX_SEAL_SIZE(len) (16 + (len))
#define SECRETBOX_OPEN_SIZE(len) ((len) < 16 ? 0 : (len) - 16)

/*
 * Secret Box
 */

TORSION_EXTERN void
secretbox_seal(unsigned char *sealed,
               const unsigned char *msg,
               size_t msg_len,
               const unsigned char *key,
               const unsigned char *nonce);

TORSION_EXTERN int
secretbox_open(unsigned char *msg,
               const unsigned char *sealed,
               size_t sealed_len,
               const unsigned char *key,
               const unsigned char *nonce);

TORSION_EXTERN void
secretbox_derive(unsigned char *key, const unsigned char *secret);

#ifdef __cplusplus
}
#endif

#endif /* TORSION_IES_H */
