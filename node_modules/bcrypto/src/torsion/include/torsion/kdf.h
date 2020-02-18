#ifndef _TORSION_KDF_H
#define _TORSION_KDF_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

/*
 * Symbol Aliases
 */

#define pbkdf2_derive torsion_pbkdf2_derive
#define scrypt_derive torsion_scrypt_derive

/*
 * PBKDF2
 */

int
pbkdf2_derive(unsigned char *out,
              int type,
              const unsigned char *pass,
              size_t pass_len,
              const unsigned char *salt,
              size_t salt_len,
              uint32_t iter,
              size_t len);

/*
 * Scrypt
 */

int
scrypt_derive(unsigned char *out,
              const unsigned char *pass,
              size_t pass_len,
              const unsigned char *salt,
              size_t salt_len,
              uint64_t N,
              uint32_t r,
              uint32_t p,
              size_t len);

#ifdef __cplusplus
}
#endif

#endif /* _TORSION_KDF_H */
