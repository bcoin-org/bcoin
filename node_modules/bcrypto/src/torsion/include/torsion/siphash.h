#ifndef _TORSION_SIPHASH_H
#define _TORSION_SIPHASH_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

/*
 * Symbol Aliases
 */

#define siphash torsion_siphash
#define siphash32 torsion_siphash32
#define siphash64 torsion_siphash64
#define siphash32k256 torsion_siphash32k256
#define siphash64k256 torsion_siphash64k256
#define sipmod torsion_sipmod

/*
 * AEAD
 */

uint64_t
siphash(const unsigned char *data, size_t len, const unsigned char *key);

uint32_t
siphash32(uint32_t num, const unsigned char *key);

uint64_t
siphash64(uint64_t num, const unsigned char *key);

uint32_t
siphash32k256(uint32_t num, const unsigned char *key);

uint64_t
siphash64k256(uint64_t num, const unsigned char *key);

uint64_t
sipmod(const unsigned char *data,
       size_t len,
       const unsigned char *key,
       uint64_t m);

#ifdef __cplusplus
}
#endif

#endif /* _TORSION_SIPHASH_H */
