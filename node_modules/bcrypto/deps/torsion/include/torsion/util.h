/*!
 * util.h - utils for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 */

#ifndef TORSION_UTIL_H
#define TORSION_UTIL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "common.h"

/*
 * Symbol Aliases
 */

#define murmur3_sum torsion_murmur3_sum
#define murmur3_tweak torsion_murmur3_tweak

/*
 * Memzero
 */

TORSION_EXTERN void
torsion_memzero(void *ptr, size_t len);

/*
 * Memequal
 */

TORSION_EXTERN int
torsion_memequal(const void *x, const void *y, size_t n);

/*
 * Memxor
 */

TORSION_EXTERN void
torsion_memxor(void *z, const void *x, size_t n);

TORSION_EXTERN void
torsion_memxor3(void *z, const void *x, const void *y, size_t n);

/*
 * Murmur3
 */

TORSION_EXTERN uint32_t
murmur3_sum(const unsigned char *data, size_t len, uint32_t seed);

TORSION_EXTERN uint32_t
murmur3_tweak(const unsigned char *data,
              size_t len, uint32_t n, uint32_t tweak);

#ifdef __cplusplus
}
#endif

#endif /* TORSION_UTIL_H */
