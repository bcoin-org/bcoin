/*!
 * rand.h - RNG for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 */

#ifndef TORSION_RAND_H
#define TORSION_RAND_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "common.h"

/*
 * Symbol Aliases
 */

#define torsion_threadsafety torsion__threadsafety
#define torsion_randomaddr torsion__randomaddr

/*
 * Definitions
 */

#define TORSION_THREADSAFETY_NONE 0
#define TORSION_THREADSAFETY_TLS 1
#define TORSION_THREADSAFETY_MUTEX 2

/*
 * Random
 */

TORSION_EXTERN int
torsion_getentropy(void *dst, size_t size);

TORSION_EXTERN int
torsion_getrandom(void *dst, size_t size);

TORSION_EXTERN int
torsion_random(uint32_t *num);

TORSION_EXTERN int
torsion_uniform(uint32_t *num, uint32_t max);

/*
 * Testing
 */

TORSION_EXTERN int
torsion_threadsafety(void);

TORSION_EXTERN uint64_t
torsion_randomaddr(void);

#ifdef __cplusplus
}
#endif

#endif /* TORSION_RAND_H */
