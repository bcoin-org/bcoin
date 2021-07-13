/*!
 * rand.h - RNG for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 */

#ifndef _TORSION_RAND_H
#define _TORSION_RAND_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "common.h"

/*
 * Symbol Aliases
 */

#define torsion_threadsafety __torsion_threadsafety
#define torsion_randomaddr __torsion_randomaddr

/*
 * Defs
 */

#define TORSION_THREAD_SAFETY_NONE 0
#define TORSION_THREAD_SAFETY_TLS 1
#define TORSION_THREAD_SAFETY_MUTEX 2

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

#endif /* _TORSION_RAND_H */
