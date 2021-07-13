/*!
 * entropy.h - entropy sources for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 */

#ifndef _TORSION_ENTROPY_H
#define _TORSION_ENTROPY_H

#include <stddef.h>
#include <stdint.h>

/*
 * Alias
 */

#define torsion_envrand __torsion_envrand
#define torsion_hrtime __torsion_hrtime
#define torsion_rdtsc __torsion_rdtsc
#define torsion_has_cpuid __torsion_has_cpuid
#define torsion_cpuid __torsion_cpuid
#define torsion_has_rdrand __torsion_has_rdrand
#define torsion_has_rdseed __torsion_has_rdseed
#define torsion_rdrand __torsion_rdrand
#define torsion_rdseed __torsion_rdseed
#define torsion_hwrand __torsion_hwrand
#define torsion_getpid __torsion_getpid
#define torsion_sysrand __torsion_sysrand

/*
 * Entropy
 */

int
torsion_envrand(unsigned char *seed);

uint64_t
torsion_hrtime(void);

uint64_t
torsion_rdtsc(void);

int
torsion_has_cpuid(void);

void
torsion_cpuid(uint32_t *a,
              uint32_t *b,
              uint32_t *c,
              uint32_t *d,
              uint32_t leaf,
              uint32_t subleaf);

int
torsion_has_rdrand(void);

int
torsion_has_rdseed(void);

uint64_t
torsion_rdrand(void);

uint64_t
torsion_rdseed(void);

int
torsion_hwrand(void *dst, size_t size);

uint64_t
torsion_getpid(void);

int
torsion_sysrand(void *dst, size_t size);

#endif /* _TORSION_ENTROPY_H */
