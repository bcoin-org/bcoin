/*!
 * entropy.h - entropy sources for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 */

#ifndef TORSION_ENTROPY_H
#define TORSION_ENTROPY_H

#include <stddef.h>
#include <stdint.h>

/*
 * Alias
 */

#define torsion_envrand torsion__envrand
#define torsion_hrtime torsion__hrtime
#define torsion_rdtsc torsion__rdtsc
#define torsion_has_cpuid torsion__has_cpuid
#define torsion_cpuid torsion__cpuid
#define torsion_has_rdrand torsion__has_rdrand
#define torsion_has_rdseed torsion__has_rdseed
#define torsion_rdrand torsion__rdrand
#define torsion_rdseed torsion__rdseed
#define torsion_hwrand torsion__hwrand
#define torsion_getpid torsion__getpid
#define torsion_sysrand torsion__sysrand

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

#endif /* TORSION_ENTROPY_H */
