/*!
 * mpi.h - multi-precision integers for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 *
 * Parts of this software are based on GMP:
 *   https://gmplib.org/
 *   Copyright (C) 1989, 1991 Free Software Foundation, Inc.
 *
 * mini-gmp, a minimalistic implementation of a GNU GMP subset.
 *
 * Contributed to the GNU project by Niels Möller
 *
 * Copyright 1991-1997, 1999-2019 Free Software Foundation, Inc.
 *
 * This file is part of the GNU MP Library.
 *
 * The GNU MP Library is free software; you can redistribute it and/or modify
 * it under the terms of either:
 *
 *   * the GNU Lesser General Public License as published by the Free
 *     Software Foundation; either version 3 of the License, or (at your
 *     option) any later version.
 *
 * or
 *
 *   * the GNU General Public License as published by the Free Software
 *     Foundation; either version 2 of the License, or (at your option) any
 *     later version.
 *
 * or both in parallel, as here.
 *
 * The GNU MP Library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * You should have received copies of the GNU General Public License and the
 * GNU Lesser General Public License along with the GNU MP Library.  If not,
 * see https://www.gnu.org/licenses/.
 */

#ifndef _TORSION_MPI_H
#define _TORSION_MPI_H

#include <stddef.h>
#include <stdint.h>
#include "internal.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Alias
 */

#define mpn_zero __torsion_mpn_zero
#define mpn_cleanse __torsion_mpn_cleanse
#define mpn_copyi __torsion_mpn_copyi
#define mpn_copyd __torsion_mpn_copyd
#define mpn_zero_p __torsion_mpn_zero_p
#define mpn_cmp __torsion_mpn_cmp
#define mpn_cmp4 __torsion_mpn_cmp4
#define mpn_add_1 __torsion_mpn_add_1
#define mpn_add_n __torsion_mpn_add_n
#define mpn_add __torsion_mpn_add
#define mpn_sub_1 __torsion_mpn_sub_1
#define mpn_sub_n __torsion_mpn_sub_n
#define mpn_sub __torsion_mpn_sub
#define mpn_mul_1 __torsion_mpn_mul_1
#define mpn_addmul_1 __torsion_mpn_addmul_1
#define mpn_submul_1 __torsion_mpn_submul_1
#define mpn_mul __torsion_mpn_mul
#define mpn_mul_n __torsion_mpn_mul_n
#define mpn_sqr __torsion_mpn_sqr
#define mpn_mont __torsion_mpn_mont
#define mpn_montmul __torsion_mpn_montmul
#define mpn_quorem __torsion_mpn_quorem
#define mpn_lshift __torsion_mpn_lshift
#define mpn_rshift __torsion_mpn_rshift
#define mpn_get_bit __torsion_mpn_get_bit
#define mpn_get_bits __torsion_mpn_get_bits
#define mpn_set_bit __torsion_mpn_set_bit
#define mpn_clr_bit __torsion_mpn_clr_bit
#define mpn_gcdext __torsion_mpn_gcdext
#define mpn_invert __torsion_mpn_invert
#define mpn_invert_n __torsion_mpn_invert_n
#define mpn_jacobi __torsion_mpn_jacobi
#define mpn_jacobi_n __torsion_mpn_jacobi_n
#define mpn_powm_sec __torsion_mpn_powm_sec
#define mpn_normalized_size __torsion_mpn_normalized_size
#define mpn_bitlen __torsion_mpn_bitlen
#define mpn_ctz __torsion_mpn_ctz
#define mpn_cnd_select __torsion_mpn_cnd_select
#define mpn_cnd_swap __torsion_mpn_cnd_swap
#define mpn_cnd_zero __torsion_mpn_cnd_zero
#define mpn_sec_zero_p __torsion_mpn_sec_zero_p
#define mpn_sec_eq __torsion_mpn_sec_eq
#define mpn_sec_lt __torsion_mpn_sec_lt
#define mpn_sec_lte __torsion_mpn_sec_lte
#define mpn_sec_gt __torsion_mpn_sec_gt
#define mpn_sec_gte __torsion_mpn_sec_gte
#define mpn_import __torsion_mpn_import
#define mpn_export __torsion_mpn_export
#define mpz_init __torsion_mpz_init
#define mpz_init2 __torsion_mpz_init2
#define mpz_init_set __torsion_mpz_init_set
#define mpz_init_set_ui __torsion_mpz_init_set_ui
#define mpz_init_set_si __torsion_mpz_init_set_si
#define mpz_init_set_u64 __torsion_mpz_init_set_u64
#define mpz_clear __torsion_mpz_clear
#define mpz_cleanse __torsion_mpz_cleanse
#define mpz_set __torsion_mpz_set
#define mpz_roset __torsion_mpz_roset
#define mpz_set_ui __torsion_mpz_set_ui
#define mpz_set_si __torsion_mpz_set_si
#define mpz_set_u64 __torsion_mpz_set_u64
#define mpz_get_ui __torsion_mpz_get_ui
#define mpz_get_si __torsion_mpz_get_si
#define mpz_get_u64 __torsion_mpz_get_u64
#define mpz_fits_ulong_p __torsion_mpz_fits_ulong_p
#define mpz_fits_slong_p __torsion_mpz_fits_slong_p
#define mpz_fits_u64_p __torsion_mpz_fits_u64_p
#define mpz_sgn __torsion_mpz_sgn
#define mpz_cmp __torsion_mpz_cmp
#define mpz_cmp_ui __torsion_mpz_cmp_ui
#define mpz_cmp_si __torsion_mpz_cmp_si
#define mpz_cmpabs __torsion_mpz_cmpabs
#define mpz_cmpabs_ui __torsion_mpz_cmpabs_ui
#define mpz_add __torsion_mpz_add
#define mpz_add_ui __torsion_mpz_add_ui
#define mpz_sub __torsion_mpz_sub
#define mpz_sub_ui __torsion_mpz_sub_ui
#define mpz_mul __torsion_mpz_mul
#define mpz_mul_ui __torsion_mpz_mul_ui
#define mpz_mul_si __torsion_mpz_mul_si
#define mpz_quorem __torsion_mpz_quorem
#define mpz_quo __torsion_mpz_quo
#define mpz_rem __torsion_mpz_rem
#define mpz_quo_ui __torsion_mpz_quo_ui
#define mpz_rem_ui __torsion_mpz_rem_ui
#define mpz_divmod __torsion_mpz_divmod
#define mpz_div __torsion_mpz_div
#define mpz_mod __torsion_mpz_mod
#define mpz_div_ui __torsion_mpz_div_ui
#define mpz_mod_ui __torsion_mpz_mod_ui
#define mpz_divexact __torsion_mpz_divexact
#define mpz_divexact_ui __torsion_mpz_divexact_ui
#define mpz_lshift __torsion_mpz_lshift
#define mpz_rshift __torsion_mpz_rshift
#define mpz_get_bit __torsion_mpz_get_bit
#define mpz_get_bits __torsion_mpz_get_bits
#define mpz_set_bit __torsion_mpz_set_bit
#define mpz_clr_bit __torsion_mpz_clr_bit
#define mpz_abs __torsion_mpz_abs
#define mpz_neg __torsion_mpz_neg
#define mpz_gcd __torsion_mpz_gcd
#define mpz_lcm __torsion_mpz_lcm
#define mpz_gcdext __torsion_mpz_gcdext
#define mpz_invert __torsion_mpz_invert
#define mpz_jacobi __torsion_mpz_jacobi
#define mpz_powm __torsion_mpz_powm
#define mpz_powm_ui __torsion_mpz_powm_ui
#define mpz_powm_sec __torsion_mpz_powm_sec
#define mpz_is_prime_mr __torsion_mpz_is_prime_mr
#define mpz_is_prime_lucas __torsion_mpz_is_prime_lucas
#define mpz_is_prime __torsion_mpz_is_prime
#define mpz_random_prime __torsion_mpz_random_prime
#define mpz_odd_p __torsion_mpz_odd_p
#define mpz_even_p __torsion_mpz_even_p
#define mpz_bitlen __torsion_mpz_bitlen
#define mpz_ctz __torsion_mpz_ctz
#define mpz_bytelen __torsion_mpz_bytelen
#define mpz_swap __torsion_mpz_swap
#define mpz_size __torsion_mpz_size
#define mpz_getlimbn __torsion_mpz_getlimbn
#define mpz_limbs_read __torsion_mpz_limbs_read
#define mpz_limbs_modify __torsion_mpz_limbs_modify
#define mpz_limbs_write __torsion_mpz_limbs_write
#define mpz_limbs_finish __torsion_mpz_limbs_finish
#define mpz_roinit_n __torsion_mpz_roinit_n
#define mpz_import __torsion_mpz_import
#define mpz_export __torsion_mpz_export
#define mpz_random_bits __torsion_mpz_random_bits
#define mpz_random_int __torsion_mpz_random_int

/*
 * Types
 */

#ifdef TORSION_HAVE_INT128
typedef uint64_t mp_limb_t;
typedef int64_t mp_long_t;
typedef torsion_uint128_t mp_wide_t;
#define MP_LIMB_BITS 64
#define MP_LIMB_C(x) UINT64_C(x)
#define MP_LIMB_MAX MP_LIMB_C(0xffffffffffffffff)
#define MP_HAS_WIDE
#ifdef TORSION_HAVE_ASM_X64
#define MPI_USE_ASM
#endif
#else
typedef uint32_t mp_limb_t;
typedef int32_t mp_long_t;
typedef uint64_t mp_wide_t;
#define MP_LIMB_BITS 32
#define MP_LIMB_C(x) UINT32_C(x)
#define MP_LIMB_MAX MP_LIMB_C(0xffffffff)
#define MP_HAS_WIDE
#endif

typedef long mp_size_t;
typedef unsigned long mp_bitcnt_t;

typedef mp_limb_t *mp_ptr;
typedef const mp_limb_t *mp_srcptr;

typedef struct {
  int _mp_alloc;    /* Number of *limbs* allocated and pointed
                       to by the _mp_d field.  */
  int _mp_size;     /* abs(_mp_size) is the number of limbs the
                       last field points to.  If _mp_size is
                       negative this is a negative number.  */
  mp_limb_t *_mp_d; /* Pointer to the limbs.  */
} __mpz_struct;

typedef __mpz_struct mpz_t[1];

typedef __mpz_struct *mpz_ptr;
typedef const __mpz_struct *mpz_srcptr;

typedef void mp_rng_f(void *out, size_t size, void *arg);

/*
 * Definitions
 */

#define MP_WND_WIDTH 4
#define MP_WND_SIZE (1 << MP_WND_WIDTH)

/*
 * Itches
 */

#define MPN_INVERT_ITCH(n) (4 * ((n) + 1))
#define MPN_JACOBI_ITCH(n) (2 * (n))
#define MPN_POWM_SEC_ITCH(n) (7 * (n) + (MP_WND_SIZE + 1) * (n))

/*
 * MPN Interface
 */

/*
 * Initialization
 */

void mpn_zero(mp_ptr, mp_size_t);

/*
 * Uninitialization
 */

void mpn_cleanse(mp_ptr, mp_size_t);

/*
 * Assignemnt
 */

void mpn_copyi(mp_ptr, mp_srcptr, mp_size_t);
void mpn_copyd(mp_ptr, mp_srcptr, mp_size_t);

/*
 * Comparison
 */

int mpn_zero_p(mp_srcptr, mp_size_t);
int mpn_cmp(mp_srcptr, mp_srcptr, mp_size_t);
int mpn_cmp4(mp_srcptr, mp_size_t, mp_srcptr, mp_size_t);

/*
 * Addition
 */

mp_limb_t mpn_add_1(mp_ptr, mp_srcptr, mp_size_t, mp_limb_t);
mp_limb_t mpn_add_n(mp_ptr, mp_srcptr, mp_srcptr, mp_size_t);
mp_limb_t mpn_add(mp_ptr, mp_srcptr, mp_size_t, mp_srcptr, mp_size_t);

/*
 * Subtraction
 */

mp_limb_t mpn_sub_1(mp_ptr, mp_srcptr, mp_size_t, mp_limb_t);
mp_limb_t mpn_sub_n(mp_ptr, mp_srcptr, mp_srcptr, mp_size_t);
mp_limb_t mpn_sub(mp_ptr, mp_srcptr, mp_size_t, mp_srcptr, mp_size_t);

/*
 * Multiplication
 */

mp_limb_t mpn_mul_1(mp_ptr, mp_srcptr, mp_size_t, mp_limb_t);
mp_limb_t mpn_addmul_1(mp_ptr, mp_srcptr, mp_size_t, mp_limb_t);
mp_limb_t mpn_submul_1(mp_ptr, mp_srcptr, mp_size_t, mp_limb_t);
mp_limb_t mpn_mul(mp_ptr, mp_srcptr, mp_size_t, mp_srcptr, mp_size_t);
void mpn_mul_n(mp_ptr, mp_srcptr, mp_srcptr, mp_size_t);
void mpn_sqr(mp_ptr, mp_srcptr, mp_size_t);

/*
 * Montgomery Multiplication
 */

void mpn_mont(mp_ptr, mp_ptr, mp_srcptr, mp_size_t);
void mpn_montmul(mp_ptr, mp_srcptr, mp_srcptr,
                 mp_srcptr, mp_limb_t, mp_size_t);

/*
 * Truncation Division
 */

void mpn_quorem(mp_ptr, mp_ptr, mp_srcptr, mp_size_t, mp_srcptr, mp_size_t);

/*
 * Left Shift
 */

mp_limb_t mpn_lshift(mp_ptr, mp_srcptr, mp_size_t, unsigned int);

/*
 * Right Shift
 */

mp_limb_t mpn_rshift(mp_ptr, mp_srcptr, mp_size_t, unsigned int);

/*
 * Bit Manipulation
 */

mp_limb_t mpn_get_bit(mp_srcptr, mp_size_t, mp_bitcnt_t);
mp_limb_t mpn_get_bits(mp_srcptr, mp_size_t, mp_bitcnt_t, mp_bitcnt_t);
void mpn_set_bit(mp_ptr, mp_size_t, mp_bitcnt_t);
void mpn_clr_bit(mp_ptr, mp_size_t, mp_bitcnt_t);

/*
 * Number Theoretic Functions
 */

mp_size_t mpn_gcdext(mp_ptr, mp_ptr, mp_size_t *,
                     mp_ptr, mp_size_t, mp_ptr, mp_size_t);
int mpn_invert(mp_ptr, mp_srcptr, mp_size_t, mp_srcptr, mp_size_t, mp_ptr);
int mpn_invert_n(mp_ptr, mp_srcptr, mp_srcptr, mp_size_t, mp_ptr);
int mpn_jacobi(mp_srcptr, mp_size_t, mp_srcptr, mp_size_t, mp_ptr);
int mpn_jacobi_n(mp_srcptr, mp_srcptr, mp_size_t, mp_ptr);
void mpn_powm_sec(mp_ptr,
                  mp_srcptr, mp_size_t,
                  mp_srcptr, mp_size_t,
                  mp_srcptr, mp_size_t,
                  mp_ptr);

/*
 * Helpers
 */

mp_size_t mpn_normalized_size(mp_srcptr, mp_size_t);
mp_bitcnt_t mpn_bitlen(mp_srcptr, mp_size_t);
mp_bitcnt_t mpn_ctz(mp_srcptr, mp_size_t);

/*
 * Constant Time
 */

void mpn_cnd_select(mp_limb_t, mp_ptr, mp_srcptr, mp_srcptr, mp_size_t);
void mpn_cnd_swap(mp_limb_t, mp_ptr, mp_ptr, mp_size_t);
void mpn_cnd_zero(mp_limb_t, mp_ptr, mp_srcptr, mp_size_t);
int mpn_sec_zero_p(mp_srcptr, mp_size_t);
int mpn_sec_eq(mp_srcptr, mp_srcptr, mp_size_t);
int mpn_sec_lt(mp_srcptr, mp_srcptr, mp_size_t);
int mpn_sec_lte(mp_srcptr, mp_srcptr, mp_size_t);
int mpn_sec_gt(mp_srcptr, mp_srcptr, mp_size_t);
int mpn_sec_gte(mp_srcptr, mp_srcptr, mp_size_t);

/*
 * Import
 */

void mpn_import(mp_ptr, mp_size_t, const unsigned char *, size_t, int);

/*
 * Export
 */

void mpn_export(unsigned char *, size_t, mp_srcptr, mp_size_t, int);

/*
 * MPZ Interface
 */

/*
 * Initialization
 */

void mpz_init(mpz_t);
void mpz_init2(mpz_t, mp_bitcnt_t);
void mpz_init_set(mpz_t, const mpz_t);
void mpz_init_set_ui(mpz_t, mp_limb_t);
void mpz_init_set_si(mpz_t, mp_long_t);
void mpz_init_set_u64(mpz_t, uint64_t);

/*
 * Uninitialization
 */

void mpz_clear(mpz_t);
void mpz_cleanse(mpz_t);

/*
 * Assignment
 */

void mpz_set(mpz_t, const mpz_t);
void mpz_roset(mpz_t, const mpz_t);
void mpz_set_ui(mpz_t, mp_limb_t);
void mpz_set_si(mpz_t, mp_long_t);
void mpz_set_u64(mpz_t, uint64_t);

/*
 * Conversion
 */

mp_limb_t mpz_get_ui(const mpz_t);
mp_long_t mpz_get_si(const mpz_t);
uint64_t mpz_get_u64(const mpz_t);

/*
 * Conversion Testing
 */

int mpz_fits_ulong_p(const mpz_t);
int mpz_fits_slong_p(const mpz_t);
int mpz_fits_u64_p(const mpz_t);

/*
 * Comparison
 */

int mpz_sgn(const mpz_t);
int mpz_cmp(const mpz_t, const mpz_t);
int mpz_cmp_ui(const mpz_t, mp_limb_t);
int mpz_cmp_si(const mpz_t, mp_long_t);

/*
 * Unsigned Comparison
 */

int mpz_cmpabs(const mpz_t, const mpz_t);
int mpz_cmpabs_ui(const mpz_t, mp_limb_t);

/*
 * Addition
 */

void mpz_add(mpz_t, const mpz_t, const mpz_t);
void mpz_add_ui(mpz_ptr, mpz_srcptr, mp_limb_t);

/*
 * Subtraction
 */

void mpz_sub(mpz_t, const mpz_t, const mpz_t);
void mpz_sub_ui(mpz_ptr, mpz_srcptr, mp_limb_t);

/*
 * Multiplication
 */

void mpz_mul(mpz_t, const mpz_t, const mpz_t);
void mpz_mul_ui(mpz_ptr, mpz_srcptr, mp_limb_t);
void mpz_mul_si(mpz_t, const mpz_t, mp_long_t);

/*
 * Truncation Division
 */

void mpz_quorem(mpz_t, mpz_t, const mpz_t, const mpz_t);
void mpz_quo(mpz_t, const mpz_t, const mpz_t);
void mpz_rem(mpz_t, const mpz_t, const mpz_t);
mp_limb_t mpz_quo_ui(mpz_t, const mpz_t, mp_limb_t);
mp_limb_t mpz_rem_ui(const mpz_t, mp_limb_t);

/*
 * Euclidean Division
 */

void mpz_divmod(mpz_t, mpz_t, const mpz_t, const mpz_t);
void mpz_div(mpz_t, const mpz_t, const mpz_t);
void mpz_mod(mpz_t, const mpz_t, const mpz_t);
mp_limb_t mpz_div_ui(mpz_t, const mpz_t, mp_limb_t);
mp_limb_t mpz_mod_ui(const mpz_t, mp_limb_t);

/*
 * Exact Division
 */

void mpz_divexact(mpz_t, const mpz_t, const mpz_t);
void mpz_divexact_ui(mpz_t, const mpz_t, mp_limb_t);

/*
 * Left Shift
 */

void mpz_lshift(mpz_t, const mpz_t, mp_bitcnt_t);

/*
 * Right Shift
 */

void mpz_rshift(mpz_t, const mpz_t, mp_bitcnt_t);

/*
 * Bit Manipulation
 */

mp_limb_t mpz_get_bit(const mpz_t, mp_bitcnt_t);
mp_limb_t mpz_get_bits(const mpz_t, mp_bitcnt_t, mp_bitcnt_t);
void mpz_set_bit(mpz_t, mp_bitcnt_t);
void mpz_clr_bit(mpz_t, mp_bitcnt_t);

/*
 * Negation
 */

void mpz_abs(mpz_t, const mpz_t);
void mpz_neg(mpz_t, const mpz_t);

/*
 * Number Theoretic Functions
 */

void mpz_gcd(mpz_t, const mpz_t, const mpz_t);
void mpz_lcm(mpz_t, const mpz_t, const mpz_t);
void mpz_gcdext(mpz_t, mpz_t, mpz_t, const mpz_t, const mpz_t);
int mpz_invert(mpz_t, const mpz_t, const mpz_t);
int mpz_jacobi(const mpz_t, const mpz_t);
void mpz_powm(mpz_t, const mpz_t, const mpz_t, const mpz_t);
void mpz_powm_ui(mpz_t, const mpz_t, mp_limb_t, const mpz_t);
void mpz_powm_sec(mpz_ptr, mpz_srcptr, mpz_srcptr, mpz_srcptr);

/*
 * Primality Testing
 */

int mpz_is_prime_mr(const mpz_t, unsigned long,
                    int, mp_rng_f *, void *);
int mpz_is_prime_lucas(const mpz_t, unsigned long);
int mpz_is_prime(const mpz_t, unsigned long, mp_rng_f *, void *);
void mpz_random_prime(mpz_t, mp_bitcnt_t, mp_rng_f *, void *);

/*
 * Helpers
 */

int mpz_odd_p(const mpz_t);
int mpz_even_p(const mpz_t);
mp_bitcnt_t mpz_bitlen(const mpz_t);
mp_bitcnt_t mpz_ctz(const mpz_t);
size_t mpz_bytelen(const mpz_t);
void mpz_swap(mpz_t, mpz_t);

/*
 * Limb Manipulation
 */

mp_size_t mpz_size(const mpz_t);
mp_limb_t mpz_getlimbn(const mpz_t, mp_size_t);
mp_srcptr mpz_limbs_read(mpz_srcptr);
mp_ptr mpz_limbs_modify(mpz_t, mp_size_t);
mp_ptr mpz_limbs_write(mpz_t, mp_size_t);
void mpz_limbs_finish(mpz_t, mp_size_t);
mpz_srcptr mpz_roinit_n(mpz_t, mp_srcptr, mp_size_t);

/*
 * Import
 */

void mpz_import(mpz_t, const unsigned char *, size_t, int);

/*
 * Export
 */

void mpz_export(unsigned char *, const mpz_t, size_t, int);

/*
 * RNG
 */

void mpz_random_bits(mpz_t, mp_bitcnt_t, mp_rng_f *, void *);
void mpz_random_int(mpz_t, const mpz_t, mp_rng_f *, void *);

#ifdef __cplusplus
}
#endif
#endif /* _TORSION_MPI_H */
