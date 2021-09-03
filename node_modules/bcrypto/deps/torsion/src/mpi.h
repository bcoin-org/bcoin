/*!
 * mpi.h - multi-precision integers for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 *
 * A from-scratch reimplementation of GMP.
 */

#ifndef TORSION_MPI_H
#define TORSION_MPI_H

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <torsion/common.h>

/*
 * Symbol Aliases
 */

#define mp_bits_per_limb torsion__mp_bits_per_limb
#define mpn_zero torsion__mpn_zero
#define mpn_cleanse torsion__mpn_cleanse
#define mpn_set_1 torsion__mpn_set_1
#define mpn_copyi torsion__mpn_copyi
#define mpn_copyd torsion__mpn_copyd
#define mpn_zero_p torsion__mpn_zero_p
#define mpn_cmp torsion__mpn_cmp
#define mpn_add_1 torsion__mpn_add_1
#define mpn_add_n torsion__mpn_add_n
#define mpn_add torsion__mpn_add
#define mpn_sec_add_1 torsion__mpn_sec_add_1
#define mpn_sec_add torsion__mpn_sec_add
#define mpn_sub_1 torsion__mpn_sub_1
#define mpn_sub_n torsion__mpn_sub_n
#define mpn_sub torsion__mpn_sub
#define mpn_sec_sub_1 torsion__mpn_sec_sub_1
#define mpn_sec_sub torsion__mpn_sec_sub
#define mpn_mul_1 torsion__mpn_mul_1
#define mpn_addmul_1 torsion__mpn_addmul_1
#define mpn_submul_1 torsion__mpn_submul_1
#define mpn_mul_n torsion__mpn_mul_n
#define mpn_mul torsion__mpn_mul
#define mpn_sqr torsion__mpn_sqr
#define mpn_mulshift torsion__mpn_mulshift
#define mpn_divmod_1 torsion__mpn_divmod_1
#define mpn_div_1 torsion__mpn_div_1
#define mpn_mod_1 torsion__mpn_mod_1
#define mpn_divmod torsion__mpn_divmod
#define mpn_div torsion__mpn_div
#define mpn_mod torsion__mpn_mod
#define mpn_divexact_1 torsion__mpn_divexact_1
#define mpn_divexact torsion__mpn_divexact
#define mpn_and_n torsion__mpn_and_n
#define mpn_ior_n torsion__mpn_ior_n
#define mpn_xor_n torsion__mpn_xor_n
#define mpn_andn_n torsion__mpn_andn_n
#define mpn_iorn_n torsion__mpn_iorn_n
#define mpn_nand_n torsion__mpn_nand_n
#define mpn_nior_n torsion__mpn_nior_n
#define mpn_xnor_n torsion__mpn_xnor_n
#define mpn_com torsion__mpn_com
#define mpn_lshift torsion__mpn_lshift
#define mpn_rshift torsion__mpn_rshift
#define mpn_getbit torsion__mpn_getbit
#define mpn_getbits torsion__mpn_getbits
#define mpn_tstbit torsion__mpn_tstbit
#define mpn_setbit torsion__mpn_setbit
#define mpn_clrbit torsion__mpn_clrbit
#define mpn_combit torsion__mpn_combit
#define mpn_scan0 torsion__mpn_scan0
#define mpn_scan1 torsion__mpn_scan1
#define mpn_popcount torsion__mpn_popcount
#define mpn_hamdist torsion__mpn_hamdist
#define mpn_mask torsion__mask
#define mpn_neg torsion__mpn_neg
#define mpn_reduce_weak torsion__mpn_reduce_weak
#define mpn_barrett torsion__mpn_barrett
#define mpn_reduce torsion__mpn_reduce
#define mpn_mont torsion__mpn_mont
#define mpn_montmul torsion__mpn_montmul
#define mpn_sec_montmul torsion__mpn_sec_montmul
#define mpn_gcd torsion__mpn_gcd
#define mpn_gcd_1 torsion__mpn_gcd_1
#define mpn_invert torsion__mpn_invert
#define mpn_invert_n torsion__mpn_invert_n
#define mpn_sec_invert torsion__mpn_sec_invert
#define mpn_sec_invert_n torsion__mpn_sec_invert_n
#define mpn_jacobi torsion__mpn_jacobi
#define mpn_jacobi_n torsion__mpn_jacobi_n
#define mpn_powm torsion__mpn_powm
#define mpn_sec_powm torsion__mpn_sec_powm
#define mpn_ctz torsion__mpn_ctz
#define mpn_bitlen torsion__mpn_bitlen
#define mpn_bytelen torsion__mpn_bytelen
#define mpn_sizeinbase torsion__mpn_sizeinbase
#define mpn_cnd_select torsion__mpn_cnd_select
#define mpn_cnd_swap torsion__mpn_cnd_swap
#define mpn_cnd_add_n torsion__mpn_cnd_add_n
#define mpn_cnd_sub_n torsion__mpn_cnd_sub_n
#define mpn_cnd_neg torsion__mpn_cnd_neg
#define mpn_sec_tabselect torsion__mpn_sec_tabselect
#define mpn_sec_zero_p torsion__mpn_sec_zero_p
#define mpn_sec_equal_p torsion__mpn_sec_equal_p
#define mpn_sec_lt_p torsion__mpn_sec_lt_p
#define mpn_sec_lte_p torsion__mpn_sec_lte_p
#define mpn_sec_gt_p torsion__mpn_sec_gt_p
#define mpn_sec_gte_p torsion__mpn_sec_gte_p
#define mpn_sec_cmp torsion__mpn_sec_cmp
#define mpn_import torsion__mpn_import
#define mpn_export torsion__mpn_export
#define mpn_set_str torsion__mpn_set_str
#define mpn_get_str torsion__mpn_get_str
#define mpn_print torsion__mpn_print
#define mpn_random torsion__mpn_random
#define mpn_randomm torsion__mpn_randomm
#define mpz_init torsion__mpz_init
#define mpz_init2 torsion__mpz_init2
#define mpz_init_set torsion__mpz_init_set
#define mpz_init_set_ui torsion__mpz_init_set_ui
#define mpz_init_set_si torsion__mpz_init_set_si
#define mpz_init_set_str torsion__mpz_init_set_str
#define mpz_clear torsion__mpz_clear
#define mpz_cleanse torsion__mpz_cleanse
#define mpz_set torsion__mpz_set
#define mpz_roset torsion__mpz_roset
#define mpz_roinit_n torsion__mpz_roinit_n
#define mpz_set_ui torsion__mpz_set_ui
#define mpz_set_si torsion__mpz_set_si
#define mpz_get_ui torsion__mpz_get_ui
#define mpz_get_si torsion__mpz_get_si
#define mpz_sgn torsion__mpz_sgn
#define mpz_cmp torsion__mpz_cmp
#define mpz_cmp_ui torsion__mpz_cmp_ui
#define mpz_cmp_si torsion__mpz_cmp_si
#define mpz_cmpabs torsion__mpz_cmpabs
#define mpz_cmpabs_ui torsion__mpz_cmpabs_ui
#define mpz_cmpabs_si torsion__mpz_cmpabs_si
#define mpz_add torsion__mpz_add
#define mpz_add_ui torsion__mpz_add_ui
#define mpz_add_si torsion__mpz_add_si
#define mpz_sub torsion__mpz_sub
#define mpz_sub_ui torsion__mpz_sub_ui
#define mpz_sub_si torsion__mpz_sub_si
#define mpz_ui_sub torsion__mpz_ui_sub
#define mpz_si_sub torsion__mpz_si_sub
#define mpz_mul torsion__mpz_mul
#define mpz_mul_ui torsion__mpz_mul_ui
#define mpz_mul_si torsion__mpz_mul_si
#define mpz_sqr torsion__mpz_sqr
#define mpz_addmul torsion__mpz_addmul
#define mpz_addmul_ui torsion__mpz_addmul_ui
#define mpz_addmul_si torsion__mpz_addmul_si
#define mpz_submul torsion__mpz_submul
#define mpz_submul_ui torsion__mpz_submul_ui
#define mpz_submul_si torsion__mpz_submul_si
#define mpz_mulshift torsion__mpz_mulshift
#define mpz_quorem torsion__mpz_quorem
#define mpz_quo torsion__mpz_quo
#define mpz_rem torsion__mpz_rem
#define mpz_quo_ui torsion__mpz_quo_ui
#define mpz_rem_ui torsion__mpz_rem_ui
#define mpz_quo_si torsion__mpz_quo_si
#define mpz_rem_si torsion__mpz_rem_si
#define mpz_divmod torsion__mpz_divmod
#define mpz_div torsion__mpz_div
#define mpz_mod torsion__mpz_mod
#define mpz_div_ui torsion__mpz_div_ui
#define mpz_mod_ui torsion__mpz_mod_ui
#define mpz_div_si torsion__mpz_div_si
#define mpz_mod_si torsion__mpz_mod_si
#define mpz_divexact torsion__mpz_divexact
#define mpz_divexact_ui torsion__mpz_divexact_ui
#define mpz_divexact_si torsion__mpz_divexact_si
#define mpz_divround torsion__mpz_divround
#define mpz_divround_ui torsion__mpz_divround_ui
#define mpz_divround_si torsion__mpz_divround_si
#define mpz_divisible_p torsion__mpz_divisible_p
#define mpz_divisible_ui_p torsion__mpz_divisible_ui_p
#define mpz_divisible_2exp_p torsion__mpz_divisible_2exp_p
#define mpz_congruent_p torsion__mpz_congruent_p
#define mpz_congruent_ui_p torsion__mpz_congruent_ui_p
#define mpz_congruent_2exp_p torsion__mpz_congruent_2exp_p
#define mpz_pow_ui torsion__mpz_pow_ui
#define mpz_ui_pow_ui torsion__mpz_ui_pow_ui
#define mpz_rootrem torsion__mpz_rootrem
#define mpz_root torsion__mpz_root
#define mpz_perfect_power_p torsion__mpz_perfect_power_p
#define mpz_sqrtrem torsion__mpz_sqrtrem
#define mpz_sqrt torsion__mpz_sqrt
#define mpz_perfect_square_p torsion__mpz_perfect_square_p
#define mpz_and torsion__mpz_and
#define mpz_and_ui torsion__mpz_and_ui
#define mpz_and_si torsion__mpz_and_si
#define mpz_ior torsion__mpz_ior
#define mpz_ior_ui torsion__mpz_ior_ui
#define mpz_ior_si torsion__mpz_ior_si
#define mpz_xor torsion__mpz_xor
#define mpz_xor_ui torsion__mpz_xor_ui
#define mpz_xor_si torsion__mpz_xor_si
#define mpz_com torsion__mpz_com
#define mpz_mul_2exp torsion__mpz_mul_2exp
#define mpz_quo_2exp torsion__mpz_quo_2exp
#define mpz_rem_2exp torsion__mpz_rem_2exp
#define mpz_div_2exp torsion__mpz_div_2exp
#define mpz_mod_2exp torsion__mpz_mod_2exp
#define mpz_tstbit torsion__mpz_tstbit
#define mpz_setbit torsion__mpz_setbit
#define mpz_clrbit torsion__mpz_clrbit
#define mpz_combit torsion__mpz_combit
#define mpz_scan0 torsion__mpz_scan0
#define mpz_scan1 torsion__mpz_scan1
#define mpz_popcount torsion__mpz_popcount
#define mpz_hamdist torsion__mpz_hamdist
#define mpz_abs torsion__mpz_abs
#define mpz_neg torsion__mpz_neg
#define mpz_gcd torsion__mpz_gcd
#define mpz_gcd_ui torsion__mpz_gcd_ui
#define mpz_lcm torsion__mpz_lcm
#define mpz_lcm_ui torsion__mpz_lcm_ui
#define mpz_gcdext torsion__mpz_gcdext
#define mpz_invert torsion__mpz_invert
#define mpz_legendre torsion__mpz_legendre
#define mpz_jacobi torsion__mpz_jacobi
#define mpz_kronecker torsion__mpz_kronecker
#define mpz_kronecker_ui torsion__mpz_kronecker_ui
#define mpz_kronecker_si torsion__mpz_kronecker_si
#define mpz_ui_kronecker torsion__mpz_ui_kronecker
#define mpz_si_kronecker torsion__mpz_si_kronecker
#define mpz_powm torsion__mpz_powm
#define mpz_powm_ui torsion__mpz_powm_ui
#define mpz_powm_sec torsion__mpz_powm_sec
#define mpz_sqrtm torsion__mpz_sqrtm
#define mpz_sqrtpq torsion__mpz_sqrtpq
#define mpz_remove torsion__mpz_remove
#define mpz_fac_ui torsion__mpz_fac_ui
#define mpz_2fac_ui torsion__mpz_2fac_ui
#define mpz_mfac_uiui torsion__mpz_mfac_uiui
#define mpz_primorial_ui torsion__mpz_primorial_ui
#define mpz_bin_ui torsion__mpz_bin_ui
#define mpz_bin_uiui torsion__mpz_bin_uiui
#define mpz_bin_siui torsion__mpz_bin_siui
#define mpz_fib_ui torsion__mpz_fib_ui
#define mpz_fib2_ui torsion__mpz_fib2_ui
#define mpz_lucnum_ui torsion__mpz_lucnum_ui
#define mpz_lucnum2_ui torsion__mpz_lucnum2_ui
#define mpz_mr_prime_p torsion__mpz_mr_prime_p
#define mpz_lucas_prime_p torsion__mpz_lucas_prime_p
#define mpz_probab_prime_p torsion__mpz_probab_prime_p
#define mpz_randprime torsion__mpz_randprime
#define mpz_nextprime torsion__mpz_nextprime
#define mpz_findprime torsion__mpz_findprime
#define mpz_fits_ui_p torsion__mpz_fits_ui_p
#define mpz_fits_si_p torsion__mpz_fits_si_p
#define mpz_odd_p torsion__mpz_odd_p
#define mpz_even_p torsion__mpz_even_p
#define mpz_ctz torsion__mpz_ctz
#define mpz_bitlen torsion__mpz_bitlen
#define mpz_bytelen torsion__mpz_bytelen
#define mpz_sizeinbase torsion__mpz_sizeinbase
#define mpz_swap torsion__mpz_swap
#define _mpz_realloc torsion__mpz_realloc
#define mpz_realloc2 torsion__mpz_realloc2
#define mpz_getlimbn torsion__mpz_getlimbn
#define mpz_size torsion__mpz_size
#define mpz_limbs_read torsion__mpz_limbs_read
#define mpz_limbs_write torsion__mpz_limbs_write
#define mpz_limbs_modify torsion__mpz_limbs_modify
#define mpz_limbs_finish torsion__mpz_limbs_finish
#define mpz_import torsion__mpz_import
#define mpz_export torsion__mpz_export
#define mpz_set_str torsion__mpz_set_str
#define mpz_get_str torsion__mpz_get_str
#define mpz_print torsion__mpz_print
#define mpz_urandomb torsion__mpz_urandomb
#define mpz_urandomm torsion__mpz_urandomm
#define test_mpi_internal torsion__test_mpi_internal
#define bench_mpi_internal torsion__bench_mpi_internal

/*
 * Types
 */

#if defined(UINTPTR_MAX) && defined(UINT64_MAX)
/* Check size of uintptr_t if available. */
#  if UINTPTR_MAX == UINT64_MAX
#    define MP_HAVE_64BIT
#  endif
#endif

#if defined(MP_HAVE_64BIT)
typedef uint64_t mp_limb_t;
typedef int64_t mp_long_t;
#  define MP_LIMB_BITS 64
#  define MP_LIMB_BYTES 8
#  define MP_LIMB_C UINT64_C
#  define MP_LIMB_MAX UINT64_MAX
#  define MP_LONG_C INT64_C
#  define MP_LONG_MIN INT64_MIN
#  define MP_LONG_MAX INT64_MAX
#else
typedef uint32_t mp_limb_t;
typedef int32_t mp_long_t;
#  define MP_LIMB_BITS 32
#  define MP_LIMB_BYTES 4
#  define MP_LIMB_C UINT32_C
#  define MP_LIMB_MAX UINT32_MAX
#  define MP_LONG_C INT32_C
#  define MP_LONG_MIN INT32_MIN
#  define MP_LONG_MAX INT32_MAX
#endif

typedef long mp_size_t;
typedef long mp_bits_t;
typedef mp_bits_t mp_bitcnt_t; /* compat */

#define MP_SIZE_C(x) x ## L
#define MP_SIZE_MIN LONG_MIN
#define MP_SIZE_MAX LONG_MAX
#define MP_BITS_C(x) x ## L
#define MP_BITS_MIN LONG_MIN
#define MP_BITS_MAX LONG_MAX

#define MP_LIMB_HI (MP_LIMB_C(1) << (MP_LIMB_BITS - 1))
#define MP_MASK(bits) ((MP_LIMB_C(1) << (bits)) - 1)
#define MP_LOW_BITS (MP_LIMB_BITS / 2)
#define MP_LOW_MASK (MP_LIMB_MAX >> MP_LOW_BITS)

struct mpz_s {
  mp_limb_t *limbs;
  mp_size_t alloc;
  mp_size_t size;
};

typedef struct mpz_s mpz_t[1];

/* Note: these types aren't strictly documented,
 * but they are sometimes referenced in the docs[1],
 * and they are no doubt used by programmers as
 * they have been mentioned on the mailing list
 * a number of times[2][3].
 *
 * [1] https://gmplib.org/manual/Integer-Special-Functions
 * [2] https://gmplib.org/list-archives/gmp-discuss/2011-February/004493.html
 * [3] https://gmplib.org/list-archives/gmp-discuss/2009-May/003769.html
 */
typedef mp_limb_t *mp_ptr;
typedef const mp_limb_t *mp_srcptr;
typedef struct mpz_s *mpz_ptr;
typedef const struct mpz_s *mpz_srcptr;

typedef int mp_puts_f(const char *s);
typedef void mp_rng_f(void *out, size_t size, void *arg);
typedef void mp_start_f(uint64_t *start, const char *name);
typedef void mp_end_f(uint64_t *start, uint64_t ops);

/*
 * Definitions
 */

#define MP_SLIDE_WIDTH 4
#define MP_SLIDE_SIZE (1 << (MP_SLIDE_WIDTH - 1))
#define MP_FIXED_WIDTH 4
#define MP_FIXED_SIZE (1 << MP_FIXED_WIDTH)

/*
 * Itches
 */

#define MPN_SQR_ITCH(n) (2 * (n))
#define MPN_MULSHIFT_ITCH(n) (2 * (n))
#define MPN_REDUCE_WEAK_ITCH(n) (n)
#define MPN_BARRETT_ITCH(shift) ((shift) + 1)
#define MPN_REDUCE_ITCH(n, shift) (1 + (shift) + ((shift) - (n) + 1))
#define MPN_MONT_ITCH(n) (2 * (n) + 1)
#define MPN_MONTMUL_ITCH(n) (2 * (n))
#define MPN_GCD_ITCH(xn, yn) ((xn) + (yn))
#define MPN_GCD_1_ITCH(xn) (xn)
#define MPN_INVERT_ITCH(n) (4 * ((n) + 1))
#define MPN_SEC_INVERT_ITCH(n) ((n) + MPN_SEC_POWM_ITCH(n))
#define MPN_JACOBI_ITCH(n) (2 * (n))
#define MPN_SLIDE_ITCH(yn, mn) ((yn) > 2 ? (MP_SLIDE_SIZE * (mn)) : 0)
#define MPN_POWM_ITCH(yn, mn) (6 * (mn) + MPN_SLIDE_ITCH(yn, mn))
#define MPN_SEC_POWM_ITCH(n) (5 * (n) + MP_FIXED_SIZE * (n) + 1)

/* Either Barrett or Montgomery precomputation. */
#define MPN_BARRETT_MONT_ITCH(shift) ((shift) + 2)

/*
 * Macros
 */

#define MPZ_ROINIT_N(xp, xs) {{(mp_limb_t *)(xp), 0, (xs)}}

/*
 * Globals
 */

/* https://gmplib.org/manual/Useful-Macros-and-Constants */
extern const int mp_bits_per_limb;

/*
 * MPN Interface
 */

/*
 * Initialization
 */

void
mpn_zero(mp_limb_t *zp, mp_size_t zn);

/*
 * Uninitialization
 */

void
mpn_cleanse(mp_limb_t *zp, mp_size_t zn);

/*
 * Assignment
 */

void
mpn_set_1(mp_limb_t *zp, mp_size_t zn, mp_limb_t x);

void
mpn_copyi(mp_limb_t *zp, const mp_limb_t *xp, mp_size_t xn);

void
mpn_copyd(mp_limb_t *zp, const mp_limb_t *xp, mp_size_t xn);

/*
 * Comparison
 */

int
mpn_zero_p(const mp_limb_t *xp, mp_size_t xn);

int
mpn_cmp(const mp_limb_t *xp, const mp_limb_t *yp, mp_size_t n);

/*
 * Addition
 */

mp_limb_t
mpn_add_1(mp_limb_t *zp, const mp_limb_t *xp, mp_size_t xn, mp_limb_t y);

mp_limb_t
mpn_add_n(mp_limb_t *zp, const mp_limb_t *xp,
                         const mp_limb_t *yp,
                         mp_size_t n);

mp_limb_t
mpn_add(mp_limb_t *zp, const mp_limb_t *xp, mp_size_t xn,
                       const mp_limb_t *yp, mp_size_t yn);

/*
 * Secure Addition
 */

mp_limb_t
mpn_sec_add_1(mp_limb_t *zp, const mp_limb_t *xp, mp_size_t xn, mp_limb_t y);

mp_limb_t
mpn_sec_add(mp_limb_t *zp, const mp_limb_t *xp, mp_size_t xn,
                           const mp_limb_t *yp, mp_size_t yn);

/*
 * Subtraction
 */

mp_limb_t
mpn_sub_1(mp_limb_t *zp, const mp_limb_t *xp, mp_size_t xn, mp_limb_t y);

mp_limb_t
mpn_sub_n(mp_limb_t *zp, const mp_limb_t *xp,
                         const mp_limb_t *yp,
                         mp_size_t n);

mp_limb_t
mpn_sub(mp_limb_t *zp, const mp_limb_t *xp, mp_size_t xn,
                       const mp_limb_t *yp, mp_size_t yn);

/*
 * Secure Subtraction
 */

mp_limb_t
mpn_sec_sub_1(mp_limb_t *zp, const mp_limb_t *xp, mp_size_t xn, mp_limb_t y);

mp_limb_t
mpn_sec_sub(mp_limb_t *zp, const mp_limb_t *xp, mp_size_t xn,
                           const mp_limb_t *yp, mp_size_t yn);

/*
 * Multiplication
 */

mp_limb_t
mpn_mul_1(mp_limb_t *zp, const mp_limb_t *xp, mp_size_t xn, mp_limb_t y);

mp_limb_t
mpn_addmul_1(mp_limb_t *zp, const mp_limb_t *xp, mp_size_t xn, mp_limb_t y);

mp_limb_t
mpn_submul_1(mp_limb_t *zp, const mp_limb_t *xp, mp_size_t xn, mp_limb_t y);

void
mpn_mul_n(mp_limb_t *zp, const mp_limb_t *xp,
                         const mp_limb_t *yp,
                         mp_size_t n);

void
mpn_mul(mp_limb_t *zp, const mp_limb_t *xp, mp_size_t xn,
                       const mp_limb_t *yp, mp_size_t yn);

void
mpn_sqr(mp_limb_t *zp, const mp_limb_t *xp, mp_size_t xn, mp_limb_t *scratch);

/*
 * Multiply + Shift
 */

mp_limb_t
mpn_mulshift(mp_limb_t *zp, const mp_limb_t *xp,
                            const mp_limb_t *yp,
                            mp_size_t n,
                            mp_bits_t bits,
                            mp_limb_t *scratch);

/*
 * Division
 */

mp_limb_t
mpn_divmod_1(mp_limb_t *qp, const mp_limb_t *np, mp_size_t nn, mp_limb_t d);

void
mpn_div_1(mp_limb_t *qp, const mp_limb_t *np, mp_size_t nn, mp_limb_t d);

mp_limb_t
mpn_mod_1(const mp_limb_t *np, mp_size_t nn, mp_limb_t d);

void
mpn_divmod(mp_limb_t *qp, mp_limb_t *rp,
           const mp_limb_t *np, mp_size_t nn,
           const mp_limb_t *dp, mp_size_t dn);

void
mpn_div(mp_limb_t *qp, const mp_limb_t *np, mp_size_t nn,
                       const mp_limb_t *dp, mp_size_t dn);

void
mpn_mod(mp_limb_t *rp, const mp_limb_t *np, mp_size_t nn,
                       const mp_limb_t *dp, mp_size_t dn);

/*
 * Exact Division
 */

void
mpn_divexact_1(mp_limb_t *qp, const mp_limb_t *np, mp_size_t nn, mp_limb_t d);

void
mpn_divexact(mp_limb_t *qp, const mp_limb_t *np, mp_size_t nn,
                            const mp_limb_t *dp, mp_size_t dn);

/*
 * AND
 */

void
mpn_and_n(mp_limb_t *zp, const mp_limb_t *xp,
                         const mp_limb_t *yp,
                         mp_size_t n);

/*
 * OR
 */

void
mpn_ior_n(mp_limb_t *zp, const mp_limb_t *xp,
                         const mp_limb_t *yp,
                         mp_size_t n);

/*
 * XOR
 */

void
mpn_xor_n(mp_limb_t *zp, const mp_limb_t *xp,
                         const mp_limb_t *yp,
                         mp_size_t n);

/*
 * AND+NOT
 */

void
mpn_andn_n(mp_limb_t *zp, const mp_limb_t *xp,
                          const mp_limb_t *yp,
                          mp_size_t n);

/*
 * OR+NOT
 */

void
mpn_iorn_n(mp_limb_t *zp, const mp_limb_t *xp,
                          const mp_limb_t *yp,
                          mp_size_t n);

/*
 * NOT+AND
 */

void
mpn_nand_n(mp_limb_t *zp, const mp_limb_t *xp,
                          const mp_limb_t *yp,
                          mp_size_t n);

/*
 * NOT+OR
 */

void
mpn_nior_n(mp_limb_t *zp, const mp_limb_t *xp,
                          const mp_limb_t *yp,
                          mp_size_t n);

/*
 * NOT+XOR
 */

void
mpn_xnor_n(mp_limb_t *zp, const mp_limb_t *xp,
                          const mp_limb_t *yp,
                          mp_size_t n);

/*
 * NOT
 */

void
mpn_com(mp_limb_t *zp, const mp_limb_t *xp, mp_size_t xn);

/*
 * Left Shift
 */

mp_limb_t
mpn_lshift(mp_limb_t *zp, const mp_limb_t *xp, mp_size_t xn, mp_bits_t bits);

/*
 * Right Shift
 */

mp_limb_t
mpn_rshift(mp_limb_t *zp, const mp_limb_t *xp, mp_size_t xn, mp_bits_t bits);

/*
 * Bit Manipulation
 */

mp_limb_t
mpn_getbit(const mp_limb_t *xp, mp_size_t xn, mp_bits_t pos);

mp_limb_t
mpn_getbits(const mp_limb_t *xp, mp_size_t xn, mp_bits_t pos, mp_bits_t width);

int
mpn_tstbit(const mp_limb_t *xp, mp_bits_t pos);

void
mpn_setbit(mp_limb_t *zp, mp_bits_t pos);

void
mpn_clrbit(mp_limb_t *zp, mp_bits_t pos);

void
mpn_combit(mp_limb_t *zp, mp_bits_t pos);

mp_bits_t
mpn_scan0(const mp_limb_t *xp, mp_size_t xn, mp_bits_t pos);

mp_bits_t
mpn_scan1(const mp_limb_t *xp, mp_size_t xn, mp_bits_t pos);

mp_bits_t
mpn_popcount(const mp_limb_t *xp, mp_size_t xn);

mp_bits_t
mpn_hamdist(const mp_limb_t *xp, const mp_limb_t *yp, mp_size_t n);

void
mpn_mask(mp_limb_t *zp, const mp_limb_t *xp, mp_size_t xn, mp_bits_t bits);

/*
 * Negation
 */

mp_limb_t
mpn_neg(mp_limb_t *zp, const mp_limb_t *xp, mp_size_t xn);

/*
 * Weak Reduction
 */

int
mpn_reduce_weak(mp_limb_t *zp, const mp_limb_t *xp,
                               const mp_limb_t *np,
                               mp_size_t n,
                               mp_limb_t hi,
                               mp_limb_t *scratch);

/*
 * Barrett Reduction
 */

void
mpn_barrett(mp_limb_t *mp, const mp_limb_t *np,
                           mp_size_t n,
                           mp_size_t shift,
                           mp_limb_t *scratch);

void
mpn_reduce(mp_limb_t *zp, const mp_limb_t *xp,
                          const mp_limb_t *mp,
                          const mp_limb_t *np,
                          mp_size_t n,
                          mp_size_t shift,
                          mp_limb_t *scratch);

/*
 * Montgomery Multiplication
 */

void
mpn_mont(mp_limb_t *kp,
         mp_limb_t *rp,
         const mp_limb_t *mp,
         mp_size_t n,
         mp_limb_t *scratch);

void
mpn_montmul(mp_limb_t *zp, const mp_limb_t *xp,
                           const mp_limb_t *yp,
                           const mp_limb_t *mp,
                           mp_size_t n,
                           mp_limb_t k,
                           mp_limb_t *scratch);

void
mpn_sec_montmul(mp_limb_t *zp, const mp_limb_t *xp,
                               const mp_limb_t *yp,
                               const mp_limb_t *mp,
                               mp_size_t n,
                               mp_limb_t k,
                               mp_limb_t *scratch);

/*
 * Number Theoretic Functions
 */

mp_size_t
mpn_gcd(mp_limb_t *zp, const mp_limb_t *xp, mp_size_t xn,
                       const mp_limb_t *yp, mp_size_t yn,
                       mp_limb_t *scratch);

mp_limb_t
mpn_gcd_1(const mp_limb_t *xp, mp_size_t xn, mp_limb_t y, mp_limb_t *scratch);

int
mpn_invert(mp_limb_t *zp, const mp_limb_t *xp, mp_size_t xn,
                          const mp_limb_t *yp, mp_size_t yn,
                          mp_limb_t *scratch);

int
mpn_invert_n(mp_limb_t *zp, const mp_limb_t *xp,
                            const mp_limb_t *yp,
                            mp_size_t n,
                            mp_limb_t *scratch);

int
mpn_sec_invert(mp_limb_t *zp, const mp_limb_t *xp, mp_size_t xn,
                              const mp_limb_t *mp, mp_size_t mn,
                              mp_limb_t *scratch);

int
mpn_sec_invert_n(mp_limb_t *zp, const mp_limb_t *xp,
                                const mp_limb_t *yp,
                                mp_size_t n,
                                mp_limb_t *scratch);

int
mpn_jacobi(const mp_limb_t *xp, mp_size_t xn,
           const mp_limb_t *yp, mp_size_t yn,
           mp_limb_t *scratch);

int
mpn_jacobi_n(const mp_limb_t *xp,
             const mp_limb_t *yp,
             mp_size_t n,
             mp_limb_t *scratch);

void
mpn_powm(mp_limb_t *zp, const mp_limb_t *xp, mp_size_t xn,
                        const mp_limb_t *yp, mp_size_t yn,
                        const mp_limb_t *mp, mp_size_t mn,
                        mp_limb_t *scratch);

void
mpn_sec_powm(mp_limb_t *zp, const mp_limb_t *xp, mp_size_t xn,
                            const mp_limb_t *yp, mp_size_t yn,
                            const mp_limb_t *mp, mp_size_t mn,
                            mp_limb_t *scratch);

/*
 * Helpers
 */

mp_bits_t
mpn_ctz(const mp_limb_t *xp, mp_size_t xn);

mp_bits_t
mpn_bitlen(const mp_limb_t *xp, mp_size_t xn);

size_t
mpn_bytelen(const mp_limb_t *xp, mp_size_t xn);

size_t
mpn_sizeinbase(const mp_limb_t *xp, mp_size_t xn, int base);

/*
 * Constant Time
 */

void
mpn_cnd_select(mp_limb_t *zp, const mp_limb_t *xp,
                              const mp_limb_t *yp,
                              mp_size_t n,
                              mp_limb_t cnd);

void
mpn_cnd_swap(mp_limb_t *xp, mp_limb_t *yp, mp_size_t n, mp_limb_t cnd);

mp_limb_t
mpn_cnd_add_n(mp_limb_t *zp, const mp_limb_t *xp,
                             const mp_limb_t *yp,
                             mp_size_t n,
                             mp_limb_t cnd);

mp_limb_t
mpn_cnd_sub_n(mp_limb_t *zp, const mp_limb_t *xp,
                             const mp_limb_t *yp,
                             mp_size_t n,
                             mp_limb_t cnd);

mp_limb_t
mpn_cnd_neg(mp_limb_t *zp, const mp_limb_t *xp, mp_size_t xn, mp_limb_t cnd);

void
mpn_sec_tabselect(mp_limb_t *zp,
                  const mp_limb_t *tp,
                  mp_size_t n,
                  mp_size_t nents,
                  mp_size_t which);

int
mpn_sec_zero_p(const mp_limb_t *xp, mp_size_t xn);

int
mpn_sec_equal_p(const mp_limb_t *xp, const mp_limb_t *yp, mp_size_t n);

int
mpn_sec_lt_p(const mp_limb_t *xp, const mp_limb_t *yp, mp_size_t n);

int
mpn_sec_lte_p(const mp_limb_t *xp, const mp_limb_t *yp, mp_size_t n);

int
mpn_sec_gt_p(const mp_limb_t *xp, const mp_limb_t *yp, mp_size_t n);

int
mpn_sec_gte_p(const mp_limb_t *xp, const mp_limb_t *yp, mp_size_t n);

int
mpn_sec_cmp(const mp_limb_t *xp, const mp_limb_t *yp, mp_size_t n);

/*
 * Import
 */

void
mpn_import(mp_limb_t *zp, mp_size_t zn,
           const unsigned char *xp, size_t xn,
           int endian);

/*
 * Export
 */

void
mpn_export(unsigned char *zp, size_t zn,
           const mp_limb_t *xp, mp_size_t xn,
           int endian);

/*
 * String Import
 */

int
mpn_set_str(mp_limb_t *zp, mp_size_t zn, const char *str, int base);

/*
 * String Export
 */

size_t
mpn_get_str(char *str, const mp_limb_t *xp, mp_size_t xn, int base);

/*
 * STDIO
 */

void
mpn_print(const mp_limb_t *xp, mp_size_t xn, int base, mp_puts_f *mp_puts);

/*
 * RNG
 */

void
mpn_random(mp_limb_t *zp, mp_size_t zn, mp_rng_f *rng, void *arg);

void
mpn_randomm(mp_limb_t *zp,
            const mp_limb_t *xp, mp_size_t xn,
            mp_rng_f *rng, void *arg);

/*
 * MPZ Interface
 */

/*
 * Initialization
 */

void
mpz_init(mpz_t z);

void
mpz_init2(mpz_t z, mp_bits_t bits);

void
mpz_init_set(mpz_t z, const mpz_t x);

void
mpz_init_set_ui(mpz_t z, mp_limb_t x);

void
mpz_init_set_si(mpz_t z, mp_long_t x);

int
mpz_init_set_str(mpz_t z, const char *str, int base);

/*
 * Uninitialization
 */

void
mpz_clear(mpz_t z);

void
mpz_cleanse(mpz_t z);

/*
 * Assignment
 */

void
mpz_set(mpz_t z, const mpz_t x);

void
mpz_roset(mpz_t z, const mpz_t x);

const struct mpz_s *
mpz_roinit_n(mpz_t z, const mp_limb_t *xp, mp_size_t xs);

void
mpz_set_ui(mpz_t z, mp_limb_t x);

void
mpz_set_si(mpz_t z, mp_long_t x);

/*
 * Conversion
 */

mp_limb_t
mpz_get_ui(const mpz_t x);

mp_long_t
mpz_get_si(const mpz_t x);

/*
 * Comparison
 */

int
mpz_sgn(const mpz_t x);

int
mpz_cmp(const mpz_t x, const mpz_t y);

int
mpz_cmp_ui(const mpz_t x, mp_limb_t y);

int
mpz_cmp_si(const mpz_t x, mp_long_t y);

/*
 * Unsigned Comparison
 */

int
mpz_cmpabs(const mpz_t x, const mpz_t y);

int
mpz_cmpabs_ui(const mpz_t x, mp_limb_t y);

int
mpz_cmpabs_si(const mpz_t x, mp_long_t y);

/*
 * Addition
 */

void
mpz_add(mpz_t z, const mpz_t x, const mpz_t y);

void
mpz_add_ui(mpz_t z, const mpz_t x, mp_limb_t y);

void
mpz_add_si(mpz_t z, const mpz_t x, mp_long_t y);

/*
 * Subtraction
 */

void
mpz_sub(mpz_t z, const mpz_t x, const mpz_t y);

void
mpz_sub_ui(mpz_t z, const mpz_t x, mp_limb_t y);

void
mpz_sub_si(mpz_t z, const mpz_t x, mp_long_t y);

void
mpz_ui_sub(mpz_t z, mp_limb_t x, const mpz_t y);

void
mpz_si_sub(mpz_t z, mp_long_t x, const mpz_t y);

/*
 * Multiplication
 */

void
mpz_mul(mpz_t z, const mpz_t x, const mpz_t y);

void
mpz_mul_ui(mpz_t z, const mpz_t x, mp_limb_t y);

void
mpz_mul_si(mpz_t z, const mpz_t x, mp_long_t y);

void
mpz_sqr(mpz_t z, const mpz_t x);

void
mpz_addmul(mpz_t z, const mpz_t x, const mpz_t y);

void
mpz_addmul_ui(mpz_t z, const mpz_t x, mp_limb_t y);

void
mpz_addmul_si(mpz_t z, const mpz_t x, mp_long_t y);

void
mpz_submul(mpz_t z, const mpz_t x, const mpz_t y);

void
mpz_submul_ui(mpz_t z, const mpz_t x, mp_limb_t y);

void
mpz_submul_si(mpz_t z, const mpz_t x, mp_long_t y);

/*
 * Multiply + Shift
 */

void
mpz_mulshift(mpz_t z, const mpz_t x, const mpz_t y, mp_bits_t bits);

/*
 * Truncation Division
 */

void
mpz_quorem(mpz_t q, mpz_t r, const mpz_t n, const mpz_t d);

void
mpz_quo(mpz_t q, const mpz_t n, const mpz_t d);

void
mpz_rem(mpz_t r, const mpz_t n, const mpz_t d);

mp_limb_t
mpz_quo_ui(mpz_t q, const mpz_t n, mp_limb_t d);

mp_limb_t
mpz_rem_ui(const mpz_t n, mp_limb_t d);

mp_long_t
mpz_quo_si(mpz_t q, const mpz_t n, mp_long_t d);

mp_long_t
mpz_rem_si(const mpz_t n, mp_long_t d);

/*
 * Euclidean Division
 */

void
mpz_divmod(mpz_t q, mpz_t r, const mpz_t n, const mpz_t d);

void
mpz_div(mpz_t q, const mpz_t n, const mpz_t d);

void
mpz_mod(mpz_t r, const mpz_t n, const mpz_t d);

mp_limb_t
mpz_div_ui(mpz_t q, const mpz_t n, mp_limb_t d);

mp_limb_t
mpz_mod_ui(const mpz_t n, mp_limb_t d);

mp_long_t
mpz_div_si(mpz_t q, const mpz_t n, mp_long_t d);

mp_long_t
mpz_mod_si(const mpz_t n, mp_long_t d);

/*
 * Exact Division
 */

void
mpz_divexact(mpz_t q, const mpz_t n, const mpz_t d);

void
mpz_divexact_ui(mpz_t q, const mpz_t n, mp_limb_t d);

void
mpz_divexact_si(mpz_t q, const mpz_t n, mp_long_t d);

/*
 * Round Division
 */

void
mpz_divround(mpz_t q, const mpz_t n, const mpz_t d);

void
mpz_divround_ui(mpz_t q, const mpz_t n, mp_limb_t d);

void
mpz_divround_si(mpz_t q, const mpz_t n, mp_long_t d);

/*
 * Divisibility
 */

int
mpz_divisible_p(const mpz_t n, const mpz_t d);

int
mpz_divisible_ui_p(const mpz_t n, mp_limb_t d);

int
mpz_divisible_2exp_p(const mpz_t n, mp_bits_t bits);

/*
 * Congruence
 */

int
mpz_congruent_p(const mpz_t x, const mpz_t y, const mpz_t d);

int
mpz_congruent_ui_p(const mpz_t x, const mpz_t y, mp_limb_t d);

int
mpz_congruent_2exp_p(const mpz_t x, const mpz_t y, mp_bits_t bits);

/*
 * Exponentiation
 */

void
mpz_pow_ui(mpz_t z, const mpz_t x, mp_limb_t y);

void
mpz_ui_pow_ui(mpz_t z, mp_limb_t x, mp_limb_t y);

/*
 * Roots
 */

void
mpz_rootrem(mpz_t z, mpz_t r, const mpz_t x, mp_limb_t k);

int
mpz_root(mpz_t z, const mpz_t x, mp_limb_t k);

int
mpz_perfect_power_p(const mpz_t x);

void
mpz_sqrtrem(mpz_t z, mpz_t r, const mpz_t x);

void
mpz_sqrt(mpz_t z, const mpz_t x);

int
mpz_perfect_square_p(const mpz_t x);

/*
 * AND
 */

void
mpz_and(mpz_t z, const mpz_t x, const mpz_t y);

mp_limb_t
mpz_and_ui(const mpz_t x, mp_limb_t y);

void
mpz_and_si(mpz_t z, const mpz_t x, mp_long_t y);

/*
 * OR
 */

void
mpz_ior(mpz_t z, const mpz_t x, const mpz_t y);

void
mpz_ior_ui(mpz_t z, const mpz_t x, mp_limb_t y);

void
mpz_ior_si(mpz_t z, const mpz_t x, mp_long_t y);

/*
 * XOR
 */

void
mpz_xor(mpz_t z, const mpz_t x, const mpz_t y);

void
mpz_xor_ui(mpz_t z, const mpz_t x, mp_limb_t y);

void
mpz_xor_si(mpz_t z, const mpz_t x, mp_long_t y);

/*
 * NOT
 */

void
mpz_com(mpz_t z, const mpz_t x);

/*
 * Left Shift
 */

void
mpz_mul_2exp(mpz_t z, const mpz_t x, mp_bits_t bits);

/*
 * Unsigned Right Shift
 */

void
mpz_quo_2exp(mpz_t z, const mpz_t x, mp_bits_t bits);

void
mpz_rem_2exp(mpz_t z, const mpz_t x, mp_bits_t bits);

/*
 * Right Shift
 */

void
mpz_div_2exp(mpz_t z, const mpz_t x, mp_bits_t bits);

void
mpz_mod_2exp(mpz_t z, const mpz_t x, mp_bits_t bits);

/*
 * Bit Manipulation
 */

int
mpz_tstbit(const mpz_t x, mp_bits_t pos);

void
mpz_setbit(mpz_t z, mp_bits_t pos);

void
mpz_clrbit(mpz_t z, mp_bits_t pos);

void
mpz_combit(mpz_t z, mp_bits_t pos);

mp_bits_t
mpz_scan0(const mpz_t x, mp_bits_t pos);

mp_bits_t
mpz_scan1(const mpz_t x, mp_bits_t pos);

mp_bits_t
mpz_popcount(const mpz_t x);

mp_bits_t
mpz_hamdist(const mpz_t x, const mpz_t y);

/*
 * Negation
 */

void
mpz_abs(mpz_t z, const mpz_t x);

void
mpz_neg(mpz_t z, const mpz_t x);

/*
 * Number Theoretic Functions
 */

void
mpz_gcd(mpz_t z, const mpz_t x, const mpz_t y);

mp_limb_t
mpz_gcd_ui(mpz_t z, const mpz_t x, mp_limb_t y);

void
mpz_lcm(mpz_t z, const mpz_t x, const mpz_t y);

void
mpz_lcm_ui(mpz_t z, const mpz_t x, mp_limb_t y);

void
mpz_gcdext(mpz_t g, mpz_t s, mpz_t t, const mpz_t x, const mpz_t y);

int
mpz_invert(mpz_t z, const mpz_t x, const mpz_t y);

int
mpz_legendre(const mpz_t x, const mpz_t p);

int
mpz_jacobi(const mpz_t x, const mpz_t y);

int
mpz_kronecker(const mpz_t x, const mpz_t y);

int
mpz_kronecker_ui(const mpz_t x, mp_limb_t y);

int
mpz_kronecker_si(const mpz_t x, mp_long_t y);

int
mpz_ui_kronecker(mp_limb_t x, const mpz_t y);

int
mpz_si_kronecker(mp_long_t x, const mpz_t y);

void
mpz_powm(mpz_t z, const mpz_t x, const mpz_t y, const mpz_t m);

void
mpz_powm_ui(mpz_t z, const mpz_t x, mp_limb_t y, const mpz_t m);

void
mpz_powm_sec(mpz_t z, const mpz_t x, const mpz_t y, const mpz_t m);

int
mpz_sqrtm(mpz_t z, const mpz_t x, const mpz_t p);

int
mpz_sqrtpq(mpz_t z, const mpz_t x, const mpz_t p, const mpz_t q);

mp_bits_t
mpz_remove(mpz_t z, const mpz_t x, const mpz_t y);

void
mpz_fac_ui(mpz_t z, mp_limb_t n);

void
mpz_2fac_ui(mpz_t z, mp_limb_t n);

void
mpz_mfac_uiui(mpz_t z, mp_limb_t n, mp_limb_t m);

void
mpz_primorial_ui(mpz_t z, mp_limb_t n);

void
mpz_bin_ui(mpz_t z, const mpz_t n, mp_limb_t k);

void
mpz_bin_uiui(mpz_t z, mp_limb_t n, mp_limb_t k);

void
mpz_bin_siui(mpz_t z, mp_long_t n, mp_limb_t k);

void
mpz_fib_ui(mpz_t fn, mp_limb_t n);

void
mpz_fib2_ui(mpz_t fn, mpz_t fn1, mp_limb_t n);

void
mpz_lucnum_ui(mpz_t ln, mp_limb_t n);

void
mpz_lucnum2_ui(mpz_t ln, mpz_t ln1, mp_limb_t n);

/*
 * Primality Testing
 */

int
mpz_mr_prime_p(const mpz_t n, int reps, int force2, mp_rng_f *rng, void *arg);

int
mpz_lucas_prime_p(const mpz_t n, mp_limb_t limit);

int
mpz_probab_prime_p(const mpz_t x, int rounds, mp_rng_f *rng, void *arg);

void
mpz_randprime(mpz_t z, mp_bits_t bits, mp_rng_f *rng, void *arg);

void
mpz_nextprime(mpz_t z, const mpz_t x, mp_rng_f *rng, void *arg);

int
mpz_findprime(mpz_t z, const mpz_t x, mp_limb_t max, mp_rng_f *rng, void *arg);

/*
 * Helpers
 */

int
mpz_fits_ui_p(const mpz_t x);

int
mpz_fits_si_p(const mpz_t x);

int
mpz_odd_p(const mpz_t x);

int
mpz_even_p(const mpz_t x);

mp_bits_t
mpz_ctz(const mpz_t x);

mp_bits_t
mpz_bitlen(const mpz_t x);

size_t
mpz_bytelen(const mpz_t x);

size_t
mpz_sizeinbase(const mpz_t x, int base);

void
mpz_swap(mpz_t x, mpz_t y);

void *
_mpz_realloc(mpz_t z, mp_size_t n);

void
mpz_realloc2(mpz_t z, mp_bits_t bits);

/*
 * Limb Helpers
 */

mp_limb_t
mpz_getlimbn(const mpz_t x, mp_size_t n);

size_t
mpz_size(const mpz_t x);

const mp_limb_t *
mpz_limbs_read(const mpz_t x);

mp_limb_t *
mpz_limbs_write(mpz_t z, mp_size_t n);

mp_limb_t *
mpz_limbs_modify(mpz_t z, mp_size_t n);

void
mpz_limbs_finish(mpz_t z, mp_size_t n);

/*
 * Import
 */

void
mpz_import(mpz_t z, const unsigned char *raw, size_t size, int endian);

/*
 * Export
 */

void
mpz_export(unsigned char *raw, const mpz_t x, size_t size, int endian);

/*
 * String Import
 */

int
mpz_set_str(mpz_t z, const char *str, int base);

/*
 * String Export
 */

char *
mpz_get_str(const mpz_t x, int base);

/*
 * STDIO
 */

void
mpz_print(const mpz_t x, int base, mp_puts_f *mp_puts);

/*
 * RNG
 */

void
mpz_urandomb(mpz_t z, mp_bits_t bits, mp_rng_f *rng, void *arg);

void
mpz_urandomm(mpz_t z, const mpz_t x, mp_rng_f *rng, void *arg);

/*
 * Testing
 */

TORSION_EXTERN void
test_mpi_internal(mp_rng_f *rng, void *arg);

/*
 * Benchmarks
 */

TORSION_EXTERN void
bench_mpi_internal(mp_start_f *start, mp_end_f *end, mp_rng_f *rng, void *arg);

#endif /* TORSION_MPI_H */
