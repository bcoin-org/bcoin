/*
 * Copyright 2017-2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2014 Cryptography Research, Inc.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Originally written by Mike Hamburg
 */

#ifndef _BCRYPTO_FIELD_H
# define _BCRYPTO_FIELD_H

# include "internal/constant_time_locl.h"
# include <string.h>
# include <assert.h>
# include "word.h"

# define BCRYPTO_NLIMBS (64/sizeof(bcrypto_word_t))
# define BCRYPTO_X_SER_BYTES 56
# define BCRYPTO_SER_BYTES 56

# if defined(__GNUC__) || defined(__clang__)
#  define BCRYPTO_INLINE_UNUSED __inline__ __attribute__((__unused__,__always_inline__))
#  define BCRYPTO_RESTRICT __restrict__
#  define BCRYPTO_ALIGNED __attribute__((__aligned__(16)))
# else
#  define BCRYPTO_INLINE_UNUSED inline
#  define BCRYPTO_RESTRICT
#  define BCRYPTO_ALIGNED
# endif

typedef struct bcrypto_gf_s {
  bcrypto_word_t limb[BCRYPTO_NLIMBS];
} BCRYPTO_ALIGNED bcrypto_gf_s, bcrypto_gf[1];

/* RFC 7748 support */
# define BCRYPTO_X_PUBLIC_BYTES  BCRYPTO_X_SER_BYTES
# define BCRYPTO_X_PRIVATE_BYTES BCRYPTO_X_PUBLIC_BYTES
# define BCRYPTO_X_PRIVATE_BITS  448

static BCRYPTO_INLINE_UNUSED void bcrypto_gf_copy(bcrypto_gf out, const bcrypto_gf a)
{
  *out = *a;
}

static BCRYPTO_INLINE_UNUSED void bcrypto_gf_add_RAW(bcrypto_gf out, const bcrypto_gf a, const bcrypto_gf b);
static BCRYPTO_INLINE_UNUSED void bcrypto_gf_sub_RAW(bcrypto_gf out, const bcrypto_gf a, const bcrypto_gf b);
static BCRYPTO_INLINE_UNUSED void bcrypto_gf_bias(bcrypto_gf inout, int amount);
static BCRYPTO_INLINE_UNUSED void bcrypto_gf_weak_reduce(bcrypto_gf inout);

void bcrypto_gf_strong_reduce(bcrypto_gf inout);
void bcrypto_gf_add(bcrypto_gf out, const bcrypto_gf a, const bcrypto_gf b);
void bcrypto_gf_sub(bcrypto_gf out, const bcrypto_gf a, const bcrypto_gf b);
void bcrypto_gf_mul(bcrypto_gf_s * BCRYPTO_RESTRICT out, const bcrypto_gf a, const bcrypto_gf b);
void bcrypto_gf_mulw_unsigned(bcrypto_gf_s * BCRYPTO_RESTRICT out, const bcrypto_gf a, uint32_t b);
void bcrypto_gf_sqr(bcrypto_gf_s * BCRYPTO_RESTRICT out, const bcrypto_gf a);
bcrypto_mask_t bcrypto_gf_isr(bcrypto_gf a, const bcrypto_gf x); /** a^2 x = 1, QNR, or 0 if x=0.  Return true if successful */
bcrypto_mask_t bcrypto_gf_eq(const bcrypto_gf x, const bcrypto_gf y);
bcrypto_mask_t bcrypto_gf_lobit(const bcrypto_gf x);
bcrypto_mask_t bcrypto_gf_hibit(const bcrypto_gf x);

void bcrypto_gf_serialize(uint8_t *serial, const bcrypto_gf x, int with_highbit);
bcrypto_mask_t bcrypto_gf_deserialize(bcrypto_gf x, const uint8_t serial[BCRYPTO_SER_BYTES], int with_hibit,
            uint8_t hi_nmask);

# include "arch_32/f_impl.h"      /* Bring in the inline implementations */

# define BCRYPTO_LIMBPERM(i) (i)
# define BCRYPTO_LIMB_MASK(i) (((1)<<BCRYPTO_LIMB_PLACE_VALUE(i))-1)

static const bcrypto_gf ZERO = {{{0}}}, ONE = {{{1}}};

/* Square x, n times. */
static inline void bcrypto_gf_sqrn(bcrypto_gf_s * BCRYPTO_RESTRICT y, const bcrypto_gf x, int n)
{
  bcrypto_gf tmp;

  assert(n > 0);
  if (n & 1) {
    bcrypto_gf_sqr(y, x);
    n--;
  } else {
    bcrypto_gf_sqr(tmp, x);
    bcrypto_gf_sqr(y, tmp);
    n -= 2;
  }
  for (; n; n -= 2) {
    bcrypto_gf_sqr(tmp, y);
    bcrypto_gf_sqr(y, tmp);
  }
}

# define bcrypto_gf_add_nr bcrypto_gf_add_RAW

/* Subtract mod p.  Bias by 2 and don't reduce  */
static inline void bcrypto_gf_sub_nr(bcrypto_gf c, const bcrypto_gf a, const bcrypto_gf b)
{
  bcrypto_gf_sub_RAW(c, a, b);
  bcrypto_gf_bias(c, 2);
  if (BCRYPTO_GF_HEADROOM < 3)
    bcrypto_gf_weak_reduce(c);
}

/* Subtract mod p. Bias by amt but don't reduce.  */
static inline void bcrypto_gf_subx_nr(bcrypto_gf c, const bcrypto_gf a, const bcrypto_gf b, int amt)
{
  bcrypto_gf_sub_RAW(c, a, b);
  bcrypto_gf_bias(c, amt);
  if (BCRYPTO_GF_HEADROOM < amt + 1)
    bcrypto_gf_weak_reduce(c);
}

/* Mul by signed int.  Not constant-time WRT the sign of that int. */
static inline void bcrypto_gf_mulw(bcrypto_gf c, const bcrypto_gf a, int32_t w)
{
  if (w > 0) {
    bcrypto_gf_mulw_unsigned(c, a, w);
  } else {
    bcrypto_gf_mulw_unsigned(c, a, -w);
    bcrypto_gf_sub(c, ZERO, c);
  }
}

/* Constant time, x = is_z ? z : y */
static inline void bcrypto_gf_cond_sel(bcrypto_gf x, const bcrypto_gf y, const bcrypto_gf z, bcrypto_mask_t is_z)
{
  size_t i;

  for (i = 0; i < BCRYPTO_NLIMBS; i++) {
#if BCRYPTO_ARCH_WORD_BITS == 32
    x[0].limb[i] = constant_time_select_32(is_z, z[0].limb[i],
                         y[0].limb[i]);
#else
    /* Must be 64 bit */
    x[0].limb[i] = constant_time_select_64(is_z, z[0].limb[i],
                         y[0].limb[i]);
#endif
  }
}

/* Constant time, if (neg) x=-x; */
static inline void bcrypto_gf_cond_neg(bcrypto_gf x, bcrypto_mask_t neg)
{
  bcrypto_gf y;

  bcrypto_gf_sub(y, ZERO, x);
  bcrypto_gf_cond_sel(x, x, y, neg);
}

/* Constant time, if (swap) (x,y) = (y,x); */
static inline void bcrypto_gf_cond_swap(bcrypto_gf x, bcrypto_gf_s * BCRYPTO_RESTRICT y, bcrypto_mask_t swap)
{
  size_t i;

  for (i = 0; i < BCRYPTO_NLIMBS; i++) {
#if BCRYPTO_ARCH_WORD_BITS == 32
    constant_time_cond_swap_32(swap, &(x[0].limb[i]), &(y->limb[i]));
#else
    /* Must be 64 bit */
    constant_time_cond_swap_64(swap, &(x[0].limb[i]), &(y->limb[i]));
#endif
  }
}

#endif              /* _BCRYPTO_FIELD_H */
