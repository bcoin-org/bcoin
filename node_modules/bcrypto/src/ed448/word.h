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

#ifndef _BCRYPTO_WORD_H
# define _BCRYPTO_WORD_H

# include <string.h>
# include <assert.h>
# include <stdlib.h>
# include <stdint.h>
# include "arch_32/arch_intrinsics.h"
# include "curve448utils.h"

# if (BCRYPTO_ARCH_WORD_BITS == 64)
typedef uint64_t bcrypto_word_t, bcrypto_mask_t;
typedef __uint128_t bcrypto_dword_t;
typedef int32_t bcrypto_hsword_t;
typedef int64_t bcrypto_sword_t;
typedef __int128_t bcrypto_dsword_t;
# elif (BCRYPTO_ARCH_WORD_BITS == 32)
typedef uint32_t bcrypto_word_t, bcrypto_mask_t;
typedef uint64_t bcrypto_dword_t;
typedef int16_t bcrypto_hsword_t;
typedef int32_t bcrypto_sword_t;
typedef int64_t bcrypto_dsword_t;
# else
#  error "For now, we only support 32- and 64-bit architectures."
# endif

/*
 * Scalar limbs are keyed off of the API word size instead of the arch word
 * size.
 */
# if BCRYPTO_C448_WORD_BITS == 64
#  define BCRYPTO_SC_BCRYPTO_LIMB(x) (x)
# elif BCRYPTO_C448_WORD_BITS == 32
#  define BCRYPTO_SC_BCRYPTO_LIMB(x) ((uint32_t)(x)),((x) >> 32)
# else
#  error "For now we only support 32- and 64-bit architectures."
# endif

/*
 * The plan on booleans: The external interface uses bcrypto_c448_bool_t, but this
 * might be a different size than our particular arch's bcrypto_word_t (and thus
 * bcrypto_mask_t).  Also, the caller isn't guaranteed to pass it as nonzero.  So
 * bool_to_mask converts word sizes and checks nonzero. On the flip side,
 * bcrypto_mask_t is always -1 or 0, but it might be a different size than
 * bcrypto_c448_bool_t. On the third hand, we have success vs boolean types, but
 * that's handled in common.h: it converts between bcrypto_c448_bool_t and
 * bcrypto_c448_error_t.
 */
static inline bcrypto_c448_bool_t mask_to_bool(bcrypto_mask_t m)
{
  return (bcrypto_c448_bcrypto_sword_t)(bcrypto_sword_t)m;
}

static inline bcrypto_mask_t bool_to_mask(bcrypto_c448_bool_t m)
{
  /* On most arches this will be optimized to a simple cast. */
  bcrypto_mask_t ret = 0;
  unsigned int i;
  unsigned int limit = sizeof(bcrypto_c448_bool_t) / sizeof(bcrypto_mask_t);

  if (limit < 1)
    limit = 1;
  for (i = 0; i < limit; i++)
    ret |= ~word_is_zero(m >> (i * 8 * sizeof(bcrypto_word_t)));

  return ret;
}

#endif              /* _BCRYPTO_WORD_H */
