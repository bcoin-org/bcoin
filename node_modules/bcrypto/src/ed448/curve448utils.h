/*
 * Copyright 2017-2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2015 Cryptography Research, Inc.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Originally written by Mike Hamburg
 */

#ifndef _BCRYPTO_CURVE448UTILS_H
# define _BCRYPTO_CURVE448UTILS_H

#include <stdint.h>

/*
 * Internal word types. Somewhat tricky.  This could be decided separately per
 * platform.  However, the structs do need to be all the same size and
 * alignment on a given platform to support dynamic linking, since even if you
 * header was built with eg arch_neon, you might end up linking a library built
 * with arch_arm32.
 */
# ifndef BCRYPTO_C448_WORD_BITS
#  if (defined(__SIZEOF_INT128__) && (__SIZEOF_INT128__ == 16)) \
    && !defined(__sparc__)
#   define BCRYPTO_C448_WORD_BITS 64    /* The number of bits in a word */
#  else
#   define BCRYPTO_C448_WORD_BITS 32    /* The number of bits in a word */
#  endif
# endif

# if BCRYPTO_C448_WORD_BITS == 64
/* Word size for internal computations */
typedef uint64_t bcrypto_c448_word_t;
/* Signed word size for internal computations */
typedef int64_t bcrypto_c448_bcrypto_sword_t;
/* "Boolean" type, will be set to all-zero or all-one (i.e. -1u) */
typedef uint64_t bcrypto_c448_bool_t;
/* Double-word size for internal computations */
typedef __uint128_t bcrypto_c448_bcrypto_dword_t;
/* Signed double-word size for internal computations */
typedef __int128_t bcrypto_c448_bcrypto_dsword_t;
# elif BCRYPTO_C448_WORD_BITS == 32
/* Word size for internal computations */
typedef uint32_t bcrypto_c448_word_t;
/* Signed word size for internal computations */
typedef int32_t bcrypto_c448_bcrypto_sword_t;
/* "Boolean" type, will be set to all-zero or all-one (i.e. -1u) */
typedef uint32_t bcrypto_c448_bool_t;
/* Double-word size for internal computations */
typedef uint64_t bcrypto_c448_bcrypto_dword_t;
/* Signed double-word size for internal computations */
typedef int64_t bcrypto_c448_bcrypto_dsword_t;
# else
#  error "Only supporting BCRYPTO_C448_WORD_BITS = 32 or 64 for now"
# endif

/* BCRYPTO_C448_TRUE = -1 so that BCRYPTO_C448_TRUE & x = x */
# define BCRYPTO_C448_TRUE    (0 - (bcrypto_c448_bool_t)1)

/* BCRYPTO_C448_FALSE = 0 so that BCRYPTO_C448_FALSE & x = 0 */
# define BCRYPTO_C448_FALSE   0

/* Another boolean type used to indicate success or failure. */
typedef enum {
  BCRYPTO_C448_SUCCESS = -1, /**< The operation succeeded. */
  BCRYPTO_C448_FAILURE = 0   /**< The operation failed. */
} bcrypto_c448_error_t;

/* Return success if x is true */
static inline bcrypto_c448_error_t bcrypto_c448_succeed_if(bcrypto_c448_bool_t x)
{
  return (bcrypto_c448_error_t) x;
}

#endif              /* __BCRYPTO_C448_COMMON_H__ */
