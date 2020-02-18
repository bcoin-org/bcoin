/*
 * Copyright 2017-2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2015-2016 Cryptography Research, Inc.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Originally written by Mike Hamburg
 */

#ifndef _BCRYPTO_POINT_448_H
# define _BCRYPTO_POINT_448_H

# include "curve448utils.h"
# include "field.h"

/* Comb config: number of combs, n, t, s. */
#define BCRYPTO_COMBS_N 5
#define BCRYPTO_COMBS_T 5
#define BCRYPTO_COMBS_S 18

/* Projective Niels coordinates */
typedef struct {
  bcrypto_gf a, b, c;
} bcrypto_niels_s, bcrypto_niels_t[1];
typedef struct {
  bcrypto_niels_t n;
  bcrypto_gf z;
} bcrypto_pniels_t[1];

/* Precomputed base */
struct bcrypto_curve448_precomputed_s {
  bcrypto_niels_t table[BCRYPTO_COMBS_N << (BCRYPTO_COMBS_T - 1)];
};

# define BCRYPTO_C448_SCALAR_LIMBS ((446-1)/BCRYPTO_C448_WORD_BITS+1)

/* The number of bits in a scalar */
# define BCRYPTO_C448_SCALAR_BITS 446

/* Number of bytes in a serialized scalar. */
# define BCRYPTO_C448_SCALAR_BYTES 56

/* X448 encoding ratio. */
# define BCRYPTO_X448_ENCODE_RATIO 2

/* Number of bytes in an x448 public key */
# define BCRYPTO_X448_PUBLIC_BYTES 56

/* Number of bytes in an x448 private key */
# define BCRYPTO_X448_PRIVATE_BYTES 56

/* Twisted Edwards extended homogeneous coordinates */
typedef struct bcrypto_curve448_point_s {
  bcrypto_gf x, y, z, t;
} bcrypto_curve448_point_t[1];

/* Precomputed table based on a point.  Can be trivial implementation. */
struct bcrypto_curve448_precomputed_s;

/* Precomputed table based on a point.  Can be trivial implementation. */
typedef struct bcrypto_curve448_precomputed_s bcrypto_curve448_precomputed_s;

/* Scalar is stored packed, because we don't need the speed. */
typedef struct bcrypto_curve448_scalar_s {
  bcrypto_c448_word_t limb[BCRYPTO_C448_SCALAR_LIMBS];
} bcrypto_curve448_scalar_t[1];

/* A scalar equal to 1. */
extern const bcrypto_curve448_scalar_t bcrypto_curve448_scalar_one;

/* A scalar equal to 0. */
extern const bcrypto_curve448_scalar_t bcrypto_curve448_scalar_zero;

/* The identity point on the curve. */
extern const bcrypto_curve448_point_t bcrypto_curve448_point_identity;

/* Precomputed table for the base point on the curve. */
extern const struct bcrypto_curve448_precomputed_s *bcrypto_curve448_precomputed_base;
extern const bcrypto_niels_t *bcrypto_curve448_wnaf_base;

/*
 * Read a scalar from wire format or from bytes.
 *
 * ser (in): Serialized form of a scalar.
 * out (out): Deserialized form.
 *
 * Returns:
 * BCRYPTO_C448_SUCCESS: The scalar was correctly encoded.
 * BCRYPTO_C448_FAILURE: The scalar was greater than the modulus, and has been reduced
 * modulo that modulus.
 */
bcrypto_c448_error_t bcrypto_curve448_scalar_decode(bcrypto_curve448_scalar_t out,
                  const unsigned char ser[BCRYPTO_C448_SCALAR_BYTES]);

/*
 * Read a scalar from wire format or from bytes.  Reduces mod scalar prime.
 *
 * ser (in): Serialized form of a scalar.
 * ser_len (in): Length of serialized form.
 * out (out): Deserialized form.
 */
void bcrypto_curve448_scalar_decode_long(bcrypto_curve448_scalar_t out,
                 const unsigned char *ser, size_t ser_len);

/*
 * Serialize a scalar to wire format.
 *
 * ser (out): Serialized form of a scalar.
 * s (in): Deserialized scalar.
 */
void bcrypto_curve448_scalar_encode(unsigned char ser[BCRYPTO_C448_SCALAR_BYTES],
              const bcrypto_curve448_scalar_t s);

/*
 * Add two scalars. |a|, |b| and |out| may alias each other.
 *
 * a (in): One scalar.
 * b (in): Another scalar.
 * out (out): a+b.
 */
void bcrypto_curve448_scalar_add(bcrypto_curve448_scalar_t out,
             const bcrypto_curve448_scalar_t a, const bcrypto_curve448_scalar_t b);

/*
 * Subtract two scalars.  |a|, |b| and |out| may alias each other.
 * a (in): One scalar.
 * b (in): Another scalar.
 * out (out): a-b.
 */
void bcrypto_curve448_scalar_sub(bcrypto_curve448_scalar_t out,
             const bcrypto_curve448_scalar_t a, const bcrypto_curve448_scalar_t b);

/*
 * Multiply two scalars. |a|, |b| and |out| may alias each other.
 *
 * a (in): One scalar.
 * b (in): Another scalar.
 * out (out): a*b.
 */
void bcrypto_curve448_scalar_mul(bcrypto_curve448_scalar_t out,
             const bcrypto_curve448_scalar_t a, const bcrypto_curve448_scalar_t b);

/*
* Halve a scalar.  |a| and |out| may alias each other.
*
* a (in): A scalar.
* out (out): a/2.
*/
void bcrypto_curve448_scalar_halve(bcrypto_curve448_scalar_t out, const bcrypto_curve448_scalar_t a);

/*
 * Copy a scalar.  The scalars may alias each other, in which case this
 * function does nothing.
 *
 * a (in): A scalar.
 * out (out): Will become a copy of a.
 */
static inline void bcrypto_curve448_scalar_copy(bcrypto_curve448_scalar_t out,
                    const bcrypto_curve448_scalar_t a)
{
  *out = *a;
}

/*
 * Copy a point.  The input and output may alias, in which case this function
 * does nothing.
 *
 * a (out): A copy of the point.
 * b (in): Any point.
 */
static inline void bcrypto_curve448_point_copy(bcrypto_curve448_point_t a,
                     const bcrypto_curve448_point_t b)
{
  *a = *b;
}

/*
 * Test whether two points are equal.  If yes, return BCRYPTO_C448_TRUE, else return
 * BCRYPTO_C448_FALSE.
 *
 * a (in): A point.
 * b (in): Another point.
 *
 * Returns:
 * BCRYPTO_C448_TRUE: The points are equal.
 * BCRYPTO_C448_FALSE: The points are not equal.
 */
bcrypto_c448_bool_t bcrypto_curve448_point_eq(const bcrypto_curve448_point_t a,
                const bcrypto_curve448_point_t b);

/*
 * Double a point. Equivalent to bcrypto_curve448_point_add(two_a,a,a), but potentially
 * faster.
 *
 * two_a (out): The sum a+a.
 * a (in): A point.
 */
void bcrypto_curve448_point_double(bcrypto_curve448_point_t two_a, const bcrypto_curve448_point_t a);

/*
 * RFC 7748 Diffie-Hellman scalarmul.  This function uses a different
 * (non-Decaf) encoding.
 *
 * out (out): The scaled point base*scalar
 * base (in): The point to be scaled.
 * scalar (in): The scalar to multiply by.
 *
 * Returns:
 * BCRYPTO_C448_SUCCESS: The scalarmul succeeded.
 * BCRYPTO_C448_FAILURE: The scalarmul didn't succeed, because the base point is in a
 * small subgroup.
 */
bcrypto_c448_error_t bcrypto_x448_int(uint8_t out[BCRYPTO_X448_PUBLIC_BYTES],
            const uint8_t base[BCRYPTO_X448_PUBLIC_BYTES],
            const uint8_t scalar[BCRYPTO_X448_PRIVATE_BYTES]);

/*
 * Multiply a point by BCRYPTO_X448_ENCODE_RATIO, then encode it like RFC 7748.
 *
 * This function is mainly used internally, but is exported in case
 * it will be useful.
 *
 * The ratio is necessary because the internal representation doesn't
 * track the cofactor information, so on output we must clear the cofactor.
 * This would multiply by the cofactor, but in fact internally points are always
 * even, so it multiplies by half the cofactor instead.
 *
 * As it happens, this aligns with the base point definitions; that is,
 * if you pass the Decaf/Ristretto base point to this function, the result
 * will be BCRYPTO_X448_ENCODE_RATIO times the X448
 * base point.
 *
 * out (out): The scaled and encoded point.
 * p (in): The point to be scaled and encoded.
 */
void bcrypto_curve448_point_mul_by_ratio_and_encode_like_x448(
                    uint8_t out[BCRYPTO_X448_PUBLIC_BYTES],
                    const bcrypto_curve448_point_t p);

/*
 * RFC 7748 Diffie-Hellman base point scalarmul.  This function uses a different
 * (non-Decaf) encoding.
 *
 * out (out): The scaled point base*scalar
 * scalar (in): The scalar to multiply by.
 */
void bcrypto_x448_derive_public_key(uint8_t out[BCRYPTO_X448_PUBLIC_BYTES],
              const uint8_t scalar[BCRYPTO_X448_PRIVATE_BYTES]);

/*
 * Multiply a precomputed base point by a scalar: out = scalar*base.
 *
 * scaled (out): The scaled point base*scalar
 * base (in): The point to be scaled.
 * scalar (in): The scalar to multiply by.
 */
void bcrypto_curve448_precomputed_scalarmul(bcrypto_curve448_point_t scaled,
                  const bcrypto_curve448_precomputed_s * base,
                  const bcrypto_curve448_scalar_t scalar);

/*
 * Multiply a base point by a scalar: out = scalar*base.
 *
 * scaled (out): The scaled point base*scalar
 * base (in): The point to be scaled.
 * scalar (in): The scalar to multiply by.
 */
void bcrypto_curve448_point_scalarmul(bcrypto_curve448_point_t a,
                  const bcrypto_curve448_point_t b,
                  const bcrypto_curve448_scalar_t scalar);

/*
 * Multiply two base points by two scalars:
 * combo = scalar1*bcrypto_curve448_point_base + scalar2*base2.
 *
 * Otherwise equivalent to bcrypto_curve448_point_double_scalarmul, but may be
 * faster at the expense of being variable time.
 *
 * combo (out): The linear combination scalar1*base + scalar2*base2.
 * scalar1 (in): A first scalar to multiply by.
 * base2 (in): A second point to be scaled.
 * scalar2 (in) A second scalar to multiply by.
 *
 * Warning: This function takes variable time, and may leak the scalars used.
 * It is designed for signature verification.
 */
void bcrypto_curve448_base_double_scalarmul_non_secret(bcrypto_curve448_point_t combo,
                         const bcrypto_curve448_scalar_t scalar1,
                         const bcrypto_curve448_point_t base2,
                         const bcrypto_curve448_scalar_t scalar2);

/*
 * Test that a point is valid, for debugging purposes.
 *
 * to_test (in): The point to test.
 *
 * Returns:
 * BCRYPTO_C448_TRUE The point is valid.
 * BCRYPTO_C448_FALSE The point is invalid.
 */
bcrypto_c448_bool_t bcrypto_curve448_point_valid(const bcrypto_curve448_point_t to_test);

/* Overwrite scalar with zeros. */
void bcrypto_curve448_scalar_destroy(bcrypto_curve448_scalar_t scalar);

/* Overwrite point with zeros. */
void bcrypto_curve448_point_destroy(bcrypto_curve448_point_t point);

void bcrypto_curve448_point_sub(
    bcrypto_curve448_point_t p,
    const bcrypto_curve448_point_t q,
    const bcrypto_curve448_point_t r
);

void bcrypto_curve448_point_add(
    bcrypto_curve448_point_t p,
    const bcrypto_curve448_point_t q,
    const bcrypto_curve448_point_t r
);

void bcrypto_curve448_point_negate(
  bcrypto_curve448_point_t nega,
  const bcrypto_curve448_point_t a
);

bcrypto_c448_bool_t
bcrypto_curve448_scalar_eq (
    const bcrypto_curve448_scalar_t a,
    const bcrypto_curve448_scalar_t b
);

bcrypto_c448_error_t bcrypto_curve448_scalar_invert(
    bcrypto_curve448_scalar_t out,
    const bcrypto_curve448_scalar_t a);

void bcrypto_curve448_scalar_negate(
    bcrypto_curve448_scalar_t out,
    const bcrypto_curve448_scalar_t a);

void bcrypto_curve448_convert_public_key_to_x448(
  uint8_t x[BCRYPTO_X_PUBLIC_BYTES],
  const uint8_t ed[57]
);

#endif              /* _BCRYPTO_POINT_448_H */
