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
#include "field.h"

static const bcrypto_gf BCRYPTO_MODULUS = {
  BCRYPTO_FIELD_LITERAL(0xffffffffffffff, 0xffffffffffffff, 0xffffffffffffff,
          0xffffffffffffff, 0xfffffffffffffe, 0xffffffffffffff,
          0xffffffffffffff, 0xffffffffffffff)
};

/* Serialize to wire format. */
void bcrypto_gf_serialize(uint8_t serial[BCRYPTO_SER_BYTES], const bcrypto_gf x, int with_hibit)
{
  unsigned int j = 0, fill = 0;
  bcrypto_dword_t buffer = 0;
  int i;
  bcrypto_gf red;

  bcrypto_gf_copy(red, x);
  bcrypto_gf_strong_reduce(red);
  if (!with_hibit)
    assert(bcrypto_gf_hibit(red) == 0);

  for (i = 0; i < (with_hibit ? BCRYPTO_X_SER_BYTES : BCRYPTO_SER_BYTES); i++) {
    if (fill < 8 && j < BCRYPTO_NLIMBS) {
      buffer |= ((bcrypto_dword_t) red->limb[BCRYPTO_LIMBPERM(j)]) << fill;
      fill += BCRYPTO_LIMB_PLACE_VALUE(BCRYPTO_LIMBPERM(j));
      j++;
    }
    serial[i] = (uint8_t)buffer;
    fill -= 8;
    buffer >>= 8;
  }
}

/* Return high bit of x = low bit of 2x mod p */
bcrypto_mask_t bcrypto_gf_hibit(const bcrypto_gf x)
{
  bcrypto_gf y;

  bcrypto_gf_add(y, x, x);
  bcrypto_gf_strong_reduce(y);
  return 0 - (y->limb[0] & 1);
}

/* Return high bit of x = low bit of 2x mod p */
bcrypto_mask_t bcrypto_gf_lobit(const bcrypto_gf x)
{
  bcrypto_gf y;

  bcrypto_gf_copy(y, x);
  bcrypto_gf_strong_reduce(y);
  return 0 - (y->limb[0] & 1);
}

/* Deserialize from wire format; return -1 on success and 0 on failure. */
bcrypto_mask_t bcrypto_gf_deserialize(bcrypto_gf x, const uint8_t serial[BCRYPTO_SER_BYTES], int with_hibit,
            uint8_t hi_nmask)
{
  unsigned int j = 0, fill = 0;
  bcrypto_dword_t buffer = 0;
  bcrypto_dsword_t scarry = 0;
  const unsigned nbytes = with_hibit ? BCRYPTO_X_SER_BYTES : BCRYPTO_SER_BYTES;
  unsigned int i;
  bcrypto_mask_t succ;

  for (i = 0; i < BCRYPTO_NLIMBS; i++) {
    while (fill < BCRYPTO_LIMB_PLACE_VALUE(BCRYPTO_LIMBPERM(i)) && j < nbytes) {
      uint8_t sj;

      sj = serial[j];
      if (j == nbytes - 1)
        sj &= ~hi_nmask;
      buffer |= ((bcrypto_dword_t) sj) << fill;
      fill += 8;
      j++;
    }
    x->limb[BCRYPTO_LIMBPERM(i)] = (bcrypto_word_t)
      ((i < BCRYPTO_NLIMBS - 1) ? buffer & BCRYPTO_LIMB_MASK(BCRYPTO_LIMBPERM(i)) : buffer);
    fill -= BCRYPTO_LIMB_PLACE_VALUE(BCRYPTO_LIMBPERM(i));
    buffer >>= BCRYPTO_LIMB_PLACE_VALUE(BCRYPTO_LIMBPERM(i));
    scarry =
      (scarry + x->limb[BCRYPTO_LIMBPERM(i)] -
       BCRYPTO_MODULUS->limb[BCRYPTO_LIMBPERM(i)]) >> (8 * sizeof(bcrypto_word_t));
  }
  succ = with_hibit ? 0 - (bcrypto_mask_t) 1 : ~bcrypto_gf_hibit(x);
  return succ & word_is_zero((bcrypto_word_t)buffer) & ~word_is_zero((bcrypto_word_t)scarry);
}

/* Reduce to canonical form. */
void bcrypto_gf_strong_reduce(bcrypto_gf a)
{
  bcrypto_dsword_t scarry;
  bcrypto_word_t scarry_0;
  bcrypto_dword_t carry = 0;
  unsigned int i;

  /* first, clear high */
  bcrypto_gf_weak_reduce(a);      /* Determined to have negligible perf impact. */

  /* now the total is less than 2p */

  /* compute total_value - p.  No need to reduce mod p. */
  scarry = 0;
  for (i = 0; i < BCRYPTO_NLIMBS; i++) {
    scarry = scarry + a->limb[BCRYPTO_LIMBPERM(i)] - BCRYPTO_MODULUS->limb[BCRYPTO_LIMBPERM(i)];
    a->limb[BCRYPTO_LIMBPERM(i)] = scarry & BCRYPTO_LIMB_MASK(BCRYPTO_LIMBPERM(i));
    scarry >>= BCRYPTO_LIMB_PLACE_VALUE(BCRYPTO_LIMBPERM(i));
  }

  /*
   * uncommon case: it was >= p, so now scarry = 0 and this = x common case:
   * it was < p, so now scarry = -1 and this = x - p + 2^255 so let's add
   * back in p.  will carry back off the top for 2^255.
   */
  assert(scarry == 0 || scarry == -1);

  scarry_0 = (bcrypto_word_t)scarry;

  /* add it back */
  for (i = 0; i < BCRYPTO_NLIMBS; i++) {
    carry =
      carry + a->limb[BCRYPTO_LIMBPERM(i)] +
      (scarry_0 & BCRYPTO_MODULUS->limb[BCRYPTO_LIMBPERM(i)]);
    a->limb[BCRYPTO_LIMBPERM(i)] = carry & BCRYPTO_LIMB_MASK(BCRYPTO_LIMBPERM(i));
    carry >>= BCRYPTO_LIMB_PLACE_VALUE(BCRYPTO_LIMBPERM(i));
  }

  assert(carry < 2 && ((bcrypto_word_t)carry + scarry_0) == 0);
}

/* Subtract two bcrypto_gf elements d=a-b */
void bcrypto_gf_sub(bcrypto_gf d, const bcrypto_gf a, const bcrypto_gf b)
{
  bcrypto_gf_sub_RAW(d, a, b);
  bcrypto_gf_bias(d, 2);
  bcrypto_gf_weak_reduce(d);
}

/* Add two field elements d = a+b */
void bcrypto_gf_add(bcrypto_gf d, const bcrypto_gf a, const bcrypto_gf b)
{
  bcrypto_gf_add_RAW(d, a, b);
  bcrypto_gf_weak_reduce(d);
}

/* Compare a==b */
bcrypto_mask_t bcrypto_gf_eq(const bcrypto_gf a, const bcrypto_gf b)
{
  bcrypto_gf c;
  bcrypto_mask_t ret = 0;
  unsigned int i;

  bcrypto_gf_sub(c, a, b);
  bcrypto_gf_strong_reduce(c);

  for (i = 0; i < BCRYPTO_NLIMBS; i++)
    ret |= c->limb[BCRYPTO_LIMBPERM(i)];

  return word_is_zero(ret);
}

bcrypto_mask_t bcrypto_gf_isr(bcrypto_gf a, const bcrypto_gf x)
{
  bcrypto_gf L0, L1, L2;

  bcrypto_gf_sqr(L1, x);
  bcrypto_gf_mul(L2, x, L1);
  bcrypto_gf_sqr(L1, L2);
  bcrypto_gf_mul(L2, x, L1);
  bcrypto_gf_sqrn(L1, L2, 3);
  bcrypto_gf_mul(L0, L2, L1);
  bcrypto_gf_sqrn(L1, L0, 3);
  bcrypto_gf_mul(L0, L2, L1);
  bcrypto_gf_sqrn(L2, L0, 9);
  bcrypto_gf_mul(L1, L0, L2);
  bcrypto_gf_sqr(L0, L1);
  bcrypto_gf_mul(L2, x, L0);
  bcrypto_gf_sqrn(L0, L2, 18);
  bcrypto_gf_mul(L2, L1, L0);
  bcrypto_gf_sqrn(L0, L2, 37);
  bcrypto_gf_mul(L1, L2, L0);
  bcrypto_gf_sqrn(L0, L1, 37);
  bcrypto_gf_mul(L1, L2, L0);
  bcrypto_gf_sqrn(L0, L1, 111);
  bcrypto_gf_mul(L2, L1, L0);
  bcrypto_gf_sqr(L0, L2);
  bcrypto_gf_mul(L1, x, L0);
  bcrypto_gf_sqrn(L0, L1, 223);
  bcrypto_gf_mul(L1, L2, L0);
  bcrypto_gf_sqr(L2, L1);
  bcrypto_gf_mul(L0, L2, x);
  bcrypto_gf_copy(a, L1);
  return bcrypto_gf_eq(L0, ONE);
}
