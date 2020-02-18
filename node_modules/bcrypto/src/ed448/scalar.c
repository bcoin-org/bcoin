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
#include "openssl/crypto.h"

#include "word.h"
#include "point_448.h"

static const bcrypto_c448_word_t MONTGOMERY_FACTOR = (bcrypto_c448_word_t) 0x3bd440fae918bc5;
static const bcrypto_curve448_scalar_t sc_p = {
  {
    {
      BCRYPTO_SC_BCRYPTO_LIMB(0x2378c292ab5844f3), BCRYPTO_SC_BCRYPTO_LIMB(0x216cc2728dc58f55),
      BCRYPTO_SC_BCRYPTO_LIMB(0xc44edb49aed63690), BCRYPTO_SC_BCRYPTO_LIMB(0xffffffff7cca23e9),
      BCRYPTO_SC_BCRYPTO_LIMB(0xffffffffffffffff), BCRYPTO_SC_BCRYPTO_LIMB(0xffffffffffffffff),
      BCRYPTO_SC_BCRYPTO_LIMB(0x3fffffffffffffff)
    }
  }
}, sc_r2 = {
  {
    {

      BCRYPTO_SC_BCRYPTO_LIMB(0xe3539257049b9b60), BCRYPTO_SC_BCRYPTO_LIMB(0x7af32c4bc1b195d9),
      BCRYPTO_SC_BCRYPTO_LIMB(0x0d66de2388ea1859), BCRYPTO_SC_BCRYPTO_LIMB(0xae17cf725ee4d838),
      BCRYPTO_SC_BCRYPTO_LIMB(0x1a9cc14ba3c47c44), BCRYPTO_SC_BCRYPTO_LIMB(0x2052bcb7e4d070af),
      BCRYPTO_SC_BCRYPTO_LIMB(0x3402a939f823b729)
    }
  }
};

#define BCRYPTO_WBITS BCRYPTO_C448_WORD_BITS   /* NB this may be different from BCRYPTO_ARCH_WORD_BITS */

const bcrypto_curve448_scalar_t bcrypto_curve448_scalar_one = {{{1}}};
const bcrypto_curve448_scalar_t bcrypto_curve448_scalar_zero = {{{0}}};

/*
 * {extra,accum} - sub +? p
 * Must have extra <= 1
 */
static void sc_subx(bcrypto_curve448_scalar_t out,
          const bcrypto_c448_word_t accum[BCRYPTO_C448_SCALAR_LIMBS],
          const bcrypto_curve448_scalar_t sub,
          const bcrypto_curve448_scalar_t p, bcrypto_c448_word_t extra)
{
  bcrypto_c448_bcrypto_dsword_t chain = 0;
  unsigned int i;
  bcrypto_c448_word_t borrow;

  for (i = 0; i < BCRYPTO_C448_SCALAR_LIMBS; i++) {
    chain = (chain + accum[i]) - sub->limb[i];
    out->limb[i] = (bcrypto_c448_word_t)chain;
    chain >>= BCRYPTO_WBITS;
  }
  borrow = (bcrypto_c448_word_t)chain + extra;   /* = 0 or -1 */

  chain = 0;
  for (i = 0; i < BCRYPTO_C448_SCALAR_LIMBS; i++) {
    chain = (chain + out->limb[i]) + (p->limb[i] & borrow);
    out->limb[i] = (bcrypto_c448_word_t)chain;
    chain >>= BCRYPTO_WBITS;
  }
}

static void sc_montmul(bcrypto_curve448_scalar_t out, const bcrypto_curve448_scalar_t a,
             const bcrypto_curve448_scalar_t b)
{
  unsigned int i, j;
  bcrypto_c448_word_t accum[BCRYPTO_C448_SCALAR_LIMBS + 1] = { 0 };
  bcrypto_c448_word_t hi_carry = 0;

  for (i = 0; i < BCRYPTO_C448_SCALAR_LIMBS; i++) {
    bcrypto_c448_word_t mand = a->limb[i];
    const bcrypto_c448_word_t *mier = b->limb;

    bcrypto_c448_bcrypto_dword_t chain = 0;
    for (j = 0; j < BCRYPTO_C448_SCALAR_LIMBS; j++) {
      chain += ((bcrypto_c448_bcrypto_dword_t) mand) * mier[j] + accum[j];
      accum[j] = (bcrypto_c448_word_t)chain;
      chain >>= BCRYPTO_WBITS;
    }
    accum[j] = (bcrypto_c448_word_t)chain;

    mand = accum[0] * MONTGOMERY_FACTOR;
    chain = 0;
    mier = sc_p->limb;
    for (j = 0; j < BCRYPTO_C448_SCALAR_LIMBS; j++) {
      chain += (bcrypto_c448_bcrypto_dword_t) mand *mier[j] + accum[j];
      if (j)
        accum[j - 1] = (bcrypto_c448_word_t)chain;
      chain >>= BCRYPTO_WBITS;
    }
    chain += accum[j];
    chain += hi_carry;
    accum[j - 1] = (bcrypto_c448_word_t)chain;
    hi_carry = chain >> BCRYPTO_WBITS;
  }

  sc_subx(out, accum, sc_p, sc_p, hi_carry);
}

void bcrypto_curve448_scalar_mul(bcrypto_curve448_scalar_t out, const bcrypto_curve448_scalar_t a,
             const bcrypto_curve448_scalar_t b)
{
  sc_montmul(out, a, b);
  sc_montmul(out, out, sc_r2);
}

static void sc_montsqr (bcrypto_curve448_scalar_t out, const bcrypto_curve448_scalar_t a) {
    sc_montmul(out,a,a);
}

bcrypto_c448_bool_t
bcrypto_curve448_scalar_eq (
    const bcrypto_curve448_scalar_t a,
    const bcrypto_curve448_scalar_t b
) {
  bcrypto_c448_word_t diff = 0;
  unsigned int i;
  for (i=0; i<BCRYPTO_C448_SCALAR_LIMBS; i++) {
      diff |= a->limb[i] ^ b->limb[i];
  }
  return mask_to_bool(word_is_zero(diff));
}

bcrypto_c448_error_t bcrypto_curve448_scalar_invert(
    bcrypto_curve448_scalar_t out,
    const bcrypto_curve448_scalar_t a
) {
    /* Fermat's little theorem, sliding window.
     * Sliding window is fine here because the modulus isn't secret.
     */
    const int SCALAR_WINDOW_BITS = 3;
    bcrypto_curve448_scalar_t precmp[1<<3];  // Rewritten from SCALAR_WINDOW_BITS for windows compatibility
    const int LAST = (1<<SCALAR_WINDOW_BITS)-1;

    /* Precompute precmp = [a^1,a^3,...] */
    sc_montmul(precmp[0],a,sc_r2);
    if (LAST > 0) sc_montmul(precmp[LAST],precmp[0],precmp[0]);

    int i;
    for (i=1; i<=LAST; i++) {
        sc_montmul(precmp[i],precmp[i-1],precmp[LAST]);
    }

    /* Sliding window */
    unsigned residue = 0, trailing = 0, started = 0;
    for (i=BCRYPTO_C448_SCALAR_BITS-1; i>=-SCALAR_WINDOW_BITS; i--) {

        if (started) sc_montsqr(out,out);

        bcrypto_c448_word_t w = (i>=0) ? sc_p->limb[i/BCRYPTO_WBITS] : 0;
        if (i >= 0 && i<BCRYPTO_WBITS) {
            assert(w >= 2);
            w-=2;
        }

        residue = (residue<<1) | ((w>>(i%BCRYPTO_WBITS))&1);
        if (residue>>SCALAR_WINDOW_BITS != 0) {
            assert(trailing == 0);
            trailing = residue;
            residue = 0;
        }

        if (trailing > 0 && (trailing & ((1<<SCALAR_WINDOW_BITS)-1)) == 0) {
            if (started) {
                sc_montmul(out,out,precmp[trailing>>(SCALAR_WINDOW_BITS+1)]);
            } else {
                bcrypto_curve448_scalar_copy(out,precmp[trailing>>(SCALAR_WINDOW_BITS+1)]);
                started = 1;
            }
            trailing = 0;
        }
        trailing <<= 1;

    }
    assert(residue==0);
    assert(trailing==0);

    /* Demontgomerize */
    sc_montmul(out,out,bcrypto_curve448_scalar_one);
    OPENSSL_cleanse(precmp, sizeof(precmp));
    return bcrypto_c448_succeed_if(~bcrypto_curve448_scalar_eq(out,bcrypto_curve448_scalar_zero));
}

void bcrypto_curve448_scalar_sub(bcrypto_curve448_scalar_t out, const bcrypto_curve448_scalar_t a,
             const bcrypto_curve448_scalar_t b)
{
  sc_subx(out, a->limb, b, sc_p, 0);
}

void bcrypto_curve448_scalar_negate(bcrypto_curve448_scalar_t out, const bcrypto_curve448_scalar_t a)
{
  if (!bcrypto_curve448_scalar_eq(a, bcrypto_curve448_scalar_zero))
    bcrypto_curve448_scalar_sub(out, sc_p, a);
}

void bcrypto_curve448_scalar_add(bcrypto_curve448_scalar_t out, const bcrypto_curve448_scalar_t a,
             const bcrypto_curve448_scalar_t b)
{
  bcrypto_c448_bcrypto_dword_t chain = 0;
  unsigned int i;

  for (i = 0; i < BCRYPTO_C448_SCALAR_LIMBS; i++) {
    chain = (chain + a->limb[i]) + b->limb[i];
    out->limb[i] = (bcrypto_c448_word_t)chain;
    chain >>= BCRYPTO_WBITS;
  }
  sc_subx(out, out->limb, sc_p, sc_p, (bcrypto_c448_word_t)chain);
}

static inline void scalar_decode_short(bcrypto_curve448_scalar_t s,
                     const unsigned char *ser,
                     size_t nbytes)
{
  size_t i, j, k = 0;

  for (i = 0; i < BCRYPTO_C448_SCALAR_LIMBS; i++) {
    bcrypto_c448_word_t out = 0;

    for (j = 0; j < sizeof(bcrypto_c448_word_t) && k < nbytes; j++, k++)
      out |= ((bcrypto_c448_word_t) ser[k]) << (8 * j);
    s->limb[i] = out;
  }
}

bcrypto_c448_error_t bcrypto_curve448_scalar_decode(
                bcrypto_curve448_scalar_t s,
                const unsigned char ser[BCRYPTO_C448_SCALAR_BYTES])
{
  unsigned int i;
  bcrypto_c448_bcrypto_dsword_t accum = 0;

  scalar_decode_short(s, ser, BCRYPTO_C448_SCALAR_BYTES);
  for (i = 0; i < BCRYPTO_C448_SCALAR_LIMBS; i++)
    accum = (accum + s->limb[i] - sc_p->limb[i]) >> BCRYPTO_WBITS;
  /* Here accum == 0 or -1 */

  bcrypto_curve448_scalar_mul(s, s, bcrypto_curve448_scalar_one); /* ham-handed reduce */

  return bcrypto_c448_succeed_if(~word_is_zero((uint32_t)accum));
}

void bcrypto_curve448_scalar_destroy(bcrypto_curve448_scalar_t scalar)
{
  OPENSSL_cleanse(scalar, sizeof(bcrypto_curve448_scalar_t));
}

void bcrypto_curve448_scalar_decode_long(bcrypto_curve448_scalar_t s,
                 const unsigned char *ser, size_t ser_len)
{
  size_t i;
  bcrypto_curve448_scalar_t t1, t2;

  if (ser_len == 0) {
    bcrypto_curve448_scalar_copy(s, bcrypto_curve448_scalar_zero);
    return;
  }

  i = ser_len - (ser_len % BCRYPTO_C448_SCALAR_BYTES);
  if (i == ser_len)
    i -= BCRYPTO_C448_SCALAR_BYTES;

  scalar_decode_short(t1, &ser[i], ser_len - i);

  if (ser_len == sizeof(bcrypto_curve448_scalar_t)) {
    assert(i == 0);
    /* ham-handed reduce */
    bcrypto_curve448_scalar_mul(s, t1, bcrypto_curve448_scalar_one);
    bcrypto_curve448_scalar_destroy(t1);
    return;
  }

  while (i) {
    i -= BCRYPTO_C448_SCALAR_BYTES;
    sc_montmul(t1, t1, sc_r2);
    (void)bcrypto_curve448_scalar_decode(t2, ser + i);
    bcrypto_curve448_scalar_add(t1, t1, t2);
  }

  bcrypto_curve448_scalar_copy(s, t1);
  bcrypto_curve448_scalar_destroy(t1);
  bcrypto_curve448_scalar_destroy(t2);
}

void bcrypto_curve448_scalar_encode(unsigned char ser[BCRYPTO_C448_SCALAR_BYTES],
              const bcrypto_curve448_scalar_t s)
{
  unsigned int i, j, k = 0;

  for (i = 0; i < BCRYPTO_C448_SCALAR_LIMBS; i++) {
    for (j = 0; j < sizeof(bcrypto_c448_word_t); j++, k++)
      ser[k] = s->limb[i] >> (8 * j);
  }
}

void bcrypto_curve448_scalar_halve(bcrypto_curve448_scalar_t out, const bcrypto_curve448_scalar_t a)
{
  bcrypto_c448_word_t mask = 0 - (a->limb[0] & 1);
  bcrypto_c448_bcrypto_dword_t chain = 0;
  unsigned int i;

  for (i = 0; i < BCRYPTO_C448_SCALAR_LIMBS; i++) {
    chain = (chain + a->limb[i]) + (sc_p->limb[i] & mask);
    out->limb[i] = (bcrypto_c448_word_t)chain;
    chain >>= BCRYPTO_C448_WORD_BITS;
  }
  for (i = 0; i < BCRYPTO_C448_SCALAR_LIMBS - 1; i++)
    out->limb[i] = out->limb[i] >> 1 | out->limb[i + 1] << (BCRYPTO_WBITS - 1);
  out->limb[i] = out->limb[i] >> 1 | (bcrypto_c448_word_t)(chain << (BCRYPTO_WBITS - 1));
}
