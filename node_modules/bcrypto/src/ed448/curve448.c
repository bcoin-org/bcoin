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
#include "field.h"

#include "point_448.h"
#include "ed448.h"
#include "curve448_lcl.h"

#define BCRYPTO_COFACTOR 4

#define BCRYPTO_C448_WINDOW_BITS 5
#define BCRYPTO_C448_WNAF_FIXED_TABLE_BITS 5
#define BCRYPTO_C448_WNAF_VAR_TABLE_BITS 3

#define BCRYPTO_EDWARDS_D     (-39081)

static const bcrypto_curve448_scalar_t point_scalarmul_adjustment = {
  {
    {
      BCRYPTO_SC_BCRYPTO_LIMB(0xc873d6d54a7bb0cf), BCRYPTO_SC_BCRYPTO_LIMB(0xe933d8d723a70aad),
      BCRYPTO_SC_BCRYPTO_LIMB(0xbb124b65129c96fd), BCRYPTO_SC_BCRYPTO_LIMB(0x00000008335dc163)
    }
  }
};

static const bcrypto_curve448_scalar_t precomputed_scalarmul_adjustment = {
  {
    {
      BCRYPTO_SC_BCRYPTO_LIMB(0xc873d6d54a7bb0cf), BCRYPTO_SC_BCRYPTO_LIMB(0xe933d8d723a70aad),
      BCRYPTO_SC_BCRYPTO_LIMB(0xbb124b65129c96fd), BCRYPTO_SC_BCRYPTO_LIMB(0x00000008335dc163)
    }
  }
};

#define BCRYPTO_TWISTED_D (BCRYPTO_EDWARDS_D - 1)

#if BCRYPTO_TWISTED_D < 0
#define BCRYPTO_EFF_D (-(BCRYPTO_TWISTED_D))
#define BCRYPTO_NEG_D 1
#else
#define BCRYPTO_EFF_D BCRYPTO_TWISTED_D
#define BCRYPTO_NEG_D 0
#endif

#define BCRYPTO_WBITS BCRYPTO_C448_WORD_BITS   /* NB this may be different from BCRYPTO_ARCH_WORD_BITS */

/* Inverse. */
static void bcrypto_gf_invert(bcrypto_gf y, const bcrypto_gf x, int assert_nonzero)
{
  bcrypto_mask_t ret;
  bcrypto_gf t1, t2;

  bcrypto_gf_sqr(t1, x);        /* o^2 */
  ret = bcrypto_gf_isr(t2, t1);     /* +-1/sqrt(o^2) = +-1/o */
  (void)ret;
  if (assert_nonzero)
    assert(ret);
  bcrypto_gf_sqr(t1, t2);
  bcrypto_gf_mul(t2, t1, x);      /* not direct to y in case of alias. */
  bcrypto_gf_copy(y, t2);
}

/** identity = (0,1) */
const bcrypto_curve448_point_t bcrypto_curve448_point_identity =
  { {{{{0}}}, {{{1}}}, {{{1}}}, {{{0}}}} };

void bcrypto_curve448_point_sub(
  bcrypto_curve448_point_t p,
  const bcrypto_curve448_point_t q,
  const bcrypto_curve448_point_t r
) {
  bcrypto_gf a, b, c, d;
  bcrypto_gf_sub_nr(b, q->y, q->x); /* 3+e */
  bcrypto_gf_sub_nr(d, r->y, r->x); /* 3+e */
  bcrypto_gf_add_nr(c, r->y, r->x); /* 2+e */
  bcrypto_gf_mul(a, c, b);
  bcrypto_gf_add_nr(b, q->y, q->x); /* 2+e */
  bcrypto_gf_mul(p->y, d, b);
  bcrypto_gf_mul(b, r->t, q->t);
  bcrypto_gf_mulw(p->x, b, 2 * BCRYPTO_EFF_D);
  bcrypto_gf_add_nr(b, a, p->y);    /* 2+e */
  bcrypto_gf_sub_nr(c, p->y, a);    /* 3+e */
  bcrypto_gf_mul(a, q->z, r->z);
  bcrypto_gf_add_nr(a, a, a);       /* 2+e */

  if (BCRYPTO_GF_HEADROOM <= 3)
    bcrypto_gf_weak_reduce(a); /* or 1+e */

#if BCRYPTO_NEG_D
  bcrypto_gf_sub_nr(p->y, a, p->x); /* 4+e or 3+e */
  bcrypto_gf_add_nr(a, a, p->x);    /* 3+e or 2+e */
#else
  bcrypto_gf_add_nr(p->y, a, p->x); /* 3+e or 2+e */
  bcrypto_gf_sub_nr(a, a, p->x);    /* 4+e or 3+e */
#endif

  bcrypto_gf_mul(p->z, a, p->y);
  bcrypto_gf_mul(p->x, p->y, c);
  bcrypto_gf_mul(p->y, a, b);
  bcrypto_gf_mul(p->t, b, c);
}

void bcrypto_curve448_point_add(
  bcrypto_curve448_point_t p,
  const bcrypto_curve448_point_t q,
  const bcrypto_curve448_point_t r
) {
  bcrypto_gf a, b, c, d;
  bcrypto_gf_sub_nr(b, q->y, q->x); /* 3+e */
  bcrypto_gf_sub_nr(c, r->y, r->x); /* 3+e */
  bcrypto_gf_add_nr(d, r->y, r->x); /* 2+e */
  bcrypto_gf_mul(a, c, b);
  bcrypto_gf_add_nr(b, q->y, q->x); /* 2+e */
  bcrypto_gf_mul(p->y, d, b);
  bcrypto_gf_mul(b, r->t, q->t);
  bcrypto_gf_mulw(p->x, b, 2 * BCRYPTO_EFF_D);
  bcrypto_gf_add_nr(b, a, p->y);    /* 2+e */
  bcrypto_gf_sub_nr(c, p->y, a);    /* 3+e */
  bcrypto_gf_mul(a, q->z, r->z);
  bcrypto_gf_add_nr(a, a, a);       /* 2+e */

  if (BCRYPTO_GF_HEADROOM <= 3)
    bcrypto_gf_weak_reduce(a); /* or 1+e */

#if BCRYPTO_NEG_D
  bcrypto_gf_add_nr(p->y, a, p->x); /* 3+e or 2+e */
  bcrypto_gf_sub_nr(a, a, p->x);    /* 4+e or 3+e */
#else
  bcrypto_gf_sub_nr(p->y, a, p->x); /* 4+e or 3+e */
  bcrypto_gf_add_nr(a, a, p->x);    /* 3+e or 2+e */
#endif

  bcrypto_gf_mul(p->z, a, p->y);
  bcrypto_gf_mul(p->x, p->y, c);
  bcrypto_gf_mul(p->y, a, b);
  bcrypto_gf_mul(p->t, b, c);
}

void bcrypto_curve448_point_negate(
  bcrypto_curve448_point_t nega,
  const bcrypto_curve448_point_t a
) {
  bcrypto_gf_sub(nega->x, ZERO, a->x);
  bcrypto_gf_copy(nega->y, a->y);
  bcrypto_gf_copy(nega->z, a->z);
  bcrypto_gf_sub(nega->t, ZERO, a->t);
}

static void point_double_internal(bcrypto_curve448_point_t p, const bcrypto_curve448_point_t q,
                  int before_double)
{
  bcrypto_gf a, b, c, d;

  bcrypto_gf_sqr(c, q->x);
  bcrypto_gf_sqr(a, q->y);
  bcrypto_gf_add_nr(d, c, a);     /* 2+e */
  bcrypto_gf_add_nr(p->t, q->y, q->x); /* 2+e */
  bcrypto_gf_sqr(b, p->t);
  bcrypto_gf_subx_nr(b, b, d, 3);   /* 4+e */
  bcrypto_gf_sub_nr(p->t, a, c);    /* 3+e */
  bcrypto_gf_sqr(p->x, q->z);
  bcrypto_gf_add_nr(p->z, p->x, p->x); /* 2+e */
  bcrypto_gf_subx_nr(a, p->z, p->t, 4); /* 6+e */
  if (BCRYPTO_GF_HEADROOM == 5)
    bcrypto_gf_weak_reduce(a);    /* or 1+e */
  bcrypto_gf_mul(p->x, a, b);
  bcrypto_gf_mul(p->z, p->t, a);
  bcrypto_gf_mul(p->y, p->t, d);
  if (!before_double)
    bcrypto_gf_mul(p->t, b, d);
}

void bcrypto_curve448_point_double(bcrypto_curve448_point_t p, const bcrypto_curve448_point_t q)
{
  point_double_internal(p, q, 0);
}

/* Operations on [p]niels */
static inline void cond_neg_niels(bcrypto_niels_t n, bcrypto_mask_t neg)
{
  bcrypto_gf_cond_swap(n->a, n->b, neg);
  bcrypto_gf_cond_neg(n->c, neg);
}

static void pt_to_pniels(bcrypto_pniels_t b, const bcrypto_curve448_point_t a)
{
  bcrypto_gf_sub(b->n->a, a->y, a->x);
  bcrypto_gf_add(b->n->b, a->x, a->y);
  bcrypto_gf_mulw(b->n->c, a->t, 2 * BCRYPTO_TWISTED_D);
  bcrypto_gf_add(b->z, a->z, a->z);
}

static void pniels_to_pt(bcrypto_curve448_point_t e, const bcrypto_pniels_t d)
{
  bcrypto_gf eu;

  bcrypto_gf_add(eu, d->n->b, d->n->a);
  bcrypto_gf_sub(e->y, d->n->b, d->n->a);
  bcrypto_gf_mul(e->t, e->y, eu);
  bcrypto_gf_mul(e->x, d->z, e->y);
  bcrypto_gf_mul(e->y, d->z, eu);
  bcrypto_gf_sqr(e->z, d->z);
}

static void niels_to_pt(bcrypto_curve448_point_t e, const bcrypto_niels_t n)
{
  bcrypto_gf_add(e->y, n->b, n->a);
  bcrypto_gf_sub(e->x, n->b, n->a);
  bcrypto_gf_mul(e->t, e->y, e->x);
  bcrypto_gf_copy(e->z, ONE);
}

static void add_niels_to_pt(bcrypto_curve448_point_t d, const bcrypto_niels_t e,
              int before_double)
{
  bcrypto_gf a, b, c;

  bcrypto_gf_sub_nr(b, d->y, d->x);   /* 3+e */
  bcrypto_gf_mul(a, e->a, b);
  bcrypto_gf_add_nr(b, d->x, d->y);   /* 2+e */
  bcrypto_gf_mul(d->y, e->b, b);
  bcrypto_gf_mul(d->x, e->c, d->t);
  bcrypto_gf_add_nr(c, a, d->y);    /* 2+e */
  bcrypto_gf_sub_nr(b, d->y, a);    /* 3+e */
  bcrypto_gf_sub_nr(d->y, d->z, d->x); /* 3+e */
  bcrypto_gf_add_nr(a, d->x, d->z);   /* 2+e */
  bcrypto_gf_mul(d->z, a, d->y);
  bcrypto_gf_mul(d->x, d->y, b);
  bcrypto_gf_mul(d->y, a, c);
  if (!before_double)
    bcrypto_gf_mul(d->t, b, c);
}

static void sub_niels_from_pt(bcrypto_curve448_point_t d, const bcrypto_niels_t e,
                int before_double)
{
  bcrypto_gf a, b, c;

  bcrypto_gf_sub_nr(b, d->y, d->x);   /* 3+e */
  bcrypto_gf_mul(a, e->b, b);
  bcrypto_gf_add_nr(b, d->x, d->y);   /* 2+e */
  bcrypto_gf_mul(d->y, e->a, b);
  bcrypto_gf_mul(d->x, e->c, d->t);
  bcrypto_gf_add_nr(c, a, d->y);    /* 2+e */
  bcrypto_gf_sub_nr(b, d->y, a);    /* 3+e */
  bcrypto_gf_add_nr(d->y, d->z, d->x); /* 2+e */
  bcrypto_gf_sub_nr(a, d->z, d->x);   /* 3+e */
  bcrypto_gf_mul(d->z, a, d->y);
  bcrypto_gf_mul(d->x, d->y, b);
  bcrypto_gf_mul(d->y, a, c);
  if (!before_double)
    bcrypto_gf_mul(d->t, b, c);
}

static void add_pniels_to_pt(bcrypto_curve448_point_t p, const bcrypto_pniels_t pn,
               int before_double)
{
  bcrypto_gf L0;

  bcrypto_gf_mul(L0, p->z, pn->z);
  bcrypto_gf_copy(p->z, L0);
  add_niels_to_pt(p, pn->n, before_double);
}

static void sub_pniels_from_pt(bcrypto_curve448_point_t p, const bcrypto_pniels_t pn,
                 int before_double)
{
  bcrypto_gf L0;

  bcrypto_gf_mul(L0, p->z, pn->z);
  bcrypto_gf_copy(p->z, L0);
  sub_niels_from_pt(p, pn->n, before_double);
}

bcrypto_c448_bool_t bcrypto_curve448_point_eq(const bcrypto_curve448_point_t p,
                const bcrypto_curve448_point_t q)
{
  bcrypto_mask_t succ;
  bcrypto_gf a, b;

  /* equality mod 2-torsion compares x/y */
  bcrypto_gf_mul(a, p->y, q->x);
  bcrypto_gf_mul(b, q->y, p->x);
  succ = bcrypto_gf_eq(a, b);

  return mask_to_bool(succ);
}

bcrypto_c448_bool_t bcrypto_curve448_point_valid(const bcrypto_curve448_point_t p)
{
  bcrypto_mask_t out;
  bcrypto_gf a, b, c;

  bcrypto_gf_mul(a, p->x, p->y);
  bcrypto_gf_mul(b, p->z, p->t);
  out = bcrypto_gf_eq(a, b);
  bcrypto_gf_sqr(a, p->x);
  bcrypto_gf_sqr(b, p->y);
  bcrypto_gf_sub(a, b, a);
  bcrypto_gf_sqr(b, p->t);
  bcrypto_gf_mulw(c, b, BCRYPTO_TWISTED_D);
  bcrypto_gf_sqr(b, p->z);
  bcrypto_gf_add(b, b, c);
  out &= bcrypto_gf_eq(a, b);
  out &= ~bcrypto_gf_eq(p->z, ZERO);
  return mask_to_bool(out);
}

static inline void constant_time_lookup_niels(bcrypto_niels_s * BCRYPTO_RESTRICT ni,
                           const bcrypto_niels_t * table,
                           int nelts, int idx)
{
  constant_time_lookup(ni, table, sizeof(bcrypto_niels_s), nelts, idx);
}

void bcrypto_curve448_precomputed_scalarmul(bcrypto_curve448_point_t out,
                  const bcrypto_curve448_precomputed_s * table,
                  const bcrypto_curve448_scalar_t scalar)
{
  unsigned int i, j, k;
  const unsigned int n = BCRYPTO_COMBS_N, t = BCRYPTO_COMBS_T, s = BCRYPTO_COMBS_S;
  bcrypto_niels_t ni;
  bcrypto_curve448_scalar_t scalar1x;

  bcrypto_curve448_scalar_add(scalar1x, scalar, precomputed_scalarmul_adjustment);
  bcrypto_curve448_scalar_halve(scalar1x, scalar1x);

  for (i = s; i > 0; i--) {
    if (i != s)
      point_double_internal(out, out, 0);

    for (j = 0; j < n; j++) {
      int tab = 0;
      bcrypto_mask_t invert;

      for (k = 0; k < t; k++) {
        unsigned int bit = (i - 1) + s * (k + j * t);

        if (bit < BCRYPTO_C448_SCALAR_BITS)
          tab |=
            (scalar1x->limb[bit / BCRYPTO_WBITS] >> (bit % BCRYPTO_WBITS) & 1) << k;
      }

      invert = (tab >> (t - 1)) - 1;
      tab ^= invert;
      tab &= (1 << (t - 1)) - 1;

      constant_time_lookup_niels(ni, &table->table[j << (t - 1)],
                     1 << (t - 1), tab);

      cond_neg_niels(ni, invert);
      if ((i != s) || j != 0)
        add_niels_to_pt(out, ni, j == n - 1 && i != 1);
      else
        niels_to_pt(out, ni);
    }
  }

  OPENSSL_cleanse(ni, sizeof(ni));
  OPENSSL_cleanse(scalar1x, sizeof(scalar1x));
}

static void
prepare_fixed_window(
  bcrypto_pniels_t *multiples,
  const bcrypto_curve448_point_t b,
  int ntable
) {
  bcrypto_curve448_point_t tmp;
  bcrypto_pniels_t pn;
  int i;

  point_double_internal(tmp, b, 0);
  pt_to_pniels(pn, tmp);
  pt_to_pniels(multiples[0], b);
  bcrypto_curve448_point_copy(tmp, b);

  for (i = 1; i < ntable; i++) {
    add_pniels_to_pt(tmp, pn, 0);
    pt_to_pniels(multiples[i], tmp);
  }

  OPENSSL_cleanse(pn, sizeof(pn));
  OPENSSL_cleanse(tmp, sizeof(tmp));
}

void bcrypto_curve448_point_scalarmul(
  bcrypto_curve448_point_t a,
  const bcrypto_curve448_point_t b,
  const bcrypto_curve448_scalar_t scalar
) {
  const int WINDOW = BCRYPTO_C448_WINDOW_BITS,
            WINDOW_MASK = (1 << WINDOW) - 1,
            WINDOW_T_MASK = WINDOW_MASK >> 1,
            NTABLE = 1 << (WINDOW - 1);

  bcrypto_curve448_scalar_t scalar1x;
  bcrypto_curve448_scalar_add(scalar1x, scalar, point_scalarmul_adjustment);
  bcrypto_curve448_scalar_halve(scalar1x, scalar1x);

  /* Set up a precomputed table with odd multiples of b. */
  bcrypto_pniels_t pn, multiples[1 << ((int)(BCRYPTO_C448_WINDOW_BITS) - 1)];
  bcrypto_curve448_point_t tmp;
  prepare_fixed_window(multiples, b, NTABLE);

  /* Initialize. */
  int i, j, first = 1;
  i = BCRYPTO_C448_SCALAR_BITS - ((BCRYPTO_C448_SCALAR_BITS - 1) % WINDOW) - 1;

  for (; i >= 0; i -= WINDOW) {
    /* Fetch another block of bits */
    bcrypto_word_t bits = scalar1x->limb[i / BCRYPTO_WBITS] >> (i % BCRYPTO_WBITS);

    if (i % BCRYPTO_WBITS >= BCRYPTO_WBITS - WINDOW
        && i / BCRYPTO_WBITS < BCRYPTO_C448_SCALAR_LIMBS - 1) {
      bits ^= scalar1x->limb[i / BCRYPTO_WBITS + 1]
           << (BCRYPTO_WBITS - (i % BCRYPTO_WBITS));
    }

    bits &= WINDOW_MASK;
    bcrypto_mask_t inv = (bits>>(WINDOW-1))-1;
    bits ^= inv;

    /* Add in from table.  Compute t only on last iteration. */
    constant_time_lookup(pn, multiples, sizeof(pn), NTABLE, bits & WINDOW_T_MASK);
    cond_neg_niels(pn->n, inv);
    if (first) {
      pniels_to_pt(tmp, pn);
      first = 0;
    } else {
     /* Using Hisil et al's lookahead method instead of extensible here
      * for no particular reason.  Double WINDOW times, but only compute t on
      * the last one.
      */
      for (j = 0; j < WINDOW - 1; j++)
        point_double_internal(tmp, tmp, -1);
      point_double_internal(tmp, tmp, 0);
      add_pniels_to_pt(tmp, pn, i ? -1 : 0);
    }
  }

  /* Write out the answer */
  bcrypto_curve448_point_copy(a, tmp);

  OPENSSL_cleanse(scalar1x, sizeof(scalar1x));
  OPENSSL_cleanse(pn, sizeof(pn));
  OPENSSL_cleanse(multiples, sizeof(multiples));
  OPENSSL_cleanse(tmp, sizeof(tmp));
}

void bcrypto_curve448_point_mul_by_ratio_and_encode_like_eddsa(
                  uint8_t enc[BCRYPTO_EDDSA_448_PUBLIC_BYTES],
                  const bcrypto_curve448_point_t p)
{
  bcrypto_gf x, y, z, t;
  bcrypto_curve448_point_t q;

  /* The point is now on the twisted curve.  Move it to untwisted. */
  bcrypto_curve448_point_copy(q, p);

  {
    /* 4-isogeny: 2xy/(y^+x^2), (y^2-x^2)/(2z^2-y^2+x^2) */
    bcrypto_gf u;

    bcrypto_gf_sqr(x, q->x);
    bcrypto_gf_sqr(t, q->y);
    bcrypto_gf_add(u, x, t);
    bcrypto_gf_add(z, q->y, q->x);
    bcrypto_gf_sqr(y, z);
    bcrypto_gf_sub(y, y, u);
    bcrypto_gf_sub(z, t, x);
    bcrypto_gf_sqr(x, q->z);
    bcrypto_gf_add(t, x, x);
    bcrypto_gf_sub(t, t, z);
    bcrypto_gf_mul(x, t, y);
    bcrypto_gf_mul(y, z, u);
    bcrypto_gf_mul(z, u, t);
    OPENSSL_cleanse(u, sizeof(u));
  }

  /* Affinize */
  bcrypto_gf_invert(z, z, 1);
  bcrypto_gf_mul(t, x, z);
  bcrypto_gf_mul(x, y, z);

  /* Encode */
  enc[BCRYPTO_EDDSA_448_PRIVATE_BYTES - 1] = 0;
  bcrypto_gf_serialize(enc, x, 1);
  enc[BCRYPTO_EDDSA_448_PRIVATE_BYTES - 1] |= 0x80 & bcrypto_gf_lobit(t);

  OPENSSL_cleanse(x, sizeof(x));
  OPENSSL_cleanse(y, sizeof(y));
  OPENSSL_cleanse(z, sizeof(z));
  OPENSSL_cleanse(t, sizeof(t));
  bcrypto_curve448_point_destroy(q);
}

bcrypto_c448_error_t bcrypto_curve448_point_decode_like_eddsa_and_mul_by_ratio(
                bcrypto_curve448_point_t p,
                const uint8_t enc[BCRYPTO_EDDSA_448_PUBLIC_BYTES])
{
  uint8_t enc2[BCRYPTO_EDDSA_448_PUBLIC_BYTES];
  bcrypto_mask_t low;
  bcrypto_mask_t succ;

  memcpy(enc2, enc, sizeof(enc2));

  low = ~word_is_zero(enc2[BCRYPTO_EDDSA_448_PRIVATE_BYTES - 1] & 0x80);
  enc2[BCRYPTO_EDDSA_448_PRIVATE_BYTES - 1] &= ~0x80;

  succ = bcrypto_gf_deserialize(p->y, enc2, 1, 0);
  succ &= word_is_zero(enc2[BCRYPTO_EDDSA_448_PRIVATE_BYTES - 1]);

  bcrypto_gf_sqr(p->x, p->y);
  bcrypto_gf_sub(p->z, ONE, p->x);  /* num = 1-y^2 */
  bcrypto_gf_mulw(p->t, p->x, BCRYPTO_EDWARDS_D); /* dy^2 */
  bcrypto_gf_sub(p->t, ONE, p->t);  /* denom = 1-dy^2 or 1-d + dy^2 */

  bcrypto_gf_mul(p->x, p->z, p->t);
  succ &= bcrypto_gf_isr(p->t, p->x); /* 1/sqrt(num * denom) */

  bcrypto_gf_mul(p->x, p->t, p->z);   /* sqrt(num / denom) */
  bcrypto_gf_cond_neg(p->x, bcrypto_gf_lobit(p->x) ^ low);
  bcrypto_gf_copy(p->z, ONE);

  {
    bcrypto_gf a, b, c, d;

    /* 4-isogeny 2xy/(y^2-ax^2), (y^2+ax^2)/(2-y^2-ax^2) */
    bcrypto_gf_sqr(c, p->x);
    bcrypto_gf_sqr(a, p->y);
    bcrypto_gf_add(d, c, a);
    bcrypto_gf_add(p->t, p->y, p->x);
    bcrypto_gf_sqr(b, p->t);
    bcrypto_gf_sub(b, b, d);
    bcrypto_gf_sub(p->t, a, c);
    bcrypto_gf_sqr(p->x, p->z);
    bcrypto_gf_add(p->z, p->x, p->x);
    bcrypto_gf_sub(a, p->z, d);
    bcrypto_gf_mul(p->x, a, b);
    bcrypto_gf_mul(p->z, p->t, a);
    bcrypto_gf_mul(p->y, p->t, d);
    bcrypto_gf_mul(p->t, b, d);
    OPENSSL_cleanse(a, sizeof(a));
    OPENSSL_cleanse(b, sizeof(b));
    OPENSSL_cleanse(c, sizeof(c));
    OPENSSL_cleanse(d, sizeof(d));
  }

  OPENSSL_cleanse(enc2, sizeof(enc2));
  assert(bcrypto_curve448_point_valid(p) || ~succ);

  return bcrypto_c448_succeed_if(mask_to_bool(succ));
}

bcrypto_c448_error_t bcrypto_x448_int(uint8_t out[BCRYPTO_X_PUBLIC_BYTES],
            const uint8_t base[BCRYPTO_X_PUBLIC_BYTES],
            const uint8_t scalar[BCRYPTO_X_PRIVATE_BYTES])
{
  bcrypto_gf x1, x2, z2, x3, z3, t1, t2;
  int t;
  bcrypto_mask_t swap = 0;
  bcrypto_mask_t nz;

  (void)bcrypto_gf_deserialize(x1, base, 1, 0);
  bcrypto_gf_copy(x2, ONE);
  bcrypto_gf_copy(z2, ZERO);
  bcrypto_gf_copy(x3, x1);
  bcrypto_gf_copy(z3, ONE);

  for (t = BCRYPTO_X_PRIVATE_BITS - 1; t >= 0; t--) {
    uint8_t sb = scalar[t / 8];
    bcrypto_mask_t k_t;

    /* Scalar conditioning */
    if (t / 8 == 0)
      sb &= -(uint8_t)BCRYPTO_COFACTOR;
    else if (t == BCRYPTO_X_PRIVATE_BITS - 1)
      sb = -1;

    k_t = (sb >> (t % 8)) & 1;
    k_t = 0 - k_t;       /* set to all 0s or all 1s */

    swap ^= k_t;
    bcrypto_gf_cond_swap(x2, x3, swap);
    bcrypto_gf_cond_swap(z2, z3, swap);
    swap = k_t;

    /*
     * The "_nr" below skips coefficient reduction. In the following
     * comments, "2+e" is saying that the coefficients are at most 2+epsilon
     * times the reduction limit.
     */
    bcrypto_gf_add_nr(t1, x2, z2);  /* A = x2 + z2 */ /* 2+e */
    bcrypto_gf_sub_nr(t2, x2, z2);  /* B = x2 - z2 */ /* 3+e */
    bcrypto_gf_sub_nr(z2, x3, z3);  /* D = x3 - z3 */ /* 3+e */
    bcrypto_gf_mul(x2, t1, z2);   /* DA */
    bcrypto_gf_add_nr(z2, z3, x3);  /* C = x3 + z3 */ /* 2+e */
    bcrypto_gf_mul(x3, t2, z2);   /* CB */
    bcrypto_gf_sub_nr(z3, x2, x3);  /* DA-CB */ /* 3+e */
    bcrypto_gf_sqr(z2, z3);     /* (DA-CB)^2 */
    bcrypto_gf_mul(z3, x1, z2);   /* z3 = x1(DA-CB)^2 */
    bcrypto_gf_add_nr(z2, x2, x3);  /* (DA+CB) */ /* 2+e */
    bcrypto_gf_sqr(x3, z2);     /* x3 = (DA+CB)^2 */

    bcrypto_gf_sqr(z2, t1);     /* AA = A^2 */
    bcrypto_gf_sqr(t1, t2);     /* BB = B^2 */
    bcrypto_gf_mul(x2, z2, t1);   /* x2 = AA*BB */
    bcrypto_gf_sub_nr(t2, z2, t1);  /* E = AA-BB */ /* 3+e */

    bcrypto_gf_mulw(t1, t2, -BCRYPTO_EDWARDS_D); /* E*-d = a24*E */
    bcrypto_gf_add_nr(t1, t1, z2);  /* AA + a24*E */ /* 2+e */
    bcrypto_gf_mul(z2, t2, t1);   /* z2 = E(AA+a24*E) */
  }

  /* Finish */
  bcrypto_gf_cond_swap(x2, x3, swap);
  bcrypto_gf_cond_swap(z2, z3, swap);
  bcrypto_gf_invert(z2, z2, 0);
  bcrypto_gf_mul(x1, x2, z2);
  bcrypto_gf_serialize(out, x1, 1);
  nz = ~bcrypto_gf_eq(x1, ZERO);

  OPENSSL_cleanse(x1, sizeof(x1));
  OPENSSL_cleanse(x2, sizeof(x2));
  OPENSSL_cleanse(z2, sizeof(z2));
  OPENSSL_cleanse(x3, sizeof(x3));
  OPENSSL_cleanse(z3, sizeof(z3));
  OPENSSL_cleanse(t1, sizeof(t1));
  OPENSSL_cleanse(t2, sizeof(t2));

  return bcrypto_c448_succeed_if(mask_to_bool(nz));
}

void bcrypto_curve448_point_mul_by_ratio_and_encode_like_x448(uint8_t
                            out[BCRYPTO_X_PUBLIC_BYTES],
                            const bcrypto_curve448_point_t p)
{
  bcrypto_curve448_point_t q;

  bcrypto_curve448_point_copy(q, p);
  bcrypto_gf_invert(q->t, q->x, 0);   /* 1/x */
  bcrypto_gf_mul(q->z, q->t, q->y);   /* y/x */
  bcrypto_gf_sqr(q->y, q->z);     /* (y/x)^2 */
  bcrypto_gf_serialize(out, q->y, 1);
  bcrypto_curve448_point_destroy(q);
}

void bcrypto_x448_derive_public_key(uint8_t out[BCRYPTO_X_PUBLIC_BYTES],
              const uint8_t scalar[BCRYPTO_X_PRIVATE_BYTES])
{
  /* Scalar conditioning */
  uint8_t scalar2[BCRYPTO_X_PRIVATE_BYTES];
  bcrypto_curve448_scalar_t the_scalar;
  bcrypto_curve448_point_t p;
  unsigned int i;

  memcpy(scalar2, scalar, sizeof(scalar2));
  scalar2[0] &= -(uint8_t)BCRYPTO_COFACTOR;

  scalar2[BCRYPTO_X_PRIVATE_BYTES - 1] &= ~((0u - 1u) << ((BCRYPTO_X_PRIVATE_BITS + 7) % 8));
  scalar2[BCRYPTO_X_PRIVATE_BYTES - 1] |= 1 << ((BCRYPTO_X_PRIVATE_BITS + 7) % 8);

  bcrypto_curve448_scalar_decode_long(the_scalar, scalar2, sizeof(scalar2));

  /* Compensate for the encoding ratio */
  for (i = 1; i < BCRYPTO_X448_ENCODE_RATIO; i <<= 1)
    bcrypto_curve448_scalar_halve(the_scalar, the_scalar);

  bcrypto_curve448_precomputed_scalarmul(p, bcrypto_curve448_precomputed_base, the_scalar);
  bcrypto_curve448_point_mul_by_ratio_and_encode_like_x448(out, p);
  bcrypto_curve448_point_destroy(p);
}

/* Thanks Johan Pascal */
void bcrypto_curve448_convert_public_key_to_x448(
  uint8_t x[BCRYPTO_X_PUBLIC_BYTES],
  const uint8_t ed[BCRYPTO_EDDSA_448_PUBLIC_BYTES]
) {
  bcrypto_gf y;
  const uint8_t mask = (uint8_t)(0xFE << (7));
  bcrypto_gf_deserialize(y, ed, 1, mask);

  {
    bcrypto_gf n, d;

    /* u = y^2 * (1-dy^2) / (1-y^2) */
    bcrypto_gf_sqr(n, y); /* y^2*/
    bcrypto_gf_sub(d, ONE, n); /* 1-y^2*/
    bcrypto_gf_invert(d, d, 0); /* 1/(1-y^2)*/
    bcrypto_gf_mul(y, n, d); /* y^2 / (1-y^2) */
    bcrypto_gf_mulw(d, n, BCRYPTO_EDWARDS_D); /* dy^2*/
    bcrypto_gf_sub(d, ONE, d); /* 1-dy^2*/
    bcrypto_gf_mul(n, y, d); /* y^2 * (1-dy^2) / (1-y^2) */
    bcrypto_gf_serialize(x, n, 1);

    OPENSSL_cleanse(y, sizeof(y));
    OPENSSL_cleanse(n, sizeof(n));
    OPENSSL_cleanse(d, sizeof(d));
  }
}

/* Control for variable-time scalar multiply algorithms. */
struct bcrypto_smvt_control {
  int power, addend;
};

#if defined(__GNUC__) && (__GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ > 3))
# define BCRYPTO_NUMTRAILINGZEROS	__builtin_ctz
#else
# define BCRYPTO_NUMTRAILINGZEROS	numtrailingzeros
static uint32_t numtrailingzeros(uint32_t i)
{
  uint32_t tmp;
  uint32_t num = 31;

  if (i == 0)
    return 32;

  tmp = i << 16;
  if (tmp != 0) {
    i = tmp;
    num -= 16;
  }
  tmp = i << 8;
  if (tmp != 0) {
    i = tmp;
    num -= 8;
  }
  tmp = i << 4;
  if (tmp != 0) {
    i = tmp;
    num -= 4;
  }
  tmp = i << 2;
  if (tmp != 0) {
    i = tmp;
    num -= 2;
  }
  tmp = i << 1;
  if (tmp != 0)
    num--;

  return num;
}
#endif

static int recode_wnaf(struct bcrypto_smvt_control *control,
             /* [nbits/(table_bits + 1) + 3] */
             const bcrypto_curve448_scalar_t scalar,
             unsigned int table_bits)
{
  unsigned int table_size = BCRYPTO_C448_SCALAR_BITS / (table_bits + 1) + 3;
  int position = table_size - 1; /* at the end */
  uint64_t current = scalar->limb[0] & 0xFFFF;
  uint32_t mask = (1 << (table_bits + 1)) - 1;
  unsigned int w;
  const unsigned int B_OVER_16 = sizeof(scalar->limb[0]) / 2;
  unsigned int n, i;

  /* place the end marker */
  control[position].power = -1;
  control[position].addend = 0;
  position--;

  /*
   * PERF: Could negate scalar if it's large.  But then would need more cases
   * in the actual code that uses it, all for an expected reduction of like
   * 1/5 op. Probably not worth it.
   */

  for (w = 1; w < (BCRYPTO_C448_SCALAR_BITS - 1) / 16 + 3; w++) {
    if (w < (BCRYPTO_C448_SCALAR_BITS - 1) / 16 + 1) {
      /* Refill the 16 high bits of current */
      current += (uint32_t)((scalar->limb[w / B_OVER_16]
             >> (16 * (w % B_OVER_16))) << 16);
    }

    while (current & 0xFFFF) {
      uint32_t pos = BCRYPTO_NUMTRAILINGZEROS((uint32_t)current);
      uint32_t odd = (uint32_t)current >> pos;
      int32_t delta = odd & mask;

      assert(position >= 0);
      if (odd & (1 << (table_bits + 1)))
        delta -= (1 << (table_bits + 1));
      current -= delta * (1 << pos);
      control[position].power = pos + 16 * (w - 1);
      control[position].addend = delta;
      position--;
    }
    current >>= 16;
  }
  assert(current == 0);

  position++;
  n = table_size - position;
  for (i = 0; i < n; i++)
    control[i] = control[i + position];

  return n - 1;
}

static void prepare_wnaf_table(bcrypto_pniels_t * output,
                 const bcrypto_curve448_point_t working,
                 unsigned int tbits)
{
  bcrypto_curve448_point_t tmp;
  int i;
  bcrypto_pniels_t twop;

  pt_to_pniels(output[0], working);

  if (tbits == 0)
    return;

  bcrypto_curve448_point_double(tmp, working);
  pt_to_pniels(twop, tmp);

  add_pniels_to_pt(tmp, output[0], 0);
  pt_to_pniels(output[1], tmp);

  for (i = 2; i < 1 << tbits; i++) {
    add_pniels_to_pt(tmp, twop, 0);
    pt_to_pniels(output[i], tmp);
  }

  bcrypto_curve448_point_destroy(tmp);
  OPENSSL_cleanse(twop, sizeof(twop));
}

void bcrypto_curve448_base_double_scalarmul_non_secret(bcrypto_curve448_point_t combo,
                         const bcrypto_curve448_scalar_t scalar1,
                         const bcrypto_curve448_point_t base2,
                         const bcrypto_curve448_scalar_t scalar2)
{
  const int table_bits_var = BCRYPTO_C448_WNAF_VAR_TABLE_BITS;
  const int table_bits_pre = BCRYPTO_C448_WNAF_FIXED_TABLE_BITS;
  struct bcrypto_smvt_control control_var[BCRYPTO_C448_SCALAR_BITS /
                  (BCRYPTO_C448_WNAF_VAR_TABLE_BITS + 1) + 3];
  struct bcrypto_smvt_control control_pre[BCRYPTO_C448_SCALAR_BITS /
                  (BCRYPTO_C448_WNAF_FIXED_TABLE_BITS + 1) + 3];
  int ncb_pre = recode_wnaf(control_pre, scalar1, table_bits_pre);
  int ncb_var = recode_wnaf(control_var, scalar2, table_bits_var);
  bcrypto_pniels_t precmp_var[1 << BCRYPTO_C448_WNAF_VAR_TABLE_BITS];
  int contp = 0, contv = 0, i;

  prepare_wnaf_table(precmp_var, base2, table_bits_var);
  i = control_var[0].power;

  if (i < 0) {
    bcrypto_curve448_point_copy(combo, bcrypto_curve448_point_identity);
    return;
  }
  if (i > control_pre[0].power) {
    pniels_to_pt(combo, precmp_var[control_var[0].addend >> 1]);
    contv++;
  } else if (i == control_pre[0].power && i >= 0) {
    pniels_to_pt(combo, precmp_var[control_var[0].addend >> 1]);
    add_niels_to_pt(combo, bcrypto_curve448_wnaf_base[control_pre[0].addend >> 1],
            i);
    contv++;
    contp++;
  } else {
    i = control_pre[0].power;
    niels_to_pt(combo, bcrypto_curve448_wnaf_base[control_pre[0].addend >> 1]);
    contp++;
  }

  for (i--; i >= 0; i--) {
    int cv = (i == control_var[contv].power);
    int cp = (i == control_pre[contp].power);

    point_double_internal(combo, combo, i && !(cv || cp));

    if (cv) {
      assert(control_var[contv].addend);

      if (control_var[contv].addend > 0)
        add_pniels_to_pt(combo,
                 precmp_var[control_var[contv].addend >> 1],
                 i && !cp);
      else
        sub_pniels_from_pt(combo,
                   precmp_var[(-control_var[contv].addend)
                        >> 1], i && !cp);
      contv++;
    }

    if (cp) {
      assert(control_pre[contp].addend);

      if (control_pre[contp].addend > 0)
        add_niels_to_pt(combo,
                bcrypto_curve448_wnaf_base[control_pre[contp].addend
                           >> 1], i);
      else
        sub_niels_from_pt(combo,
                  bcrypto_curve448_wnaf_base[(-control_pre
                            [contp].addend) >> 1], i);
      contp++;
    }
  }

  /* This function is non-secret, but whatever this is cheap. */
  OPENSSL_cleanse(control_var, sizeof(control_var));
  OPENSSL_cleanse(control_pre, sizeof(control_pre));
  OPENSSL_cleanse(precmp_var, sizeof(precmp_var));

  assert(contv == ncb_var);
  (void)ncb_var;
  assert(contp == ncb_pre);
  (void)ncb_pre;
}

void bcrypto_curve448_point_destroy(bcrypto_curve448_point_t point)
{
  OPENSSL_cleanse(point, sizeof(bcrypto_curve448_point_t));
}

int bcrypto_x448(uint8_t out_shared_key[56], const uint8_t private_key[56],
     const uint8_t peer_public_value[56])
{
  return bcrypto_x448_int(out_shared_key, peer_public_value, private_key)
       == BCRYPTO_C448_SUCCESS;
}

void bcrypto_x448_public_from_private(uint8_t out_public_value[56],
                const uint8_t private_key[56])
{
  bcrypto_x448_derive_public_key(out_public_value, private_key);
}
