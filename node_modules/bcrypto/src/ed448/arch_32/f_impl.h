/*
 * Copyright 2017-2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2014-2016 Cryptography Research, Inc.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Originally written by Mike Hamburg
 */

#ifndef _BCRYPTO_ARCH_32_F_IMPL_H
# define _BCRYPTO_ARCH_32_F_IMPL_H

# define BCRYPTO_GF_HEADROOM 2
# define BCRYPTO_LIMB(x) ((x) & ((1 << 28) - 1)), ((x) >> 28)
# define BCRYPTO_FIELD_LITERAL(a, b, c, d, e, f, g, h) \
  {{BCRYPTO_LIMB(a), BCRYPTO_LIMB(b), BCRYPTO_LIMB(c), BCRYPTO_LIMB(d), BCRYPTO_LIMB(e), BCRYPTO_LIMB(f), BCRYPTO_LIMB(g), BCRYPTO_LIMB(h)}}

# define BCRYPTO_LIMB_PLACE_VALUE(i) 28

void bcrypto_gf_add_RAW(bcrypto_gf out, const bcrypto_gf a, const bcrypto_gf b)
{
  unsigned int i;

  for (i = 0; i < BCRYPTO_NLIMBS; i++)
    out->limb[i] = a->limb[i] + b->limb[i];
}

void bcrypto_gf_sub_RAW(bcrypto_gf out, const bcrypto_gf a, const bcrypto_gf b)
{
  unsigned int i;

  for (i = 0; i < BCRYPTO_NLIMBS; i++)
    out->limb[i] = a->limb[i] - b->limb[i];
}

void bcrypto_gf_bias(bcrypto_gf a, int amt)
{
  unsigned int i;
  uint32_t co1 = ((1 << 28) - 1) * amt, co2 = co1 - amt;

  for (i = 0; i < BCRYPTO_NLIMBS; i++)
    a->limb[i] += (i == BCRYPTO_NLIMBS / 2) ? co2 : co1;
}

void bcrypto_gf_weak_reduce(bcrypto_gf a)
{
  uint32_t mask = (1 << 28) - 1;
  uint32_t tmp = a->limb[BCRYPTO_NLIMBS - 1] >> 28;
  unsigned int i;

  a->limb[BCRYPTO_NLIMBS / 2] += tmp;
  for (i = BCRYPTO_NLIMBS - 1; i > 0; i--)
    a->limb[i] = (a->limb[i] & mask) + (a->limb[i - 1] >> 28);
  a->limb[0] = (a->limb[0] & mask) + tmp;
}

#endif          /* _BCRYPTO_ARCH_32_F_IMPL_H */
