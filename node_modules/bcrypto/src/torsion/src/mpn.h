/*!
 * mpn.h - mpn helpers for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 *
 * Parts of this software are based on gnutls/nettle:
 *   Copyright (c) 1998-2019, Niels Möller and Contributors
 *   https://github.com/gnutls/nettle
 */

#ifndef _TORSION_MPN_H
#define _TORSION_MPN_H

#include <stddef.h>
#include <stdint.h>
#ifdef TORSION_TEST
#include <stdio.h>
#endif
#include <torsion/util.h>

#include "gmp-compat.h"

/* Avoid collisions with future versions of GMP. */
#define mpn_bitlen torsion_mpn_bitlen
#define mpn_cmp_limb torsion_mpn_cmp_limb
#define mpn_cleanse torsion_mpn_cleanse
#ifndef mpn_cnd_swap
#define mpn_cnd_swap torsion_mpn_cnd_swap
#define mpn_needs_cnd_swap
#endif
#define mpn_cnd_select torsion_mpn_cnd_select
#define mpn_import_be torsion_mpn_import_be
#define mpn_import_le torsion_mpn_import_le
#define mpn_import torsion_mpn_import
#define mpn_export_be torsion_mpn_export_be
#define mpn_export_le torsion_mpn_export_le
#define mpn_export torsion_mpn_export
#define mpn_invert_n torsion_mpn_invert_n
#define mpn_print torsion_mpn_print

#define MAX_EGCD_LIMBS ((521 + GMP_NUMB_BITS - 1) / GMP_NUMB_BITS)

/*
 * MPN Extras (some borrowed from nettle)
 */

static mp_size_t
mpn_bitlen(const mp_limb_t *xp, mp_size_t n) {
  mp_size_t i, b;
  mp_limb_t w;

  for (i = n - 1; i >= 0; i--) {
    if (xp[i] != 0)
      break;
  }

  if (i < 0)
    return 0;

  w = xp[i];
  b = 0;

  while (w != 0) {
    w >>= 1;
    b += 1;
  }

  return i * GMP_NUMB_BITS + b;
}

static int
mpn_cmp_limb(const mp_limb_t *xp, mp_size_t xn, int32_t num) {
  mp_limb_t w = 0;
  mp_limb_t n = num;

  if (num < 0)
    return 1;

  if (xn > 1)
    return 1;

  if (xn > 0)
    w = xp[0];

  return (int)(w > n) - (int)(w < n);
}

static void
mpn_cleanse(mp_limb_t *p, mp_size_t n) {
  cleanse(p, n * sizeof(mp_limb_t));
}

#ifdef mpn_needs_cnd_swap
static void
mpn_cnd_swap(mp_limb_t cnd, mp_limb_t *ap, mp_limb_t *bp, mp_size_t n) {
  mp_limb_t mask = -(mp_limb_t)(cnd != 0);
  mp_size_t i;

  for (i = 0; i < n; i++) {
    mp_limb_t a = ap[i];
    mp_limb_t b = bp[i];
    mp_limb_t w = (a ^ b) & mask;

    ap[i] = a ^ w;
    bp[i] = b ^ w;
  }
}
#endif

static void
mpn_cnd_select(mp_limb_t cnd,
               mp_limb_t *rp,
               const mp_limb_t *ap,
               const mp_limb_t *bp,
               mp_size_t n) {
  mp_limb_t cond = (cnd != 0);
  mp_limb_t mask0 = cond - 1;
  mp_limb_t mask1 = ~mask0;
  mp_size_t i;

  for (i = 0; i < n; i++)
    rp[i] = (ap[i] & mask0) | (bp[i] & mask1);
}

static void
mpn_import_be(mp_limb_t *rp, mp_size_t rn,
              const unsigned char *xp, size_t xn) {
  size_t xi;
  mp_limb_t out;
  unsigned int bits;

  for (xi = xn, out = bits = 0; xi > 0 && rn > 0;) {
    mp_limb_t in = xp[--xi];

    out |= (in << bits) & GMP_NUMB_MASK;
    bits += 8;

    if (bits >= GMP_NUMB_BITS) {
      *rp++ = out;
      rn--;

      bits -= GMP_NUMB_BITS;
      out = in >> (8 - bits);
    }
  }

  if (rn > 0) {
    *rp++ = out;
    if (--rn > 0)
      mpn_zero(rp, rn);
  }
}

static void
mpn_import_le(mp_limb_t *rp, mp_size_t rn,
              const unsigned char *xp, size_t xn) {
  size_t xi;
  mp_limb_t out;
  unsigned int bits;

  for (xi = 0, out = bits = 0; xi < xn && rn > 0; ) {
    mp_limb_t in = xp[xi++];

    out |= (in << bits) & GMP_NUMB_MASK;
    bits += 8;

    if (bits >= GMP_NUMB_BITS) {
      *rp++ = out;
      rn--;

      bits -= GMP_NUMB_BITS;
      out = in >> (8 - bits);
    }
  }

  if (rn > 0) {
    *rp++ = out;
    if (--rn > 0)
      mpn_zero(rp, rn);
  }
}

static void
mpn_import(mp_limb_t *rp, mp_size_t rn,
           const unsigned char *xp, size_t xn, int endian) {
  if (endian == 1)
    mpn_import_be(rp, rn, xp, xn);
  else
    mpn_import_le(rp, rn, xp, xn);
}

static void
mpn_export_be(unsigned char *rp, size_t rn,
              const mp_limb_t *xp, mp_size_t xn) {
  unsigned int bits;
  unsigned char old;
  mp_limb_t in;

  for (bits = in = 0; xn > 0 && rn > 0;) {
    if (bits >= 8) {
      rp[--rn] = in;
      in >>= 8;
      bits -= 8;
    } else {
      old = in;
      in = *xp++;
      xn--;
      rp[--rn] = old | (in << bits);
      in >>= (8 - bits);
      bits += GMP_NUMB_BITS - 8;
    }
  }

  while (rn > 0) {
    rp[--rn] = in;
    in >>= 8;
  }
}

static void
mpn_export_le(unsigned char *rp, size_t rn,
              const mp_limb_t *xp, mp_size_t xn) {
  unsigned int bits;
  unsigned char old;
  mp_limb_t in;

  for (bits = in = 0; xn > 0 && rn > 0;) {
    if (bits >= 8) {
      *rp++ = in;
      rn--;
      in >>= 8;
      bits -= 8;
    } else {
      old = in;
      in = *xp++;
      xn--;
      *rp++ = old | (in << bits);
      rn--;
      in >>= (8 - bits);
      bits += GMP_NUMB_BITS - 8;
    }
  }

  while (rn > 0) {
    *rp++ = in;
    rn--;
    in >>= 8;
  }
}

static void
mpn_export(unsigned char *rp, size_t rn,
           const mp_limb_t *xp, mp_size_t xn, int endian) {
  if (endian == 1)
    mpn_export_be(rp, rn, xp, xn);
  else
    mpn_export_le(rp, rn, xp, xn);
}

static int
mpn_invert_n(mp_limb_t *rp,
             const mp_limb_t *xp,
             const mp_limb_t *yp,
             mp_size_t n) {
  mp_limb_t gp[MAX_EGCD_LIMBS + 1];
  mp_limb_t sp[MAX_EGCD_LIMBS + 1];
  mp_limb_t up[MAX_EGCD_LIMBS + 1];
  mp_limb_t vp[MAX_EGCD_LIMBS + 1];
  mp_size_t sn = n + 1;
  mp_size_t gn;

  assert(n <= (mp_size_t)MAX_EGCD_LIMBS);

  if (mpn_zero_p(xp, n)) {
    mpn_zero(rp, n);
    return 0;
  }

  mpn_copyi(up, xp, n);
  mpn_copyi(vp, yp, n);

  gn = mpn_gcdext(gp, sp, &sn, up, n, vp, n);

  assert(gn == 1);
  assert(gp[0] == 1);

  if (sn < 0) {
    mpn_sub(sp, yp, n, sp, -sn);
    sn = n;
  }

  assert(sn <= n);

  mpn_zero(rp + sn, n - sn);
  mpn_copyi(rp, sp, sn);

  return 1;
}

#ifdef TORSION_TEST
static void
mpn_print(const mp_limb_t *p, mp_size_t n, int base) {
  mpz_t x;
  mpz_roinit_n(x, p, n);
  mpz_out_str(stdout, base, x);
}
#endif

#endif /* _TORSION_MPN_H */
