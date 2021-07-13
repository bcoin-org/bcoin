/*!
 * gmp-compat.h - gmp wrapper libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 */

#ifndef _TORSION_GMP_COMPAT_H
#define _TORSION_GMP_COMPAT_H

#ifdef TORSION_USE_GMP

#include <gmp.h>

/* Nails probably break our code. */
#if GMP_NAIL_BITS != 0 || GMP_LIMB_BITS != GMP_NUMB_BITS
#error "please use a build of gmp without nails"
#endif

#if (GMP_NUMB_BITS & 31) != 0
#error "invalid gmp bit alignment"
#endif

#else /* TORSION_USE_GMP */

#include <assert.h>
#include <limits.h>
#include "mini-gmp.h"

#define GMP_LIMB_BITS (sizeof(mp_limb_t) * CHAR_BIT)
#define GMP_NAIL_BITS 0
#define GMP_NUMB_BITS GMP_LIMB_BITS
#define GMP_NUMB_MASK (~((mp_limb_t)0))
#define GMP_NUMB_MAX GMP_NUMB_MASK
#define GMP_NAIL_MASK 0

/* `mpz_jacobi` is not implemented in mini-gmp. */
static int
mpz_jacobi(const mpz_t x, const mpz_t y) {
  mp_limb_t bmod8;
  mp_size_t s;
  mpz_t a, b, c;
  int j = 1;

  assert(mpz_odd_p(y));

  mpz_init(a);
  mpz_init(b);
  mpz_init(c);

  mpz_set(a, x);
  mpz_set(b, y);

  if (mpz_sgn(b) < 0) {
    if (mpz_sgn(a) < 0)
      j = -1;

    mpz_neg(b, b);
  }

  for (;;) {
    if (mpz_cmp_ui(b, 1) == 0)
      break;

    if (mpz_sgn(a) == 0) {
      j = 0;
      break;
    }

    mpz_mod(a, a, b);

    if (mpz_sgn(a) == 0) {
      j = 0;
      break;
    }

    s = mpz_scan1(a, 0);

    if (s & 1) {
      bmod8 = mpz_getlimbn(b, 0) & 7;

      if (bmod8 == 3 || bmod8 == 5)
        j = -j;
    }

    mpz_tdiv_q_2exp(c, a, s);

    if ((mpz_getlimbn(b, 0) & 3) == 3 && (mpz_getlimbn(c, 0) & 3) == 3)
      j = -j;

    mpz_set(a, b);
    mpz_set(b, c);
  }

  mpz_clear(a);
  mpz_clear(b);
  mpz_clear(c);

  return j;
}

/* `mpz_powm_sec` is not implemented in mini-gmp. */
static void
mpz_powm_sec(mpz_t rop, const mpz_t base, const mpz_t exp, const mpz_t mod) {
  assert(mpz_sgn(exp) > 0);
  assert(mpz_odd_p(mod));

  mpz_powm(rop, base, exp, mod);
}

static void
mpn_set_mpz(mp_limb_t *xp, mpz_srcptr x, mp_size_t n) {
  mp_size_t xn = mpz_size(x);

  assert(xn <= n);

  mpn_copyi(xp, mpz_limbs_read(x), xn);

  if (xn < n)
    mpn_zero(xp + xn, n - xn);
}

/* `mpn_tdiv_qr` is not exposed in mini-gmp. */
static void
mpn_tdiv_qr(mp_limb_t *qp,
            mp_limb_t *rp,
            mp_size_t qxn,
            const mp_limb_t *np,
            mp_size_t nn,
            const mp_limb_t *dp,
            mp_size_t dn) {
  mpz_t q, r, n, d;

  assert(nn >= dn);
  assert(dn > 0);
  assert(qxn == 0);
  assert(dp[dn - 1] != 0);

  mpz_init(q);
  mpz_init(r);
  mpz_roinit_n(n, np, nn);
  mpz_roinit_n(d, dp, dn);

  mpz_tdiv_qr(q, r, n, d);

  mpn_set_mpz(qp, q, nn - dn + 1);
  mpn_set_mpz(rp, r, dn);

  mpz_clear(q);
  mpz_clear(r);
}

/* `mpn_gcdext` is not exposed in mini-gmp. */
static mp_size_t
mpn_gcdext(mp_limb_t *gp,
           mp_limb_t *sp,
           mp_size_t *sn,
           mp_limb_t *up,
           mp_size_t un,
           mp_limb_t *vp,
           mp_size_t vn) {
  mp_size_t gn;
  mpz_t g, s, u, v;

  assert(un >= vn);
  assert(vn > 0);

  mpz_init(g);
  mpz_init(s);
  mpz_roinit_n(u, up, un);
  mpz_roinit_n(v, vp, vn);

  mpz_gcdext(g, s, NULL, u, v);

  mpn_zero(up, un);
  mpn_zero(vp, vn);

  gn = mpz_size(g);
  *sn = mpz_size(s);

  mpn_set_mpz(gp, g, vn);
  mpn_set_mpz(sp, s, vn + 1);

  if (mpz_sgn(s) < 0)
    *sn = -(*sn);

  mpz_clear(g);
  mpz_clear(s);

  return gn;
}

#endif /* TORSION_USE_GMP */

#endif /* _TORSION_GMP_COMPAT_H */
