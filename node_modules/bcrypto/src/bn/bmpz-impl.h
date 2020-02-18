#include "../random/random.h"

typedef int (*bmpz_rng_t)(
  mpz_t ret,
  unsigned long bits,
  void *data
);

static inline size_t
bmpz_bitlen(const mpz_t n) {
  if (mpz_sgn(n) == 0)
    return 0;

  return mpz_sizeinbase(n, 2);
}

static inline size_t
bmpz_bytelen(const mpz_t n) {
  if (mpz_sgn(n) == 0)
    return 0;

  return (mpz_sizeinbase(n, 16) + 1) >> 1;
}

static inline unsigned long
bmpz_zerobits(const mpz_t n) {
  int sgn = mpz_sgn(n);

  // if n == 0
  if (sgn == 0)
    return 0;

  // Note: mpz_ptr is undocumented.
  // https://gmplib.org/list-archives/gmp-discuss/2009-May/003769.html
  // https://gmplib.org/list-archives/gmp-devel/2013-February/002775.html

  // if n < 0
  if (sgn < 0) {
    // n = -n;
    mpz_neg((mpz_ptr)n, n);
  }

  unsigned long bits = mpz_scan1(n, 0);

  if (sgn < 0) {
    // n = -n;
    mpz_neg((mpz_ptr)n, n);
  }

  return bits;
}

static void
bmpz_pow(mpz_t ret, const mpz_t a, mpz_t b) {
  if (mpz_sgn(a) != 0) {
    mpz_t x, y;

    mpz_init(x);
    mpz_init(y);

    mpz_set(x, a);
    mpz_set(y, b);

    mpz_abs(y, y);

    mpz_set_ui(ret, 1);

    while (mpz_sgn(y) != 0) {
      if (mpz_odd_p(y))
        mpz_mul(ret, ret, x);
      mpz_fdiv_q_2exp(y, y, 1);
      mpz_mul(x, x, x);
    }

    mpz_clear(x);
    mpz_clear(y);
  } else {
    mpz_set(ret, a);
  }
}

static int
bmpz_powm(mpz_t ret, const mpz_t a, const mpz_t b, const mpz_t c) {
  int r = 1;

  if (mpz_sgn(b) < 0) {
    mpz_t i;
    mpz_init(i);

    r = mpz_invert(i, b, c);

    if (r != 0)
      mpz_powm(ret, a, i, c);

    mpz_clear(i);
  } else {
    mpz_powm(ret, a, b, c);
  }

  return r;
}

static int
bmpz_powm_si(mpz_t ret, const mpz_t a, long b, const mpz_t c) {
  int r = 1;

  if (b < 0) {
    mpz_t i;
    mpz_init(i);
    mpz_set_si(i, b);

    r = mpz_invert(i, i, c);

    if (r != 0)
      mpz_powm(ret, a, i, c);

    mpz_clear(i);
  } else {
    mpz_powm_ui(ret, a, b, c);
  }

  return r;
}

static int
bmpz_finvm(mpz_t ret, const mpz_t a, const mpz_t b) {
  int r = 0;
  mpz_t e;

  mpz_init(e);
  mpz_sub_ui(e, b, 2);

  // Invert using fermat's little theorem.
  if (!bmpz_powm(ret, a, e, b))
    goto fail;

  r = 1;
fail:
  mpz_clear(e);
  return r;
}

static void
bmpz_and_si(mpz_t ret, const mpz_t a, long b) {
  mpz_t x;
  mpz_init(x);
  mpz_set_si(x, b);
  mpz_and(ret, a, x);
  mpz_clear(x);
}

static void
bmpz_ior_si(mpz_t ret, const mpz_t a, long b) {
  mpz_t x;
  mpz_init(x);
  mpz_set_si(x, b);
  mpz_ior(ret, a, x);
  mpz_clear(x);
}

static void
bmpz_xor_si(mpz_t ret, const mpz_t a, long b) {
  mpz_t x;
  mpz_init(x);
  mpz_set_si(x, b);
  mpz_xor(ret, a, x);
  mpz_clear(x);
}

static void
bmpz_not(mpz_t ret, const mpz_t a, unsigned long width) {
  mpz_t mask;
  mpz_init(mask);
  mpz_set_ui(mask, 1);
  mpz_mul_2exp(mask, mask, width);
  mpz_sub_ui(mask, mask, 1);
  mpz_xor(ret, a, mask);
  mpz_clear(mask);
}

static void
bmpz_mask(mpz_t ret, const mpz_t a, unsigned long bit) {
  mpz_t mask;
  mpz_init(mask);
  mpz_set_ui(mask, 1);
  mpz_mul_2exp(mask, mask, bit);
  mpz_sub_ui(mask, mask, 1);
  mpz_and(ret, a, mask);
  mpz_clear(mask);
}

static void
bmpz_binc(mpz_t ret, const mpz_t a, unsigned long bit) {
  mpz_t saved;
  mpz_init(saved);
  bmpz_mask(saved, a, bit);
  mpz_fdiv_q_2exp(ret, a, bit);
  mpz_add_ui(ret, ret, 1);
  mpz_mul_2exp(ret, ret, bit);
  mpz_ior(ret, ret, saved);
  mpz_clear(saved);
}

static void
bmpz_to_twos(mpz_t ret, const mpz_t a, unsigned long width) {
  mpz_set(ret, a);

  if (mpz_sgn(ret) < 0) {
    mpz_neg(ret, ret);
    bmpz_not(ret, ret, width);
    mpz_add_ui(ret, ret, 1);
  }
}

static void
bmpz_from_twos(mpz_t ret, const mpz_t a, unsigned long width) {
  mpz_set(ret, a);

  if (mpz_tstbit(ret, width - 1)) {
    bmpz_not(ret, ret, width);
    mpz_add_ui(ret, ret, 1);
    mpz_neg(ret, ret);
  }
}

static int
bmpz_random_bits(mpz_t ret, unsigned long bits) {
  unsigned long total = 0;
  uint8_t out[32];
  int r = 0;
  mpz_t tmp;

  mpz_init(tmp);

  mpz_set_ui(ret, 0);

  while (total < bits) {
    if (!bcrypto_random(&out[0], 32))
      goto fail;

    mpz_import(tmp, 32, 1, 1, 0, 0, &out[0]);
    mpz_mul_2exp(ret, ret, 256);
    mpz_ior(ret, ret, tmp);
    total += 256;
  }

  if (total > bits)
    mpz_fdiv_q_2exp(ret, ret, total - bits);

  r = 1;
fail:
  mpz_clear(tmp);
  return r;
}

static int
bmpz_rng_default(mpz_t ret, unsigned long bits, void *data) {
  return bmpz_random_bits(ret, bits);
}

static int
bmpz_random_int(mpz_t ret,
                const mpz_t min, const mpz_t max,
                bmpz_rng_t rng, void *data) {
  if (mpz_cmp(min, max) > 0)
    return 0;

  int r = 0;

  mpz_t space;
  mpz_init(space);
  mpz_sub(space, max, min);
  mpz_abs(space, space);

  unsigned long bits = bmpz_bitlen(space);

  if (bits == 0) {
    mpz_set_ui(ret, 0);
    goto success;
  }

  for (;;) {
    if (!rng(ret, bits, data))
      goto fail;

    if (mpz_cmp(ret, space) < 0)
      break;
  }

success:
  mpz_add(ret, ret, min);
  r = 1;
fail:
  mpz_clear(space);
  return r;
}

static void
bmpz_div_round(mpz_t ret, const mpz_t x, const mpz_t y) {
  mpz_t q, r, h;
  mpz_init(q);
  mpz_init(r);
  mpz_init(h);

  // [q, r] = divmod(x, y)
  mpz_tdiv_qr(q, r, x, y);

  // if r == 0
  if (mpz_sgn(r) == 0) {
    // ret = q
    mpz_set(ret, q);
    goto done;
  }

  // if q < 0
  if (mpz_sgn(q) < 0) {
    // r = r - y
    mpz_sub(r, r, y);
  }

  // h = y >> 1
  mpz_fdiv_q_2exp(h, y, 1);

  // Round down.
  // if r < h
  if (mpz_cmp(r, h) < 0) {
    // ret = q
    mpz_set(ret, q);
    goto done;
  }

  // if (y & 1) && r == h
  if (mpz_odd_p(y) && mpz_cmp(r, h) == 0) {
    mpz_set(ret, q);
    goto done;
  }

  // Round up.
  // if q < 0
  if (mpz_sgn(q) < 0) {
    // q = q - 1
    mpz_sub_ui(q, q, 1);
  } else {
    // q = q + 1
    mpz_add_ui(q, q, 1);
  }

  // ret = q
  mpz_set(ret, q);

done:
  mpz_clear(q);
  mpz_clear(r);
  mpz_clear(h);
}

#if !defined(BCRYPTO_HAS_GMP)
// https://github.com/golang/go/blob/aadaec5/src/math/big/int.go#L754
static int
bmpz_jacobi(const mpz_t x, const mpz_t y) {
  // Undefined behavior.
  // if y == 0 || y & 1 == 0
  if (mpz_sgn(y) == 0 || mpz_even_p(y))
    return 0;

  mpz_t a;
  mpz_t b;
  mpz_t c;
  int j;

  mpz_init(a);
  mpz_init(b);
  mpz_init(c);
  j = 0;

  // a = x
  mpz_set(a, x);
  // b = y
  mpz_set(b, y);
  j = 1;

  // if b < 0
  if (mpz_sgn(b) < 0) {
    // if a < 0
    if (mpz_sgn(a) < 0)
      j = -1;
    // b = -b
    mpz_neg(b, b);
  }

  for (;;) {
    // if b == 1
    if (mpz_cmp_ui(b, 1) == 0)
      break;

    // if a == 0
    if (mpz_sgn(a) == 0) {
      j = 0;
      break;
    }

    // a = a mod b
    mpz_mod(a, a, b);

    // if a == 0
    if (mpz_sgn(a) == 0) {
      j = 0;
      break;
    }

    // s = zerbits(a)
    unsigned long s = bmpz_zerobits(a);

    if (s & 1) {
      // bmod8 = b & 7
      unsigned long bmod8 = mpz_tdiv_ui(b, 8);

      if (bmod8 == 3 || bmod8 == 5)
        j = -j;
    }

    // c = a >> s
    mpz_fdiv_q_2exp(c, a, s);

    // if b & 3 == 3 and c & 3 == 3
    if (mpz_tdiv_ui(b, 4) == 3 && mpz_tdiv_ui(c, 4) == 3)
      j = -j;

    // a = b
    mpz_set(a, b);
    // b = c
    mpz_set(b, c);
  }

  mpz_clear(a);
  mpz_clear(b);
  mpz_clear(c);

  return j;
}
#else
#define bmpz_jacobi mpz_jacobi
#endif

// https://github.com/golang/go/blob/aadaec5/src/math/big/prime.go#L81
// https://github.com/indutny/miller-rabin/blob/master/lib/mr.js
static int
bmpz_prime_mr(
  const mpz_t n,
  unsigned long reps,
  int force2,
  bmpz_rng_t rng,
  void *data
) {
  // if n < 7
  if (mpz_cmp_ui(n, 7) < 0) {
    // if n == 2 or n == 3 or n == 5
    if (mpz_cmp_ui(n, 2) == 0
        || mpz_cmp_ui(n, 3) == 0
        || mpz_cmp_ui(n, 5) == 0) {
      return 1;
    }
    return 0;
  }

  if (mpz_even_p(n))
    return 0;

  int r = 0;
  mpz_t zero, nm1, nm3, q, x, y;
  unsigned long k;

  mpz_init(zero);
  mpz_init(nm1);
  mpz_init(nm3);
  mpz_init(q);
  mpz_init(x);
  mpz_init(y);

  // zero = 0
  mpz_set_ui(zero, 0);

  // nm1 = n - 1
  mpz_sub_ui(nm1, n, 1);

  // nm3 = nm1 - 2
  mpz_sub_ui(nm3, nm1, 2);

  // k = zero_bits(nm1)
  k = bmpz_zerobits(nm1);
  // q = nm1 >> k
  mpz_fdiv_q_2exp(q, nm1, k);

  for (unsigned long i = 0; i < reps; i++) {
    if (i == reps - 1 && force2) {
      // x = 2
      mpz_set_ui(x, 2);
    } else {
      // x = getrandint(nm3)
      if (!bmpz_random_int(x, zero, nm3, rng, data)) {
        r = -1;
        goto fail;
      }
      // x += 2
      mpz_add_ui(x, x, 2);
    }

    // y = x^q mod n
    mpz_powm(y, x, q, n);

    // if y == 1 || y == nm1
    if (mpz_cmp_ui(y, 1) == 0 || mpz_cmp(y, nm1) == 0)
      continue;

    for (unsigned long j = 1; j < k; j++) {
      // y = y^2 mod n
      mpz_powm_ui(y, y, 2, n);

      // if y == nm1
      if (mpz_cmp(y, nm1) == 0)
        goto next;

      // if y == 1
      if (mpz_cmp_ui(y, 1) == 0)
        goto fail;
    }

    goto fail;
next:
    ;
  }

  r = 1;
fail:
  mpz_clear(zero);
  mpz_clear(nm1);
  mpz_clear(nm3);
  mpz_clear(q);
  mpz_clear(x);
  mpz_clear(y);
  return r;
}

// https://github.com/golang/go/blob/aadaec5/src/math/big/prime.go#L150
static int
bmpz_prime_lucas(const mpz_t n, unsigned long limit) {
  int r = 0;
  unsigned long p;
  unsigned long zb;
  mpz_t d;
  mpz_t s, nm2;
  mpz_t vk, vk1;
  mpz_t t1, t2, t3;

  mpz_init(d);
  mpz_init(s);
  mpz_init(nm2);
  mpz_init(vk);
  mpz_init(vk1);
  mpz_init(t1);
  mpz_init(t2);
  mpz_init(t3);

  // Ignore 0 and 1.
  // if n <= 1
  if (mpz_cmp_ui(n, 1) <= 0)
    goto fail;

  // Two is the only even prime.
  // if n & 1 == 0
  if (mpz_even_p(n)) {
    // if n == 2
    if (mpz_cmp_ui(n, 2) == 0)
      goto succeed;
    goto fail;
  }

  // Baillie-OEIS "method C" for choosing D, P, Q.
  // See: https://oeis.org/A217719/a217719.txt.
  // p = 3
  p = 3;
  // d = 1
  mpz_set_ui(d, 1);

  for (;;) {
    if (p > 10000) {
      // Thought to be impossible.
      goto fail;
    }

    if (limit > 0 && p > limit) {
      // It's thought to be impossible for `p`
      // to be larger than 10,000, but fail
      // on anything higher than a limit to
      // prevent DoS attacks. `p` never seems
      // to be higher than 30 in practice.
      goto fail;
    }

    // d = p * p - 4
    mpz_set_ui(d, p * p - 4);

    int j = bmpz_jacobi(d, n);

    if (j == -1)
      break;

    if (j == 0) {
      // if n == p + 2
      if (mpz_cmp_ui(n, p + 2) == 0)
        goto succeed;
      goto fail;
    }

    if (p == 40) {
      // if is_square(n)
      if (mpz_perfect_square_p(n))
        goto fail;
    }

    p += 1;
  }

  // Check for Grantham definition of
  // "extra strong Lucas pseudoprime".
  // s = n + 1
  mpz_add_ui(s, n, 1);

  // zb = zerobits(s)
  zb = bmpz_zerobits(s);

  // nm2 = n - 2
  mpz_sub_ui(nm2, n, 2);

  // s >>= zb
  mpz_fdiv_q_2exp(s, s, zb);

  // vk = 2
  mpz_set_ui(vk, 2);
  // vk1 = p
  mpz_set_ui(vk1, p);

  for (long i = (long)bmpz_bitlen(s); i >= 0; i--) {
    if (mpz_tstbit(s, i)) {
      // t1 = vk * vk1
      mpz_mul(t1, vk, vk1);
      // t1 += n
      mpz_add(t1, t1, n);
      // t1 -= p
      mpz_sub_ui(t1, t1, p);
      // vk = t1 mod n
      mpz_mod(vk, t1, n);
      // t1 = vk1 * vk1
      mpz_mul(t1, vk1, vk1);
      // t1 += nm2
      mpz_add(t1, t1, nm2);
      // vk1 = t1 mod n
      mpz_mod(vk1, t1, n);
    } else {
      // t1 = vk * vk1
      mpz_mul(t1, vk, vk1);
      // t1 += n
      mpz_add(t1, t1, n);
      // t1 -= p
      mpz_sub_ui(t1, t1, p);
      // vk1 = t1 mod n
      mpz_mod(vk1, t1, n);
      // t1 = vk * vk
      mpz_mul(t1, vk, vk);
      // t1 += nm2
      mpz_add(t1, t1, nm2);
      // vk = t1 mod n
      mpz_mod(vk, t1, n);
    }
  }

  // if vk == 2 or vk == nm2
  if (mpz_cmp_ui(vk, 2) == 0 || mpz_cmp(vk, nm2) == 0) {
    // t1 = vk * p
    mpz_mul_ui(t1, vk, p);
    // t2 = vk1 << 1
    mpz_mul_2exp(t2, vk1, 1);

    // if t1 < t2
    if (mpz_cmp(t1, t2) < 0) {
      // [t1, t2] = [t2, t1]
      mpz_swap(t1, t2);
    }

    // t1 -= t2
    mpz_sub(t1, t1, t2);

    // t3 = t1 mod n
    mpz_mod(t3, t1, n);

    // if t3 == 0
    if (mpz_sgn(t3) == 0)
      goto succeed;
  }

  for (long t = 0; t < (long)zb - 1; t++) {
    // if vk == 0
    if (mpz_sgn(vk) == 0)
      goto succeed;

    // if vk == 2
    if (mpz_cmp_ui(vk, 2) == 0)
      goto fail;

    // t1 = vk * vk
    mpz_mul(t1, vk, vk);
    // t1 -= 2
    mpz_sub_ui(t1, t1, 2);
    // vk = t1 mod n
    mpz_mod(vk, t1, n);
  }

  goto fail;

succeed:
  r = 1;
fail:
  mpz_clear(d);
  mpz_clear(s);
  mpz_clear(nm2);
  mpz_clear(vk);
  mpz_clear(vk1);
  mpz_clear(t1);
  mpz_clear(t2);
  mpz_clear(t3);
  return r;
}

// https://github.com/golang/go/blob/c86d464/src/math/big/int.go#L906
static int
bmpz_sqrtp(mpz_t ret, const mpz_t num, const mpz_t p) {
  int r = 0;
  unsigned long z, k;
  mpz_t x, e, t, a, s, n, y, b, g;

  mpz_init(x);
  mpz_init(e);
  mpz_init(t);
  mpz_init(a);
  mpz_init(s);
  mpz_init(n);
  mpz_init(y);
  mpz_init(b);
  mpz_init(g);

  // x = num
  mpz_set(x, num);

  if (mpz_sgn(p) <= 0 || mpz_even_p(p))
    goto fail;

  switch (bmpz_jacobi(x, p)) {
    case -1:
      goto fail;
    case 0:
      mpz_set_ui(ret, 0);
      goto success;
    case 1:
      break;
  }

  // if x < 0 || x >= p
  if (mpz_sgn(x) < 0 || mpz_cmp(x, p) >= 0) {
    // x = x mod p
    mpz_mod(x, x, p);
  }

  // if p mod 4 == 3
  if (mpz_tdiv_ui(p, 4) == 3) {
    // e = (p + 1) >> 2
    mpz_add_ui(e, p, 1);
    mpz_fdiv_q_2exp(e, e, 2);
    // ret = x^e mod p
    mpz_powm(ret, x, e, p);
    goto success;
  }

  // if p mod 8 == 5
  if (mpz_tdiv_ui(p, 8) == 5) {
    // e = p >> 3
    mpz_fdiv_q_2exp(e, p, 3);
    // t = x << 1
    mpz_mul_2exp(t, x, 1);
    // a = t^e mod p
    mpz_powm(a, t, e, p);
    // b = a^2 mod p
    mpz_powm_ui(b, a, 2, p);
    // b = (b * t) mod p
    mpz_mul(b, b, t);
    mpz_mod(b, b, p);
    // b = (b - 1) mod p
    mpz_sub_ui(b, b, 1);
    mpz_mod(b, b, p);
    // b = (b * x) mod p
    mpz_mul(b, b, x);
    mpz_mod(b, b, p);
    // b = (b * a) mod p
    mpz_mul(b, b, a);
    mpz_mod(b, b, p);
    // ret = b
    mpz_set(ret, b);
    goto success;
  }

  // s = p - 1
  mpz_sub_ui(s, p, 1);

  // z = zerobits(s)
  z = bmpz_zerobits(s);

  // s = s >> z
  mpz_fdiv_q_2exp(s, s, z);

  // n = 2
  mpz_set_ui(n, 2);

  // while jacobi(n, p) != -1
  while (bmpz_jacobi(n, p) != -1) {
    // n = n + 1
    mpz_add_ui(n, n, 1);
  }

  // y = s + 1
  mpz_add_ui(y, s, 1);
  // y = y >> 1
  mpz_fdiv_q_2exp(y, y, 1);
  // y = x^y mod p
  mpz_powm(y, x, y, p);
  // b = x^s mod p
  mpz_powm(b, x, s, p);
  // g = n^s mod p
  mpz_powm(g, n, s, p);

  // k = z
  k = z;

  for (;;) {
    unsigned long m = 0;

    // t = b
    mpz_set(t, b);

    // while t != 1
    while (mpz_cmp_ui(t, 1) != 0) {
      // t = t^2 mod p
      mpz_powm_ui(t, t, 2, p);
      m += 1;
    }

    // if m == 0
    if (m == 0)
      break;

    // if m == k
    if (m == k)
      goto fail;

    // t = 1 << (k - m - 1)
    mpz_set_ui(t, 1);
    mpz_mul_2exp(t, t, k - m - 1);
    // t = g^t mod p
    mpz_powm(t, g, t, p);
    // g = t^2 mod p
    mpz_powm_ui(g, t, 2, p);
    // y = (y * t) mod p
    mpz_mul(y, y, t);
    mpz_mod(y, y, p);
    // b = (b * g) mod p
    mpz_mul(b, b, g);
    mpz_mod(b, b, p);
    // k = m
    k = m;
  }

  // ret = y
  mpz_set(ret, y);
  goto success;

success:
  r = 1;
fail:
  mpz_clear(x);
  mpz_clear(e);
  mpz_clear(t);
  mpz_clear(a);
  mpz_clear(s);
  mpz_clear(n);
  mpz_clear(y);
  mpz_clear(b);
  mpz_clear(g);
  return r;
}

static int
bmpz_sqrtpq(mpz_t ret, const mpz_t x, const mpz_t p, const mpz_t q) {
  int r = 0;
  mpz_t sp, sq, mp, mq, xx, yy;

  mpz_init(sp);
  mpz_init(sq);
  mpz_init(mp);
  mpz_init(mq);
  mpz_init(xx);
  mpz_init(yy);

  // sp = sqrtp(x, p)
  // sq = sqrtp(x, q)
  if (!bmpz_sqrtp(sp, x, p)
      || !bmpz_sqrtp(sq, x, q)) {
    goto fail;
  }

  // [mp, mq] = egcd(p, q)
  mpz_gcdext(ret, mp, mq, p, q);

  // xx = sq * mp * p
  mpz_mul(xx, sq, mp);
  mpz_mul(xx, xx, p);

  // yy = sp * mq * q
  mpz_mul(yy, sp, mq);
  mpz_mul(yy, yy, q);

  // xx = xx + yy
  mpz_add(xx, xx, yy);

  // yy = p * q
  mpz_mul(yy, p, q);

  // ret = xx mod yy
  mpz_mod(ret, xx, yy);

  r = 1;
fail:
  mpz_clear(sp);
  mpz_clear(sq);
  mpz_clear(mp);
  mpz_clear(mq);
  mpz_clear(xx);
  mpz_clear(yy);
  return r;
}
