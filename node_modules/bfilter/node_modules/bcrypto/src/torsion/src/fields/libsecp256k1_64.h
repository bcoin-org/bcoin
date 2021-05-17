/*!
 * libsecp256k1_64.h - optional libsecp256k1 backend
 *
 * From bitcoin-core/secp256k1:
 *   Copyright (c) 2013, Pieter Wuille
 *   Copyright (c) 2013-2014 Diederik Huys, Pieter Wuille
 *   https://github.com/bitcoin-core/secp256k1
 *
 * Modified to look like a fiat backend (note: this is NOT a fiat backend).
 */

#include <stdint.h>

typedef unsigned char fiat_secp256k1_uint1;
FIAT_EXTENSION typedef unsigned __int128 fiat_secp256k1_uint128;

#if (-1 & 3) != 3
#error "This code only works on a two's complement system"
#endif

static void fiat_secp256k1_carry_mul(uint64_t r[5], const uint64_t a[5], const uint64_t b[5]) {
#ifdef TORSION_USE_ASM
  /**
   * Registers: rdx:rax = multiplication accumulator
   *      r9:r8   = c
   *      r15:rcx = d
   *      r10-r14 = a0-a4
   *      rbx   = b
   *      rdi   = r
   *      rsi   = a / t?
   */
  uint64_t tmp1, tmp2, tmp3;

  __asm__ __volatile__(
    "movq 0(%%rsi),%%r10\n"
    "movq 8(%%rsi),%%r11\n"
    "movq 16(%%rsi),%%r12\n"
    "movq 24(%%rsi),%%r13\n"
    "movq 32(%%rsi),%%r14\n"

    /* d += a3 * b0 */
    "movq 0(%%rbx),%%rax\n"
    "mulq %%r13\n"
    "movq %%rax,%%rcx\n"
    "movq %%rdx,%%r15\n"
    /* d += a2 * b1 */
    "movq 8(%%rbx),%%rax\n"
    "mulq %%r12\n"
    "addq %%rax,%%rcx\n"
    "adcq %%rdx,%%r15\n"
    /* d += a1 * b2 */
    "movq 16(%%rbx),%%rax\n"
    "mulq %%r11\n"
    "addq %%rax,%%rcx\n"
    "adcq %%rdx,%%r15\n"
    /* d = a0 * b3 */
    "movq 24(%%rbx),%%rax\n"
    "mulq %%r10\n"
    "addq %%rax,%%rcx\n"
    "adcq %%rdx,%%r15\n"
    /* c = a4 * b4 */
    "movq 32(%%rbx),%%rax\n"
    "mulq %%r14\n"
    "movq %%rax,%%r8\n"
    "movq %%rdx,%%r9\n"
    /* d += (c & M) * R */
    "movq $0xfffffffffffff,%%rdx\n"
    "andq %%rdx,%%rax\n"
    "movq $0x1000003d10,%%rdx\n"
    "mulq %%rdx\n"
    "addq %%rax,%%rcx\n"
    "adcq %%rdx,%%r15\n"
    /* c >>= 52 (%%r8 only) */
    "shrdq $52,%%r9,%%r8\n"
    /* t3 (tmp1) = d & M */
    "movq %%rcx,%%rsi\n"
    "movq $0xfffffffffffff,%%rdx\n"
    "andq %%rdx,%%rsi\n"
    "movq %%rsi,%q1\n"
    /* d >>= 52 */
    "shrdq $52,%%r15,%%rcx\n"
    "xorq %%r15,%%r15\n"
    /* d += a4 * b0 */
    "movq 0(%%rbx),%%rax\n"
    "mulq %%r14\n"
    "addq %%rax,%%rcx\n"
    "adcq %%rdx,%%r15\n"
    /* d += a3 * b1 */
    "movq 8(%%rbx),%%rax\n"
    "mulq %%r13\n"
    "addq %%rax,%%rcx\n"
    "adcq %%rdx,%%r15\n"
    /* d += a2 * b2 */
    "movq 16(%%rbx),%%rax\n"
    "mulq %%r12\n"
    "addq %%rax,%%rcx\n"
    "adcq %%rdx,%%r15\n"
    /* d += a1 * b3 */
    "movq 24(%%rbx),%%rax\n"
    "mulq %%r11\n"
    "addq %%rax,%%rcx\n"
    "adcq %%rdx,%%r15\n"
    /* d += a0 * b4 */
    "movq 32(%%rbx),%%rax\n"
    "mulq %%r10\n"
    "addq %%rax,%%rcx\n"
    "adcq %%rdx,%%r15\n"
    /* d += c * R */
    "movq %%r8,%%rax\n"
    "movq $0x1000003d10,%%rdx\n"
    "mulq %%rdx\n"
    "addq %%rax,%%rcx\n"
    "adcq %%rdx,%%r15\n"
    /* t4 = d & M (%%rsi) */
    "movq %%rcx,%%rsi\n"
    "movq $0xfffffffffffff,%%rdx\n"
    "andq %%rdx,%%rsi\n"
    /* d >>= 52 */
    "shrdq $52,%%r15,%%rcx\n"
    "xorq %%r15,%%r15\n"
    /* tx = t4 >> 48 (tmp3) */
    "movq %%rsi,%%rax\n"
    "shrq $48,%%rax\n"
    "movq %%rax,%q3\n"
    /* t4 &= (M >> 4) (tmp2) */
    "movq $0xffffffffffff,%%rax\n"
    "andq %%rax,%%rsi\n"
    "movq %%rsi,%q2\n"
    /* c = a0 * b0 */
    "movq 0(%%rbx),%%rax\n"
    "mulq %%r10\n"
    "movq %%rax,%%r8\n"
    "movq %%rdx,%%r9\n"
    /* d += a4 * b1 */
    "movq 8(%%rbx),%%rax\n"
    "mulq %%r14\n"
    "addq %%rax,%%rcx\n"
    "adcq %%rdx,%%r15\n"
    /* d += a3 * b2 */
    "movq 16(%%rbx),%%rax\n"
    "mulq %%r13\n"
    "addq %%rax,%%rcx\n"
    "adcq %%rdx,%%r15\n"
    /* d += a2 * b3 */
    "movq 24(%%rbx),%%rax\n"
    "mulq %%r12\n"
    "addq %%rax,%%rcx\n"
    "adcq %%rdx,%%r15\n"
    /* d += a1 * b4 */
    "movq 32(%%rbx),%%rax\n"
    "mulq %%r11\n"
    "addq %%rax,%%rcx\n"
    "adcq %%rdx,%%r15\n"
    /* u0 = d & M (%%rsi) */
    "movq %%rcx,%%rsi\n"
    "movq $0xfffffffffffff,%%rdx\n"
    "andq %%rdx,%%rsi\n"
    /* d >>= 52 */
    "shrdq $52,%%r15,%%rcx\n"
    "xorq %%r15,%%r15\n"
    /* u0 = (u0 << 4) | tx (%%rsi) */
    "shlq $4,%%rsi\n"
    "movq %q3,%%rax\n"
    "orq %%rax,%%rsi\n"
    /* c += u0 * (R >> 4) */
    "movq $0x1000003d1,%%rax\n"
    "mulq %%rsi\n"
    "addq %%rax,%%r8\n"
    "adcq %%rdx,%%r9\n"
    /* r[0] = c & M */
    "movq %%r8,%%rax\n"
    "movq $0xfffffffffffff,%%rdx\n"
    "andq %%rdx,%%rax\n"
    "movq %%rax,0(%%rdi)\n"
    /* c >>= 52 */
    "shrdq $52,%%r9,%%r8\n"
    "xorq %%r9,%%r9\n"
    /* c += a1 * b0 */
    "movq 0(%%rbx),%%rax\n"
    "mulq %%r11\n"
    "addq %%rax,%%r8\n"
    "adcq %%rdx,%%r9\n"
    /* c += a0 * b1 */
    "movq 8(%%rbx),%%rax\n"
    "mulq %%r10\n"
    "addq %%rax,%%r8\n"
    "adcq %%rdx,%%r9\n"
    /* d += a4 * b2 */
    "movq 16(%%rbx),%%rax\n"
    "mulq %%r14\n"
    "addq %%rax,%%rcx\n"
    "adcq %%rdx,%%r15\n"
    /* d += a3 * b3 */
    "movq 24(%%rbx),%%rax\n"
    "mulq %%r13\n"
    "addq %%rax,%%rcx\n"
    "adcq %%rdx,%%r15\n"
    /* d += a2 * b4 */
    "movq 32(%%rbx),%%rax\n"
    "mulq %%r12\n"
    "addq %%rax,%%rcx\n"
    "adcq %%rdx,%%r15\n"
    /* c += (d & M) * R */
    "movq %%rcx,%%rax\n"
    "movq $0xfffffffffffff,%%rdx\n"
    "andq %%rdx,%%rax\n"
    "movq $0x1000003d10,%%rdx\n"
    "mulq %%rdx\n"
    "addq %%rax,%%r8\n"
    "adcq %%rdx,%%r9\n"
    /* d >>= 52 */
    "shrdq $52,%%r15,%%rcx\n"
    "xorq %%r15,%%r15\n"
    /* r[1] = c & M */
    "movq %%r8,%%rax\n"
    "movq $0xfffffffffffff,%%rdx\n"
    "andq %%rdx,%%rax\n"
    "movq %%rax,8(%%rdi)\n"
    /* c >>= 52 */
    "shrdq $52,%%r9,%%r8\n"
    "xorq %%r9,%%r9\n"
    /* c += a2 * b0 */
    "movq 0(%%rbx),%%rax\n"
    "mulq %%r12\n"
    "addq %%rax,%%r8\n"
    "adcq %%rdx,%%r9\n"
    /* c += a1 * b1 */
    "movq 8(%%rbx),%%rax\n"
    "mulq %%r11\n"
    "addq %%rax,%%r8\n"
    "adcq %%rdx,%%r9\n"
    /* c += a0 * b2 (last use of %%r10 = a0) */
    "movq 16(%%rbx),%%rax\n"
    "mulq %%r10\n"
    "addq %%rax,%%r8\n"
    "adcq %%rdx,%%r9\n"
    /* fetch t3 (%%r10, overwrites a0), t4 (%%rsi) */
    "movq %q2,%%rsi\n"
    "movq %q1,%%r10\n"
    /* d += a4 * b3 */
    "movq 24(%%rbx),%%rax\n"
    "mulq %%r14\n"
    "addq %%rax,%%rcx\n"
    "adcq %%rdx,%%r15\n"
    /* d += a3 * b4 */
    "movq 32(%%rbx),%%rax\n"
    "mulq %%r13\n"
    "addq %%rax,%%rcx\n"
    "adcq %%rdx,%%r15\n"
    /* c += (d & M) * R */
    "movq %%rcx,%%rax\n"
    "movq $0xfffffffffffff,%%rdx\n"
    "andq %%rdx,%%rax\n"
    "movq $0x1000003d10,%%rdx\n"
    "mulq %%rdx\n"
    "addq %%rax,%%r8\n"
    "adcq %%rdx,%%r9\n"
    /* d >>= 52 (%%rcx only) */
    "shrdq $52,%%r15,%%rcx\n"
    /* r[2] = c & M */
    "movq %%r8,%%rax\n"
    "movq $0xfffffffffffff,%%rdx\n"
    "andq %%rdx,%%rax\n"
    "movq %%rax,16(%%rdi)\n"
    /* c >>= 52 */
    "shrdq $52,%%r9,%%r8\n"
    "xorq %%r9,%%r9\n"
    /* c += t3 */
    "addq %%r10,%%r8\n"
    /* c += d * R */
    "movq %%rcx,%%rax\n"
    "movq $0x1000003d10,%%rdx\n"
    "mulq %%rdx\n"
    "addq %%rax,%%r8\n"
    "adcq %%rdx,%%r9\n"
    /* r[3] = c & M */
    "movq %%r8,%%rax\n"
    "movq $0xfffffffffffff,%%rdx\n"
    "andq %%rdx,%%rax\n"
    "movq %%rax,24(%%rdi)\n"
    /* c >>= 52 (%%r8 only) */
    "shrdq $52,%%r9,%%r8\n"
    /* c += t4 (%%r8 only) */
    "addq %%rsi,%%r8\n"
    /* r[4] = c */
    "movq %%r8,32(%%rdi)\n"
    : "+S"(a), "=m"(tmp1), "=m"(tmp2), "=m"(tmp3)
    : "b"(b), "D"(r)
    : "%rax", "%rcx", "%rdx", "%r8", "%r9", "%r10", "%r11", "%r12", "%r13", "%r14", "%r15", "cc", "memory"
  );
#else
  fiat_secp256k1_uint128 c, d;
  uint64_t t3, t4, tx, u0;
  uint64_t a0 = a[0], a1 = a[1], a2 = a[2], a3 = a[3], a4 = a[4];
  const uint64_t M = 0xFFFFFFFFFFFFFULL, R = 0x1000003D10ULL;

  d  = (fiat_secp256k1_uint128)a0 * b[3]
     + (fiat_secp256k1_uint128)a1 * b[2]
     + (fiat_secp256k1_uint128)a2 * b[1]
     + (fiat_secp256k1_uint128)a3 * b[0];
  c  = (fiat_secp256k1_uint128)a4 * b[4];
  d += (c & M) * R; c >>= 52;
  t3 = d & M; d >>= 52;

  d += (fiat_secp256k1_uint128)a0 * b[4]
     + (fiat_secp256k1_uint128)a1 * b[3]
     + (fiat_secp256k1_uint128)a2 * b[2]
     + (fiat_secp256k1_uint128)a3 * b[1]
     + (fiat_secp256k1_uint128)a4 * b[0];
  d += c * R;
  t4 = d & M; d >>= 52;
  tx = (t4 >> 48); t4 &= (M >> 4);

  c  = (fiat_secp256k1_uint128)a0 * b[0];
  d += (fiat_secp256k1_uint128)a1 * b[4]
     + (fiat_secp256k1_uint128)a2 * b[3]
     + (fiat_secp256k1_uint128)a3 * b[2]
     + (fiat_secp256k1_uint128)a4 * b[1];
  u0 = d & M; d >>= 52;
  u0 = (u0 << 4) | tx;
  c += (fiat_secp256k1_uint128)u0 * (R >> 4);
  r[0] = c & M; c >>= 52;

  c += (fiat_secp256k1_uint128)a0 * b[1]
     + (fiat_secp256k1_uint128)a1 * b[0];
  d += (fiat_secp256k1_uint128)a2 * b[4]
     + (fiat_secp256k1_uint128)a3 * b[3]
     + (fiat_secp256k1_uint128)a4 * b[2];
  c += (d & M) * R; d >>= 52;
  r[1] = c & M; c >>= 52;

  c += (fiat_secp256k1_uint128)a0 * b[2]
     + (fiat_secp256k1_uint128)a1 * b[1]
     + (fiat_secp256k1_uint128)a2 * b[0];
  d += (fiat_secp256k1_uint128)a3 * b[4]
     + (fiat_secp256k1_uint128)a4 * b[3];
  c += (d & M) * R; d >>= 52;

  r[2] = c & M; c >>= 52;
  c   += d * R + t3;
  r[3] = c & M; c >>= 52;
  c   += t4;
  r[4] = c;
#endif
}

static void fiat_secp256k1_carry_square(uint64_t r[5], const uint64_t a[5]) {
#ifdef TORSION_USE_ASM
  /**
   * Registers: rdx:rax = multiplication accumulator
   *      r9:r8   = c
   *      rcx:rbx = d
   *      r10-r14 = a0-a4
   *      r15   = M (0xfffffffffffff)
   *      rdi   = r
   *      rsi   = a / t?
   */
  uint64_t tmp1, tmp2, tmp3;

  __asm__ __volatile__(
    "movq 0(%%rsi),%%r10\n"
    "movq 8(%%rsi),%%r11\n"
    "movq 16(%%rsi),%%r12\n"
    "movq 24(%%rsi),%%r13\n"
    "movq 32(%%rsi),%%r14\n"
    "movq $0xfffffffffffff,%%r15\n"

    /* d = (a0*2) * a3 */
    "leaq (%%r10,%%r10,1),%%rax\n"
    "mulq %%r13\n"
    "movq %%rax,%%rbx\n"
    "movq %%rdx,%%rcx\n"
    /* d += (a1*2) * a2 */
    "leaq (%%r11,%%r11,1),%%rax\n"
    "mulq %%r12\n"
    "addq %%rax,%%rbx\n"
    "adcq %%rdx,%%rcx\n"
    /* c = a4 * a4 */
    "movq %%r14,%%rax\n"
    "mulq %%r14\n"
    "movq %%rax,%%r8\n"
    "movq %%rdx,%%r9\n"
    /* d += (c & M) * R */
    "andq %%r15,%%rax\n"
    "movq $0x1000003d10,%%rdx\n"
    "mulq %%rdx\n"
    "addq %%rax,%%rbx\n"
    "adcq %%rdx,%%rcx\n"
    /* c >>= 52 (%%r8 only) */
    "shrdq $52,%%r9,%%r8\n"
    /* t3 (tmp1) = d & M */
    "movq %%rbx,%%rsi\n"
    "andq %%r15,%%rsi\n"
    "movq %%rsi,%q1\n"
    /* d >>= 52 */
    "shrdq $52,%%rcx,%%rbx\n"
    "xorq %%rcx,%%rcx\n"
    /* a4 *= 2 */
    "addq %%r14,%%r14\n"
    /* d += a0 * a4 */
    "movq %%r10,%%rax\n"
    "mulq %%r14\n"
    "addq %%rax,%%rbx\n"
    "adcq %%rdx,%%rcx\n"
    /* d+= (a1*2) * a3 */
    "leaq (%%r11,%%r11,1),%%rax\n"
    "mulq %%r13\n"
    "addq %%rax,%%rbx\n"
    "adcq %%rdx,%%rcx\n"
    /* d += a2 * a2 */
    "movq %%r12,%%rax\n"
    "mulq %%r12\n"
    "addq %%rax,%%rbx\n"
    "adcq %%rdx,%%rcx\n"
    /* d += c * R */
    "movq %%r8,%%rax\n"
    "movq $0x1000003d10,%%rdx\n"
    "mulq %%rdx\n"
    "addq %%rax,%%rbx\n"
    "adcq %%rdx,%%rcx\n"
    /* t4 = d & M (%%rsi) */
    "movq %%rbx,%%rsi\n"
    "andq %%r15,%%rsi\n"
    /* d >>= 52 */
    "shrdq $52,%%rcx,%%rbx\n"
    "xorq %%rcx,%%rcx\n"
    /* tx = t4 >> 48 (tmp3) */
    "movq %%rsi,%%rax\n"
    "shrq $48,%%rax\n"
    "movq %%rax,%q3\n"
    /* t4 &= (M >> 4) (tmp2) */
    "movq $0xffffffffffff,%%rax\n"
    "andq %%rax,%%rsi\n"
    "movq %%rsi,%q2\n"
    /* c = a0 * a0 */
    "movq %%r10,%%rax\n"
    "mulq %%r10\n"
    "movq %%rax,%%r8\n"
    "movq %%rdx,%%r9\n"
    /* d += a1 * a4 */
    "movq %%r11,%%rax\n"
    "mulq %%r14\n"
    "addq %%rax,%%rbx\n"
    "adcq %%rdx,%%rcx\n"
    /* d += (a2*2) * a3 */
    "leaq (%%r12,%%r12,1),%%rax\n"
    "mulq %%r13\n"
    "addq %%rax,%%rbx\n"
    "adcq %%rdx,%%rcx\n"
    /* u0 = d & M (%%rsi) */
    "movq %%rbx,%%rsi\n"
    "andq %%r15,%%rsi\n"
    /* d >>= 52 */
    "shrdq $52,%%rcx,%%rbx\n"
    "xorq %%rcx,%%rcx\n"
    /* u0 = (u0 << 4) | tx (%%rsi) */
    "shlq $4,%%rsi\n"
    "movq %q3,%%rax\n"
    "orq %%rax,%%rsi\n"
    /* c += u0 * (R >> 4) */
    "movq $0x1000003d1,%%rax\n"
    "mulq %%rsi\n"
    "addq %%rax,%%r8\n"
    "adcq %%rdx,%%r9\n"
    /* r[0] = c & M */
    "movq %%r8,%%rax\n"
    "andq %%r15,%%rax\n"
    "movq %%rax,0(%%rdi)\n"
    /* c >>= 52 */
    "shrdq $52,%%r9,%%r8\n"
    "xorq %%r9,%%r9\n"
    /* a0 *= 2 */
    "addq %%r10,%%r10\n"
    /* c += a0 * a1 */
    "movq %%r10,%%rax\n"
    "mulq %%r11\n"
    "addq %%rax,%%r8\n"
    "adcq %%rdx,%%r9\n"
    /* d += a2 * a4 */
    "movq %%r12,%%rax\n"
    "mulq %%r14\n"
    "addq %%rax,%%rbx\n"
    "adcq %%rdx,%%rcx\n"
    /* d += a3 * a3 */
    "movq %%r13,%%rax\n"
    "mulq %%r13\n"
    "addq %%rax,%%rbx\n"
    "adcq %%rdx,%%rcx\n"
    /* c += (d & M) * R */
    "movq %%rbx,%%rax\n"
    "andq %%r15,%%rax\n"
    "movq $0x1000003d10,%%rdx\n"
    "mulq %%rdx\n"
    "addq %%rax,%%r8\n"
    "adcq %%rdx,%%r9\n"
    /* d >>= 52 */
    "shrdq $52,%%rcx,%%rbx\n"
    "xorq %%rcx,%%rcx\n"
    /* r[1] = c & M */
    "movq %%r8,%%rax\n"
    "andq %%r15,%%rax\n"
    "movq %%rax,8(%%rdi)\n"
    /* c >>= 52 */
    "shrdq $52,%%r9,%%r8\n"
    "xorq %%r9,%%r9\n"
    /* c += a0 * a2 (last use of %%r10) */
    "movq %%r10,%%rax\n"
    "mulq %%r12\n"
    "addq %%rax,%%r8\n"
    "adcq %%rdx,%%r9\n"
    /* fetch t3 (%%r10, overwrites a0),t4 (%%rsi) */
    "movq %q2,%%rsi\n"
    "movq %q1,%%r10\n"
    /* c += a1 * a1 */
    "movq %%r11,%%rax\n"
    "mulq %%r11\n"
    "addq %%rax,%%r8\n"
    "adcq %%rdx,%%r9\n"
    /* d += a3 * a4 */
    "movq %%r13,%%rax\n"
    "mulq %%r14\n"
    "addq %%rax,%%rbx\n"
    "adcq %%rdx,%%rcx\n"
    /* c += (d & M) * R */
    "movq %%rbx,%%rax\n"
    "andq %%r15,%%rax\n"
    "movq $0x1000003d10,%%rdx\n"
    "mulq %%rdx\n"
    "addq %%rax,%%r8\n"
    "adcq %%rdx,%%r9\n"
    /* d >>= 52 (%%rbx only) */
    "shrdq $52,%%rcx,%%rbx\n"
    /* r[2] = c & M */
    "movq %%r8,%%rax\n"
    "andq %%r15,%%rax\n"
    "movq %%rax,16(%%rdi)\n"
    /* c >>= 52 */
    "shrdq $52,%%r9,%%r8\n"
    "xorq %%r9,%%r9\n"
    /* c += t3 */
    "addq %%r10,%%r8\n"
    /* c += d * R */
    "movq %%rbx,%%rax\n"
    "movq $0x1000003d10,%%rdx\n"
    "mulq %%rdx\n"
    "addq %%rax,%%r8\n"
    "adcq %%rdx,%%r9\n"
    /* r[3] = c & M */
    "movq %%r8,%%rax\n"
    "andq %%r15,%%rax\n"
    "movq %%rax,24(%%rdi)\n"
    /* c >>= 52 (%%r8 only) */
    "shrdq $52,%%r9,%%r8\n"
    /* c += t4 (%%r8 only) */
    "addq %%rsi,%%r8\n"
    /* r[4] = c */
    "movq %%r8,32(%%rdi)\n"
    : "+S"(a), "=m"(tmp1), "=m"(tmp2), "=m"(tmp3)
    : "D"(r)
    : "%rax", "%rbx", "%rcx", "%rdx", "%r8", "%r9", "%r10", "%r11", "%r12", "%r13", "%r14", "%r15", "cc", "memory"
  );
#else
  fiat_secp256k1_uint128 c, d;
  uint64_t a0 = a[0], a1 = a[1], a2 = a[2], a3 = a[3], a4 = a[4];
  int64_t t3, t4, tx, u0;
  const uint64_t M = 0xFFFFFFFFFFFFFULL, R = 0x1000003D10ULL;

  d  = (fiat_secp256k1_uint128)(a0*2) * a3
     + (fiat_secp256k1_uint128)(a1*2) * a2;
  c  = (fiat_secp256k1_uint128)a4 * a4;
  d += (c & M) * R; c >>= 52;
  t3 = d & M; d >>= 52;

  a4 *= 2;
  d += (fiat_secp256k1_uint128)a0 * a4
     + (fiat_secp256k1_uint128)(a1*2) * a3
     + (fiat_secp256k1_uint128)a2 * a2;
  d += c * R;
  t4 = d & M; d >>= 52;
  tx = (t4 >> 48); t4 &= (M >> 4);

  c  = (fiat_secp256k1_uint128)a0 * a0;
  d += (fiat_secp256k1_uint128)a1 * a4
     + (fiat_secp256k1_uint128)(a2*2) * a3;
  u0 = d & M; d >>= 52;
  u0 = (u0 << 4) | tx;
  c += (fiat_secp256k1_uint128)u0 * (R >> 4);
  r[0] = c & M; c >>= 52;

  a0 *= 2;
  c += (fiat_secp256k1_uint128)a0 * a1;
  d += (fiat_secp256k1_uint128)a2 * a4
     + (fiat_secp256k1_uint128)a3 * a3;
  c += (d & M) * R; d >>= 52;
  r[1] = c & M; c >>= 52;

  c += (fiat_secp256k1_uint128)a0 * a2
     + (fiat_secp256k1_uint128)a1 * a1;
  d += (fiat_secp256k1_uint128)a3 * a4;
  c += (d & M) * R; d >>= 52;
  r[2] = c & M; c >>= 52;

  c   += d * R + t3;
  r[3] = c & M; c >>= 52;
  c   += t4;
  r[4] = c;
#endif
}

static void fiat_secp256k1_carry(uint64_t r[5], const uint64_t a[5]) {
  uint64_t t0 = a[0];
  uint64_t t1 = a[1];
  uint64_t t2 = a[2];
  uint64_t t3 = a[3];
  uint64_t t4 = a[4];
  uint64_t m;
  uint64_t x = t4 >> 48; t4 &= 0x0FFFFFFFFFFFFULL;

  t0 += x * 0x1000003D1ULL;
  t1 += (t0 >> 52); t0 &= 0xFFFFFFFFFFFFFULL;
  t2 += (t1 >> 52); t1 &= 0xFFFFFFFFFFFFFULL; m = t1;
  t3 += (t2 >> 52); t2 &= 0xFFFFFFFFFFFFFULL; m &= t2;
  t4 += (t3 >> 52); t3 &= 0xFFFFFFFFFFFFFULL; m &= t3;

  x = (t4 >> 48) | ((t4 == 0x0FFFFFFFFFFFFULL) & (m == 0xFFFFFFFFFFFFFULL)
    & (t0 >= 0xFFFFEFFFFFC2FULL));

  t0 += x * 0x1000003D1ULL;
  t1 += (t0 >> 52); t0 &= 0xFFFFFFFFFFFFFULL;
  t2 += (t1 >> 52); t1 &= 0xFFFFFFFFFFFFFULL;
  t3 += (t2 >> 52); t2 &= 0xFFFFFFFFFFFFFULL;
  t4 += (t3 >> 52); t3 &= 0xFFFFFFFFFFFFFULL;

  t4 &= 0x0FFFFFFFFFFFFULL;

  r[0] = t0;
  r[1] = t1;
  r[2] = t2;
  r[3] = t3;
  r[4] = t4;
}

static void fiat_secp256k1_add(uint64_t r[5], const uint64_t a[5], const uint64_t b[5]) {
  r[0] = a[0] + b[0];
  r[1] = a[1] + b[1];
  r[2] = a[2] + b[2];
  r[3] = a[3] + b[3];
  r[4] = a[4] + b[4];
}

static void fiat_secp256k1_sub(uint64_t r[5], const uint64_t a[5], const uint64_t b[5]) {
  uint64_t t0 = 0xFFFFEFFFFFC2FULL * 2 * (1 + 1) - b[0];
  uint64_t t1 = 0xFFFFFFFFFFFFFULL * 2 * (1 + 1) - b[1];
  uint64_t t2 = 0xFFFFFFFFFFFFFULL * 2 * (1 + 1) - b[2];
  uint64_t t3 = 0xFFFFFFFFFFFFFULL * 2 * (1 + 1) - b[3];
  uint64_t t4 = 0x0FFFFFFFFFFFFULL * 2 * (1 + 1) - b[4];

  r[0] = a[0] + t0;
  r[1] = a[1] + t1;
  r[2] = a[2] + t2;
  r[3] = a[3] + t3;
  r[4] = a[4] + t4;
}

static void fiat_secp256k1_opp(uint64_t r[5], const uint64_t a[5]) {
  r[0] = 0xFFFFEFFFFFC2FULL * 2 * (1 + 1) - a[0];
  r[1] = 0xFFFFFFFFFFFFFULL * 2 * (1 + 1) - a[1];
  r[2] = 0xFFFFFFFFFFFFFULL * 2 * (1 + 1) - a[2];
  r[3] = 0xFFFFFFFFFFFFFULL * 2 * (1 + 1) - a[3];
  r[4] = 0x0FFFFFFFFFFFFULL * 2 * (1 + 1) - a[4];
}

static void fiat_secp256k1_nonzero(uint64_t* r, const uint64_t a[5]) {
  uint64_t t0 = a[0];
  uint64_t t1 = a[1];
  uint64_t t2 = a[2];
  uint64_t t3 = a[3];
  uint64_t t4 = a[4];
  uint64_t z0, z1;
  uint64_t x = t4 >> 48; t4 &= 0x0FFFFFFFFFFFFULL;

  t0 += x * 0x1000003D1ULL;
  t1 += (t0 >> 52); t0 &= 0xFFFFFFFFFFFFFULL; z0  = t0; z1  = t0 ^ 0x1000003D0ULL;
  t2 += (t1 >> 52); t1 &= 0xFFFFFFFFFFFFFULL; z0 |= t1; z1 &= t1;
  t3 += (t2 >> 52); t2 &= 0xFFFFFFFFFFFFFULL; z0 |= t2; z1 &= t2;
  t4 += (t3 >> 52); t3 &= 0xFFFFFFFFFFFFFULL; z0 |= t3; z1 &= t3;
                                              z0 |= t4; z1 &= t4 ^ 0xF000000000000ULL;

  *r = ((z0 == 0) | (z1 == 0xFFFFFFFFFFFFFULL)) ^ 1;
}

static void fiat_secp256k1_selectznz(uint64_t r[5], fiat_secp256k1_uint1 flag, const uint64_t a[5], const uint64_t b[5]) {
  uint64_t mask0, mask1;
  mask0 = flag + ~((uint64_t)0);
  mask1 = ~mask0;
  r[0] = (a[0] & mask0) | (b[0] & mask1);
  r[1] = (a[1] & mask0) | (b[1] & mask1);
  r[2] = (a[2] & mask0) | (b[2] & mask1);
  r[3] = (a[3] & mask0) | (b[3] & mask1);
  r[4] = (a[4] & mask0) | (b[4] & mask1);
}

static void fiat_secp256k1_to_bytes(uint8_t r[32], const uint64_t a[5]) {
  r[31] = (a[4] >> 40) & 0xFF;
  r[30] = (a[4] >> 32) & 0xFF;
  r[29] = (a[4] >> 24) & 0xFF;
  r[28] = (a[4] >> 16) & 0xFF;
  r[27] = (a[4] >> 8) & 0xFF;
  r[26] = a[4] & 0xFF;
  r[25] = (a[3] >> 44) & 0xFF;
  r[24] = (a[3] >> 36) & 0xFF;
  r[23] = (a[3] >> 28) & 0xFF;
  r[22] = (a[3] >> 20) & 0xFF;
  r[21] = (a[3] >> 12) & 0xFF;
  r[20] = (a[3] >> 4) & 0xFF;
  r[19] = ((a[2] >> 48) & 0xF) | ((a[3] & 0xF) << 4);
  r[18] = (a[2] >> 40) & 0xFF;
  r[17] = (a[2] >> 32) & 0xFF;
  r[16] = (a[2] >> 24) & 0xFF;
  r[15] = (a[2] >> 16) & 0xFF;
  r[14] = (a[2] >> 8) & 0xFF;
  r[13] = a[2] & 0xFF;
  r[12] = (a[1] >> 44) & 0xFF;
  r[11] = (a[1] >> 36) & 0xFF;
  r[10] = (a[1] >> 28) & 0xFF;
  r[9] = (a[1] >> 20) & 0xFF;
  r[8] = (a[1] >> 12) & 0xFF;
  r[7] = (a[1] >> 4) & 0xFF;
  r[6] = ((a[0] >> 48) & 0xF) | ((a[1] & 0xF) << 4);
  r[5] = (a[0] >> 40) & 0xFF;
  r[4] = (a[0] >> 32) & 0xFF;
  r[3] = (a[0] >> 24) & 0xFF;
  r[2] = (a[0] >> 16) & 0xFF;
  r[1] = (a[0] >> 8) & 0xFF;
  r[0] = a[0] & 0xFF;
}

static void fiat_secp256k1_from_bytes(uint64_t r[5], const uint8_t a[32]) {
  r[0] = (uint64_t)a[0]
       | ((uint64_t)a[1] << 8)
       | ((uint64_t)a[2] << 16)
       | ((uint64_t)a[3] << 24)
       | ((uint64_t)a[4] << 32)
       | ((uint64_t)a[5] << 40)
       | ((uint64_t)(a[6] & 0xF)  << 48);
  r[1] = (uint64_t)((a[6] >> 4) & 0xF)
       | ((uint64_t)a[7] << 4)
       | ((uint64_t)a[8] << 12)
       | ((uint64_t)a[9] << 20)
       | ((uint64_t)a[10] << 28)
       | ((uint64_t)a[11] << 36)
       | ((uint64_t)a[12] << 44);
  r[2] = (uint64_t)a[13]
       | ((uint64_t)a[14] << 8)
       | ((uint64_t)a[15] << 16)
       | ((uint64_t)a[16] << 24)
       | ((uint64_t)a[17] << 32)
       | ((uint64_t)a[18] << 40)
       | ((uint64_t)(a[19] & 0xF) << 48);
  r[3] = (uint64_t)((a[19] >> 4) & 0xF)
       | ((uint64_t)a[20] << 4)
       | ((uint64_t)a[21] << 12)
       | ((uint64_t)a[22]  << 20)
       | ((uint64_t)a[23]  << 28)
       | ((uint64_t)a[24]  << 36)
       | ((uint64_t)a[25]  << 44);
  r[4] = (uint64_t)a[26]
       | ((uint64_t)a[27] << 8)
       | ((uint64_t)a[28] << 16)
       | ((uint64_t)a[29] << 24)
       | ((uint64_t)a[30] << 32)
       | ((uint64_t)a[31] << 40);
}

static void fiat_secp256k1_to_bytes_be(uint8_t r[32], const uint64_t a[5]) {
  r[0] = (a[4] >> 40) & 0xFF;
  r[1] = (a[4] >> 32) & 0xFF;
  r[2] = (a[4] >> 24) & 0xFF;
  r[3] = (a[4] >> 16) & 0xFF;
  r[4] = (a[4] >> 8) & 0xFF;
  r[5] = a[4] & 0xFF;
  r[6] = (a[3] >> 44) & 0xFF;
  r[7] = (a[3] >> 36) & 0xFF;
  r[8] = (a[3] >> 28) & 0xFF;
  r[9] = (a[3] >> 20) & 0xFF;
  r[10] = (a[3] >> 12) & 0xFF;
  r[11] = (a[3] >> 4) & 0xFF;
  r[12] = ((a[2] >> 48) & 0xF) | ((a[3] & 0xF) << 4);
  r[13] = (a[2] >> 40) & 0xFF;
  r[14] = (a[2] >> 32) & 0xFF;
  r[15] = (a[2] >> 24) & 0xFF;
  r[16] = (a[2] >> 16) & 0xFF;
  r[17] = (a[2] >> 8) & 0xFF;
  r[18] = a[2] & 0xFF;
  r[19] = (a[1] >> 44) & 0xFF;
  r[20] = (a[1] >> 36) & 0xFF;
  r[21] = (a[1] >> 28) & 0xFF;
  r[22] = (a[1] >> 20) & 0xFF;
  r[23] = (a[1] >> 12) & 0xFF;
  r[24] = (a[1] >> 4) & 0xFF;
  r[25] = ((a[0] >> 48) & 0xF) | ((a[1] & 0xF) << 4);
  r[26] = (a[0] >> 40) & 0xFF;
  r[27] = (a[0] >> 32) & 0xFF;
  r[28] = (a[0] >> 24) & 0xFF;
  r[29] = (a[0] >> 16) & 0xFF;
  r[30] = (a[0] >> 8) & 0xFF;
  r[31] = a[0] & 0xFF;
}

static void fiat_secp256k1_from_bytes_be(uint64_t r[5], const uint8_t a[32]) {
  r[0] = (uint64_t)a[31]
       | ((uint64_t)a[30] << 8)
       | ((uint64_t)a[29] << 16)
       | ((uint64_t)a[28] << 24)
       | ((uint64_t)a[27] << 32)
       | ((uint64_t)a[26] << 40)
       | ((uint64_t)(a[25] & 0xF)  << 48);
  r[1] = (uint64_t)((a[25] >> 4) & 0xF)
       | ((uint64_t)a[24] << 4)
       | ((uint64_t)a[23] << 12)
       | ((uint64_t)a[22] << 20)
       | ((uint64_t)a[21] << 28)
       | ((uint64_t)a[20] << 36)
       | ((uint64_t)a[19] << 44);
  r[2] = (uint64_t)a[18]
       | ((uint64_t)a[17] << 8)
       | ((uint64_t)a[16] << 16)
       | ((uint64_t)a[15] << 24)
       | ((uint64_t)a[14] << 32)
       | ((uint64_t)a[13] << 40)
       | ((uint64_t)(a[12] & 0xF) << 48);
  r[3] = (uint64_t)((a[12] >> 4) & 0xF)
       | ((uint64_t)a[11] << 4)
       | ((uint64_t)a[10] << 12)
       | ((uint64_t)a[9]  << 20)
       | ((uint64_t)a[8]  << 28)
       | ((uint64_t)a[7]  << 36)
       | ((uint64_t)a[6]  << 44);
  r[4] = (uint64_t)a[5]
       | ((uint64_t)a[4] << 8)
       | ((uint64_t)a[3] << 16)
       | ((uint64_t)a[2] << 24)
       | ((uint64_t)a[1] << 32)
       | ((uint64_t)a[0] << 40);
}
