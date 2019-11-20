/* sha3.c - an implementation of Secure Hash Algorithm 3 (Keccak).
 * based on the
 * The Keccak SHA-3 submission. Submission to NIST (Round 3), 2011
 * by Guido Bertoni, Joan Daemen, Michaël Peeters and Gilles Van Assche
 *
 * Copyright: 2013 Aleksey Kravchenko <rhash.admin@gmail.com>
 *
 * Permission is hereby granted,  free of charge,  to any person  obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction,  including without limitation
 * the rights to  use, copy, modify,  merge, publish, distribute, sublicense,
 * and/or sell copies  of  the Software,  and to permit  persons  to whom the
 * Software is furnished to do so.
 *
 * This program  is  distributed  in  the  hope  that it will be useful,  but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  Use this program  at  your own risk!
 */

#include <assert.h>
#include <string.h>
#include <stdint.h>
#include "keccak.h"

#define BCRYPTO_KECCAK_ROUNDS 24
#define BCRYPTO_KECCAK_FINALIZED 0x80000000

#if defined(i386) || defined(__i386__) || defined(__i486__) \
  || defined(__i586__) || defined(__i686__) || defined(__pentium__) \
  || defined(__pentiumpro__) || defined(__pentium4__) \
  || defined(__nocona__) || defined(prescott) || defined(__core2__) \
  || defined(__k6__) || defined(__k8__) || defined(__athlon__) \
  || defined(__amd64) || defined(__amd64__) \
  || defined(__x86_64) || defined(__x86_64__) || defined(_M_IX86) \
  || defined(_M_AMD64) || defined(_M_IA64) || defined(_M_X64)
#if defined(_LP64) || defined(__LP64__) || defined(__x86_64) \
  || defined(__x86_64__) || defined(_M_AMD64) || defined(_M_X64)
#define CPU_X64
#else
#define CPU_IA32
#endif
#endif

#define ROTL64(qword, n) ((qword) << (n) ^ ((qword) >> (64 - (n))))

#if defined(_MSC_VER) || defined(__BORLANDC__)
#define I64(x) x##ui64
#else
#define I64(x) x##ULL
#endif

#define IS_ALIGNED_64(p) (0 == (7 & ((const char *)(p) - (const char *)0)))

#ifndef __has_builtin
#define __has_builtin(x) 0
#endif

#if (defined(__GNUC__) \
      && (__GNUC__ >= 4) \
      && (__GNUC__ > 4 || __GNUC_MINOR__ >= 3)) \
    || (defined(__clang__) \
    && __has_builtin(__builtin_bswap32) \
    && __has_builtin(__builtin_bswap64))
#define bswap_32(x) __builtin_bswap32(x)
#define bswap_64(x) __builtin_bswap64(x)
#elif (_MSC_VER > 1300) && (defined(CPU_IA32) || defined(CPU_X64))
#define bswap_32(x) _byteswap_ulong((unsigned long)x)
#define bswap_64(x) _byteswap_uint64((__int64)x)
#else
static inline uint32_t
bswap_32(uint32_t x)
{
#if defined(__GNUC__) && defined(CPU_IA32) && !defined(__i386__)
  __asm("bswap\t%0" : "=r" (x) : "0" (x));
  return x;
#else
  x = ((x << 8) & 0xFF00FF00u) | ((x >> 8) & 0x00FF00FFu);
  return (x >> 16) | (x << 16);
#endif
}

static inline uint64_t
bswap_64(uint64_t x) {
  union {
    uint64_t ll;
    uint32_t l[2];
  } w, r;
  w.ll = x;
  r.l[0] = bswap_32(w.l[1]);
  r.l[1] = bswap_32(w.l[0]);
  return r.ll;
}
#endif

static void
swap_copy_u64_to_str(void *t, const void *f, size_t l) {
  if (0 == (((int)((char *)t - (char *)0) | ((char *)f - (char *)0) | l) & 7)) {
    const uint64_t *src = (const uint64_t *)f;
    const uint64_t *end = (const uint64_t *)((const char *)src + l);
    uint64_t *dst = (uint64_t *)t;
    while (src < end)
      *(dst++) = bswap_64(*(src++));
  } else {
    size_t i;
    char *dst = (char *)t;
    for (i = 0; i < l; i++)
      *(dst++) = ((char *)f)[i ^ 7];
  }
}

#ifdef BCRYPTO_BIG_ENDIAN
#define le2me_64(x) bswap_64(x)
#define me64_to_le_str(to, from, length) \
  swap_copy_u64_to_str((to), (from), (length))
#else
#define le2me_64(x) (x)
#define me64_to_le_str(to, from, length) \
  memcpy((to), (from), (length))
#endif

#ifdef BCRYPTO_USE_ASM
static uint64_t bcrypto_keccak_round_constants[BCRYPTO_KECCAK_ROUNDS + 1] = {
  I64(0x0000000000000000),
  I64(0x8000000080008008), I64(0x0000000080000001),
  I64(0x8000000000008080), I64(0x8000000080008081),
  I64(0x800000008000000A), I64(0x000000000000800A),
  I64(0x8000000000000080), I64(0x8000000000008002),
  I64(0x8000000000008003), I64(0x8000000000008089),
  I64(0x800000000000008B), I64(0x000000008000808B),
  I64(0x000000008000000A), I64(0x0000000080008009),
  I64(0x0000000000000088), I64(0x000000000000008A),
  I64(0x8000000000008009), I64(0x8000000080008081),
  I64(0x0000000080000001), I64(0x000000000000808B),
  I64(0x8000000080008000), I64(0x800000000000808A),
  I64(0x0000000000008082), I64(0x0000000000000001)
};
#else
static uint64_t bcrypto_keccak_round_constants[BCRYPTO_KECCAK_ROUNDS] = {
  I64(0x0000000000000001), I64(0x0000000000008082),
  I64(0x800000000000808A), I64(0x8000000080008000),
  I64(0x000000000000808B), I64(0x0000000080000001),
  I64(0x8000000080008081), I64(0x8000000000008009),
  I64(0x000000000000008A), I64(0x0000000000000088),
  I64(0x0000000080008009), I64(0x000000008000000A),
  I64(0x000000008000808B), I64(0x800000000000008B),
  I64(0x8000000000008089), I64(0x8000000000008003),
  I64(0x8000000000008002), I64(0x8000000000000080),
  I64(0x000000000000800A), I64(0x800000008000000A),
  I64(0x8000000080008081), I64(0x8000000000008080),
  I64(0x0000000080000001), I64(0x8000000080008008)
};
#endif

int
bcrypto_keccak_init(bcrypto_keccak_ctx *ctx, unsigned bits) {
  if (bits < 128 || bits > 512)
    return 0;

  unsigned rate = 1600 - bits * 2;

  if (rate > 1600 || (rate & 63) != 0)
    return 0;

  memset(ctx, 0, sizeof(bcrypto_keccak_ctx));
  ctx->block_size = rate / 8;

  return 1;
}

void
bcrypto_keccak_224_init(bcrypto_keccak_ctx *ctx) {
  assert(bcrypto_keccak_init(ctx, 224));
}

void
bcrypto_keccak_256_init(bcrypto_keccak_ctx *ctx) {
  assert(bcrypto_keccak_init(ctx, 256));
}

void
bcrypto_keccak_384_init(bcrypto_keccak_ctx *ctx) {
  assert(bcrypto_keccak_init(ctx, 384));
}

void
bcrypto_keccak_512_init(bcrypto_keccak_ctx *ctx) {
  assert(bcrypto_keccak_init(ctx, 512));
}

static void
bcrypto_keccak_theta(uint64_t *A) {
  unsigned int x;
  uint64_t C[5], D[5];

  for (x = 0; x < 5; x++)
    C[x] = A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20];

  D[0] = ROTL64(C[1], 1) ^ C[4];
  D[1] = ROTL64(C[2], 1) ^ C[0];
  D[2] = ROTL64(C[3], 1) ^ C[1];
  D[3] = ROTL64(C[4], 1) ^ C[2];
  D[4] = ROTL64(C[0], 1) ^ C[3];

  for (x = 0; x < 5; x++) {
    A[x] ^= D[x];
    A[x + 5] ^= D[x];
    A[x + 10] ^= D[x];
    A[x + 15] ^= D[x];
    A[x + 20] ^= D[x];
  }
}

static void
bcrypto_keccak_pi(uint64_t *A) {
  uint64_t A1;
  A1 = A[1];
  A[1] = A[6];
  A[6] = A[9];
  A[9] = A[22];
  A[22] = A[14];
  A[14] = A[20];
  A[20] = A[2];
  A[2] = A[12];
  A[12] = A[13];
  A[13] = A[19];
  A[19] = A[23];
  A[23] = A[15];
  A[15] = A[4];
  A[4] = A[24];
  A[24] = A[21];
  A[21] = A[8];
  A[8] = A[16];
  A[16] = A[5];
  A[5] = A[3];
  A[3] = A[18];
  A[18] = A[17];
  A[17] = A[11];
  A[11] = A[7];
  A[7] = A[10];
  A[10] = A1;
}

static void
bcrypto_keccak_chi(uint64_t *A) {
  int i;
  for (i = 0; i < 25; i += 5) {
    uint64_t A0 = A[0 + i], A1 = A[1 + i];
    A[0 + i] ^= ~A1 & A[2 + i];
    A[1 + i] ^= ~A[2 + i] & A[3 + i];
    A[2 + i] ^= ~A[3 + i] & A[4 + i];
    A[3 + i] ^= ~A[4 + i] & A0;
    A[4 + i] ^= ~A0 & A1;
  }
}

static void
bcrypto_keccak_permutation(uint64_t *state) {
#ifdef BCRYPTO_USE_ASM
  // Borrowed from:
  // https://github.com/gnutls/nettle/blob/master/x86_64/sha3-permute.asm
  //
  // Note: we stripped out the handmade clobber guards
  // and use %rbx instead of %rbp (GCC doesn't allow
  // clobber guards for %rbp).
  //
  // Also note: node.js really needs to build with sha3
  // support so I don't have to do shit like this anymore.
  //
  // Layout:
  //   %rdi = state pointer (&state[0])
  //   %r14 = constants pointer (&round_const[0] - reversed)
  //   %r8 = round counter (starts at 24, decrements)
  //
  // For reference, our full range of clobbered registers:
  // rax, rbx, rcx, rdx, rdi, r8, r9, r10, r11, r12, r13, r14
  __asm__ __volatile__(
    "movq %[st], %%rdi\n"
    "movq %[rc], %%r14\n"
    "movl $24, %%r8d\n"

    "movq (%%rdi), %%rax\n"
    "movups 8(%%rdi), %%xmm0\n"
    "movups 24(%%rdi), %%xmm1\n"
    "movq %%rax, %%r10\n"

    "movq 40(%%rdi), %%rcx\n"
    "movdqa %%xmm0, %%xmm10\n"
    "movups 48(%%rdi), %%xmm2\n"
    "movdqa %%xmm1, %%xmm11\n"
    "movups 64(%%rdi), %%xmm3\n"
    "xorq %%rcx, %%r10\n"

    "movq 80(%%rdi), %%rdx\n"
    "pxor %%xmm2, %%xmm10\n"
    "movups 88(%%rdi), %%xmm4\n"
    "pxor %%xmm3, %%xmm11\n"
    "movups 104(%%rdi), %%xmm5\n"
    "xorq %%rdx, %%r10\n"

    "movq 120(%%rdi), %%rbx\n"
    "pxor %%xmm4, %%xmm10\n"
    "movups 128(%%rdi), %%xmm6\n"
    "pxor %%xmm5, %%xmm11\n"
    "movups 144(%%rdi), %%xmm7\n"
    "xorq %%rbx, %%r10\n"

    "movq 160(%%rdi), %%r9\n"
    "pxor %%xmm6, %%xmm10\n"
    "movups 168(%%rdi), %%xmm8\n"
    "pxor %%xmm7, %%xmm11\n"
    "movups 184(%%rdi), %%xmm9\n"
    "xorq %%r9, %%r10\n"
    "pxor %%xmm8, %%xmm10\n"
    "pxor %%xmm9, %%xmm11\n"

    "1:\n"

    "pshufd $0x4e, %%xmm11, %%xmm11\n"
    "movdqa %%xmm10, %%xmm13\n"

    "movq %%r10, (%%rdi)\n"
    "movq (%%rdi), %%xmm12\n"

    "punpcklqdq %%xmm10, %%xmm12\n"
    "punpckhqdq %%xmm11, %%xmm13\n"
    "punpcklqdq %%xmm12, %%xmm11\n"

    "movq %%xmm11, (%%rdi)\n"
    "movq (%%rdi), %%r11\n"

    "movq %%xmm10, (%%rdi)\n"
    "movq (%%rdi), %%r12\n"

    "rolq $1, %%r12\n"
    "xorq %%r12, %%r11\n"

    "movdqa %%xmm13, %%xmm14\n"
    "movdqa %%xmm13, %%xmm15\n"
    "psllq $1, %%xmm14\n"
    "psrlq $63, %%xmm15\n"
    "pxor %%xmm14, %%xmm12\n"
    "pxor %%xmm15, %%xmm12\n"

    "movdqa %%xmm11, %%xmm10\n"
    "psrlq $63, %%xmm11\n"
    "psllq $1, %%xmm10\n"
    "pxor %%xmm11, %%xmm13\n"
    "pxor %%xmm10, %%xmm13\n"

    "xorq %%r11, %%rax\n"
    "xorq %%r11, %%rcx\n"
    "xorq %%r11, %%rdx\n"
    "xorq %%r11, %%rbx\n"
    "xorq %%r11, %%r9\n"
    "pxor %%xmm12, %%xmm0\n"
    "pxor %%xmm12, %%xmm2\n"
    "pxor %%xmm12, %%xmm4\n"
    "pxor %%xmm12, %%xmm6\n"
    "pxor %%xmm12, %%xmm8\n"
    "pxor %%xmm13, %%xmm1\n"
    "pxor %%xmm13, %%xmm3\n"
    "pxor %%xmm13, %%xmm5\n"
    "pxor %%xmm13, %%xmm7\n"
    "pxor %%xmm13, %%xmm9\n"

    "movdqa %%xmm0, %%xmm14\n"
    "movdqa %%xmm0, %%xmm15\n"
    "movdqa %%xmm0, %%xmm12\n"
    "psllq $1, %%xmm0\n"
    "psrlq $63, %%xmm14\n"
    "psllq $62, %%xmm15\n"
    "por %%xmm0, %%xmm14\n"
    "psrlq $2, %%xmm12\n"
    "por %%xmm15, %%xmm12\n"

    "movdqa %%xmm1, %%xmm0\n"
    "movdqa %%xmm1, %%xmm15\n"
    "psllq $28, %%xmm0\n"
    "psrlq $36, %%xmm15\n"
    "por %%xmm15, %%xmm0\n"
    "movdqa %%xmm1, %%xmm15\n"
    "psllq $27, %%xmm1\n"
    "psrlq $37, %%xmm15\n"
    "por %%xmm15, %%xmm1\n"

    "punpcklqdq %%xmm14, %%xmm0\n"
    "punpckhqdq %%xmm12, %%xmm1\n"

    "rolq $36, %%rcx\n"

    "movq %%rcx, (%%rdi)\n"
    "movq (%%rdi), %%xmm14\n"

    "movq %%xmm2, (%%rdi)\n"
    "movq (%%rdi), %%rcx\n"

    "rolq $44, %%rcx\n"

    "movdqa %%xmm2, %%xmm15\n"
    "psllq $6, %%xmm2\n"
    "psrlq $58, %%xmm15\n"

    "por %%xmm2, %%xmm15\n"
    "movdqa %%xmm3, %%xmm2\n"

    "movdqa %%xmm2, %%xmm12\n"
    "psllq $20, %%xmm2\n"
    "psrlq $44, %%xmm12\n"

    "por %%xmm12, %%xmm2\n"
    "punpckhqdq %%xmm15, %%xmm2\n"

    "movdqa %%xmm3, %%xmm15\n"
    "psllq $55, %%xmm3\n"
    "psrlq $9, %%xmm15\n"

    "por %%xmm3, %%xmm15\n"
    "movdqa %%xmm14, %%xmm3\n"
    "punpcklqdq %%xmm15, %%xmm3\n"

    "rolq $42, %%rdx\n"
    "pshufd $0x4e, %%xmm4, %%xmm14\n"

    "movq %%rdx, (%%rdi)\n"
    "movq (%%rdi), %%xmm4\n"

    "movq %%xmm14, (%%rdi)\n"
    "movq (%%rdi), %%rdx\n"

    "rolq $43, %%rdx\n"

    "punpcklqdq %%xmm5, %%xmm4\n"

    "movdqa %%xmm4, %%xmm15\n"
    "psllq $25, %%xmm4\n"
    "psrlq $39, %%xmm15\n"

    "por %%xmm15, %%xmm4\n"

    "movdqa %%xmm5, %%xmm12\n"
    "psllq $39, %%xmm5\n"
    "psrlq $25, %%xmm12\n"

    "por %%xmm5, %%xmm12\n"

    "movdqa %%xmm14, %%xmm5\n"
    "psllq $10, %%xmm14\n"
    "psrlq $54, %%xmm5\n"

    "por %%xmm14, %%xmm5\n"
    "punpckhqdq %%xmm12, %%xmm5\n"

    "pshufd $0x4e, %%xmm7, %%xmm14\n"
    "rolq $41, %%rbx\n"

    "movq %%rbx, (%%rdi)\n"
    "movq (%%rdi), %%xmm15\n"

    "movq %%xmm7, (%%rdi)\n"
    "movq (%%rdi), %%rbx\n"

    "rolq $21, %%rbx\n"
    "pshufd $0x4e, %%xmm6, %%xmm7\n"

    "movdqa %%xmm6, %%xmm12\n"
    "psllq $45, %%xmm6\n"
    "psrlq $19, %%xmm12\n"

    "por %%xmm12, %%xmm6\n"

    "movdqa %%xmm14, %%xmm13\n"
    "psllq $8, %%xmm14\n"
    "psrlq $56, %%xmm13\n"

    "por %%xmm13, %%xmm14\n"
    "punpcklqdq %%xmm14, %%xmm6\n"

    "movdqa %%xmm7, %%xmm12\n"
    "psllq $15, %%xmm7\n"
    "psrlq $49, %%xmm12\n"

    "por %%xmm12, %%xmm7\n"
    "punpcklqdq %%xmm15, %%xmm7\n"

    "rolq $18, %%r9\n"

    "movq %%r9, (%%rdi)\n"
    "movq (%%rdi), %%xmm14\n"

    "pshufd $0x4e, %%xmm9, %%xmm15\n"
    "movd %%xmm15, %%r9\n"
    "rolq $14, %%r9\n"

    "movdqa %%xmm9, %%xmm15\n"
    "psllq $56, %%xmm9\n"
    "psrlq $8, %%xmm15\n"

    "por %%xmm15, %%xmm9\n"

    "movdqa %%xmm8, %%xmm12\n"

    "movdqa %%xmm12, %%xmm15\n"
    "psllq $2, %%xmm12\n"
    "psrlq $62, %%xmm15\n"

    "por %%xmm15, %%xmm12\n"
    "punpcklqdq %%xmm12, %%xmm9\n"

    "movdqa %%xmm8, %%xmm15\n"
    "psllq $61, %%xmm8\n"
    "psrlq $3, %%xmm15\n"

    "por %%xmm15, %%xmm8\n"
    "psrldq $8, %%xmm8\n"
    "punpcklqdq %%xmm14, %%xmm8\n"

    "movq %%rcx, %%r12\n"
    "notq %%r12\n"
    "andq %%rdx, %%r12\n"
    "movq %%rdx, %%r13\n"
    "notq %%r13\n"
    "andq %%rbx, %%r13\n"
    "movq %%rbx, %%r11\n"
    "notq %%r11\n"
    "andq %%r9, %%r11\n"
    "xorq %%r11, %%rdx\n"
    "movq %%r9, %%r10\n"
    "notq %%r10\n"
    "andq %%rax, %%r10\n"
    "xorq %%r10, %%rbx\n"
    "movq %%rax, %%r11\n"
    "notq %%r11\n"
    "andq %%rcx, %%r11\n"
    "xorq %%r11, %%r9\n"
    "xorq %%r12, %%rax\n"
    "xorq %%r13, %%rcx\n"

    "movdqa %%xmm2, %%xmm14\n"
    "pandn %%xmm4, %%xmm14\n"
    "movdqa %%xmm4, %%xmm15\n"
    "pandn %%xmm6, %%xmm15\n"
    "movdqa %%xmm6, %%xmm12\n"
    "pandn %%xmm8, %%xmm12\n"
    "pxor %%xmm12, %%xmm4\n"
    "movdqa %%xmm8, %%xmm13\n"
    "pandn %%xmm0, %%xmm13\n"
    "pxor %%xmm13, %%xmm6\n"
    "movdqa %%xmm0, %%xmm12\n"
    "pandn %%xmm2, %%xmm12\n"
    "pxor %%xmm12, %%xmm8\n"
    "pxor %%xmm14, %%xmm0\n"
    "pxor %%xmm15, %%xmm2\n"

    "movdqa %%xmm3, %%xmm14\n"
    "pandn %%xmm5, %%xmm14\n"
    "movdqa %%xmm5, %%xmm15\n"
    "pandn %%xmm7, %%xmm15\n"
    "movdqa %%xmm7, %%xmm12\n"
    "pandn %%xmm9, %%xmm12\n"
    "pxor %%xmm12, %%xmm5\n"
    "movdqa %%xmm9, %%xmm13\n"
    "pandn %%xmm1, %%xmm13\n"
    "pxor %%xmm13, %%xmm7\n"
    "movdqa %%xmm1, %%xmm12\n"
    "pandn %%xmm3, %%xmm12\n"
    "pxor %%xmm12, %%xmm9\n"
    "pxor %%xmm14, %%xmm1\n"
    "pxor %%xmm15, %%xmm3\n"

    "xorq (%%r14, %%r8, 8), %%rax\n"

    "movq %%rcx, (%%rdi)\n"
    "movq (%%rdi), %%xmm10\n"

    "movq %%rbx, (%%rdi)\n"
    "movq (%%rdi), %%xmm11\n"

    "movq %%rdx, (%%rdi)\n"
    "movq (%%rdi), %%xmm14\n"

    "movq %%r9, (%%rdi)\n"
    "movq (%%rdi), %%xmm15\n"

    "movq %%rax, %%r10\n"
    "punpcklqdq %%xmm14, %%xmm10\n"
    "punpcklqdq %%xmm15, %%xmm11\n"

    "movq %%xmm0, (%%rdi)\n"
    "movq (%%rdi), %%rcx\n"

    "movq %%xmm1, (%%rdi)\n"
    "movq (%%rdi), %%rbx\n"

    "psrldq $8, %%xmm0\n"
    "psrldq $8, %%xmm1\n"
    "xorq %%rcx, %%r10\n"
    "xorq %%rbx, %%r10\n"

    "movq %%xmm0, (%%rdi)\n"
    "movq (%%rdi), %%rdx\n"

    "movq %%xmm1, (%%rdi)\n"
    "movq (%%rdi), %%r9\n"

    "movdqa %%xmm10, %%xmm0\n"
    "movdqa %%xmm11, %%xmm1\n"

    "movdqa %%xmm2, %%xmm14\n"
    "punpcklqdq %%xmm4, %%xmm2\n"
    "xorq %%rdx, %%r10\n"
    "xorq %%r9, %%r10\n"
    "punpckhqdq %%xmm14, %%xmm4\n"
    "pshufd $0x4e, %%xmm4, %%xmm4\n"

    "movdqa %%xmm7, %%xmm14\n"
    "punpcklqdq %%xmm9, %%xmm7\n"
    "pxor %%xmm2, %%xmm10\n"
    "pxor %%xmm4, %%xmm10\n"
    "punpckhqdq %%xmm14, %%xmm9\n"
    "pshufd $0x4e, %%xmm9, %%xmm9\n"

    "movdqa %%xmm3, %%xmm14\n"
    "movdqa %%xmm5, %%xmm15\n"
    "movdqa %%xmm6, %%xmm3\n"
    "movdqa %%xmm8, %%xmm5\n"
    "pxor %%xmm7, %%xmm11\n"
    "pxor %%xmm9, %%xmm11\n"
    "punpcklqdq %%xmm8, %%xmm3\n"
    "punpckhqdq %%xmm6, %%xmm5\n"
    "pshufd $0x4e, %%xmm5, %%xmm5\n"
    "movdqa %%xmm14, %%xmm6\n"
    "movdqa %%xmm15, %%xmm8\n"
    "pxor %%xmm3, %%xmm11\n"
    "pxor %%xmm5, %%xmm11\n"
    "punpcklqdq %%xmm15, %%xmm6\n"
    "punpckhqdq %%xmm14, %%xmm8\n"
    "pshufd $0x4e, %%xmm8, %%xmm8\n"

    "decl %%r8d\n"
    "pxor %%xmm6, %%xmm10\n"
    "pxor %%xmm8, %%xmm10\n"
    "jnz 1b\n"

    "movq %%rax, (%%rdi)\n"
    "movups %%xmm0, 8(%%rdi)\n"
    "movups %%xmm1, 24(%%rdi)\n"

    "movq %%rcx, 40(%%rdi)\n"
    "movups %%xmm2, 48(%%rdi)\n"
    "movups %%xmm3, 64(%%rdi)\n"

    "movq %%rdx, 80(%%rdi)\n"
    "movups %%xmm4, 88(%%rdi)\n"
    "movups %%xmm5, 104(%%rdi)\n"

    "movq %%rbx, 120(%%rdi)\n"
    "movups %%xmm6, 128(%%rdi)\n"
    "movups %%xmm7, 144(%%rdi)\n"

    "movq %%r9, 160(%%rdi)\n"
    "movups %%xmm8, 168(%%rdi)\n"
    "movups %%xmm9, 184(%%rdi)\n"
    :
    : [st] "r" (state),
      [rc] "r" (bcrypto_keccak_round_constants)
    : "rbx", "r12", "r13", "r14", // Necessary
      "rax", "rcx", "rdx", "rdi", // Not necessary (but better to be safe)
      "r8",  "r9",  "r10", "r11",
      "cc", "memory"
  );
#else
  int round;
  for (round = 0; round < BCRYPTO_KECCAK_ROUNDS; round++) {
    bcrypto_keccak_theta(state);

    state[1] = ROTL64(state[1], 1);
    state[2] = ROTL64(state[2], 62);
    state[3] = ROTL64(state[3], 28);
    state[4] = ROTL64(state[4], 27);
    state[5] = ROTL64(state[5], 36);
    state[6] = ROTL64(state[6], 44);
    state[7] = ROTL64(state[7], 6);
    state[8] = ROTL64(state[8], 55);
    state[9] = ROTL64(state[9], 20);
    state[10] = ROTL64(state[10], 3);
    state[11] = ROTL64(state[11], 10);
    state[12] = ROTL64(state[12], 43);
    state[13] = ROTL64(state[13], 25);
    state[14] = ROTL64(state[14], 39);
    state[15] = ROTL64(state[15], 41);
    state[16] = ROTL64(state[16], 45);
    state[17] = ROTL64(state[17], 15);
    state[18] = ROTL64(state[18], 21);
    state[19] = ROTL64(state[19], 8);
    state[20] = ROTL64(state[20], 18);
    state[21] = ROTL64(state[21], 2);
    state[22] = ROTL64(state[22], 61);
    state[23] = ROTL64(state[23], 56);
    state[24] = ROTL64(state[24], 14);

    bcrypto_keccak_pi(state);
    bcrypto_keccak_chi(state);

    *state ^= bcrypto_keccak_round_constants[round];
  }
#endif
}

static void
bcrypto_keccak_process_block(
  uint64_t hash[25],
  const uint64_t *block,
  size_t block_size
) {
  switch (block_size) {
    case 144: { // SHA3-224
      hash[17] ^= le2me_64(block[17]);
    }

    case 136: { // SHA3-256
      hash[16] ^= le2me_64(block[16]);
      hash[15] ^= le2me_64(block[15]);
      hash[14] ^= le2me_64(block[14]);
      hash[13] ^= le2me_64(block[13]);
    }

    case 104: { // SHA3-384
      hash[12] ^= le2me_64(block[12]);
      hash[11] ^= le2me_64(block[11]);
      hash[10] ^= le2me_64(block[10]);
      hash[9] ^= le2me_64(block[9]);
    }

    case 72: { // SHA3-512
      hash[8] ^= le2me_64(block[8]);
      hash[7] ^= le2me_64(block[7]);
      hash[6] ^= le2me_64(block[6]);
      hash[5] ^= le2me_64(block[5]);
      hash[4] ^= le2me_64(block[4]);
      hash[3] ^= le2me_64(block[3]);
      hash[2] ^= le2me_64(block[2]);
      hash[1] ^= le2me_64(block[1]);
      hash[0] ^= le2me_64(block[0]);
      break;
    }

    default: {
      assert(block_size <= 192);

      size_t blocks = block_size / 8;
      size_t i;

      for (i = 0; i < blocks; i++)
        hash[i] ^= le2me_64(block[i]);

      break;
    }
  }

  bcrypto_keccak_permutation(hash);
}

void
bcrypto_keccak_update(
  bcrypto_keccak_ctx *ctx,
  const unsigned char *msg,
  size_t size
) {
  size_t index = (size_t)ctx->rest;
  size_t block_size = (size_t)ctx->block_size;

  if (ctx->rest & BCRYPTO_KECCAK_FINALIZED)
    return;

  ctx->rest = (unsigned)((ctx->rest + size) % block_size);

  if (index) {
    size_t left = block_size - index;
    memcpy((char *)ctx->message + index, msg, (size < left ? size : left));

    if (size < left)
      return;

    bcrypto_keccak_process_block(ctx->hash, ctx->message, block_size);
    msg += left;
    size -= left;
  }

  while (size >= block_size) {
    uint64_t *aligned_message_block;

    if (IS_ALIGNED_64(msg)) {
      aligned_message_block = (uint64_t *)msg;
    } else {
      memcpy(ctx->message, msg, block_size);
      aligned_message_block = ctx->message;
    }

    bcrypto_keccak_process_block(ctx->hash, aligned_message_block, block_size);
    msg += block_size;
    size -= block_size;
  }

  if (size)
    memcpy(ctx->message, msg, size);
}

int
bcrypto_keccak_final(
  bcrypto_keccak_ctx *ctx,
  int pad,
  unsigned char *result,
  size_t digest_length,
  size_t *result_length
) {
  const size_t block_size = ctx->block_size;

  if (digest_length == 0)
    digest_length = 100 - block_size / 2;

  if (digest_length > 200)
    return 0;

  if (digest_length >= block_size)
    return 0;

  if (!(ctx->rest & BCRYPTO_KECCAK_FINALIZED)) {
    memset((char *)ctx->message + ctx->rest, 0, block_size - ctx->rest);
    ((char *)ctx->message)[ctx->rest] |= pad;
    ((char *)ctx->message)[block_size - 1] |= 0x80;

    bcrypto_keccak_process_block(ctx->hash, ctx->message, block_size);
    ctx->rest = BCRYPTO_KECCAK_FINALIZED;
  }

  assert(block_size > digest_length);

  if (result)
    me64_to_le_str(result, ctx->hash, digest_length);

  if (result_length)
    *result_length = digest_length;

  return 1;
}
