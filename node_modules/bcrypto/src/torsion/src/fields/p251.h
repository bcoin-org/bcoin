/*!
 * p251.h - p251 field element for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 */

#ifdef TORSION_USE_64BIT
typedef uint64_t p251_fe_word_t;
#define P251_FIELD_WORDS 5
#include "p251_64.h"
#else
typedef uint32_t p251_fe_word_t;
#define P251_FIELD_WORDS 10
#include "p251_32.h"
#endif

static void
p251_clamp(unsigned char *raw) {
  raw[0] &= 0xfc; /* -4 */
  raw[31] &= 0x07;
  raw[31] |= 0x08;
}
