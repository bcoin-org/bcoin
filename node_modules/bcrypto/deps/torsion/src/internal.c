/*!
 * internal.c - internal utils for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 */

#ifdef TORSION_DEBUG
#  include <stdio.h>
#endif

#include <stdlib.h>
#include "internal.h"

TORSION_NORETURN void
torsion__assert_fail(const char *file, int line, const char *expr) {
  /* LCOV_EXCL_START */
#if defined(TORSION_DEBUG)
  fprintf(stderr, "%s:%d: Assertion `%s' failed.\n", file, line, expr);
  fflush(stderr);
#else
  (void)file;
  (void)line;
  (void)expr;
#endif
  abort();
  /* LCOV_EXCL_STOP */
}

TORSION_NORETURN void
torsion__abort(void) {
  abort(); /* LCOV_EXCL_LINE */
}

int
torsion__memcmp(const void *s1, const void *s2, size_t n) {
  const unsigned char *x = (const unsigned char *)s1;
  const unsigned char *y = (const unsigned char *)s2;
  size_t i;

  for (i = 0; i < n; i++) {
    if (x[i] != y[i])
      return (int)x[i] - (int)y[i];
  }

  return 0;
}
