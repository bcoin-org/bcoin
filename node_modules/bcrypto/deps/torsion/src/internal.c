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

void
__torsion_assert_fail(const char *file, int line, const char *expr) {
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

void
__torsion_abort(void) {
  abort(); /* LCOV_EXCL_LINE */
}

int
__torsion_memcmp(const void *s1, const void *s2, size_t n) {
  const unsigned char *x = s1;
  const unsigned char *y = s2;
  size_t i;

  for (i = 0; i < n; i++) {
    if (x[i] != y[i])
      return (int)x[i] - (int)y[i];
  }

  return 0;
}
