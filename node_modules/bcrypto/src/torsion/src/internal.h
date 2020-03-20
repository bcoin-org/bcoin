#ifndef _TORSION_INTERNAL_H
#define _TORSION_INTERNAL_H

#include <stdio.h>
#include <stdlib.h>

#define CHECK(expr) do {                               \
  if (!(expr)) {                                       \
    fprintf(stderr, "%s:%d: Assertion `%s' failed.\n", \
            __FILE__, __LINE__, #expr);                \
    fflush(stderr);                                    \
    abort();                                           \
  }                                                    \
} while (0)

#if defined(__GNUC__) && __GNUC__ >= 3
#  define TORSION_INLINE __inline__
#elif defined(_MSC_VER)
#  define TORSION_INLINE __inline
#else
#  define TORSION_INLINE
#endif

#define ENTROPY_SIZE 32

#endif /* _TORSION_INTERNAL_H */
