/*!
 * common.h - common definitions for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 */

#ifndef TORSION_COMMON_H
#define TORSION_COMMON_H

#ifdef TORSION_BUILD
#  if defined(__EMSCRIPTEN__)
#    include <emscripten.h>
#    define TORSION_EXTERN EMSCRIPTEN_KEEPALIVE
#  elif defined(__wasm__)
#    define TORSION_EXTERN __attribute__((visibility("default")))
#  elif defined(_WIN32)
#    define TORSION_EXTERN __declspec(dllexport)
#  elif defined(__GNUC__) && __GNUC__ >= 4
#    define TORSION_EXTERN __attribute__((visibility("default")))
#  elif (defined(__SUNPRO_C) && __SUNPRO_C >= 0x550) \
     || (defined(__SUNPRO_CC) && __SUNPRO_CC >= 0x550)
#    define TORSION_EXTERN __global
#  endif
#endif

#ifndef TORSION_EXTERN
#  define TORSION_EXTERN
#endif

#endif /* TORSION_COMMON_H */
