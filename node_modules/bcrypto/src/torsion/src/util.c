/*!
 * util.c - utils for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 */

#include <stddef.h>
#include <string.h>

#ifdef _WIN32
/* For SecureZeroMemory (actually defined in winbase.h). */
#include <windows.h>
#endif

#include <torsion/util.h>

/*
 * Util
 */

void
cleanse(void *ptr, size_t len) {
#if defined(_WIN32)
  /* https://github.com/jedisct1/libsodium/blob/3b26a5c/src/libsodium/sodium/utils.c#L112 */
  SecureZeroMemory(ptr, len);
#elif defined(__GNUC__)
  /* https://github.com/torvalds/linux/blob/37d4e84/include/linux/string.h#L233 */
  /* https://github.com/torvalds/linux/blob/37d4e84/include/linux/compiler-gcc.h#L21 */
  /* https://github.com/bminor/glibc/blob/master/string/explicit_bzero.c */
  memset(ptr, 0, len);
  __asm__ __volatile__("": :"r"(ptr) :"memory");
#else
  /* http://www.daemonology.net/blog/2014-09-04-how-to-zero-a-buffer.html */
  static void *(*const volatile memset_ptr)(void *, int, size_t) = memset;
  (memset_ptr)(ptr, 0, len);
#endif
}
