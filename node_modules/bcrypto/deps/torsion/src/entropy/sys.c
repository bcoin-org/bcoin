/*!
 * sys.c - os/system entropy for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/Entropy-supplying_system_calls
 *   https://en.wikipedia.org/wiki/CryptGenRandom
 *   https://en.wikipedia.org/wiki/dev/random
 *
 * Windows:
 *   https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgenrandom
 *   https://docs.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-rtlgenrandom
 *
 * Linux:
 *   http://man7.org/linux/man-pages/man2/getrandom.2.html
 *   http://man7.org/linux/man-pages/man4/random.4.html
 *   https://man7.org/linux/man-pages/man2/_sysctl.2.html
 *   https://github.com/torvalds/linux/blob/v5.4/include/uapi/linux/sysctl.h
 *
 * OSX/iOS:
 *   https://www.unix.com/man-page/mojave/2/getentropy/
 *   https://www.unix.com/man-page/mojave/4/random/
 *
 * FreeBSD:
 *   https://www.freebsd.org/cgi/man.cgi?getrandom(2)
 *   https://www.freebsd.org/cgi/man.cgi?getentropy(3)
 *   https://www.freebsd.org/cgi/man.cgi?sysctl(3)
 *   https://github.com/freebsd/freebsd/commit/3ef9d41
 *   https://github.com/freebsd/freebsd/commit/fb176db
 *   https://www.freebsd.org/cgi/man.cgi?random(4)
 *
 * OpenBSD:
 *   https://man.openbsd.org/getentropy.2
 *   https://github.com/openbsd/src/blob/2981a53/sys/sys/sysctl.h#L140
 *   https://github.com/openbsd/src/commit/9914119
 *   https://github.com/openbsd/src/commit/fce3886
 *   https://github.com/openbsd/src/commit/4680fe5
 *   https://man.openbsd.org/random.4
 *
 * NetBSD:
 *   https://netbsd.gw.com/cgi-bin/man-cgi?sysctl+3+NetBSD-8.0
 *   https://github.com/NetBSD/src/commit/0a9d2ad
 *   https://github.com/NetBSD/src/commit/3f78162
 *   https://netbsd.gw.com/cgi-bin/man-cgi?random+4+NetBSD-8.0
 *
 * DragonFly BSD:
 *   https://leaf.dragonflybsd.org/cgi/web-man?command=getrandom&section=2
 *   https://leaf.dragonflybsd.org/cgi/web-man?command=random&section=4
 *
 * Solaris/Illumos:
 *   https://docs.oracle.com/cd/E88353_01/html/E37841/getrandom-2.html
 *   https://docs.oracle.com/cd/E36784_01/html/E36884/random-7d.html
 *
 * IBM i (PASE):
 *   https://www.ibm.com/support/knowledgecenter/en/ssw_ibm_i_71/rzalf/rzalf.pdf
 *
 * AIX:
 *   https://www.ibm.com/support/knowledgecenter/ssw_aix_71/filesreference/random.html
 *
 * Haiku:
 *   No official documentation for /dev/random.
 *
 * Redox:
 *   https://github.com/redox-os/randd/blob/2f0ad18/src/main.rs
 *   https://github.com/redox-os/relibc/blob/a6fffd3/src/platform/redox/mod.rs#L559
 *   https://github.com/redox-os/relibc/commit/a6fffd3
 *
 * VxWorks:
 *   https://docs.windriver.com/bundle/vxworks_7_application_core_os_sr0630-enus/page/CORE/randomNumGenLib.html
 *
 * Fuchsia:
 *   https://fuchsia.dev/fuchsia-src/zircon/syscalls/cprng_draw
 *
 * CloudABI:
 *   https://nuxi.nl/cloudabi/#random_get
 *   https://github.com/NuxiNL/cloudabi/blob/d283c05/headers/cloudabi_syscalls.h#L193
 *   https://github.com/NuxiNL/cloudabi/blob/d283c05/headers/cloudabi_types_common.h#L89
 *
 * WASI:
 *   https://github.com/WebAssembly/WASI/blob/5d10b2c/design/WASI-core.md#random_get
 *   https://github.com/WebAssembly/WASI/blob/2627acd/phases/snapshot/witx/typenames.witx#L34
 *   https://github.com/WebAssembly/WASI/blob/2627acd/phases/snapshot/witx/wasi_snapshot_preview1.witx#L481
 *   https://github.com/emscripten-core/emscripten/blob/b45948b/system/include/wasi/api.h#L2648
 *
 * Emscripten (wasm, asm.js):
 *   https://emscripten.org/docs/api_reference/emscripten.h.html
 *   https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues
 *   https://nodejs.org/api/crypto.html#crypto_crypto_randomfillsync_buffer_offset_size
 *   https://github.com/emscripten-core/emscripten/blob/7c3ced6/src/library_uuid.js#L31
 *   https://github.com/emscripten-core/emscripten/blob/32e1d73/system/include/uuid/uuid.h
 */

/**
 * OS/System Entropy
 *
 * We try to avoid /dev/{u,}random as much as possible. Not
 * only can they behave differenly on different OSes, but they
 * are unreliable in terms of usability (for example, what if
 * we are inside a chroot where /dev has not been setup?).
 *
 * To avoid locking ourselves down to a particular build system,
 * we check for features using only the C preprocessor.
 *
 * In the future, we may consider using dlsym(3) to check
 * features at runtime. This would ensure better ABI compat
 * across builds. If GCC, Clang, or Sun Studio are used, we
 * can utilize `__attribute__((weak))` or `#pragma weak` over
 * dlsym(3).
 *
 * We try to match the behavior of the getrandom rust library[1].
 * The primary difference involves the fact that we do not call
 * `SecRandomCopyBytes` on iOS as it requires us to link to the
 * Apple Security Framework.
 *
 * Our current entropy backends are as follows...
 *
 * Windows:
 *   Source: BCryptGenRandom
 *   Fallback: RtlGenRandom (SystemFunction036)
 *   Support: BCryptGenRandom added in Windows Vista (2007).
 *            RtlGenRandom added in Windows XP (2001).
 *
 * Linux/Android:
 *   Source: getrandom(2)
 *   Fallback 1: /dev/urandom (after polling /dev/random)
 *   Fallback 2: _sysctl(2) w/ kern.random.uuid
 *   Support: getrandom(2) added in Linux 3.17 (2014).
 *            /dev/urandom added in Linux 1.3.30 (1995).
 *            _sysctl(2) added in Linux 1.3.57 (1995).
 *            _sysctl(2) deprecated in Linux 2.6.24 (2008).
 *            _sysctl(2) removed in Linux 5.5 (2020).
 *            kern.random.uuid added in Linux 2.3.16 (1999).
 *
 * OSX/iOS/tvOS/watchOS:
 *   Source: getentropy(2)
 *   Fallback: /dev/random (identical to /dev/urandom)
 *   Support: getentropy(2) added in OSX 10.12 (2016).
 *            getentropy(2) added in iOS 10.0 (2016).
 *            getentropy(2) added in tvOS 10.0 (2016).
 *            getentropy(2) added in watchOS 3.0 (2016).
 *
 * FreeBSD:
 *   Source: getrandom(2)
 *   Fallback 1: sysctl(2) w/ kern.arandom
 *   Fallback 2: /dev/urandom
 *   Support: getrandom(2) added in FreeBSD 12.0 (2018).
 *            kern.arandom added in FreeBSD 7.0 (2008).
 *            kern.arandom modernized in FreeBSD 7.1 (2009).
 *
 * OpenBSD:
 *   Source: getentropy(2)
 *   Fallback 1: sysctl(2) w/ kern.arandom
 *   Fallback 2: /dev/urandom
 *   Support: getentropy(2) added in OpenBSD 5.6 (2014).
 *            kern.arandom added in OpenBSD 2.6 (1999).
 *            kern.arandom modernized in OpenBSD 3.8 (2005).
 *            kern.arandom removed in OpenBSD 6.1 (2017).
 *
 * NetBSD:
 *   Source: sysctl(2) w/ kern.arandom
 *   Fallback: /dev/urandom
 *   Support: kern.arandom added in NetBSD 2.0 (2004).
 *            kern.arandom modernized in NetBSD 4.0 (2007).
 *
 * DragonFly BSD:
 *   Source: getrandom(2)
 *   Fallback: /dev/random
 *   Support: getrandom(2) added in DragonFly BSD 5.8 (2020).
 *
 * Solaris/Illumos:
 *   Source: getrandom(2)
 *   Fallback: /dev/random
 *   Support: getrandom(2) added in Solaris 11.3 (2015) (SunOS 5.11.3).
 *
 * IBM i (PASE):
 *   Source: /dev/urandom
 *   Fallback: none
 *
 * AIX:
 *   Source: /dev/random
 *   Fallback: none
 *
 * Haiku:
 *   Source: /dev/random
 *   Fallback: none
 *
 * Redox:
 *   Source: rand:
 *   Fallback: none
 *
 * Unix:
 *   Source: /dev/urandom
 *   Fallback: /dev/random
 *
 * VxWorks:
 *   Source: randABytes (after polling randSecure)
 *   Fallback: none
 *   Support: randABytes added in VxWorks 7 (2016).
 *
 * Fuchsia:
 *   Source: zx_cprng_draw(2)
 *   Fallback: none
 *
 * CloudABI:
 *   Source: cloudabi_sys_random_get
 *   Fallback: none
 *
 * WASI:
 *   Source: __wasi_random_get
 *   Fallback: none
 *
 * Emscripten (wasm, asm.js):
 *   Browser:
 *     Source: window.crypto.getRandomValues
 *     Fallback: none
 *   Node.js
 *     Source: crypto.randomFillSync
 *     Fallback: none
 *
 * [1] https://docs.rs/getrandom/0.1.14/getrandom/
 */

#if defined(__linux__) && !defined(_GNU_SOURCE)
/* For syscall(2). */
#  define _GNU_SOURCE
#endif

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "entropy.h"

#undef HAVE_BCRYPTGENRANDOM
#undef HAVE_RANDABYTES
#undef HAVE_GETRANDOM
#undef HAVE_SYSCTL_UUID
#undef HAVE_GETENTROPY
#undef HAVE_SYSCTL_ARND
#undef HAVE_DEV_RANDOM
#undef HAVE_GETPID
#undef DEV_RANDOM_NAME
#undef ALT_RANDOM_NAME

#if defined(_WIN32)
#  include <windows.h> /* _WIN32_WINNT */
#  if defined(_MSC_VER) && _MSC_VER > 1500 /* VS 2008 */ \
   && defined(_WIN32_WINNT) && _WIN32_WINNT >= 0x0600 /* Vista (2007) */
#    include <bcrypt.h> /* BCryptGenRandom */
#    ifndef STATUS_SUCCESS
#      define STATUS_SUCCESS ((NTSTATUS)0)
#    endif
#    pragma comment(lib, "bcrypt.lib")
#    define HAVE_BCRYPTGENRANDOM
#  else
#    define RtlGenRandom SystemFunction036
BOOLEAN NTAPI
RtlGenRandom(PVOID RandomBuffer, ULONG RandomBufferLength);
#    pragma comment(lib, "advapi32.lib")
#  endif
#elif defined(__vxworks)
#  include <version.h>
#  if defined(_WRS_VXWORKS_MAJOR) && _WRS_VXWORKS_MAJOR >= 7 /* 7 (2016) */
#    include <randomNumGen.h> /* randABytes, randSecure */
#    include <taskLib.h> /* taskDelay */
#    define HAVE_RANDABYTES
#  endif
#elif defined(__Fuchsia__) || defined(__fuchsia__)
#  include <zircon/syscalls.h> /* zx_cprng_draw */
#elif defined(__CloudABI__)
#  include <cloudabi_syscalls.h> /* cloudabi_sys_random_get */
#elif defined(__EMSCRIPTEN__)
#  include <emscripten.h> /* EM_JS */
#elif defined(__wasi__)
#  include <wasi/api.h> /* __wasi_random_get */
#elif defined(__unix) || defined(__unix__)     \
  || (defined(__APPLE__) && defined(__MACH__))
#  include <sys/types.h> /* open */
#  include <sys/stat.h> /* open, stat */
#  include <fcntl.h> /* open, fcntl */
#  include <unistd.h> /* stat, read, close, syscall */
#  if defined(__linux__)
#    include <poll.h> /* poll */
#    include <sys/syscall.h> /* syscall */
#    if defined(SYS_getrandom) && defined(__NR_getrandom) /* 3.17 (2014) */
#      define getrandom(buf, len, flags) syscall(SYS_getrandom, buf, len, flags)
#      define HAVE_GETRANDOM
#    endif
#    if defined(SYS__sysctl) && defined(__NR__sysctl) /* 2.3.16 (1999) */
#      define HAVE_SYSCTL_UUID
#    endif
#    define DEV_RANDOM_NAME "/dev/urandom"
#  elif defined(__APPLE__)
#    include <AvailabilityMacros.h>
#    if MAC_OS_X_VERSION_MAX_ALLOWED >= 101200 /* 10.12 (2016) */
#      include <sys/random.h> /* getentropy */
#      define HAVE_GETENTROPY
#    endif
#    define DEV_RANDOM_NAME "/dev/random"
#  elif defined(__FreeBSD__) || defined(__FreeBSD_kernel__)
#    include <sys/param.h>
#    if defined(__FreeBSD_version) && __FreeBSD_version >= 1200000 /* 12.0 (2018) */
#      include <sys/random.h> /* getrandom, getentropy */
#      define HAVE_GETRANDOM
#      define HAVE_GETENTROPY
#    endif
#    if defined(__FreeBSD_version) && __FreeBSD_version >= 701000 /* 7.1 (2009) */
#      include <sys/sysctl.h> /* sysctl */
#      if defined(CTL_KERN) && defined(KERN_ARND)
#        define HAVE_SYSCTL_ARND
#      endif
#    endif
#    define DEV_RANDOM_NAME "/dev/urandom"
#  elif defined(__OpenBSD__)
#    include <sys/param.h>
#    if defined(OpenBSD) && OpenBSD >= 201411 /* 5.6 (2014) */
#      define HAVE_GETENTROPY /* resides in unistd.h */
#    endif
#    if defined(OpenBSD) && OpenBSD >= 200511 /* 3.8 (2005) */
#      include <sys/sysctl.h> /* sysctl */
#      if defined(CTL_KERN) && defined(KERN_ARND)
#        define HAVE_SYSCTL_ARND
#      endif
#    endif
#    define DEV_RANDOM_NAME "/dev/urandom"
#  elif defined(__NetBSD__)
#    include <sys/param.h>
#    if defined(__NetBSD_Version__) && __NetBSD_Version__ >= 400000000 /* 4.0 (2007) */
#      include <sys/sysctl.h> /* sysctl */
#      if defined(CTL_KERN) && defined(KERN_ARND)
#        define HAVE_SYSCTL_ARND
#      endif
#    endif
#    define DEV_RANDOM_NAME "/dev/urandom"
#  elif defined(__DragonFly__)
#    include <sys/param.h>
#    if defined(__DragonFly_version) && __DragonFly_version >= 500800 /* 5.8 (2020) */
#      include <sys/random.h> /* getrandom */
#      define HAVE_GETRANDOM
#    endif
#    define DEV_RANDOM_NAME "/dev/random"
#  elif defined(__sun) && defined(__SVR4) /* 11.3 (2015) */
#    if defined(__SUNPRO_C) && __SUNPRO_C >= 0x5140 /* 5.14 (2016) */
#      include <sys/random.h> /* getrandom */
#      define HAVE_GETRANDOM
#    endif
#    define DEV_RANDOM_NAME "/dev/random"
#  elif defined(__PASE__)
#    define DEV_RANDOM_NAME "/dev/urandom"
#  elif defined(_AIX)
#    define DEV_RANDOM_NAME "/dev/random"
#  elif defined(__HAIKU__)
#    define DEV_RANDOM_NAME "/dev/random"
#  elif defined(__redox__)
#    define DEV_RANDOM_NAME "rand:"
#  else
#    define DEV_RANDOM_NAME "/dev/urandom"
#    define ALT_RANDOM_NAME "/dev/random"
#  endif
#  ifdef __GNUC__
#    pragma GCC diagnostic ignored "-Waddress"
#  endif
#  ifndef S_ISNAM
#    define S_ISNAM(x) 0
#  endif
#  define HAVE_DEV_RANDOM
#  define HAVE_GETPID
#endif

/*
 * Helpers
 */

#ifdef HAVE_DEV_RANDOM
static int
torsion_open(const char *name, int flags) {
  int fd, r;

#ifdef O_CLOEXEC
  fd = open(name, flags | O_CLOEXEC);

  if (fd != -1 || errno != EINVAL)
    return fd;
#endif

  fd = open(name, flags);

#if defined(F_GETFD) && defined(F_SETFD) && defined(FD_CLOEXEC)
  if (fd == -1)
    return fd;

  do {
    r = fcntl(fd, F_GETFD);
  } while (r == -1 && errno == EINTR);

  if (r == -1)
    return fd;

  flags = r | FD_CLOEXEC;

  do {
    r = fcntl(fd, F_SETFD, flags);
  } while (r == -1 && errno == EINTR);
#else
  (void)r;
#endif

  return fd;
}
#endif /* HAVE_DEV_RANDOM */

/*
 * Emscripten Entropy
 */

#ifdef __EMSCRIPTEN__
EM_JS(unsigned short, js_random_get, (unsigned char *dst, unsigned long len), {
  if (ENVIRONMENT_IS_NODE) {
    var crypto = module.require('crypto');
    var buf = Buffer.from(HEAPU8.buffer, dst, len);

    try {
      crypto.randomFillSync(buf, 0, len);
    } catch (e) {
      return 1;
    }

    return 0;
  }

  if (ENVIRONMENT_IS_WEB || ENVIRONMENT_IS_WORKER) {
    var global = ENVIRONMENT_IS_WORKER ? self : window;
    var crypto = global.crypto || global.msCrypto;
    var max = 65536;

    if (!crypto || !crypto.getRandomValues)
      return 1;

    while (len > 0) {
      if (max > len)
        max = len;

      var buf = HEAPU8.subarray(dst, dst + max);

      crypto.getRandomValues(buf);

      dst += max;
      len -= max;
    }

    return 0;
  }

  if (ENVIRONMENT_IS_SHELL) {
    while (len--)
      HEAPU8[dst++] = Math.floor(Math.random() * 0x100);

    return 0;
  }

  return 1;
})
#endif /* __EMSCRIPTEN__ */

/*
 * Syscall Entropy
 */

static int
torsion_callrand(void *dst, size_t size) {
#if defined(HAVE_BCRYPTGENRANDOM) /* _WIN32 */
  return BCryptGenRandom(NULL, (PUCHAR)dst, (ULONG)size,
                         BCRYPT_USE_SYSTEM_PREFERRED_RNG) == STATUS_SUCCESS;
#elif defined(_WIN32)
  return RtlGenRandom((PVOID)dst, (ULONG)size) == TRUE;
#elif defined(HAVE_RANDABYTES) /* __vxworks */
  unsigned char *data = (unsigned char *)dst;
  size_t max = (size_t)INT_MAX;
  int ret;

  for (;;) {
    ret = randSecure();

    if (ret != 0)
      break;

    taskDelay(5);
  }

  if (ret != 1)
    return 0;

  while (size > 0) {
    if (max > size)
      max = size;

    ret = randABytes(data, (int)max);

    if (ret != 0)
      return 0;

    data += max;
    size -= max;
  }

  return 1;
#elif defined(__Fuchsia__) || defined(__fuchsia__)
  zx_cprng_draw(dst, size);
  return 1;
#elif defined(__CloudABI__)
  return cloudabi_sys_random_get(dst, size) == 0;
#elif defined(__EMSCRIPTEN__)
  return js_random_get((uint8_t *)dst, size) == 0;
#elif defined(__wasi__)
  return __wasi_random_get((uint8_t *)dst, size) == 0;
#elif defined(HAVE_GETRANDOM)
  unsigned char *data = (unsigned char *)dst;
  size_t max = 256;
  int nread;

  while (size > 0) {
    if (max > size)
      max = size;

    do {
      nread = getrandom(data, max, 0);
    } while (nread < 0 && (errno == EINTR || errno == EAGAIN));

    if (nread < 0)
      return 0;

    if ((size_t)nread > max)
      abort();

    data += nread;
    size -= nread;
  }

  return 1;
#elif defined(HAVE_GETENTROPY)
  unsigned char *data = (unsigned char *)dst;
  size_t max = 256;

#ifdef __APPLE__
  /* Apple uses weak symbols depending on
     the minimum OS version requested. */
  if (getentropy == NULL)
    return 0;
#endif

  while (size > 0) {
    if (max > size)
      max = size;

    if (getentropy(data, max) != 0)
      return 0;

    data += max;
    size -= max;
  }

  return 1;
#elif defined(HAVE_SYSCTL_ARND)
  static int name[2] = {CTL_KERN, KERN_ARND};
  unsigned char *data = (unsigned char *)dst;
  size_t max = 256;
  size_t nread;

  while (size > 0) {
    if (max > size)
      max = size;

    nread = max;

    if (sysctl(name, 2, data, &nread, NULL, 0) != 0)
      return 0;

    if (nread > max)
      abort();

    data += nread;
    size -= nread;
  }

  return 1;
#else
  (void)dst;
  (void)size;
  return 0;
#endif
}

/*
 * Device Entropy
 */

#ifdef HAVE_DEV_RANDOM
static int
torsion_devrand(const char *name, void *dst, size_t size) {
  unsigned char *data = (unsigned char *)dst;
  struct stat st;
  int fd, nread;
#ifdef __linux__
  struct pollfd pfd;
  int r;

  do {
    fd = torsion_open("/dev/random", O_RDONLY);
  } while (fd == -1 && errno == EINTR);

  if (fd == -1)
    return 0;

  if (fstat(fd, &st) != 0)
    goto fail;

  if (!S_ISCHR(st.st_mode))
    goto fail;

  pfd.fd = fd;
  pfd.events = POLLIN;
  pfd.revents = 0;

  do {
    r = poll(&pfd, 1, -1);
  } while (r == -1 && errno == EINTR);

  if (r != 1)
    goto fail;

  close(fd);
#endif

  do {
    fd = torsion_open(name, O_RDONLY);
  } while (fd == -1 && errno == EINTR);

  if (fd == -1)
    return 0;

  if (fstat(fd, &st) != 0)
    goto fail;

  if (!S_ISCHR(st.st_mode) && !S_ISNAM(st.st_mode))
    goto fail;

  while (size > 0) {
    do {
      nread = read(fd, data, size);
    } while (nread < 0 && (errno == EINTR || errno == EAGAIN));

    if (nread <= 0)
      break;

    if ((size_t)nread > size)
      abort();

    data += nread;
    size -= nread;
  }

fail:
  close(fd);

  return size == 0;
}
#endif /* HAVE_DEV_RANDOM */

/*
 * Random UUID (Linux)
 */

#ifdef HAVE_SYSCTL_UUID
struct torsion__sysctl_args {
  int *name;
  int nlen;
  void *oldval;
  size_t *oldlenp;
  void *newval;
  size_t newlen;
  unsigned long unused[4];
};

static int
torsion_uuidrand(void *dst, size_t size) {
  /* Called if we cannot open /dev/urandom (idea from libuv). */
  static int name[3] = {1, 40, 6}; /* kern.random.uuid */
  struct torsion__sysctl_args args;
  unsigned char *data = dst;
  size_t max = 14;
  char uuid[16];
  size_t nread;

  while (size > 0) {
    nread = sizeof(uuid);

    memset(&args, 0, sizeof(args));

    args.name = name;
    args.nlen = 3;
    args.oldval = uuid;
    args.oldlenp = &nread;

    if (syscall(SYS__sysctl, &args) == -1)
      return 0;

    if (nread != sizeof(uuid))
      return 0;

    uuid[6] = uuid[14];
    uuid[8] = uuid[15];

    if (max > size)
      max = size;

    memcpy(data, uuid, max);

    data += max;
    size -= max;
  }

  return 1;
}
#endif /* HAVE_SYSCTL_UUID */

/*
 * PID (exposed for a fork-aware RNG)
 */

uint64_t
torsion_getpid(void) {
#if defined(HAVE_GETPID)
  return (uint64_t)getpid();
#else
  return 0;
#endif
}

/*
 * Entropy
 */

int
torsion_sysrand(void *dst, size_t size) {
  if (size == 0)
    return 1;

  if (torsion_callrand(dst, size))
    return 1;

#ifdef DEV_RANDOM_NAME
  if (torsion_devrand(DEV_RANDOM_NAME, dst, size))
    return 1;
#endif

#ifdef ALT_RANDOM_NAME
  if (torsion_devrand(ALT_RANDOM_NAME, dst, size))
    return 1;
#endif

#ifdef HAVE_SYSCTL_UUID
  if (torsion_uuidrand(dst, size))
    return 1;
#endif

  return 0;
}
