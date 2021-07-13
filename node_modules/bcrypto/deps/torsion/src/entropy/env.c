/*!
 * env.c - entropy gathering for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 *
 * Parts of this software are based on bitcoin/bitcoin:
 *   Copyright (c) 2009-2019, The Bitcoin Core Developers (MIT License).
 *   Copyright (c) 2009-2019, The Bitcoin Developers (MIT License).
 *   https://github.com/bitcoin/bitcoin
 *
 * Resources:
 *   https://github.com/bitcoin/bitcoin/blob/master/src/randomenv.cpp
 */

/**
 * Entropy Gathering
 *
 * Most ideas for entropy gathering here are taken from Bitcoin Core.
 * We more or less faithfully port randomenv.cpp to C (see above).
 * Our primary difference is that we add more win32 entropy sources.
 *
 * There are many sources of entropy on a given OS. This includes:
 *
 *   - Clocks (Get{System,Local}Time, gettimeofday, clock_gettime)
 *   - Environment Variables (GetEnvironmentStringsA, char **environ)
 *   - Network Interfaces (GetAdaptersAddresses, getifaddrs(3))
 *   - Kernel Information (GetSystemInfo, uname(2))
 *   - CPU Information (cpuid)
 *   - Machine Hostname (GetComputerNameExA, gethostname(3))
 *   - Process/User/Group IDs (GetCurrentProcessId, GetCurrentThreadId,
 *                             getpid(3), getppid(3), getsid(3), getpgid(3),
 *                             getuid(3), geteuid(3), getgid(3), getegid(3))
 *   - Resource Usage (GetProcessTimes, GetProcessMemoryInfo,
 *                     GetProcessIoCounters, GetSystemTimes,
 *                     GlobalMemoryStatusEx, GetDiskFreeSpaceExA,
 *                     getrusage(3))
 *   - Disk Usage (GetDiskFreeSpaceExA, /proc/diskstats, HW_DISKSTATS)
 *   - Pointers (stack and heap locations)
 *   - File Descriptors (the underlying integer)
 *   - stat(2) calls on system files & directories
 *   - System files (/etc/{passwd,group,hosts,resolv.conf,timezone})
 *   - HKEY_PERFORMANCE_DATA (win32)
 *   - The /proc filesystem (linux)
 *   - sysctl(2) (osx, ios, bsd)
 *   - I/O timing, system load
 *
 * We use whatever data we can get our hands on and hash it
 * into a single 64 byte seed for use with a PRNG.
 *
 * Note that in the past, we used HKEY_PERFORMANCE_DATA as an
 * entropy source on Windows, however, reading this data from
 * the Windows registry proved to be unacceptably slow (taking
 * up to ~2 seconds in some cases!). If the person building
 * this library requires significantly more entropy, it can
 * be re-enabled by defining TORSION_USE_PERFDATA.
 */

#if !defined(_WIN32) && !defined(_GNU_SOURCE)
/* For gethostname(3), getsid(3), getpgid(3),
   clock_gettime(2), dl_iterate_phdr(3). */
#  define _GNU_SOURCE
#endif

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <torsion/hash.h>
#include "entropy.h"

#undef HAVE_MANUAL_ENTROPY
#undef HAVE_DLITERATEPHDR
#undef HAVE_GETIFADDRS
#undef HAVE_GETAUXVAL
#undef HAVE_SYSCTL
#undef HAVE_CLOCK_GETTIME
#undef HAVE_GETHOSTNAME
#undef HAVE_GETSID
#undef HAVE_OS_IPHONE

#if defined(_WIN32)
#  include <winsock2.h> /* required by iphlpapi.h */
#  include <iphlpapi.h> /* GetAdaptersAddresses */
#  include <psapi.h> /* GetProcessMemoryInfo */
#  include <windows.h>
#  pragma comment(lib, "advapi32.lib") /* GetUserNameA, RegQueryValueExA */
#  pragma comment(lib, "iphlpapi.lib")
#  pragma comment(lib, "kernel32.lib")
#  pragma comment(lib, "psapi.lib")
#  define HAVE_MANUAL_ENTROPY
#elif defined(__vxworks)
/* Unsupported. */
#elif defined(__Fuchsia__) || defined(__fuchsia__)
/* Unsupported. */
#elif defined(__CloudABI__)
/* Could gather static entropy from filesystem in the future. */
#elif defined(__EMSCRIPTEN__)
/* No reliable entropy sources available for emscripten. */
#elif defined(__wasi__)
/* Could gather static entropy from args/env in the future. */
#elif defined(__unix) || defined(__unix__)     \
  || (defined(__APPLE__) && defined(__MACH__))
#  include <sys/types.h> /* open */
#  include <sys/stat.h> /* open, stat */
#  include <sys/time.h> /* gettimeofday, timeval */
#  include <sys/resource.h> /* getrusage */
#  include <sys/utsname.h> /* uname */
#  include <fcntl.h> /* open */
#  include <unistd.h> /* stat, read, close, gethostname */
#  include <time.h> /* clock_gettime */
#  ifdef __linux__
#    if defined(__GLIBC_PREREQ)
#      define TORSION_GLIBC_PREREQ(maj, min) __GLIBC_PREREQ(maj, min)
#    else
#      define TORSION_GLIBC_PREREQ(maj, min) 0
#    endif
#    if TORSION_GLIBC_PREREQ(2, 3)
#      if defined(__GNUC__) && defined(__SIZEOF_INT128__)
#        include <link.h> /* dl_iterate_phdr */
#        define HAVE_DLITERATEPHDR
#      endif
#      include <sys/socket.h> /* AF_INET{,6} */
#      include <netinet/in.h> /* sockaddr_in{,6} */
#      include <ifaddrs.h> /* getifaddrs */
#      define HAVE_GETIFADDRS
#    endif
#    if TORSION_GLIBC_PREREQ(2, 16)
#      include <sys/auxv.h> /* getauxval */
#      define HAVE_GETAUXVAL
#    endif
#  endif
#  if defined(__APPLE__)     \
   || defined(__FreeBSD__)   \
   || defined(__OpenBSD__)   \
   || defined(__NetBSD__)    \
   || defined(__DragonFly__)
#    include <sys/sysctl.h> /* sysctl */
#    include <sys/socket.h> /* AF_INET{,6} */
#    include <netinet/in.h> /* sockaddr_in{,6} */
#    include <ifaddrs.h> /* getifaddrs */
#    define HAVE_SYSCTL
#    define HAVE_GETIFADDRS
#  endif
#  if defined(__FreeBSD__) || defined(__DragonFly__)
#    include <vm/vm_param.h> /* VM_{LOADAVG,TOTAL,METER} */
#  endif
#  ifdef __APPLE__
#    include <TargetConditionals.h>
#    if defined(TARGET_OS_IPHONE) && TARGET_OS_IPHONE
#      define HAVE_OS_IPHONE
#    endif
#  endif
#  if defined(__APPLE__) && !defined(HAVE_OS_IPHONE)
#    include <crt_externs.h>
#    define environ (*_NSGetEnviron())
#  else
#    ifndef environ
extern char **environ;
#    endif
#  endif
#  ifdef _POSIX_VERSION
#    if _POSIX_VERSION >= 199309L
#      if defined(CLOCK_REALTIME) || defined(CLOCK_MONOTONIC)
#        define HAVE_CLOCK_GETTIME
#      endif
#    endif
#    if _POSIX_VERSION >= 200112L
#      define HAVE_GETHOSTNAME
#    endif
#    if _POSIX_VERSION >= 200809L
#      define HAVE_GETSID
#    endif
#  endif
#  ifdef __GNUC__
#    pragma GCC diagnostic ignored "-Waddress"
#  endif
#  define HAVE_MANUAL_ENTROPY
#endif

#ifdef HAVE_MANUAL_ENTROPY
static void
sha512_write(sha512_t *hash, const void *data, size_t size) {
  sha512_update(hash, data, size);
}

static void
sha512_write_data(sha512_t *hash, const void *data, size_t size) {
  sha512_write(hash, &size, sizeof(size));
  sha512_write(hash, data, size);
}

static void
sha512_write_string(sha512_t *hash, const char *str) {
  sha512_write_data(hash, str, str == NULL ? 0 : strlen(str));
}

static void
sha512_write_int(sha512_t *hash, uint64_t num) {
  sha512_write(hash, &num, sizeof(num));
}

static void
sha512_write_tsc(sha512_t *hash) {
  sha512_write_int(hash, torsion_rdtsc());
}

static void
sha512_write_ptr(sha512_t *hash, const void *ptr) {
#if defined(UINTPTR_MAX)
  uintptr_t uptr = (uintptr_t)ptr;
#else
  size_t uptr = (size_t)ptr;
#endif

  sha512_write(hash, &uptr, sizeof(uptr));
}

#ifndef _WIN32
static void
sha512_write_stat(sha512_t *hash, const char *file) {
  struct stat st;

  memset(&st, 0, sizeof(st));

  if (stat(file, &st) == 0) {
    sha512_write_string(hash, file);
    sha512_write(hash, &st, sizeof(st));
  }
}

static void
sha512_write_file(sha512_t *hash, const char *file) {
  unsigned char buf[4096];
  size_t total = 0;
  struct stat st;
  int fd, nread;

  memset(&st, 0, sizeof(st));

  do {
#if defined(O_CLOEXEC)
    fd = open(file, O_RDONLY | O_CLOEXEC);

    if (fd == -1 && errno == EINVAL)
      fd = open(file, O_RDONLY);
#else
    fd = open(file, O_RDONLY);
#endif
  } while (fd == -1 && errno == EINTR);

  if (fd == -1)
    return;

  if (fstat(fd, &st) != 0)
    goto done;

  sha512_write_string(hash, file);
  sha512_write_int(hash, fd);
  sha512_write(hash, &st, sizeof(st));

  do {
    do {
      nread = read(fd, buf, sizeof(buf));
    } while (nread < 0 && (errno == EINTR || errno == EAGAIN));

    if (nread <= 0)
      break;

    if ((size_t)nread > sizeof(buf))
      abort();

    sha512_write(hash, buf, nread);

    total += nread;
  } while (total < 1048576);

done:
  close(fd);
}
#endif /* !_WIN32 */

#ifdef HAVE_DLITERATEPHDR
static int
sha512_write_phdr(struct dl_phdr_info *info, size_t size, void *data) {
  sha512_t *hash = data;

  (void)size;

  sha512_write(hash, &info->dlpi_addr, sizeof(info->dlpi_addr));
  sha512_write_ptr(hash, info->dlpi_name);
  sha512_write_string(hash, info->dlpi_name);
  sha512_write_ptr(hash, info->dlpi_phdr);

  return 0;
}
#endif /* HAVE_DLITERATEPHDR */

#ifdef HAVE_GETIFADDRS
static void
sha512_write_sockaddr(sha512_t *hash, const struct sockaddr *addr) {
  if (addr == NULL)
    return;

  sha512_write_ptr(hash, addr);

  switch (addr->sa_family) {
    case AF_INET:
      sha512_write(hash, addr, sizeof(struct sockaddr_in));
      break;
#ifdef AF_INET6
    case AF_INET6:
      sha512_write(hash, addr, sizeof(struct sockaddr_in6));
      break;
#endif
    default:
      sha512_write(hash, &addr->sa_family, sizeof(addr->sa_family));
      break;
  }
}
#endif /* HAVE_GETIFADDRS */

#ifdef HAVE_SYSCTL
static void
sha512_write_sysctl(sha512_t *hash, int *name, unsigned int namelen) {
  unsigned char buf[65536];
  size_t size = sizeof(buf);
  int ret;

  ret = sysctl(name, namelen, buf, &size, NULL, 0);

  if (ret == 0 || (ret == -1 && errno == ENOMEM)) {
    sha512_write_data(hash, name, namelen * sizeof(int));

    if (size > sizeof(buf))
      size = sizeof(buf);

    sha512_write_data(hash, buf, size);
  }
}

static void
sha512_write_sysctl2(sha512_t *hash, int ctl, int opt) {
  int name[2];

  name[0] = ctl;
  name[1] = opt;

  sha512_write_sysctl(hash, name, 2);
}

static void
sha512_write_sysctl3(sha512_t *hash, int ctl, int opt, int sub) {
  int name[3];

  name[0] = ctl;
  name[1] = opt;
  name[2] = sub;

  sha512_write_sysctl(hash, name, 3);
}
#endif /* HAVE_SYSCTL */

static void
sha512_write_cpuid(sha512_t *hash,
                   uint32_t *ax, uint32_t *bx,
                   uint32_t *cx, uint32_t *dx,
                   uint32_t leaf, uint32_t subleaf) {
  torsion_cpuid(ax, bx, cx, dx, leaf, subleaf);

  sha512_write_int(hash, leaf);
  sha512_write_int(hash, subleaf);
  sha512_write_int(hash, *ax);
  sha512_write_int(hash, *bx);
  sha512_write_int(hash, *cx);
  sha512_write_int(hash, *dx);
}

static void
sha512_write_cpuids(sha512_t *hash) {
  uint32_t max, leaf, maxsub, subleaf, maxext;
  uint32_t ax, bx, cx, dx;

  /* Iterate over all standard leaves. */
  sha512_write_cpuid(hash, &ax, &bx, &cx, &dx, 0, 0);

  /* Max leaf in ax. */
  max = ax;

  for (leaf = 1; leaf <= max && leaf <= 0xff; leaf++) {
    maxsub = 0;

    for (subleaf = 0; subleaf <= 0xff; subleaf++) {
      sha512_write_cpuid(hash, &ax, &bx, &cx, &dx, leaf, subleaf);

      /* Iterate subleafs for leaf values 4, 7, 11, 13. */
      if (leaf == 4) {
        if ((ax & 0x1f) == 0)
          break;
      } else if (leaf == 7) {
        if (subleaf == 0)
          maxsub = ax;

        if (subleaf == maxsub)
          break;
      } else if (leaf == 11) {
        if ((cx & 0xff00) == 0)
          break;
      } else if (leaf == 13) {
        if (ax == 0 && bx == 0 && cx == 0 && dx == 0)
          break;
      } else {
        /* For any other leaf, stop after subleaf 0. */
        break;
      }
    }
  }

  /* Iterate over all extended leaves. */
  sha512_write_cpuid(hash, &ax, &bx, &cx, &dx, 0x80000000, 0);

  /* Max extended leaf in ax. */
  maxext = ax;

  for (leaf = 0x80000001; leaf <= maxext && leaf <= 0x800000ff; leaf++)
    sha512_write_cpuid(hash, &ax, &bx, &cx, &dx, leaf, 0);
}

#ifdef _WIN32
#ifdef TORSION_USE_PERFDATA
/* This function is extraordinarily slow.
   We prefer not to use it as we have more
   win32 entropy sources than Bitcoin Core. */
static void
sha512_write_perfdata(sha512_t *hash, size_t max) {
  size_t size = max < 80 ? max : max / 40;
  BYTE *data = malloc(size);
  DWORD nread;
  LSTATUS ret;

  if (data == NULL)
    return;

  memset(data, 0, size);

  for (;;) {
    nread = size;
    ret = RegQueryValueExA(HKEY_PERFORMANCE_DATA,
                           "Global", NULL, NULL,
                           data, &nread);

    if (ret != ERROR_MORE_DATA || size >= max)
      break;

    size = (size * 3) / 2;

    if (size > max)
      size = max;

    data = realloc(data, size);

    if (data == NULL)
      break;

    memset(data, 0, size);
  }

  RegCloseKey(HKEY_PERFORMANCE_DATA);

  if (ret == ERROR_SUCCESS) {
    sha512_write_data(hash, data, nread);
#ifdef SecureZeroMemory
    SecureZeroMemory(data, nread);
#endif
  }

  if (data != NULL)
    free(data);
}
#endif /* TORSION_USE_PERFDATA */
#endif /* _WIN32 */

static void
sha512_write_static_env(sha512_t *hash) {
  /* Some compile-time static properties. */
  sha512_write_int(hash, CHAR_MIN < 0);
  sha512_write_int(hash, sizeof(void *));
  sha512_write_int(hash, sizeof(long));
  sha512_write_int(hash, sizeof(int));

#if defined(__GNUC__) && defined(__GNUC_MINOR__) && defined(__GNUC_PATCHLEVEL__)
  sha512_write_int(hash, __GNUC__);
  sha512_write_int(hash, __GNUC_MINOR__);
  sha512_write_int(hash, __GNUC_PATCHLEVEL__);
#endif

#if defined(__clang_major__)      \
 && defined(__clang_minor__)      \
 && defined(__clang_patchlevel__)
  sha512_write_int(hash, __clang_major__);
  sha512_write_int(hash, __clang_minor__);
  sha512_write_int(hash, __clang_patchlevel__);
#endif

#ifdef __INTEL_COMPILER
  sha512_write_int(hash, __INTEL_COMPILER);
#endif

#ifdef _MSC_VER
  sha512_write_int(hash, _MSC_VER);
#endif

#ifdef _WIN32_WINNT
  sha512_write_int(hash, _WIN32_WINNT);
#endif

#if defined(__GLIBC__) && defined(__GLIBC_MINOR__)
  sha512_write_int(hash, __GLIBC__);
  sha512_write_int(hash, __GLIBC_MINOR__);
#endif

#ifdef _POSIX_VERSION
  sha512_write_int(hash, _POSIX_VERSION);
#endif

#ifdef _XOPEN_VERSION
  sha512_write_int(hash, _XOPEN_VERSION);
#endif

#ifdef __VERSION__
  sha512_write_string(hash, __VERSION__);
#endif

#ifdef PACKAGE_STRING
  sha512_write_string(hash, PACKAGE_STRING);
#endif

  /* CPU features. */
  if (torsion_has_cpuid())
    sha512_write_cpuids(hash);

  /* Memory locations. */
  sha512_write_ptr(hash, hash);
  sha512_write_ptr(hash, &errno);
#ifndef _WIN32
  sha512_write_ptr(hash, &environ);
#endif

#if defined(_WIN32)
  /* System information. */
  {
    SYSTEM_INFO info;

    memset(&info, 0, sizeof(info));

    GetSystemInfo(&info);

    sha512_write(hash, &info, sizeof(info));
  }

  /* Performance frequency. */
  {
    LARGE_INTEGER freq;

    if (QueryPerformanceFrequency(&freq))
      sha512_write_int(hash, freq.QuadPart);
  }

  /* Disk information. */
  {
    char vname[MAX_PATH + 1];
    char fsname[MAX_PATH + 1];
    DWORD serial, maxcmp, flags;

    if (GetVolumeInformationA(NULL, vname, sizeof(vname),
                              &serial, &maxcmp, &flags,
                              fsname, sizeof(fsname))) {
      sha512_write_string(hash, vname);
      sha512_write_int(hash, serial);
      sha512_write_int(hash, maxcmp);
      sha512_write_int(hash, flags);
      sha512_write_string(hash, fsname);
    }

    sha512_write_int(hash, GetLogicalDrives());
  }

  /* Hostname. */
  {
    /* MAX_COMPUTERNAME_LENGTH is 15 or 31 depending,
       however, documentation explicitly states that
       a DNS hostname may be larger than this. */
    char hname[256 + 1];
    DWORD size = sizeof(hname);

    if (GetComputerNameExA(ComputerNameDnsHostname, hname, &size))
      sha512_write_string(hash, hname);
  }

  /* Network interfaces. */
  {
    IP_ADAPTER_ADDRESSES *addrs = NULL;
    ULONG flags = GAA_FLAG_INCLUDE_PREFIX;
    ULONG size = 0;
    ULONG ret;

    for (;;) {
      ret = GetAdaptersAddresses(AF_UNSPEC, flags, NULL, addrs, &size);

      if (ret == ERROR_BUFFER_OVERFLOW) {
        addrs = realloc(addrs, size);

        if (addrs == NULL)
          break;

        memset(addrs, 0, size);

        continue;
      }

      break;
    }

    if (ret == ERROR_SUCCESS)
      sha512_write_data(hash, addrs, size);

    if (addrs != NULL)
      free(addrs);
  }

  /* Current directory. */
  {
    char cwd[MAX_PATH + 1];
    DWORD len;

    len = GetCurrentDirectoryA(sizeof(cwd), cwd);

    if (len >= 1 && len <= MAX_PATH)
      sha512_write_string(hash, cwd);
  }

  /* Console title. */
  {
    char title[1024 + 1];

    if (GetConsoleTitleA(title, sizeof(title)))
      sha512_write_string(hash, title);
  }

  /* Command line. */
  {
    char *cmd = GetCommandLineA();

    if (cmd != NULL) {
      sha512_write_ptr(hash, cmd);
      sha512_write_string(hash, cmd);
    }
  }

  /* Environment variables. */
  {
    char *env = GetEnvironmentStringsA();

    if (env != NULL) {
      char *penv = env;

      sha512_write_ptr(hash, env);

      while (*penv != '\0') {
        sha512_write_string(hash, penv);
        penv += strlen(penv) + 1;
      }

      FreeEnvironmentStringsA(env);
    }
  }

  /* Username. */
  {
    char name[256 + 1]; /* UNLEN + 1 */
    DWORD size = sizeof(name);

    if (GetUserNameA(name, &size))
      sha512_write_string(hash, name);
  }

  /* Process/Thread ID. */
  sha512_write_int(hash, GetCurrentProcessId());
  sha512_write_int(hash, GetCurrentThreadId());
#else /* !_WIN32 */
  /* UNIX kernel information. */
  {
    struct utsname name;

    if (uname(&name) != -1) {
      sha512_write_string(hash, name.sysname);
      sha512_write_string(hash, name.nodename);
      sha512_write_string(hash, name.release);
      sha512_write_string(hash, name.version);
      sha512_write_string(hash, name.machine);
    }
  }

#ifdef HAVE_DLITERATEPHDR
  /* Shared objects. */
  dl_iterate_phdr(sha512_write_phdr, hash);
#endif /* HAVE_DLITERATEPHDR */

#ifdef HAVE_GETAUXVAL
  /* Information available through getauxval(). */
#ifdef AT_HWCAP
  sha512_write_int(hash, getauxval(AT_HWCAP));
#endif
#ifdef AT_HWCAP2
  sha512_write_int(hash, getauxval(AT_HWCAP2));
#endif
#ifdef AT_RANDOM
  {
    const unsigned char *random_aux =
      (const unsigned char *)getauxval(AT_RANDOM);

    if (random_aux != NULL) {
      sha512_write_ptr(hash, random_aux);
      sha512_write(hash, random_aux, 16);
    }
  }
#endif
#ifdef AT_PLATFORM
  {
    const char *platform_str = (const char *)getauxval(AT_PLATFORM);

    if (platform_str != NULL) {
      sha512_write_ptr(hash, platform_str);
      sha512_write_string(hash, platform_str);
    }
  }
#endif
#ifdef AT_EXECFN
  {
    const char *exec_str = (const char *)getauxval(AT_EXECFN);

    if (exec_str != NULL) {
      sha512_write_ptr(hash, exec_str);
      sha512_write_string(hash, exec_str);
    }
  }
#endif
#endif /* HAVE_GETAUXVAL */

  /* Hostname. */
#ifdef HAVE_GETHOSTNAME
  {
    /* HOST_NAME_MAX is 64 on Linux, but we go a
       bit bigger in case an OS has a higher value. */
    char hname[256 + 1];

    if (gethostname(hname, sizeof(hname)) == 0) {
      /* Handle impl-defined behavior. */
      hname[sizeof(hname) - 1] = '\0';
      sha512_write_string(hash, hname);
    }
  }
#endif /* HAVE_GETHOSTNAME */

#ifdef HAVE_GETIFADDRS
  /* Network interfaces. */
  {
    struct ifaddrs *ifad = NULL;

    if (getifaddrs(&ifad) == 0) {
      struct ifaddrs *ifit = ifad;

      while (ifit != NULL) {
        sha512_write_ptr(hash, ifit);
        sha512_write_string(hash, ifit->ifa_name);
        sha512_write_int(hash, ifit->ifa_flags);
        sha512_write_sockaddr(hash, ifit->ifa_addr);
        sha512_write_sockaddr(hash, ifit->ifa_netmask);
        sha512_write_sockaddr(hash, ifit->ifa_dstaddr);

        ifit = ifit->ifa_next;
      }

      freeifaddrs(ifad);
    }
  }
#endif /* HAVE_GETIFADDRS */

  /* Path and filesystem provided data. */
  sha512_write_stat(hash, "/");
  sha512_write_stat(hash, ".");
  sha512_write_stat(hash, "/tmp");
  sha512_write_stat(hash, "/home");
  sha512_write_stat(hash, "/proc");
#ifdef __linux__
  sha512_write_file(hash, "/proc/cmdline");
  sha512_write_file(hash, "/proc/cpuinfo");
  sha512_write_file(hash, "/proc/version");
#endif /* __linux__ */
  sha512_write_file(hash, "/etc/passwd");
  sha512_write_file(hash, "/etc/group");
  sha512_write_file(hash, "/etc/hosts");
  sha512_write_file(hash, "/etc/resolv.conf");
  sha512_write_file(hash, "/etc/timezone");
  sha512_write_file(hash, "/etc/localtime");

  /* Information available through sysctl(2). */
#ifdef HAVE_SYSCTL
  (void)sha512_write_sysctl2;
#ifdef CTL_HW
#ifdef HW_MACHINE
  sha512_write_sysctl2(hash, CTL_HW, HW_MACHINE);
#endif
#ifdef HW_MODEL
  sha512_write_sysctl2(hash, CTL_HW, HW_MODEL);
#endif
#ifdef HW_NCPU
  sha512_write_sysctl2(hash, CTL_HW, HW_NCPU);
#endif
#ifdef HW_PHYSMEM
  sha512_write_sysctl2(hash, CTL_HW, HW_PHYSMEM);
#endif
#ifdef HW_USERMEM
  sha512_write_sysctl2(hash, CTL_HW, HW_USERMEM);
#endif
#ifdef HW_MACHINE_ARCH
  sha512_write_sysctl2(hash, CTL_HW, HW_MACHINE_ARCH);
#endif
#ifdef HW_REALMEM
  sha512_write_sysctl2(hash, CTL_HW, HW_REALMEM);
#endif
#ifdef HW_CPU_FREQ
  sha512_write_sysctl2(hash, CTL_HW, HW_CPU_FREQ);
#endif
#ifdef HW_BUS_FREQ
  sha512_write_sysctl2(hash, CTL_HW, HW_BUS_FREQ);
#endif
#ifdef HW_CACHELINE
  sha512_write_sysctl2(hash, CTL_HW, HW_CACHELINE);
#endif
#endif /* CTL_HW */

#ifdef CTL_KERN
#ifdef KERN_BOOTFILE
  sha512_write_sysctl2(hash, CTL_KERN, KERN_BOOTFILE);
#endif
#ifdef KERN_BOOTTIME
  sha512_write_sysctl2(hash, CTL_KERN, KERN_BOOTTIME);
#endif
#ifdef KERN_CLOCKRATE
  sha512_write_sysctl2(hash, CTL_KERN, KERN_CLOCKRATE);
#endif
#ifdef KERN_HOSTID
  sha512_write_sysctl2(hash, CTL_KERN, KERN_HOSTID);
#endif
#ifdef KERN_HOSTUUID
  sha512_write_sysctl2(hash, CTL_KERN, KERN_HOSTUUID);
#endif
#ifdef KERN_HOSTNAME
  sha512_write_sysctl2(hash, CTL_KERN, KERN_HOSTNAME);
#endif
#ifdef KERN_OSRELDATE
  sha512_write_sysctl2(hash, CTL_KERN, KERN_OSRELDATE);
#endif
#ifdef KERN_OSRELEASE
  sha512_write_sysctl2(hash, CTL_KERN, KERN_OSRELEASE);
#endif
#ifdef KERN_OSREV
  sha512_write_sysctl2(hash, CTL_KERN, KERN_OSREV);
#endif
#ifdef KERN_OSTYPE
  sha512_write_sysctl2(hash, CTL_KERN, KERN_OSTYPE);
#endif
#ifdef KERN_POSIX1
  sha512_write_sysctl2(hash, CTL_KERN, KERN_OSREV);
#endif
#ifdef KERN_VERSION
  sha512_write_sysctl2(hash, CTL_KERN, KERN_VERSION);
#endif
#endif /* CTL_KERN */
#endif /* HAVE_SYSCTL */

  /* Current directory. */
  {
    char cwd[4096 + 1]; /* PATH_MAX + 1 */

    if (getcwd(cwd, sizeof(cwd)) != NULL)
      sha512_write_string(hash, cwd);
  }

  /* Environment variables. */
  if (environ != NULL) {
    size_t i;

    sha512_write_ptr(hash, environ);

    for (i = 0; environ[i] != NULL; i++)
      sha512_write_string(hash, environ[i]);
  }

  /* Process/User/Group IDs. */
  sha512_write_int(hash, getpid());
  sha512_write_int(hash, getppid());
#ifdef HAVE_GETSID
  sha512_write_int(hash, getsid(0));
  sha512_write_int(hash, getpgid(0));
#endif
  sha512_write_int(hash, getuid());
  sha512_write_int(hash, geteuid());
  sha512_write_int(hash, getgid());
  sha512_write_int(hash, getegid());
#endif /* !_WIN32 */
}

static void
sha512_write_dynamic_env(sha512_t *hash) {
#if defined(_WIN32)
  /* System time. */
  {
    FILETIME ftime;

    memset(&ftime, 0, sizeof(ftime));

    GetSystemTimeAsFileTime(&ftime);

    sha512_write(hash, &ftime, sizeof(ftime));
  }

  /* Various clocks. */
  {
    SYSTEMTIME stime, ltime;
    LARGE_INTEGER ctr;

    memset(&stime, 0, sizeof(stime));
    memset(&ltime, 0, sizeof(ltime));

    GetSystemTime(&stime);
    GetLocalTime(&ltime);

    sha512_write(hash, &stime, sizeof(stime));
    sha512_write(hash, &ltime, sizeof(ltime));
    sha512_write_int(hash, GetTickCount());

    if (QueryPerformanceCounter(&ctr))
      sha512_write_int(hash, ctr.QuadPart);
  }

  /* Current resource usage. */
  {
    FILETIME ctime, etime, ktime, utime;
    PROCESS_MEMORY_COUNTERS mctrs;
    IO_COUNTERS ioctrs;

    memset(&ctime, 0, sizeof(ctime));
    memset(&ktime, 0, sizeof(ktime));
    memset(&utime, 0, sizeof(utime));
    memset(&mctrs, 0, sizeof(mctrs));
    memset(&ioctrs, 0, sizeof(ioctrs));

    if (GetProcessTimes(GetCurrentProcess(), &ctime, &etime, &ktime, &utime)) {
      /* Exit time value is undefined (our process has not exited). */
      sha512_write(hash, &ctime, sizeof(ctime));
      sha512_write(hash, &ktime, sizeof(ktime));
      sha512_write(hash, &utime, sizeof(utime));
    }

    if (GetProcessMemoryInfo(GetCurrentProcess(), &mctrs, sizeof(mctrs)))
      sha512_write(hash, &mctrs, sizeof(mctrs));

    if (GetProcessIoCounters(GetCurrentProcess(), &ioctrs))
      sha512_write(hash, &ioctrs, sizeof(ioctrs));
  }

  /* CPU usage. */
  {
    FILETIME idle, kern, user;

    memset(&idle, 0, sizeof(idle));
    memset(&kern, 0, sizeof(kern));
    memset(&user, 0, sizeof(user));

    if (GetSystemTimes(&idle, &kern, &user)) {
      sha512_write(hash, &idle, sizeof(idle));
      sha512_write(hash, &kern, sizeof(kern));
      sha512_write(hash, &user, sizeof(user));
    }
  }

  /* Memory usage. */
  {
    MEMORYSTATUSEX status;

    memset(&status, 0, sizeof(status));

    status.dwLength = sizeof(status);

    if (GlobalMemoryStatusEx(&status))
      sha512_write(hash, &status, sizeof(status));
  }

  /* Disk usage. */
  {
    ULARGE_INTEGER caller, total, avail;

    if (GetDiskFreeSpaceExA(NULL, &caller, &total, &avail)) {
      sha512_write_int(hash, caller.QuadPart);
      sha512_write_int(hash, total.QuadPart);
      sha512_write_int(hash, avail.QuadPart);
    }
  }

#ifdef TORSION_USE_PERFDATA
  /* Performance data. */
  sha512_write_perfdata(hash, 10000000);
#endif
#else /* !_WIN32 */
  /* System time. */
  {
    struct timeval tv;

    memset(&tv, 0, sizeof(tv));

    if (gettimeofday(&tv, NULL) == 0)
      sha512_write(hash, &tv, sizeof(tv));
  }

#ifdef HAVE_CLOCK_GETTIME
  /* Various clocks. */
  if (clock_gettime != NULL) {
    struct timespec ts;

    memset(&ts, 0, sizeof(ts));

#ifdef CLOCK_REALTIME
    if (clock_gettime(CLOCK_REALTIME, &ts) == 0)
      sha512_write(hash, &ts, sizeof(ts));
#endif

#ifdef CLOCK_MONOTONIC
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
      sha512_write(hash, &ts, sizeof(ts));
#endif

#ifdef CLOCK_PROCESS_CPUTIME_ID
    if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts) == 0)
      sha512_write(hash, &ts, sizeof(ts));
#endif

#ifdef CLOCK_THREAD_CPUTIME_ID
    if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts) == 0)
      sha512_write(hash, &ts, sizeof(ts));
#endif

#ifdef CLOCK_BOOTTIME
    if (clock_gettime(CLOCK_BOOTTIME, &ts) == 0)
      sha512_write(hash, &ts, sizeof(ts));
#endif
  }
#endif /* HAVE_CLOCK_GETTIME */

  /* Current resource usage. */
  {
    struct rusage usage;

    memset(&usage, 0, sizeof(usage));

    if (getrusage(RUSAGE_SELF, &usage) == 0)
      sha512_write(hash, &usage, sizeof(usage));

#ifdef RUSAGE_THREAD
    if (getrusage(RUSAGE_THREAD, &usage) == 0)
      sha512_write(hash, &usage, sizeof(usage));
#endif
  }

#ifdef __linux__
  sha512_write_file(hash, "/proc/diskstats");
  sha512_write_file(hash, "/proc/vmstat");
  sha512_write_file(hash, "/proc/schedstat");
  sha512_write_file(hash, "/proc/zoneinfo");
  sha512_write_file(hash, "/proc/loadavg");
  sha512_write_file(hash, "/proc/meminfo");
  sha512_write_file(hash, "/proc/softirqs");
  sha512_write_file(hash, "/proc/stat");
  sha512_write_file(hash, "/proc/self/schedstat");
  sha512_write_file(hash, "/proc/self/status");
#endif

#ifdef HAVE_SYSCTL
  (void)sha512_write_sysctl3;
  (void)sha512_write_sysctl2;
#ifdef CTL_KERN
#if defined(KERN_PROC) && defined(KERN_PROC_ALL)
  sha512_write_sysctl3(hash, CTL_KERN, KERN_PROC, KERN_PROC_ALL);
#endif
#endif /* CTL_KERN */
#ifdef CTL_HW
#ifdef HW_DISKSTATS
  sha512_write_sysctl2(hash, CTL_HW, HW_DISKSTATS);
#endif
#endif /* CTL_HW */
#ifdef CTL_VM
#ifdef VM_LOADAVG
  sha512_write_sysctl2(hash, CTL_VM, VM_LOADAVG);
#endif
#ifdef VM_TOTAL
  sha512_write_sysctl2(hash, CTL_VM, VM_TOTAL);
#endif
#ifdef VM_METER
  sha512_write_sysctl2(hash, CTL_VM, VM_METER);
#endif
#endif /* CTL_VM */
#endif /* HAVE_SYSCTL */
#endif /* !_WIN32 */

  /* High-resolution time. */
  sha512_write_int(hash, torsion_hrtime());

  /* Stack and heap location. */
  {
    void *addr = malloc(4097);

    sha512_write_ptr(hash, &addr);

    if (addr != NULL) {
      sha512_write_ptr(hash, addr);
      free(addr);
    }
  }
}
#endif /* HAVE_MANUAL_ENTROPY */

int
torsion_envrand(unsigned char *seed) {
#if defined(HAVE_MANUAL_ENTROPY)
  sha512_t hash;
  sha512_init(&hash);
  sha512_write_ptr(&hash, seed);
  sha512_write_tsc(&hash);
  sha512_write_static_env(&hash);
  sha512_write_tsc(&hash);
  sha512_write_dynamic_env(&hash);
  sha512_write_tsc(&hash);
  sha512_final(&hash, seed);
  return 1;
#else /* !HAVE_MANUAL_ENTROPY */
  (void)seed;
  return 0;
#endif /* !HAVE_MANUAL_ENTROPY */
}
