# CMakeLists.txt - cmake build for libtorsion
# Copyright (c) 2020, Christopher Jeffrey (MIT License).
# https://github.com/bcoin-org/libtorsion

#
# Initialization
#

cmake_minimum_required(VERSION 3.4)
project(libtorsion LANGUAGES C)

#
# Includes
#

include(../../cmake/AppendCCompilerFlag.cmake)
include(../../cmake/CheckCThreadLocalStorage.cmake)
include(CheckCSourceCompiles)
include(NodeJS)

#
# Options
#

option(TORSION_ENABLE_ASM "Use inline x86-64 assembly if available" ON)
option(TORSION_ENABLE_CRT "Enable chinese remainder theorem for RSA" OFF)
option(TORSION_ENABLE_DEBUG "Enable debug build" OFF)
option(TORSION_ENABLE_INT128 "Use __int128 if available" ON)
option(TORSION_ENABLE_LIBSECP256K1 "Use libsecp256k1 field element backend" OFF)
option(TORSION_ENABLE_PTHREAD "Use pthread as a fallback for TLS" ON)
option(TORSION_ENABLE_TLS "Enable thread-local storage" ON)
option(TORSION_ENABLE_VERIFY "Enable scalar bounds checks" OFF)

#
# Flags
#

set(torsion_cflags)

set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 90)
set(CMAKE_OSX_DEPLOYMENT_TARGET 10.7)

if(MSVC)
  append_c_compiler_flag(torsion_cflags /wd4146
                                        /wd4244
                                        /wd4267
                                        /wd4334)
else()
  append_c_compiler_flag(torsion_cflags -pedantic
                                        -Wall
                                        -Wextra
                                        -Wcast-align
                                        -Wno-implicit-fallthrough
                                        -Wno-long-long
                                        -Wno-overlength-strings
                                        -Wshadow)
endif()

if(TORSION_ENABLE_DEBUG)
  if(MSVC)
    append_c_compiler_flag(torsion_cflags /Zi)
  else()
    append_c_compiler_flag(torsion_cflags -g)
  endif()
endif()

#
# Feature Testing
#

if(TORSION_ENABLE_ASM)
  check_c_source_compiles([=[
    int main(void) {
      unsigned char ptr[32];
      int x = 0;
      __asm__ ("" : "+r" (x) ::);
      __asm__ __volatile__ ("" :: "r" (ptr) : "memory");
      return x;
    }
  ]=] TORSION_HAS_ASM)
else()
  set(TORSION_HAS_ASM)
endif()

if(TORSION_ENABLE_ASM)
  check_c_source_compiles([=[
    #if defined(__amd64__) || defined(__x86_64__)
    #  error "not an x86 platform"
    #endif
    #ifndef __i386__
    #  error "not an x86 platform"
    #endif
    int main(void) {
      unsigned int n1 = 0;
      unsigned int n0 = 100;
      unsigned int d = 3;
      unsigned int q0, r0;
      __asm__ __volatile__ (
        "divl %k4\\n"
        : "=a" (q0), "=d" (r0)
        : "0" (n0), "1" (n1), "rm" (d)
      );
      return 0;
    }
  ]=] TORSION_HAS_ASM_X86)
else()
  set(TORSION_HAS_ASM_X86)
endif()

if(TORSION_ENABLE_ASM)
  check_c_source_compiles([=[
    #if !defined(__amd64__) && !defined(__x86_64__)
    #  error "not an x64 platform"
    #endif
    int main(void) {
      unsigned int dst[8], src[8];
      __asm__ __volatile__ (
        "movups (%%rsi), %%xmm0\\n"
        "movups 16(%%rsi), %%xmm1\\n"
        "pxor %%xmm1, %%xmm0\\n"
        "movups %%xmm0,(%%rdi)\\n"
        "movups %%xmm1,16(%%rdi)\\n"
        :
        : "D" (dst), "S" (src)
        : "xmm0", "xmm1", "cc", "memory"
      );
      return 0;
    }
  ]=] TORSION_HAS_ASM_X64)
else()
  set(TORSION_HAS_ASM_X64)
endif()

if(TORSION_ENABLE_INT128)
  check_c_source_compiles([=[
    typedef char check_64bit_t[sizeof(void *) >= 8 ? 1 : -1];
    typedef signed __int128 int128_t;
    typedef unsigned __int128 uint128_t;
    int main(void) {
      uint128_t r = 1;
      r <<= 64;
      r *= 113;
      r >>= 65;
      return r & 1;
    }
  ]=] TORSION_HAS_INT128)
else()
  set(TORSION_HAS_INT128)
endif()

if(TORSION_ENABLE_PTHREAD)
  set(THREADS_PREFER_PTHREAD_FLAG ON)

  find_package(Threads)

  set(TORSION_HAS_PTHREAD ${CMAKE_USE_PTHREADS_INIT})
else()
  set(TORSION_HAS_PTHREAD 0)
endif()

if(TORSION_ENABLE_TLS)
  check_c_thread_local_storage(TORSION_TLS)
else()
  set(TORSION_TLS)
endif()

if(NOT TORSION_TLS)
  set(TORSION_HAS_TLS_FALLBACK ${TORSION_HAS_PTHREAD})
else()
  set(TORSION_HAS_TLS_FALLBACK 0)
endif()

#
# Defines
#

set(torsion_defines)

list(APPEND torsion_defines TORSION_HAVE_CONFIG)

if(WIN32)
  list(APPEND torsion_defines _WIN32_WINNT=0x0600)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  list(APPEND torsion_defines _POSIX_C_SOURCE=200112)
endif()

if(TORSION_HAS_ASM)
  list(APPEND torsion_defines TORSION_HAVE_ASM)
endif()

if(TORSION_HAS_ASM_X86)
  list(APPEND torsion_defines TORSION_HAVE_ASM_X86)
endif()

if(TORSION_HAS_ASM_X64)
  list(APPEND torsion_defines TORSION_HAVE_ASM_X64)
endif()

if(TORSION_ENABLE_CRT)
  list(APPEND torsion_defines TORSION_USE_CRT)
endif()

if(TORSION_ENABLE_DEBUG)
  list(APPEND torsion_defines TORSION_DEBUG)
else()
  list(APPEND torsion_defines $<$<CONFIG:Debug>:TORSION_DEBUG>)
endif()

if(TORSION_HAS_INT128)
  list(APPEND torsion_defines TORSION_HAVE_INT128)
endif()

if(TORSION_ENABLE_LIBSECP256K1)
  list(APPEND torsion_defines TORSION_USE_LIBSECP256K1)
endif()

if(TORSION_TLS)
  list(APPEND torsion_defines TORSION_HAVE_TLS)
  list(APPEND torsion_defines TORSION_TLS=${TORSION_TLS})
else()
  list(APPEND torsion_defines TORSION_TLS=)
endif()

if(TORSION_HAS_TLS_FALLBACK)
  list(APPEND torsion_defines TORSION_HAVE_PTHREAD)
endif()

if(TORSION_ENABLE_VERIFY)
  list(APPEND torsion_defines TORSION_VERIFY)
endif()

#
# Targets
#

set(torsion_sources src/aead.c
                    src/asn1.c
                    src/cipher.c
                    src/ecc.c
                    src/encoding.c
                    src/drbg.c
                    src/dsa.c
                    src/hash.c
                    src/ies.c
                    src/internal.c
                    src/kdf.c
                    src/mac.c
                    src/mpi.c
                    src/rsa.c
                    src/stream.c
                    src/util.c
                    src/entropy/env.c
                    src/entropy/hw.c
                    src/entropy/sys.c
                    src/rand.c)

set(torsion_includes ${PROJECT_SOURCE_DIR}/include)
set(torsion_libs)

if(TORSION_HAS_TLS_FALLBACK)
  list(APPEND torsion_libs Threads::Threads)
endif()

add_node_library(torsion STATIC ${torsion_sources})
target_compile_definitions(torsion PRIVATE ${torsion_defines})
target_compile_options(torsion PRIVATE ${torsion_cflags})
target_include_directories(torsion PUBLIC ${torsion_includes})
target_link_libraries(torsion INTERFACE ${torsion_libs})
