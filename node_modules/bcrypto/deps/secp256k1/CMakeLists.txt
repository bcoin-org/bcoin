# CMakeLists.txt - cmake build for secp256k1
# Copyright (c) 2020, Christopher Jeffrey (MIT License).
# https://github.com/bcoin-org/bcrypto

#
# Initialization
#

cmake_minimum_required(VERSION 3.4)
project(libsecp256k1 LANGUAGES C)

#
# Includes
#

include(../../cmake/AppendCCompilerFlag.cmake)
include(CheckCSourceCompiles)
include(NodeJS)
include(TestBigEndian)

#
# Options
#

option(SECP256K1_ENABLE_ASM "Use inline x86-64 assembly if available" ON)
option(SECP256K1_ENABLE_INT128 "Use __int128 if available" ON)

#
# Flags
#

set(secp256k1_cflags)

set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 90)

if(MSVC)
  append_c_compiler_flag(secp256k1_cflags /wd4244
                                          /wd4267
                                          /wd4334)
else()
  append_c_compiler_flag(secp256k1_cflags -pedantic
                                          -Wall
                                          -Wextra
                                          -Wcast-align
                                          -Wnested-externs
                                          -Wno-implicit-fallthrough
                                          -Wno-long-long
                                          -Wno-nonnull-compare
                                          -Wno-overlength-strings
                                          -Wno-unused-function
                                          -Wshadow
                                          -Wstrict-prototypes)
endif()

#
# Feature Testing
#

if(SECP256K1_ENABLE_ASM)
  check_c_source_compiles([=[
    #include <stdint.h>
    int main(void) {
      uint64_t a = 11, tmp;
      __asm__ __volatile__("movq $0x100000000,%1; mulq %%rsi"
                           : "+a" (a) : "S" (tmp) : "cc", "%rdx");
      return 0;
    }
  ]=] SECP256K1_HAS_ASM_X64)
else()
  set(SECP256K1_HAS_ASM_X64)
endif()

test_big_endian(SECP256K1_BIGENDIAN)

if(SECP256K1_ENABLE_INT128)
  check_type_size("__int128" SECP256K1_HAS_INT128)
else()
  set(SECP256K1_HAS_INT128)
endif()

#
# Defines
#

set(secp256k1_defines USE_NUM_NONE=1
                      USE_FIELD_INV_BUILTIN=1
                      USE_SCALAR_INV_BUILTIN=1
                      ECMULT_WINDOW_SIZE=15
                      ECMULT_GEN_PREC_BITS=4
                      USE_ENDOMORPHISM=1
                      ENABLE_MODULE_ECDH=1
                      ENABLE_MODULE_RECOVERY=1
                      ENABLE_MODULE_EXTRAKEYS=1
                      ENABLE_MODULE_SCHNORRSIG=1
                      ENABLE_MODULE_SCHNORRLEG=1
                      ENABLE_MODULE_ELLIGATOR=1
                      ENABLE_MODULE_EXTRA=1)

if(SECP256K1_HAS_ASM_X64)
  list(APPEND secp256k1_defines USE_ASM_X86_64=1)
endif()

if(SECP256K1_HAS_INT128)
  list(APPEND secp256k1_defines USE_FORCE_WIDEMUL_INT128=1)
else()
  list(APPEND secp256k1_defines USE_FORCE_WIDEMUL_INT64=1)
endif()

if(SECP256K1_BIGENDIAN)
  list(APPEND secp256k1_defines SECP256K1_BIG_ENDIAN)
else()
  list(APPEND secp256k1_defines SECP256K1_LITTLE_ENDIAN)
endif()

#
# Targets
#

add_node_library(secp256k1 STATIC contrib/lax_der_parsing.c src/secp256k1.c)
target_compile_definitions(secp256k1 PRIVATE ${secp256k1_defines})
target_compile_options(secp256k1 PRIVATE ${secp256k1_cflags})
target_include_directories(secp256k1 PRIVATE ${PROJECT_SOURCE_DIR}
                                             ${PROJECT_SOURCE_DIR}/src
                                     PUBLIC ${PROJECT_SOURCE_DIR}/include
                                     INTERFACE ${PROJECT_SOURCE_DIR}/contrib)
