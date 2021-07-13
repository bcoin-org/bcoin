# CMakeLists.txt - cmake build for bcrypto
# Copyright (c) 2020, Christopher Jeffrey (MIT License).
# https://github.com/bcoin-org/bcrypto

cmake_minimum_required(VERSION 3.4)
project(bcrypto LANGUAGES C)

include(cmake/AppendCCompilerFlag.cmake)
include(NodeJS)

set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 99)

option(BCRYPTO_ENABLE_LIBSECP256K1 "Use libsecp256k1" ON)

set(bcrypto_cflags)
set(bcrypto_defines)
set(bcrypto_libs)

if(MSVC)
  append_c_compiler_flag(bcrypto_cflags /wd4244
                                        /wd4267)
else()
  append_c_compiler_flag(bcrypto_cflags -Wall
                                        -Wextra
                                        -Wcast-align
                                        -Wshadow)
endif()

add_subdirectory(deps/torsion)
list(APPEND bcrypto_libs torsion)

if(BCRYPTO_ENABLE_LIBSECP256K1)
  add_subdirectory(deps/secp256k1)
  list(APPEND bcrypto_defines BCRYPTO_USE_SECP256K1)
  list(APPEND bcrypto_libs secp256k1)
endif()

add_node_module(bcrypto src/bcrypto.c)
target_compile_definitions(bcrypto PRIVATE ${bcrypto_defines})
target_compile_options(bcrypto PRIVATE ${bcrypto_cflags})
target_link_libraries(bcrypto PRIVATE ${bcrypto_libs})
