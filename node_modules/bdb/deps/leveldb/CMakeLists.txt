# Copyright 2017 The LevelDB Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file. See the AUTHORS file for names of contributors.

cmake_minimum_required(VERSION 3.9)
# Keep the version below in sync with the one in db.h
project(leveldb VERSION 1.22.0 LANGUAGES C CXX)

include(NodeJS)

# This project can use C11, but will gracefully decay down to C89.
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED OFF)
set(CMAKE_C_EXTENSIONS OFF)

# This project requires C++11.
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if (WIN32)
  set(LEVELDB_PLATFORM_NAME LEVELDB_PLATFORM_WINDOWS)
  # TODO(cmumford): Make UNICODE configurable for Windows.
  add_definitions(-D_UNICODE -DUNICODE)
else (WIN32)
  set(LEVELDB_PLATFORM_NAME LEVELDB_PLATFORM_POSIX)
endif (WIN32)

include(TestBigEndian)
test_big_endian(LEVELDB_IS_BIG_ENDIAN)

include(CheckIncludeFile)
check_include_file("unistd.h" HAVE_UNISTD_H)

set(HAVE_CRC32C 0)
set(HAVE_SNAPPY 1)
set(HAVE_TCMALLOC 0)

include(CheckCXXSymbolExists)
# Using check_cxx_symbol_exists() instead of check_c_symbol_exists() because
# we're including the header from C++, and feature detection should use the same
# compiler language that the project will use later. Principles aside, some
# versions of do not expose fdatasync() in <unistd.h> in standard C mode
# (-std=c11), but do expose the function in standard C++ mode (-std=c++11).
check_cxx_symbol_exists(fdatasync "unistd.h" HAVE_FDATASYNC)
check_cxx_symbol_exists(F_FULLFSYNC "fcntl.h" HAVE_FULLFSYNC)

include(CheckCXXSourceCompiles)

# Test whether -Wthread-safety is available. See
# https://clang.llvm.org/docs/ThreadSafetyAnalysis.html
# -Werror is necessary because unknown attributes only generate warnings.
set(OLD_CMAKE_REQUIRED_FLAGS ${CMAKE_REQUIRED_FLAGS})
list(APPEND CMAKE_REQUIRED_FLAGS -Werror -Wthread-safety)
check_cxx_source_compiles("
struct __attribute__((lockable)) Lock {
  void Acquire() __attribute__((exclusive_lock_function()));
  void Release() __attribute__((unlock_function()));
};
struct ThreadSafeType {
  Lock lock_;
  int data_ __attribute__((guarded_by(lock_)));
};
int main() { return 0; }
"  HAVE_CLANG_THREAD_SAFETY)
set(CMAKE_REQUIRED_FLAGS ${OLD_CMAKE_REQUIRED_FLAGS})

# Test whether C++17 __has_include is available.
check_cxx_source_compiles("
#if defined(__has_include) &&  __has_include(<string>)
#include <string>
#endif
int main() { std::string str; return 0; }
" HAVE_CXX17_HAS_INCLUDE)

set(LEVELDB_PUBLIC_INCLUDE_DIR "include/leveldb")
set(LEVELDB_PORT_CONFIG_DIR "include/port")

configure_file(
  "${PROJECT_SOURCE_DIR}/port/port_config.h.in"
  "${PROJECT_BINARY_DIR}/${LEVELDB_PORT_CONFIG_DIR}/port_config.h"
)

include_directories(
  "${PROJECT_BINARY_DIR}/include"
  "${PROJECT_SOURCE_DIR}"
)

add_node_library(leveldb STATIC "")
target_sources(leveldb
  PRIVATE
    "${PROJECT_BINARY_DIR}/${LEVELDB_PORT_CONFIG_DIR}/port_config.h"
    "${PROJECT_SOURCE_DIR}/db/builder.cc"
    "${PROJECT_SOURCE_DIR}/db/builder.h"
    "${PROJECT_SOURCE_DIR}/db/c.cc"
    "${PROJECT_SOURCE_DIR}/db/db_impl.cc"
    "${PROJECT_SOURCE_DIR}/db/db_impl.h"
    "${PROJECT_SOURCE_DIR}/db/db_iter.cc"
    "${PROJECT_SOURCE_DIR}/db/db_iter.h"
    "${PROJECT_SOURCE_DIR}/db/dbformat.cc"
    "${PROJECT_SOURCE_DIR}/db/dbformat.h"
    "${PROJECT_SOURCE_DIR}/db/dumpfile.cc"
    "${PROJECT_SOURCE_DIR}/db/filename.cc"
    "${PROJECT_SOURCE_DIR}/db/filename.h"
    "${PROJECT_SOURCE_DIR}/db/log_format.h"
    "${PROJECT_SOURCE_DIR}/db/log_reader.cc"
    "${PROJECT_SOURCE_DIR}/db/log_reader.h"
    "${PROJECT_SOURCE_DIR}/db/log_writer.cc"
    "${PROJECT_SOURCE_DIR}/db/log_writer.h"
    "${PROJECT_SOURCE_DIR}/db/memtable.cc"
    "${PROJECT_SOURCE_DIR}/db/memtable.h"
    "${PROJECT_SOURCE_DIR}/db/repair.cc"
    "${PROJECT_SOURCE_DIR}/db/skiplist.h"
    "${PROJECT_SOURCE_DIR}/db/snapshot.h"
    "${PROJECT_SOURCE_DIR}/db/table_cache.cc"
    "${PROJECT_SOURCE_DIR}/db/table_cache.h"
    "${PROJECT_SOURCE_DIR}/db/version_edit.cc"
    "${PROJECT_SOURCE_DIR}/db/version_edit.h"
    "${PROJECT_SOURCE_DIR}/db/version_set.cc"
    "${PROJECT_SOURCE_DIR}/db/version_set.h"
    "${PROJECT_SOURCE_DIR}/db/write_batch_internal.h"
    "${PROJECT_SOURCE_DIR}/db/write_batch.cc"
    "${PROJECT_SOURCE_DIR}/port/port_stdcxx.h"
    "${PROJECT_SOURCE_DIR}/port/port.h"
    "${PROJECT_SOURCE_DIR}/port/thread_annotations.h"
    "${PROJECT_SOURCE_DIR}/table/block_builder.cc"
    "${PROJECT_SOURCE_DIR}/table/block_builder.h"
    "${PROJECT_SOURCE_DIR}/table/block.cc"
    "${PROJECT_SOURCE_DIR}/table/block.h"
    "${PROJECT_SOURCE_DIR}/table/filter_block.cc"
    "${PROJECT_SOURCE_DIR}/table/filter_block.h"
    "${PROJECT_SOURCE_DIR}/table/format.cc"
    "${PROJECT_SOURCE_DIR}/table/format.h"
    "${PROJECT_SOURCE_DIR}/table/iterator_wrapper.h"
    "${PROJECT_SOURCE_DIR}/table/iterator.cc"
    "${PROJECT_SOURCE_DIR}/table/merger.cc"
    "${PROJECT_SOURCE_DIR}/table/merger.h"
    "${PROJECT_SOURCE_DIR}/table/table_builder.cc"
    "${PROJECT_SOURCE_DIR}/table/table.cc"
    "${PROJECT_SOURCE_DIR}/table/two_level_iterator.cc"
    "${PROJECT_SOURCE_DIR}/table/two_level_iterator.h"
    "${PROJECT_SOURCE_DIR}/util/arena.cc"
    "${PROJECT_SOURCE_DIR}/util/arena.h"
    "${PROJECT_SOURCE_DIR}/util/bloom.cc"
    "${PROJECT_SOURCE_DIR}/util/cache.cc"
    "${PROJECT_SOURCE_DIR}/util/coding.cc"
    "${PROJECT_SOURCE_DIR}/util/coding.h"
    "${PROJECT_SOURCE_DIR}/util/comparator.cc"
    "${PROJECT_SOURCE_DIR}/util/crc32c.cc"
    "${PROJECT_SOURCE_DIR}/util/crc32c.h"
    "${PROJECT_SOURCE_DIR}/util/env.cc"
    "${PROJECT_SOURCE_DIR}/util/filter_policy.cc"
    "${PROJECT_SOURCE_DIR}/util/hash.cc"
    "${PROJECT_SOURCE_DIR}/util/hash.h"
    "${PROJECT_SOURCE_DIR}/util/logging.cc"
    "${PROJECT_SOURCE_DIR}/util/logging.h"
    "${PROJECT_SOURCE_DIR}/util/mutexlock.h"
    "${PROJECT_SOURCE_DIR}/util/no_destructor.h"
    "${PROJECT_SOURCE_DIR}/util/options.cc"
    "${PROJECT_SOURCE_DIR}/util/random.h"
    "${PROJECT_SOURCE_DIR}/util/status.cc"

  # Only CMake 3.3+ supports PUBLIC sources in targets exported by "install".
  $<$<VERSION_GREATER:CMAKE_VERSION,3.2>:PUBLIC>
    "${LEVELDB_PUBLIC_INCLUDE_DIR}/c.h"
    "${LEVELDB_PUBLIC_INCLUDE_DIR}/cache.h"
    "${LEVELDB_PUBLIC_INCLUDE_DIR}/comparator.h"
    "${LEVELDB_PUBLIC_INCLUDE_DIR}/db.h"
    "${LEVELDB_PUBLIC_INCLUDE_DIR}/dumpfile.h"
    "${LEVELDB_PUBLIC_INCLUDE_DIR}/env.h"
    "${LEVELDB_PUBLIC_INCLUDE_DIR}/export.h"
    "${LEVELDB_PUBLIC_INCLUDE_DIR}/filter_policy.h"
    "${LEVELDB_PUBLIC_INCLUDE_DIR}/iterator.h"
    "${LEVELDB_PUBLIC_INCLUDE_DIR}/options.h"
    "${LEVELDB_PUBLIC_INCLUDE_DIR}/slice.h"
    "${LEVELDB_PUBLIC_INCLUDE_DIR}/status.h"
    "${LEVELDB_PUBLIC_INCLUDE_DIR}/table_builder.h"
    "${LEVELDB_PUBLIC_INCLUDE_DIR}/table.h"
    "${LEVELDB_PUBLIC_INCLUDE_DIR}/write_batch.h"
)

if (WIN32)
  target_sources(leveldb
    PRIVATE
      "${PROJECT_SOURCE_DIR}/util/env_windows.cc"
      "${PROJECT_SOURCE_DIR}/util/windows_logger.h"
  )
else (WIN32)
  target_sources(leveldb
    PRIVATE
      "${PROJECT_SOURCE_DIR}/util/env_posix.cc"
      "${PROJECT_SOURCE_DIR}/util/posix_logger.h"
  )
endif (WIN32)

# MemEnv is not part of the interface and could be pulled to a separate library.
target_sources(leveldb
  PRIVATE
    "${PROJECT_SOURCE_DIR}/helpers/memenv/memenv.cc"
    "${PROJECT_SOURCE_DIR}/helpers/memenv/memenv.h"
)

target_include_directories(leveldb
  PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

set_target_properties(leveldb
  PROPERTIES VERSION ${PROJECT_VERSION} SOVERSION ${PROJECT_VERSION_MAJOR})

target_compile_definitions(leveldb
  PRIVATE
    # Used by include/export.h when building shared libraries.
    LEVELDB_COMPILE_LIBRARY
    # Used by port/port.h.
    ${LEVELDB_PLATFORM_NAME}=1
)
if (NOT HAVE_CXX17_HAS_INCLUDE)
  target_compile_definitions(leveldb
    PRIVATE
      LEVELDB_HAS_PORT_CONFIG_H=1
  )
endif(NOT HAVE_CXX17_HAS_INCLUDE)

if(HAVE_CLANG_THREAD_SAFETY)
  target_compile_options(leveldb
    PUBLIC
      -Werror -Wthread-safety)
endif(HAVE_CLANG_THREAD_SAFETY)

add_subdirectory(deps/snappy)
target_link_libraries(leveldb PRIVATE snappy)

# Needed by port_stdcxx.h
find_package(Threads REQUIRED)
target_link_libraries(leveldb PRIVATE Threads::Threads)
