# CMakeLists.txt - cmake build for leveldown
# Copyright (c) 2020, Christopher Jeffrey (MIT License).
# https://github.com/bcoin-org/bdb

cmake_minimum_required(VERSION 3.4)
project(leveldown LANGUAGES CXX)

include(NodeJS)

set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)
set(CMAKE_CXX_STANDARD 11)

if(MSVC)
  add_compile_options(/wd4018
                      /wd4244
                      /wd4267
                      /wd4355
                      /wd4506
                      /wd4530
                      /wd4722
                      /wd4996)
endif()

add_subdirectory(deps/leveldb)

add_node_module(leveldown src/binding.cc)
target_include_directories(leveldown PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(leveldown PRIVATE leveldb)
