# AppendCCompilerFlag.cmake - checked c flags appending
# Copyright (c) 2020, Christopher Jeffrey (MIT License).
# https://github.com/chjj

if(COMMAND append_c_compiler_flag)
  return()
endif()

include(CheckCCompilerFlag)

function(append_c_compiler_flag list)
  foreach(flag IN LISTS ARGN)
    string(TOUPPER "CMAKE_HAVE_C_FLAG${flag}" name)
    string(REGEX REPLACE "[^A-Z0-9]" "_" name "${name}")

    check_c_compiler_flag(${flag} ${name})

    if(${name})
      list(APPEND ${list} ${flag})
    endif()
  endforeach()

  set(${list} ${${list}} PARENT_SCOPE)
endfunction()
