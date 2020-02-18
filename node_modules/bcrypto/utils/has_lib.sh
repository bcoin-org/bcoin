#!/usr/bin/env bash

# Taken from secp256k1-node (and then rewritten several times).
# Copyright (c) 2014-2016, secp256k1-node contributors (MIT License).

has_lib() {
  # Try checking common library locations.
  for dir in /lib \
             /usr/lib \
             /usr/local/lib \
             /opt/local/lib \
             /usr/lib/x86_64-linux-gnu \
             /usr/lib/i386-linux-gnu; do
    test -e "$dir/lib$1.so" && return 0
    test -e "$dir/lib$1.dylib" && return 0
  done

  return 1
}

has_headers() {
  # Try checking common include locations.
  for dir in /include \
             /usr/include \
             /usr/local/include \
             /opt/local/include \
             /usr/include/x86_64-linux-gnu \
             /usr/include/i386-linux-gnu; do
    test -e "$dir/$1.h" && return 0
  done

  return 1
}

has_all() {
  has_lib "$@" && has_headers "$@"
}

for name in "$@"; do
  if ! has_all "$name" > /dev/null 2>& 1; then
    echo false
    exit 0
  fi
done

echo true
