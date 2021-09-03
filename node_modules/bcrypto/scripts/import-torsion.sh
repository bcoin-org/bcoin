#!/bin/bash

set -ex

type rsync > /dev/null 2>& 1
test $# -eq 1
test ! -z "$1"

prefix="$1"

test -f package.json
test -d "$prefix"
test -d "$prefix/src"
test -d "$prefix/include"

if test ! -d deps/torsion; then
  mkdir deps/torsion
fi

if test ! -d deps/torsion/src; then
  mkdir deps/torsion/src
fi

if test ! -d deps/torsion/include; then
  mkdir deps/torsion/include
fi

cp -f "$prefix/LICENSE" deps/torsion/

rsync -av --exclude '*.o' \
          --exclude '*.lo' \
          --exclude '.deps' \
          --exclude '.dirstamp' \
          --exclude '.libs' \
          --exclude '*.md' \
          "$prefix/src/" deps/torsion/src/

rsync -av "$prefix/include/" deps/torsion/include/
