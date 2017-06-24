#!/bin/bash

dir=$(dirname "$(which "$0")")
url='https://raw.githubusercontent.com/nodejs/node/master/src/node_root_certs.h'
json=$(curl -s "$url")

sha256() {
  cat | openssl dgst -sha256 -hex | sed 's/^(stdin)= //'
}

getcerts() {
  local buf=''
  echo "$json" | sed 's/\\/\\\\/g' | while read line; do
    if echo "$line" | grep 'BEGIN CERT' > /dev/null; then
      buf="$line"
      continue
    fi
    if echo "$line" | grep 'END CERT' > /dev/null; then
      buf="$buf$line"
      echo "$buf" | sed 's/"//g' | sed 's/,//g'
      continue
    fi
    buf="$buf$line"
  done
}

gethashes() {
  local buf=''
  echo "$json" | sed 's/\\n/:/g' | while read line; do
    if echo "$line" | grep 'BEGIN CERT' > /dev/null; then
      buf="$line"
      continue
    fi
    if echo "$line" | grep 'END CERT' > /dev/null; then
      buf="$buf$line"
      echo "$buf" \
        | sed 's/"//g' \
        | sed 's/,//g' \
        | tr ':' '\n' \
        | openssl x509 -outform DER \
        | sha256
      continue
    fi
    buf="$buf$line"
  done
}

tojs() {
  local data=$(cat)
  local body=$(echo "$data" | head -n -1)
  local last=$(echo "$data" | tail -n 1)
  echo "'use strict';"
  echo ''
  echo 'module.exports = ['
  echo "$body" | while read line; do
    echo "  '${line}',"
  done
  echo "  '${last}'"
  echo '];'
}

gethashes | tojs > "${dir}/../lib/bip70/certs.js"
