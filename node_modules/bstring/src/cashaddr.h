/* Copyright (c) 2018 the bcoin developers
 * Copyright (c) 2017 Pieter Wuille
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef _BSTRING_CASHADDR_H
#define _BSTRING_CASHADDR_H 1

typedef enum bstring_cashaddr_error_t {
  bstring_cashaddr_ERR_NULL = 0,
  bstring_cashaddr_ERR_CHECKSUM,
  bstring_cashaddr_ERR_LENGTH,
  bstring_cashaddr_ERR_CASING,
  bstring_cashaddr_ERR_PADDING,
  bstring_cashaddr_ERR_NONZERO_PADDING,
  bstring_cashaddr_ERR_CHARACTER,
  bstring_cashaddr_ERR_PREFIX,
  bstring_cashaddr_ERR_TYPE,
  bstring_cashaddr_ERR_SIZE,
  bstring_cashaddr_ERR_SEPARATOR
} bstring_cashaddr_error;

#include <stdint.h>

/** Encode a CashAddr
 *
 *  Out:
 *    err:             Pointer to an int that will be updated to contain the error
 *                     number with specific details.
 *    output:          Pointer to a buffer of max 83 + 1 + 112 + 1 bytes (197 bytes)
 *                     that will be updated to contain the null-terminated address.
 *  In:
 *    prefix:          Pointer to the null-terminated human readable prefix to use
 *                     (chain/network specific), 83 bytes max.
 *    type:            The type of the address 0 or 1 for P2KH and P2SH.
 *    hash:            Data bytes for the hash from 20, 24, 28, 32, 40, 48, 56 and 64 bytes.
 *    hash_len:        Number of data bytes in hash from 20 to 64 bytes.
 *  Returns true if successful.
 */
bool
bstring_cashaddr_encode(
  bstring_cashaddr_error *err,
  char *output,
  const char *prefix,
  int type,
  const uint8_t *hash,
  size_t hash_len
);

/** Decode a CashAddr
 *
 *  Out:
 *    err:             Pointer to an int that will be updated to contain the error
 *                     number with specific details.
 *    type:            Pointer to an int that will be updated to contain the type
 *                     of address (0 or 1 for P2KH or P2SH).
 *    hash:            Pointer to a buffer of size 20, 24, 28, 32, 40, 48, 56 and 64
 *                     bytes that will be updated to contain the hash.
 *    hash_len:        Pointer to a size_t that will be updated to contain the
 *                     length of bytes in the hash.
 *    prefix:          Pointer to the null-terminated human readable prefix that
 *                     will be updated to contain the string, 83 bytes max.
 *  In:
 *    default_prefix:  Default prefix to be used, in the event that the addr
 *                     does not include the prefix. Should be lowercase and w/o numbers.
 *    addr:            Pointer to the null-terminated address.
 *  Returns true if successful.
 */
bool
bstring_cashaddr_decode(
  bstring_cashaddr_error *err,
  int* type,
  uint8_t* hash,
  size_t* hash_len,
  char* prefix,
  const char* default_prefix,
  const char* addr
);

bool
bstring_cashaddr_test(
  bstring_cashaddr_error *err,
  const char *default_prefix,
  const char *addr
);

const char *
bstring_cashaddr_strerror(bstring_cashaddr_error err);

#endif
