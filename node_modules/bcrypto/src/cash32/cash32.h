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

#ifndef _BCRYPTO_CASH32_H
#define _BCRYPTO_CASH32_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define cash32_serialize _bcrypto_cash32_serialize
#define cash32_deserialize _bcrypto_cash32_deserialize
#define cash32_is _bcrypto_cash32_is
#define cash32_convert_bits _bcrypto_cash32_convert_bits
#define cash32_encode _bcrypto_cash32_encode
#define cash32_decode _bcrypto_cash32_decode
#define cash32_test _bcrypto_cash32_test

int
cash32_serialize(char *output,
                 const char *prefix,
                 const uint8_t *data,
                 size_t data_len);

int
cash32_deserialize(char *prefix,
                   uint8_t *data,
                   size_t *data_len,
                   const char *default_prefix,
                   const char *input);

int
cash32_is(const char *default_prefix,
          const char *addr);

int
cash32_convert_bits(uint8_t *out,
                    size_t *outlen,
                    int outbits,
                    const uint8_t *in,
                    size_t inlen,
                    int inbits,
                    int pad);

int
cash32_encode(char *output,
              const char *prefix,
              int type,
              const uint8_t *hash,
              size_t hash_len);

int
cash32_decode(int *type,
              uint8_t *hash,
              size_t *hash_len,
              char *prefix,
              const char *default_prefix,
              const char *addr);

int
cash32_test(const char *default_prefix,
            const char *addr);

#ifdef __cplusplus
}
#endif

#endif
