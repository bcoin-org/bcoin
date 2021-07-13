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

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "cash32.h"

static uint64_t
polymod_step(uint64_t pre) {
  uint8_t b = pre >> 35;
  return ((pre & 0x07ffffffff) << 5)
    ^ (-((b >> 0) & 1) & 0x98f2bc8e61ul)
    ^ (-((b >> 1) & 1) & 0x79b76d99e2ul)
    ^ (-((b >> 2) & 1) & 0xf33e5fb3c4ul)
    ^ (-((b >> 3) & 1) & 0xae2eabe2a8ul)
    ^ (-((b >> 4) & 1) & 0x1e4f43e470ul);
}

static const char *CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static const int TABLE[128] = {
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,
  -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
   1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
  -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
   1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1
};

static int
cash32_encoded_size(size_t bytes, size_t *encoded_size) {
  switch (bytes * 8) {
    case 160:
      *encoded_size = 0;
      break;
    case 192:
      *encoded_size = 1;
      break;
    case 224:
      *encoded_size = 2;
      break;
    case 256:
      *encoded_size = 3;
      break;
    case 320:
      *encoded_size = 4;
      break;
    case 384:
      *encoded_size = 5;
      break;
    case 448:
      *encoded_size = 6;
      break;
    case 512:
      *encoded_size = 7;
      break;
    default:
      return 0;
  }
  return 1;
}

int
bcrypto_cash32_serialize(bcrypto_cash32_error *err,
                         char *output,
                         const char *prefix,
                         const uint8_t *data,
                         size_t data_len) {
  uint64_t chk = 1;
  size_t i = 0;
  int have_lower = 0;
  int have_upper = 0;

  while (prefix[i] != 0) {
    const char pch = prefix[i];

    if (!(pch >> 5))
      return 0;

    if (pch >= 'a' && pch <= 'z') {
      have_lower = 1;
    } else if (pch >= 'A' && pch <= 'Z') {
      have_upper = 1;
    } else if (pch >= '0' && pch <= '9') {
      *err = BCRYPTO_CASH32_ERR_PREFIX;
      return 0;
    }

    chk = polymod_step(chk);
    chk ^= (prefix[i] & 0x1f);

    /* Lowercase prefix. */
    if (prefix[i] >= 65 && prefix[i] <= 90)
      *(output++) = prefix[i] + 32;
    else
      *(output++) = prefix[i];

    i += 1;

    if (i > 83) {
      *err = BCRYPTO_CASH32_ERR_PREFIX;
      return 0;
    }
  }

  if ((have_upper && have_lower) || i == 0) {
    *err = BCRYPTO_CASH32_ERR_PREFIX;
    return 0;
  }

  chk = polymod_step(chk);
  *(output++) = ':';

  for (i = 0; i < data_len; i++) {
    uint8_t ch = data[i];

    if (ch >> 5)
      return 0;

    chk = polymod_step(chk);
    chk ^= ch;

    *(output++) = CHARSET[ch];
  }

  for (i = 0; i < 8; i++)
    chk = polymod_step(chk);

  chk ^= 1;

  for (i = 0; i < 8; i++)
    *(output++) = CHARSET[(chk >> ((7 - i) * 5)) & 0x1f];

  return 1;
}

int
bcrypto_cash32_deserialize(bcrypto_cash32_error *err,
                           char *prefix,
                           uint8_t *data,
                           size_t *data_len,
                           const char *default_prefix,
                           const char *input) {
  uint64_t chk = 1;
  size_t input_len = strlen(input);
  size_t prefix_len = 0;
  int have_lower = 0;
  int have_upper = 0;
  int has_prefix, valid_checksum;
  const char *prefix_input;
  size_t i, j, prefix_input_len, payload_len;

  if (input_len < 8 || input_len > 196) { /* 83 + 1 + 112 */
    *err = BCRYPTO_CASH32_ERR_LENGTH;
    return 0;
  }

  while (prefix_len < input_len && input[prefix_len] != ':') {
    prefix_len++;
    if (prefix_len > 83) {
      *err = BCRYPTO_CASH32_ERR_PREFIX;
      return 0;
    }
  }

  has_prefix = !(prefix_len == input_len);
  prefix_input = has_prefix ? input : default_prefix;
  prefix_input_len = has_prefix ? prefix_len : strlen(default_prefix);

  *data_len = has_prefix ? input_len - (1 + prefix_len) : input_len;

  if (prefix_input_len < 1) {
    *err = BCRYPTO_CASH32_ERR_PREFIX;
    return 0;
  }

  if (*data_len < 8) {
    *err = BCRYPTO_CASH32_ERR_LENGTH;
    return 0;
  }

  *data_len -= 8;

  for (i = 0; i < prefix_input_len; i++) {
    int ch = prefix_input[i];

    if (ch < 33 || ch > 126) {
      *err = BCRYPTO_CASH32_ERR_CHARACTER;
      return 0;
    }

    if (ch >= 'a' && ch <= 'z') {
      have_lower = 1;
    } else if (ch >= 'A' && ch <= 'Z') {
      have_upper = 1;
      ch = (ch - 'A') + 'a';
    } else if (ch >= '0' && ch <= '9') {
      *err = BCRYPTO_CASH32_ERR_PREFIX;
      return 0;
    }

    prefix[i] = ch;
    chk = polymod_step(chk);
    chk ^= (ch | 0x20) & 0x1f;
  }

  chk = polymod_step(chk);

  j = has_prefix ? prefix_len + 1 : 0;
  payload_len = 0;

  while (j < input_len) {
    int v = (input[j] & 0xff80) ? -1 : TABLE[(int)input[j]];

    if (input[j] >= 'a' && input[j] <= 'z')
      have_lower = 1;

    if (input[j] >= 'A' && input[j] <= 'Z')
      have_upper = 1;

    if (input[j] == ':') {
      *err = BCRYPTO_CASH32_ERR_SEPARATOR;
      return 0;
    }

    if (v == -1) {
      *err = BCRYPTO_CASH32_ERR_CHARACTER;
      return 0;
    }

    chk = polymod_step(chk) ^ v;

    if (j + 8 < input_len) {
      int x = has_prefix ? j - (1 + prefix_len) : j;
      data[x] = v;
    }

    j += 1;
    payload_len += 1;

    if (payload_len > 112) {
      *err = BCRYPTO_CASH32_ERR_LENGTH;
      return 0;
    }
  }

  if (payload_len <= 8) {
    *err = BCRYPTO_CASH32_ERR_LENGTH;
    return 0;
  }

  if (have_lower && have_upper) {
    *err = BCRYPTO_CASH32_ERR_CASING;
    return 0;
  }

  valid_checksum = (chk == 1) && (strcmp(prefix, default_prefix) == 0);

  if (!valid_checksum)
    *err = BCRYPTO_CASH32_ERR_CHECKSUM;

  return valid_checksum;
}

int
bcrypto_cash32_is(bcrypto_cash32_error *err,
                  const char *default_prefix,
                  const char *addr) {
  char prefix[84];
  uint8_t data[188];
  size_t data_len = 0;

  memset(prefix, 0x00, sizeof(prefix));
  memset(data, 0x00, sizeof(data));

  if (!bcrypto_cash32_deserialize(err, prefix, data,
                                  &data_len, default_prefix, addr)) {
    return 0;
  }

  return 1;
}

int
bcrypto_cash32_convert_bits(bcrypto_cash32_error *err,
                            uint8_t *out,
                            size_t *outlen,
                            int outbits,
                            const uint8_t *in,
                            size_t inlen,
                            int inbits,
                            int pad) {
  uint32_t val = 0;
  int bits = 0;
  uint32_t maxv = (((uint32_t)1) << outbits) - 1;

  while (inlen--) {
    uint8_t value = *(in++);

    if ((value >> inbits) != 0) {
      *err = BCRYPTO_CASH32_ERR_CHARACTER;
      return 0;
    }

    val = (val << inbits) | value;
    bits += inbits;

    while (bits >= outbits) {
      bits -= outbits;
      out[(*outlen)++] = (val >> bits) & maxv;
    }
  }

  if (pad && bits) {
    out[(*outlen)++] = (val << (outbits - bits)) & maxv;
  } else if (bits >= inbits || ((val << (outbits - bits)) & maxv)) {
    *err = BCRYPTO_CASH32_ERR_CHARACTER;
    return 0;
  }

  return 1;
}

int
bcrypto_cash32_encode(bcrypto_cash32_error *err,
                      char *output,
                      const char *prefix,
                      int type,
                      const uint8_t *hash,
                      size_t hash_len) {
  size_t encoded_size = 0;
  uint8_t data[65];
  uint8_t converted[(65 * 8 + 4) / 5 + 1]; /* 105 */
  size_t converted_len = 0;

  /* There are 4 bits available for the version (2 ^ 4 = 16) */
  if (type < 0 || type > 15) {
    *err = BCRYPTO_CASH32_ERR_TYPE;
    return 0;
  }

  if (!cash32_encoded_size(hash_len, &encoded_size)) {
    *err = BCRYPTO_CASH32_ERR_SIZE;
    return 0;
  }

  data[0] = type << 3 | (uint8_t)encoded_size;
  memcpy(data + 1, hash, hash_len);

  memset(converted, 0x00, sizeof(converted));

  if (!bcrypto_cash32_convert_bits(err, converted, &converted_len,
                                   5, data, hash_len + 1, 8, 1)) {
    return 0;
  }

  return bcrypto_cash32_serialize(err, output, prefix,
                                  converted, converted_len);
}

int
bcrypto_cash32_decode(bcrypto_cash32_error *err,
                      int *type,
                      uint8_t *hash,
                      size_t *hash_len,
                      char *prefix,
                      const char *default_prefix,
                      const char *addr) {
  uint8_t data[188];
  uint8_t converted[(188 * 5 + 7) / 8]; /* 118 */
  size_t converted_len = 0;
  size_t data_len = 0;
  size_t extrabits, last, mask, size;

  memset(data, 0x00, sizeof(data));

  if (!bcrypto_cash32_deserialize(err, prefix, data,
                                  &data_len, default_prefix, addr)) {
    return 0;
  }

  extrabits = (data_len * 5) & 7;

  if (extrabits >= 5) {
    *err = BCRYPTO_CASH32_ERR_PADDING;
    return 0;
  }

  last = (size_t)data[data_len - 1];
  mask = (1 << extrabits) - 1;

  if (last & mask) {
    *err = BCRYPTO_CASH32_ERR_NONZERO_PADDING;
    return 0;
  }

  memset(converted, 0x00, sizeof(converted));

  if (!bcrypto_cash32_convert_bits(err, converted, &converted_len,
                                   8, data, data_len, 5, 0)) {
    return 0;
  }

  if (converted_len > 1 + 64) {
    *err = BCRYPTO_CASH32_ERR_LENGTH;
    return 0;
  }

  *type = (converted[0] >> 3) & 0x1f;
  *hash_len = converted_len - 1;
  memcpy(hash, converted + 1, *hash_len);

  size = 20 + 4 * (converted[0] & 0x03);

  if (converted[0] & 0x04)
    size *= 2;

  if (size != *hash_len) {
    *err = BCRYPTO_CASH32_ERR_LENGTH;
    return 0;
  }

  return 1;
}

int
bcrypto_cash32_test(bcrypto_cash32_error *err,
                    const char *default_prefix,
                    const char *addr) {
  char prefix[84];
  uint8_t hash[64];
  size_t hash_len;
  int type = 0;

  memset(prefix, 0x00, sizeof(prefix));
  memset(hash, 0x00, sizeof(hash));

  if (!bcrypto_cash32_decode(err, &type, hash, &hash_len,
                             prefix, default_prefix, addr)) {
    return 0;
  }

  return 1;
}

const char *
bcrypto_cash32_strerror(bcrypto_cash32_error err) {
  switch (err) {
  case BCRYPTO_CASH32_ERR_CHECKSUM:
    return "Invalid cash32 checksum.";
  case BCRYPTO_CASH32_ERR_LENGTH:
    return "Invalid cash32 data length.";
  case BCRYPTO_CASH32_ERR_CASING:
    return "Invalid cash32 casing.";
  case BCRYPTO_CASH32_ERR_PADDING:
    return "Invalid padding in data.";
  case BCRYPTO_CASH32_ERR_NONZERO_PADDING:
    return "Non zero padding.";
  case BCRYPTO_CASH32_ERR_CHARACTER:
    return "Invalid cash32 character.";
  case BCRYPTO_CASH32_ERR_PREFIX:
    return "Invalid cash32 prefix.";
  case BCRYPTO_CASH32_ERR_TYPE:
    return "Invalid cash32 type.";
  case BCRYPTO_CASH32_ERR_SIZE:
    return "Non standard length.";
  case BCRYPTO_CASH32_ERR_SEPARATOR:
    return "Invalid cash32 separators.";
  default:
    return "Invalid cash32 string.";
  }
}
