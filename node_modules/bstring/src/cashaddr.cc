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

#include "cashaddr.h"

static uint64_t
cashaddr_polymod_step(uint64_t pre) {
  uint8_t b = pre >> 35;
  return ((pre & 0x07ffffffff) << 5)
    ^ (-((b >> 0) & 1) & 0x98f2bc8e61ul)
    ^ (-((b >> 1) & 1) & 0x79b76d99e2ul)
    ^ (-((b >> 2) & 1) & 0xf33e5fb3c4ul)
    ^ (-((b >> 3) & 1) & 0xae2eabe2a8ul)
    ^ (-((b >> 4) & 1) & 0x1e4f43e470ul);
}

static const char *CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static const int8_t TABLE[128] = {
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,
  -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
   1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
  -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
   1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1
};

static bool
cashaddr_encoded_size(size_t bytes, uint8_t *encoded_size) {
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
    return false;
  }
  return true;
}

static bool
cashaddr_encode(
  bstring_cashaddr_error *err,
  char *output,
  const char *prefix,
  const uint8_t *data,
  size_t data_len
) {
  uint64_t chk = 1;
  size_t i = 0;

  bool have_lower = false;
  bool have_upper = false;

  while (prefix[i] != 0) {
    const char pch = prefix[i];
    if (!(pch >> 5))
      return false;

    if (pch >= 'a' && pch <= 'z') {
      have_lower = true;
    } else if (pch >= 'A' && pch <= 'Z') {
      have_upper = true;
    } else if (pch >= '0' && pch <= '9') {
      *err = bstring_cashaddr_ERR_PREFIX;
      return false;
    }

    chk = cashaddr_polymod_step(chk);
    chk ^= (prefix[i] & 0x1f);

    // lowercase prefix
    if (prefix[i] >= 65 && prefix[i] <= 90) {
      *(output++) = prefix[i] + 32;
    } else {
      *(output++) = prefix[i];
    }

    i += 1;
    if (i > 83) {
      *err = bstring_cashaddr_ERR_PREFIX;
      return false;
    }
  }

  if ((have_upper && have_lower) || i == 0) {
    *err = bstring_cashaddr_ERR_PREFIX;
    return false;
  }

  chk = cashaddr_polymod_step(chk);
  *(output++) = ':';

  for (i = 0; i < data_len; i++) {
    uint8_t ch = data[i];
    if (ch >> 5)
      return false;

    chk = cashaddr_polymod_step(chk);
    chk ^= ch;
    *(output++) = CHARSET[ch];
  }

  for (i = 0; i < 8; i++)
    chk = cashaddr_polymod_step(chk);

  chk ^= 1;

  for (i = 0; i < 8; i++)
    *(output++) = CHARSET[(chk >> ((7 - i) * 5)) & 0x1f];

  return true;
}

static bool
cashaddr_decode(
  bstring_cashaddr_error *err,
  char *prefix,
  uint8_t *data,
  size_t *data_len,
  const char *default_prefix,
  const char *input
) {
  uint64_t chk = 1;
  size_t input_len = strlen(input);
  size_t prefix_len = 0;

  bool have_lower = false;
  bool have_upper = false;

  if (input_len < 8 || input_len > 196) { // 83 + 1 + 112
    *err = bstring_cashaddr_ERR_LENGTH;
    return false;
  }

  while (prefix_len < input_len && input[prefix_len] != ':') {
    prefix_len++;
    if (prefix_len > 83) {
      *err = bstring_cashaddr_ERR_PREFIX;
      return false;
    }
  }

  const bool has_prefix = !(prefix_len == input_len);

  const char *prefix_input = has_prefix ? input : default_prefix;
  size_t prefix_input_len = has_prefix ? prefix_len : strlen(default_prefix);
  *data_len = has_prefix ? input_len - (1 + prefix_len) : input_len;

  if (prefix_input_len < 1) {
    *err = bstring_cashaddr_ERR_PREFIX;
    return false;
  }

  if (*data_len < 8) {
    *err = bstring_cashaddr_ERR_LENGTH;
    return false;
  }

  *data_len -= 8;

  for (size_t i = 0; i < prefix_input_len; i++) {
    int ch = prefix_input[i];

    if (ch < 33 || ch > 126) {
      *err = bstring_cashaddr_ERR_CHARACTER;
      return false;
    }

    if (ch >= 'a' && ch <= 'z') {
      have_lower = true;
    } else if (ch >= 'A' && ch <= 'Z') {
      have_upper = true;
      ch = (ch - 'A') + 'a';
    } else if (ch >= '0' && ch <= '9') {
      *err = bstring_cashaddr_ERR_PREFIX;
      return false;
    }

    prefix[i] = ch;
    chk = cashaddr_polymod_step(chk);
    chk ^= (ch | 0x20) & 0x1f;
  }

  chk = cashaddr_polymod_step(chk);

  size_t j = has_prefix ? prefix_len + 1 : 0;
  size_t payload_len = 0;

  while (j < input_len) {
    int v = (input[j] & 0xff80) ? -1 : TABLE[(int)input[j]];

    if (input[j] >= 'a' && input[j] <= 'z')
      have_lower = true;

    if (input[j] >= 'A' && input[j] <= 'Z')
      have_upper = true;

    if (input[j] == ':') {
      *err = bstring_cashaddr_ERR_SEPARATOR;
      return false;
    }

    if (v == -1) {
      *err = bstring_cashaddr_ERR_CHARACTER;
      return false;
    }

    chk = cashaddr_polymod_step(chk) ^ v;

    if (j + 8 < input_len) {
      int x = has_prefix ? j - (1 + prefix_len) : j;
      data[x] = v;
    }

    j += 1;
    payload_len += 1;

    if (payload_len > 112) {
      *err = bstring_cashaddr_ERR_LENGTH;
      return false;
    }

  }

  if (payload_len <= 8) {
    *err = bstring_cashaddr_ERR_LENGTH;
    return false;
  }

  if (have_lower && have_upper) {
    *err = bstring_cashaddr_ERR_CASING;
    return false;
  }

  bool valid_checksum = (chk == 1) && (strcmp(prefix, default_prefix) == 0);
  if (!valid_checksum)
    *err = bstring_cashaddr_ERR_CHECKSUM;

  return valid_checksum;
}

static bool
convert_bits(
  bstring_cashaddr_error *err,
  uint8_t *out,
  size_t *outlen,
  int outbits,
  const uint8_t *in,
  size_t inlen,
  int inbits,
  int pad
) {
  uint32_t val = 0;
  int bits = 0;
  uint32_t maxv = (((uint32_t)1) << outbits) - 1;

  while (inlen--) {
    uint8_t value = *(in++);

    if ((value >> inbits) != 0) {
      *err = bstring_cashaddr_ERR_CHARACTER;
      return false;
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
    *err = bstring_cashaddr_ERR_CHARACTER;
    return false;
  }

  return true;
}

bool
bstring_cashaddr_encode(
  bstring_cashaddr_error *err,
  char *output,
  const char *prefix,
  int type,
  const uint8_t *hash,
  size_t hash_len
) {
  uint8_t encoded_size = 0;

  // There are 4 bits available for the version (2 ^ 4 = 16)
  if (type < 0 || type > 15) {
    *err = bstring_cashaddr_ERR_TYPE;
    return false;
  }

  if (!cashaddr_encoded_size(hash_len, &encoded_size)) {
    *err = bstring_cashaddr_ERR_SIZE;
    return false;
  }

  uint8_t version_byte = type << 3 | encoded_size;

  size_t data_len = hash_len + 1;
  uint8_t data[data_len];
  data[0] = version_byte;
  memcpy(data + 1, hash, hash_len);

  size_t converted_len = 0;
  uint8_t converted[(data_len * 8 / 5) + 1];

  if (!convert_bits(err, converted, &converted_len, 5, data, data_len, 8, 1))
    return false;

  return cashaddr_encode(err, output, prefix, converted, converted_len);
}

bool
bstring_cashaddr_decode(
  bstring_cashaddr_error *err,
  int *type,
  uint8_t *hash,
  size_t *hash_len,
  char *prefix,
  const char *default_prefix,
  const char *addr
) {
  uint8_t data[112 + 1];
  memset(&data, 0, 112 + 1);
  size_t data_len = 0;

  if (!cashaddr_decode(err, prefix, data, &data_len, default_prefix, addr))
    return false;

  size_t extrabits = (data_len * 5) % 8;
  if (extrabits >= 5) {
    *err = bstring_cashaddr_ERR_PADDING;
    return false;
  }

  uint8_t last = data[data_len - 1];
  size_t mask = (1 << extrabits) - 1;

  if (last & mask) {
    *err = bstring_cashaddr_ERR_NONZERO_PADDING;
    return false;
  }

  size_t _converted_len = (data_len * 5 / 8) + 1;
  uint8_t converted[_converted_len + 1];
  memset(&converted, 0, _converted_len + 1);
  size_t converted_len = 0;

  if (!convert_bits(err, converted, &converted_len, 8, data, data_len, 5, 0))
    return false;

  *type = (converted[0] >> 3) & 0x1f;
  *hash_len = converted_len - 1;
  // TODO set pointer instead of memcpy?
  memcpy(hash, converted + 1, *hash_len);

  uint8_t size = 20 + 4 * (converted[0] & 0x03);

  if (converted[0] & 0x04)
    size *= 2;

  if (size != *hash_len) {
    *err = bstring_cashaddr_ERR_LENGTH;
    return false;
  }

  return true;
}

bool
bstring_cashaddr_test(
  bstring_cashaddr_error *err,
  const char *default_prefix,
  const char *addr
) {
  char prefix[84];
  uint8_t hash[65];
  memset(hash, 0, 65);
  size_t hash_len;
  int type = 0;

  if (!bstring_cashaddr_decode(err, &type, hash, &hash_len, prefix, default_prefix, addr))
    return false;

  return true;
}

const char *
bstring_cashaddr_strerror(bstring_cashaddr_error err) {
  switch (err) {
  case bstring_cashaddr_ERR_CHECKSUM:
    return "Invalid cashaddr checksum.";
  case bstring_cashaddr_ERR_LENGTH:
    return "Invalid cashaddr data length.";
  case bstring_cashaddr_ERR_CASING:
    return "Invalid cashaddr casing.";
  case bstring_cashaddr_ERR_PADDING:
    return "Invalid padding in data.";
  case bstring_cashaddr_ERR_NONZERO_PADDING:
    return "Non zero padding.";
  case bstring_cashaddr_ERR_CHARACTER:
    return "Invalid cashaddr character.";
  case bstring_cashaddr_ERR_PREFIX:
    return "Invalid cashaddr prefix.";
  case bstring_cashaddr_ERR_TYPE:
    return "Invalid cashaddr type.";
  case bstring_cashaddr_ERR_SIZE:
    return "Non standard length.";
  case bstring_cashaddr_ERR_SEPARATOR:
    return "Invalid cashaddr separators.";
  default:
    return "Invalid cashaddr string.";
  }
}
