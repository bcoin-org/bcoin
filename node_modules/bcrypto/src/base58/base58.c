#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "base58.h"

static const char *CHARSET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static const int TABLE[128] = {
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1,  0,  1,  2,  3,  4,  5,  6,  7,  8, -1, -1, -1, -1, -1, -1,
  -1,  9, 10, 11, 12, 13, 14, 15, 16, -1, 17, 18, 19, 20, 21, -1,
  22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, -1, -1, -1, -1, -1,
  -1, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, -1, 44, 45, 46,
  47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, -1, -1, -1, -1, -1
};

int
base58_encode(char **str, size_t *str_len,
              const uint8_t *data, size_t data_len) {
  uint64_t b58size = (uint64_t)data_len * 138 / 100 + 1;
  size_t b58len = (size_t)b58size; /* 31 bit max */
  uint8_t *b58;
  size_t zeroes = 0;
  size_t length = 0;
  size_t i, j;

  if (data_len > 1073741823ul) /* 2^30 - 1 */
    return 0;

  for (i = 0; i < data_len; i++) {
    if (data[i] != 0)
      break;

    zeroes += 1;
  }

  b58 = malloc(b58len);

  if (b58 == NULL)
    return 0;

  memset(b58, 0, b58len);

  for (; i < data_len; i++) {
    unsigned long carry = data[i];
    size_t k;

    for (j = 0; j < b58len; j++) {
      if (carry == 0 && j >= length)
        break;

      k = b58len - 1 - j;
      carry += 256 * b58[k];
      b58[k] = carry % 58;
      carry /= 58;
    }

    assert(carry == 0);

    length = j;
  }

  i = b58len - length;

  while (i < b58len && b58[i] == 0)
    i += 1;

  *str = malloc(zeroes + (b58len - i) + 1);

  if (*str == NULL) {
    free(b58);
    return 0;
  }

  for (j = 0; j < zeroes; j++)
    (*str)[j] = '1';

  for (; i < b58len; i++)
    (*str)[j++] = CHARSET[b58[i]];

  (*str)[j] = '\0';
  *str_len = j;

  free(b58);

  return 1;
}

int
base58_decode(uint8_t **data, size_t *data_len,
              const char *str, size_t str_len) {
  uint64_t b256size = (uint64_t)str_len * 733 / 1000 + 1;
  size_t b256len = (size_t)b256size;
  uint8_t *b256;
  size_t zeroes = 0;
  size_t length = 0;
  size_t i, j;

  if (str_len > 1481763716ul) /* (2^30 - 1) * 138 / 100 + 1 */
    return 0;

  for (i = 0; i < str_len; i++) {
    if (str[i] != '1')
      break;

    zeroes += 1;
  }

  b256 = malloc(b256len);

  if (b256 == NULL)
    return 0;

  memset(b256, 0, b256len);

  for (; i < str_len; i++) {
    uint8_t ch = (uint8_t)str[i];
    int v = (ch & 0x80) ? -1 : TABLE[ch];
    unsigned long carry = v;
    size_t k;

    if (v == -1) {
      free(b256);
      return 0;
    }

    for (j = 0; j < b256len; j++) {
      if (carry == 0 && j >= length)
        break;

      k = b256len - 1 - j;
      carry += 58 * b256[k];
      b256[k] = carry & 0xff;
      carry >>= 8;
    }

    assert(carry == 0);

    length = j;
  }

  i = 0;

  while (i < b256len && b256[i] == 0)
    i += 1;

  *data = malloc(zeroes + (b256len - i) + 1);

  if (*data == NULL) {
    free(b256);
    return 0;
  }

  for (j = 0; j < zeroes; j++)
    (*data)[j] = 0;

  while (i < b256len)
    (*data)[j++] = b256[i++];

  *data_len = j;

  free(b256);

  return 1;
}

int
base58_test(const char *str, size_t str_len) {
  size_t i = 0;

  for (; i < str_len; i++) {
    uint8_t ch = (uint8_t)str[i];

    if (ch & 0x80)
      return 0;

    if (TABLE[ch] == -1)
      return 0;
  }

  return 1;
}
