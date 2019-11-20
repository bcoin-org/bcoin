#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <assert.h>

static const char *CHARSET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static const int8_t TABLE[128] = {
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1,  0,  1,  2,  3,  4,  5,  6,  7,  8, -1, -1, -1, -1, -1, -1,
  -1,  9, 10, 11, 12, 13, 14, 15, 16, -1, 17, 18, 19, 20, 21, -1,
  22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, -1, -1, -1, -1, -1,
  -1, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, -1, 44, 45, 46,
  47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, -1, -1, -1, -1, -1
};

bool
bstring_base58_encode(
  const uint8_t *data,
  size_t datalen,
  uint8_t **str,
  size_t *strlen
) {
  *str = NULL;
  *strlen = 0;

  int32_t dlen = (int32_t)datalen;

  if (dlen < 0)
    return false;

  if (dlen == 0)
    return true;

  assert(data != NULL);

  int32_t zeroes = 0;
  int32_t i;

  for (i = 0; i < dlen; i++) {
    if (data[i] != 0)
      break;
    zeroes += 1;
  }

  size_t b58size = (size_t)dlen * 138 / 100 + 1;
  int32_t b58len = (int32_t)b58size;

  if (b58len < 0)
    return false;

  uint8_t *b58 = (uint8_t *)malloc(b58size);
  int32_t length = 0;

  if (b58 == NULL)
    return false;

  memset(b58, 0, b58len);

  for (; i < dlen; i++) {
    int32_t carry = data[i];
    int32_t j = 0;
    int32_t k;

    for (k = b58len - 1; k >= 0; k--, j++) {
      if (carry == 0 && j >= length)
        break;
      carry += 256 * b58[k];
      b58[k] = carry % 58;
      carry = carry / 58;
    }

    assert(carry == 0);
    length = j;
  }

  i = b58len - length;
  while (i < b58len && b58[i] == 0)
    i += 1;

  *str = (uint8_t *)malloc(zeroes + (b58len - i) + 1);

  if (*str == NULL) {
    free(b58);
    return false;
  }

  int32_t j;
  for (j = 0; j < zeroes; j++)
    (*str)[j] = '1';

  for (; i < b58len; i++)
    (*str)[j++] = CHARSET[b58[i]];

  (*str)[j] = 0;
  *strlen = (size_t)j;

  free(b58);

  return true;
}

bool
bstring_base58_decode(
  const uint8_t *str,
  size_t strlen,
  uint8_t **data,
  size_t *datalen
) {
  *data = NULL;
  *datalen = 0;

  int32_t slen = (int32_t)strlen;

  if (slen < 0)
    return false;

  if (slen == 0)
    return true;

  assert(str != NULL);

  int32_t zeroes = 0;
  int32_t i;

  for (i = 0; i < slen; i++) {
    if (str[i] != '1')
      break;
    zeroes += 1;
  }

  int32_t b256len = slen * 733 / 1000 + 1;

  if (b256len < 0)
    return false;

  uint8_t *b256 = (uint8_t *)malloc(b256len);
  int32_t length = 0;

  if (b256 == NULL)
    return false;

  memset(b256, 0, b256len);

  for (; i < slen; i++) {
    int32_t v = (str[i] & 0x80) ? -1 : (int32_t)TABLE[str[i]];

    if (v == -1) {
      free(b256);
      return false;
    }

    int32_t carry = v;
    int32_t j = 0;
    int32_t k;

    for (k = b256len - 1; k >= 0; k--, j++) {
      if (carry == 0 && j >= length)
        break;
      carry += 58 * b256[k];
      b256[k] = carry % 256;
      carry = carry / 256;
    }

    assert(carry == 0);
    length = j;
  }

  i = 0;
  while (i < b256len && b256[i] == 0)
    i += 1;

  int32_t dlen = zeroes + (b256len - i);

  *data = (uint8_t *)malloc(dlen);

  if (*data == NULL) {
    free(b256);
    return false;
  }

  int32_t j;
  for (j = 0; j < zeroes; j++)
    (*data)[j] = 0;

  while (i < b256len)
    (*data)[j++] = b256[i++];

  assert(j == dlen);

  *datalen = (size_t)j;

  free(b256);

  return true;
}

bool
bstring_base58_test(const uint8_t *str, size_t strlen) {
  int32_t slen = (int32_t)strlen;

  if (slen < 0)
    return false;

  if (slen == 0)
    return true;

  assert(str != NULL);

  int32_t i = 0;

  for (; i < slen; i++) {
    if (str[i] & 0x80)
      return false;

    if ((int32_t)TABLE[str[i]] == -1)
      return false;
  }

  return true;
}
