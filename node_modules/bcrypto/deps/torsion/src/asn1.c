/*!
 * asn1.c - asn1 for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 */

#include <limits.h>
#include <stddef.h>
#include <string.h>
#include "asn1.h"
#include "internal.h"
#include "mpi.h"

/*
 * ASN1
 */

int
asn1_read_size(size_t *size,
               const unsigned char **data,
               size_t *len, int strict) {
  unsigned char ch;

  STATIC_ASSERT(sizeof(size_t) * CHAR_BIT >= 32);

  if (*len == 0)
    goto fail;

  ch = **data;

  *data += 1;
  *len -= 1;

  if ((ch & 0x80) == 0) {
    /* Short form. */
    *size = ch;
  } else {
    size_t bytes = ch & 0x7f;
    size_t i;

    /* Indefinite form. */
    if (strict && bytes == 0)
      goto fail;

    /* Long form. */
    *size = 0;

    for (i = 0; i < bytes; i++) {
      if (*len == 0)
        goto fail;

      ch = **data;
      *data += 1;
      *len -= 1;

      if (*size >= ((size_t)1 << 24))
        goto fail;

      *size <<= 8;
      *size |= ch;

      if (strict && *size == 0)
        goto fail;
    }

    if (strict && *size < 0x80)
      goto fail;
  }

  return 1;
fail:
  *size = 0;
  return 0;
}

int
asn1_read_seq(const unsigned char **data, size_t *len, int strict) {
  size_t size;

  if (*len == 0 || **data != 0x30)
    return 0;

  *data += 1;
  *len -= 1;

  if (!asn1_read_size(&size, data, len, strict))
    return 0;

  if (strict && size != *len)
    return 0;

  return 1;
}

int
asn1_read_int(unsigned char *out, size_t out_len,
              const unsigned char **data, size_t *len, int strict) {
  size_t size;

  if (*len == 0 || **data != 0x02)
    goto fail;

  *data += 1;
  *len -= 1;

  if (!asn1_read_size(&size, data, len, strict))
    goto fail;

  /* Out of bounds. */
  if (size > *len)
    goto fail;

  if (strict) {
    const unsigned char *num = *data;

    /* Zero-length integer. */
    if (size == 0)
      goto fail;

    /* No negatives. */
    if (num[0] & 0x80)
      goto fail;

    /* Allow zero only if it prefixes a high bit. */
    if (size > 1 && num[0] == 0x00) {
      if ((num[1] & 0x80) == 0x00)
        goto fail;
    }
  }

  /* Eat leading zeroes. */
  while (size > 0 && **data == 0x00) {
    *data += 1;
    *len -= 1;
    size -= 1;
  }

  /* Invalid size. */
  if (size > out_len)
    goto fail;

  memset(out, 0x00, out_len - size);
  memcpy(out + out_len - size, *data, size);

  *data += size;
  *len -= size;

  return 1;
fail:
  memset(out, 0x00, out_len);
  return 0;
}

int
asn1_read_mpz(mpz_t n, const unsigned char **data, size_t *len, int strict) {
  size_t size;

  if (*len == 0 || **data != 0x02)
    goto fail;

  *data += 1;
  *len -= 1;

  if (!asn1_read_size(&size, data, len, 1))
    goto fail;

  /* Out of bounds. */
  if (size > *len)
    goto fail;

  if (strict) {
    const unsigned char *num = *data;

    /* Zero-length integer. */
    if (size == 0)
      goto fail;

    /* No negatives. */
    if (num[0] & 0x80)
      goto fail;

    /* Allow zero only if it prefixes a high bit. */
    if (size > 1 && num[0] == 0x00) {
      if ((num[1] & 0x80) == 0x00)
        goto fail;
    }
  }

  /* Eat leading zeroes. */
  while (size > 0 && **data == 0x00) {
    *data += 1;
    *len -= 1;
    size -= 1;
  }

  /* Invalid size. */
  if (size > 2048)
    goto fail;

  mpz_import(n, *data, size, 1);

  *data += size;
  *len -= size;

  return 1;
fail:
  mpz_set_ui(n, 0);
  return 0;
}

int
asn1_read_version(const unsigned char **data, size_t *len,
                  unsigned int version, int strict) {
  int ret = 0;
  mpz_t n;

  if (strict) {
    const unsigned char *num = *data;

    if (*len < 3)
      return 0;

    if (num[0] != 0x02 || num[1] != 0x01 || num[2] != version)
      return 0;

    *data += 3;
    *len -= 3;

    return 1;
  }

  mpz_init(n);

  if (asn1_read_mpz(n, data, len, 0))
    ret = (mpz_cmp_ui(n, version) == 0);

  mpz_clear(n);

  return ret;
}

int
asn1_read_dumb(mpz_t n, const unsigned char **data, size_t *len) {
  const unsigned char *buf = *data;
  size_t size;

  if (*len < 2)
    goto fail;

  size = ((size_t)buf[0] << 8) | (size_t)buf[1];

  *data += 2;
  *len -= 2;

  if (size > *len)
    goto fail;

  mpz_import(n, *data, size, 1);

  *data += size;
  *len -= size;

  return 1;
fail:
  mpz_set_ui(n, 0);
  return 0;
}

size_t
asn1_size_size(size_t size) {
  if (size <= 0x7f) /* [size] */
    return 1;

  if (size <= 0xff) /* 0x81 [size] */
    return 2;

  return 3; /* 0x82 [size-hi] [size-lo] */
}

size_t
asn1_size_int(const unsigned char *num, size_t len) {
  /* 0x02 [size] [0x00?] [int] */
  while (len > 0 && num[0] == 0x00) {
    len--;
    num++;
  }

  if (len == 0)
    return 3;

  len += num[0] >> 7;

  return 1 + asn1_size_size(len) + len;
}

size_t
asn1_size_mpz(const mpz_t n) {
  /* 0x02 [size] [0x00?] [int] */
  size_t bits = mpz_bitlen(n);
  size_t size = (bits + 7) / 8;

  if (bits > 0 && (bits & 7) == 0)
    size += mpz_tstbit(n, bits - 1);

  if (bits == 0)
    size = 1;

  return 1 + asn1_size_size(size) + size;
}

size_t
asn1_size_version(unsigned int version) {
  (void)version;
  return 3;
}

size_t
asn1_write_size(unsigned char *data, size_t pos, size_t size) {
  if (size <= 0x7f)  {
    /* [size] */
    data[pos++] = size;
  } else if (size <= 0xff) {
    /* 0x81 [size] */
    data[pos++] = 0x81;
    data[pos++] = size;
  } else {
    /* 0x82 [size-hi] [size-lo] */
    CHECK(size <= 0xffff);

    data[pos++] = 0x82;
    data[pos++] = size >> 8;
    data[pos++] = size & 0xff;
  }

  return pos;
}

size_t
asn1_write_seq(unsigned char *data, size_t pos, size_t size) {
  data[pos++] = 0x30;
  return asn1_write_size(data, pos, size);
}

size_t
asn1_write_int(unsigned char *data, size_t pos,
               const unsigned char *num, size_t len) {
  size_t pad = 0;

  /* 0x02 [size] [0x00?] [int] */
  while (len > 0 && num[0] == 0x00) {
    len--;
    num++;
  }

  if (len == 0) {
    data[pos++] = 0x02;
    data[pos++] = 0x01;
    data[pos++] = 0x00;
    return pos;
  }

  pad = num[0] >> 7;

  data[pos++] = 0x02;

  pos = asn1_write_size(data, pos, pad + len);

  if (pad)
    data[pos++] = 0x00;

  memcpy(data + pos, num, len);

  pos += len;

  return pos;
}

size_t
asn1_write_mpz(unsigned char *data, size_t pos, const mpz_t n) {
  /* 0x02 [size] [0x00?] [int] */
  size_t bits = mpz_bitlen(n);
  size_t size = (bits + 7) / 8;
  size_t pad = 0;

  if (bits > 0 && (bits & 7) == 0)
    pad = mpz_tstbit(n, bits - 1);

  if (bits == 0)
    size = 1;

  data[pos++] = 0x02;

  pos = asn1_write_size(data, pos, pad + size);

  if (pad)
    data[pos++] = 0x00;

  mpz_export(data + pos, n, size, 1);

  pos += size;

  return pos;
}

size_t
asn1_write_version(unsigned char *data, size_t pos, unsigned int version) {
  CHECK(version <= 0xff);

  data[pos++] = 0x02;
  data[pos++] = 0x01;
  data[pos++] = version;

  return pos;
}

size_t
asn1_write_dumb(unsigned char *data, size_t pos, const mpz_t n) {
  size_t size = mpz_bytelen(n);

  CHECK(size <= 0xffff);

  data[pos++] = size >> 8;
  data[pos++] = size & 0xff;

  mpz_export(data + pos, n, size, 1);

  pos += size;

  return pos;
}
