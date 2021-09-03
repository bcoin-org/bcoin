/*!
 * asn1.h - asn1 for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 */

#ifndef TORSION_ASN1_H
#define TORSION_ASN1_H

#include <stddef.h>
#include "mpi.h"

/*
 * Alias
 */

#define asn1_read_size torsion__asn1_read_size
#define asn1_read_seq torsion__asn1_read_seq
#define asn1_read_int torsion__asn1_read_int
#define asn1_read_mpz torsion__asn1_read_mpz
#define asn1_read_version torsion__asn1_read_version
#define asn1_read_dumb torsion__asn1_read_dumb
#define asn1_size_size torsion__asn1_size_size
#define asn1_size_int torsion__asn1_size_int
#define asn1_size_mpz torsion__asn1_size_mpz
#define asn1_size_version torsion__asn1_size_version
#define asn1_write_size torsion__asn1_write_size
#define asn1_write_seq torsion__asn1_write_seq
#define asn1_write_int torsion__asn1_write_int
#define asn1_write_mpz torsion__asn1_write_mpz
#define asn1_write_version torsion__asn1_write_version
#define asn1_write_dumb torsion__asn1_write_dumb

/*
 * ASN1
 */

int
asn1_read_size(size_t *size,
               const unsigned char **data,
               size_t *len, int strict);

int
asn1_read_seq(const unsigned char **data, size_t *len, int strict);

int
asn1_read_int(unsigned char *out, size_t out_len,
              const unsigned char **data, size_t *len, int strict);

int
asn1_read_mpz(mpz_t n, const unsigned char **data, size_t *len, int strict);

int
asn1_read_version(const unsigned char **data, size_t *len,
                  unsigned int version, int strict);

int
asn1_read_dumb(mpz_t n, const unsigned char **data, size_t *len);

size_t
asn1_size_size(size_t size);

size_t
asn1_size_int(const unsigned char *num, size_t len);

size_t
asn1_size_mpz(const mpz_t n);

size_t
asn1_size_version(unsigned int version);

size_t
asn1_write_size(unsigned char *data, size_t pos, size_t size);

size_t
asn1_write_seq(unsigned char *data, size_t pos, size_t size);

size_t
asn1_write_int(unsigned char *data, size_t pos,
               const unsigned char *num, size_t len);

size_t
asn1_write_mpz(unsigned char *data, size_t pos, const mpz_t n);

size_t
asn1_write_version(unsigned char *data, size_t pos, unsigned int version);

size_t
asn1_write_dumb(unsigned char *data, size_t pos, const mpz_t n);

#endif /* TORSION_ASN1_H */
