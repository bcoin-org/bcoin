/*!
 * asn1.h - asn1 for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 */

#ifndef _TORSION_ASN1_H
#define _TORSION_ASN1_H

#include <stddef.h>
#include "mpi.h"

/*
 * Alias
 */

#define asn1_read_size __torsion_asn1_read_size
#define asn1_read_seq __torsion_asn1_read_seq
#define asn1_read_int __torsion_asn1_read_int
#define asn1_read_mpz __torsion_asn1_read_mpz
#define asn1_read_version __torsion_asn1_read_version
#define asn1_read_dumb __torsion_asn1_read_dumb
#define asn1_size_size __torsion_asn1_size_size
#define asn1_size_int __torsion_asn1_size_int
#define asn1_size_mpz __torsion_asn1_size_mpz
#define asn1_size_version __torsion_asn1_size_version
#define asn1_write_size __torsion_asn1_write_size
#define asn1_write_seq __torsion_asn1_write_seq
#define asn1_write_int __torsion_asn1_write_int
#define asn1_write_mpz __torsion_asn1_write_mpz
#define asn1_write_version __torsion_asn1_write_version
#define asn1_write_dumb __torsion_asn1_write_dumb

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

#endif /* _TORSION_ASN1_H */
