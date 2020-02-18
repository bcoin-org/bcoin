/*!
 * objects.js - OIDs encoding for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on golang/go:
 *   Copyright (c) 2009, The Go Authors. All rights reserved.
 *   https://github.com/golang/go
 *
 * Resources:
 *   https://www.ietf.org/rfc/rfc2459.txt
 *   https://tools.ietf.org/html/rfc3279
 *   http://oid-info.com/get/1.2.840.10040.4
 *   http://oid-info.com/get/1.2.840.113549.1.1
 *   http://oid-info.com/get/1.2.840.10045.4.3
 *   https://tools.ietf.org/html/draft-jivsov-openpgp-sha3-01
 *   https://github.com/golang/go/blob/master/src/crypto/x509/x509.go
 *   https://github.com/golang/go/blob/master/src/crypto/x509/pkix/pkix.go
 *   https://tools.ietf.org/html/draft-josefsson-pkix-eddsa-01
 *   https://tools.ietf.org/html/rfc5480
 *   https://tools.ietf.org/html/draft-josefsson-pkix-newcurves-00
 *   https://tools.ietf.org/id/draft-ietf-curdle-pkix-06.html
 *   https://tools.ietf.org/html/rfc7693
 */

'use strict';

const NONE = '0.0';

const attrs = {
  COUNTRY: '2.5.4.6',
  ORGANIZATION: '2.5.4.10',
  ORGANIZATIONALUNIT: '2.5.4.11',
  COMMONNAME: '2.5.4.3',
  SERIALNUMBER: '2.5.4.5',
  LOCALITY: '2.5.4.7',
  PROVINCE: '2.5.4.8',
  STREETADDRESS: '2.5.4.9',
  POSTALCODE: '2.5.4.17'
};

const attrsByVal = {
  [attrs.COUNTRY]: 'COUNTRY',
  [attrs.ORGANIZATION]: 'ORGANIZATION',
  [attrs.ORGANIZATIONALUNIT]: 'ORGANIZATIONALUNIT',
  [attrs.COMMONNAME]: 'COMMONNAME',
  [attrs.SERIALNUMBER]: 'SERIALNUMBER',
  [attrs.LOCALITY]: 'LOCALITY',
  [attrs.PROVINCE]: 'PROVINCE',
  [attrs.STREETADDRESS]: 'STREETADDRESS',
  [attrs.POSTALCODE]: 'POSTALCODE'
};

const keyAlgs = {
  DH: '1.2.840.113549.1.3.1',
  DSA: '1.2.840.10040.4.1',
  DSA_ALT: '1.2.840.10040.4.2',
  RSA: '1.2.840.113549.1.1.1',
  ECDSA: '1.2.840.10045.2.1',
  EDDSA: '1.3.6.1.4.1.11591.4.12.1'
};

const keyAlgsByVal = {
  [keyAlgs.DH]: 'DH',
  [keyAlgs.DSA]: 'DSA',
  [keyAlgs.DSA_ALT]: 'DSA',
  [keyAlgs.RSA]: 'RSA',
  [keyAlgs.ECDSA]: 'ECDSA',
  [keyAlgs.EDDSA]: 'EDDSA'
};

const hashes = {
  BLAKE2B160: '1.3.6.1.4.1.1722.12.2.1.5',
  BLAKE2B256: '1.3.6.1.4.1.1722.12.2.1.8',
  BLAKE2B384: '1.3.6.1.4.1.1722.12.2.1.12',
  BLAKE2B512: '1.3.6.1.4.1.1722.12.2.1.16',
  BLAKE2S128: '1.3.6.1.4.1.1722.12.2.2.4',
  BLAKE2S160: '1.3.6.1.4.1.1722.12.2.2.5',
  BLAKE2S224: '1.3.6.1.4.1.1722.12.2.2.7',
  BLAKE2S256: '1.3.6.1.4.1.1722.12.2.2.8',
  GOST94: '1.2.643.2.2.20',
  MD2: '1.2.840.113549.2.2',
  MD4: '1.2.840.113549.2.4',
  MD5: '1.2.840.113549.2.5',
  MDC2: '1.3.14.3.2.19',
  RIPEMD160: '1.0.10118.3.0.49',
  RIPEMD160_ALT: '1.3.36.3.2.1',
  SHA1: '1.3.14.3.2.26',
  SHA224: '2.16.840.1.101.3.4.2.4',
  SHA256: '2.16.840.1.101.3.4.2.1',
  SHA384: '2.16.840.1.101.3.4.2.2',
  SHA512: '2.16.840.1.101.3.4.2.3',
  SHA3_224: '2.16.840.1.101.3.4.2.7',
  SHA3_256: '2.16.840.1.101.3.4.2.8',
  SHA3_384: '2.16.840.1.101.3.4.2.9',
  SHA3_512: '2.16.840.1.101.3.4.2.10',
  SHAKE128: '2.16.840.1.101.3.4.2.11',
  SHAKE256: '2.16.840.1.101.3.4.2.12',
  SM3: '1.0.10118.3.0.65',
  WHIRLPOOL: '1.0.10118.3.0.55'
};

const hashesByVal = {
  [hashes.BLAKE2B160]: 'BLAKE2B160',
  [hashes.BLAKE2B256]: 'BLAKE2B256',
  [hashes.BLAKE2B384]: 'BLAKE2B384',
  [hashes.BLAKE2B512]: 'BLAKE2B512',
  [hashes.BLAKE2S128]: 'BLAKE2S128',
  [hashes.BLAKE2S160]: 'BLAKE2S160',
  [hashes.BLAKE2S224]: 'BLAKE2S224',
  [hashes.BLAKE2S256]: 'BLAKE2S256',
  [hashes.GOST94]: 'GOST94',
  [hashes.MD2]: 'MD2',
  [hashes.MD4]: 'MD4',
  [hashes.MD5]: 'MD5',
  [hashes.MDC2]: 'MDC2',
  [hashes.RIPEMD160]: 'RIPEMD160',
  [hashes.RIPEMD160_ALT]: 'RIPEMD160',
  [hashes.SHA1]: 'SHA1',
  [hashes.SHA224]: 'SHA224',
  [hashes.SHA256]: 'SHA256',
  [hashes.SHA384]: 'SHA384',
  [hashes.SHA512]: 'SHA512',
  [hashes.SHA3_224]: 'SHA3_224',
  [hashes.SHA3_256]: 'SHA3_256',
  [hashes.SHA3_384]: 'SHA3_384',
  [hashes.SHA3_512]: 'SHA3_512',
  [hashes.SHAKE128]: 'SHAKE128',
  [hashes.SHAKE256]: 'SHAKE256',
  [hashes.SM3]: 'SM3',
  [hashes.WHIRLPOOL]: 'WHIRLPOOL'
};

const curves = {
  P192: '1.2.840.10045.3.1.1',
  P224: '1.3.132.0.33',
  P256: '1.2.840.10045.3.1.7',
  P384: '1.3.132.0.34',
  P521: '1.3.132.0.35',
  BRAINPOOLP256: '1.3.36.3.3.2.8.1.1.7',
  BRAINPOOLP384: '1.3.36.3.3.2.8.1.1.11',
  BRAINPOOLP512: '1.3.36.3.3.2.8.1.1.13',
  SECP192K1: '1.3.132.0.31',
  SECP224K1: '1.3.132.0.32',
  SECP256K1: '1.3.132.0.10',
  FRP256V1: '1.2.250.1.223.101.256.1',
  X25519: '1.3.101.110',
  X25519_ALT: '1.3.6.1.4.1.11591.7',
  ED25519: '1.3.101.112',
  X448: '1.3.101.111',
  X448_ALT: '1.3.6.1.4.1.11591.8',
  ED448: '1.3.101.113',
  // Non-standard, but officially registered:
  // See: https://github.com/weidai11/cryptopp/issues/67#issuecomment-162191213
  ED1174: '1.3.6.1.4.1.9509.5.2.6',
  ED41417: '1.3.6.1.4.1.9509.5.2.5',
  CURVE383187: '1.3.6.1.4.1.9509.5.1.4',
  M221: '1.3.6.1.4.1.9509.5.1.1',
  E222: '1.3.6.1.4.1.9509.5.2.1',
  M383: '1.3.6.1.4.1.9509.5.1.2',
  E382: '1.3.6.1.4.1.9509.5.2.2',
  M511: '1.3.6.1.4.1.9509.5.1.3',
  E521: '1.3.6.1.4.1.9509.5.2.4'
};

const curvesByVal = {
  [curves.P192]: 'P192',
  [curves.P224]: 'P224',
  [curves.P256]: 'P256',
  [curves.P384]: 'P384',
  [curves.P521]: 'P521',
  [curves.BRAINPOOLP256]: 'BRAINPOOLP256',
  [curves.BRAINPOOLP384]: 'BRAINPOOLP384',
  [curves.BRAINPOOLP512]: 'BRAINPOOLP512',
  [curves.SECP192K1]: 'SECP192K1',
  [curves.SECP224K1]: 'SECP224K1',
  [curves.SECP256K1]: 'SECP256K1',
  [curves.FRP256V1]: 'FRP256V1',
  [curves.X25519]: 'X25519',
  [curves.X25519_ALT]: 'X25519',
  [curves.ED25519]: 'ED25519',
  [curves.X448]: 'X448',
  [curves.X448_ALT]: 'X448',
  [curves.ED448]: 'ED448',
  [curves.ED1174]: 'ED1174',
  [curves.ED41417]: 'ED41417',
  [curves.CURVE383187]: 'CURVE383187',
  [curves.M221]: 'M221',
  [curves.E222]: 'E222',
  [curves.M383]: 'M383',
  [curves.E382]: 'E382',
  [curves.M511]: 'M511',
  [curves.E521]: 'E521'
};

const sigAlgs = {
  DSASHA1: '1.2.840.10040.4.3',
  RSAMD2: '1.2.840.113549.1.1.2',
  RSAMD4: '1.2.840.113549.1.1.3',
  RSAMD5: '1.2.840.113549.1.1.4',
  RSASHA1: '1.2.840.113549.1.1.5',
  RSASHA1_MS: '1.3.14.3.2.29',
  RSAPSS: '1.2.840.113549.1.1.10',
  RSASHA256: '1.2.840.113549.1.1.11',
  RSASHA384: '1.2.840.113549.1.1.12',
  RSASHA512: '1.2.840.113549.1.1.13',
  RSASHA224: '1.2.840.113549.1.1.14',
  MGF1: '1.2.840.113549.1.1.8',
  RSASHA3_256: '2.16.840.1.101.3.4.2.8',
  RSASHA3_384: '2.16.840.1.101.3.4.2.9',
  RSASHA3_512: '2.16.840.1.101.3.4.2.10',
  ECDSASHA1: '1.2.840.10045.4.1',
  ECDSASHA224: '1.2.840.10045.4.3.1',
  ECDSASHA256: '1.2.840.10045.4.3.2',
  ECDSASHA384: '1.2.840.10045.4.3.3',
  ECDSASHA512: '1.2.840.10045.4.3.4',
  EDDSA: '1.3.6.1.4.1.11591.4.12.2'
};

const sigAlgsByVal = {
  [sigAlgs.DSASHA1]: 'DSASHA1',
  [sigAlgs.RSAMD2]: 'RSAMD2',
  [sigAlgs.RSAMD4]: 'RSAMD4',
  [sigAlgs.RSAMD5]: 'RSAMD5',
  [sigAlgs.RSASHA1]: 'RSASHA1',
  [sigAlgs.RSASHA1_MS]: 'RSASHA1',
  [sigAlgs.RSAPSS]: 'RSAPSS',
  [sigAlgs.RSASHA256]: 'RSASHA256',
  [sigAlgs.RSASHA384]: 'RSASHA384',
  [sigAlgs.RSASHA512]: 'RSASHA512',
  [sigAlgs.MGF1]: 'MGF1',
  [sigAlgs.RSASHA3_256]: 'RSASHA3_256',
  [sigAlgs.RSASHA3_384]: 'RSASHA3_384',
  [sigAlgs.RSASHA3_512]: 'RSASHA3_512',
  [sigAlgs.ECDSASHA1]: 'ECDSASHA1',
  [sigAlgs.ECDSASHA224]: 'ECDSASHA224',
  [sigAlgs.ECDSASHA384]: 'ECDSASHA384',
  [sigAlgs.ECDSASHA512]: 'ECDSASHA512',
  [sigAlgs.EDDSA]: 'EDDSA'
};

const sigToHash = {
  [sigAlgs.DSASHA1]: hashes.SHA1,
  [sigAlgs.RSAMD2]: hashes.MD2,
  [sigAlgs.RSAMD4]: hashes.MD4,
  [sigAlgs.RSAMD5]: hashes.MD5,
  [sigAlgs.RSASHA1]: hashes.SHA1,
  [sigAlgs.RSASHA1_MS]: hashes.SHA1,
  [sigAlgs.RSAPSS]: null,
  [sigAlgs.RSASHA256]: hashes.SHA256,
  [sigAlgs.RSASHA384]: hashes.SHA384,
  [sigAlgs.RSASHA512]: hashes.SHA512,
  [sigAlgs.MGF1]: null,
  [sigAlgs.RSASHA3_256]: hashes.SHA3_256,
  [sigAlgs.RSASHA3_384]: hashes.SHA3_384,
  [sigAlgs.RSASHA3_512]: hashes.SHA3_512,
  [sigAlgs.ECDSASHA1]: hashes.SHA1,
  [sigAlgs.ECDSASHA224]: hashes.SHA224,
  [sigAlgs.ECDSASHA384]: hashes.SHA384,
  [sigAlgs.ECDSASHA512]: hashes.SHA512,
  [sigAlgs.EDDSA]: null
};

/*
 * Expose
 */

exports.NONE = NONE;
exports.attrs = attrs;
exports.attrsByVal = attrsByVal;
exports.keyAlgs = keyAlgs;
exports.keyAlgsByVal = keyAlgsByVal;
exports.hashes = hashes;
exports.hashesByVal = hashesByVal;
exports.curves = curves;
exports.curvesByVal = curvesByVal;
exports.sigAlgs = sigAlgs;
exports.sigAlgsByVal = sigAlgsByVal;
exports.sigToHash = sigToHash;
