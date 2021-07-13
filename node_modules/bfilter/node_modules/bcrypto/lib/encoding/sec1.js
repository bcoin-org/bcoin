/*!
 * sec1.js - SEC1 encoding for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on golang/go:
 *   Copyright (c) 2009, The Go Authors. All rights reserved.
 *   https://github.com/golang/go
 *
 * Resources:
 *   http://www.secg.org/sec1-v2.pdf
 *   https://github.com/openssl/openssl/blob/master/crypto/ec/ec_asn1.c
 *   https://github.com/golang/go/blob/master/src/crypto/x509/sec1.go
 *   https://tools.ietf.org/html/rfc5915
 */

'use strict';

const asn1 = require('./asn1');
const pem = require('./pem');

/**
 * ECPrivateKey
 */

// ECPrivateKey ::= SEQUENCE {
//   version INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
//   privateKey OCTET STRING,
//   parameters [0] ECDomainParameters {{ SECGCurveNames }} OPTIONAL,
//   publicKey [1] BIT STRING OPTIONAL
// }

// ECDomainParameters{ECDOMAIN:IOSet} ::= CHOICE {
//   specified SpecifiedECDomain,
//   named ECDOMAIN.&id({IOSet}),
//   implicitCA NULL
// }

// ECDOMAIN ::= CLASS {
//   &id OBJECT IDENTIFIER UNIQUE
// }

// Golang seems to be using this instead:
// ECPrivateKey ::= SEQUENCE {
//   version       INTEGER { ecPrivkeyVer1(1) },
//   privateKey    OCTET STRING,
//   parameters    [0] EXPLICIT ECDomainParameters OPTIONAL,
//   publicKey     [1] EXPLICIT BIT STRING OPTIONAL
// }

class ECPrivateKey extends asn1.Sequence {
  constructor(version, privateKey, namedCurveOID, publicKey) {
    super();
    this.version = new asn1.Unsigned(version);
    this.privateKey = new asn1.OctString(privateKey);
    this.namedCurveOID = new asn1.OID(namedCurveOID).explicit(0).optional();
    this.publicKey = new asn1.BitString(publicKey).explicit(1).optional();
  }

  getBodySize() {
    let size = 0;
    size += this.version.getSize();
    size += this.privateKey.getSize();
    size += this.namedCurveOID.getSize();
    size += this.publicKey.getSize();
    return size;
  }

  writeBody(bw) {
    this.version.write(bw);
    this.privateKey.write(bw);
    this.namedCurveOID.write(bw);
    this.publicKey.write(bw);
    return bw;
  }

  readBody(br) {
    this.version.read(br);
    this.privateKey.read(br);
    this.namedCurveOID.read(br);
    this.publicKey.read(br);
    return this;
  }

  clean() {
    return this.version.clean()
        && this.privateKey.clean()
        && this.namedCurveOID.clean()
        && this.publicKey.clean();
  }

  toPEM() {
    return pem.toPEM(this.encode(), 'EC PRIVATE KEY');
  }

  fromPEM(str) {
    const data = pem.fromPEM(str, 'EC PRIVATE KEY');
    return this.decode(data);
  }

  format() {
    return {
      type: this.constructor.name,
      version: this.version,
      privateKey: this.privateKey,
      namedCurveOID: this.namedCurveOID,
      publicKey: this.publicKey
    };
  }
}

/**
 * ECDSA Signature
 */

// ECDSA-Signature ::= CHOICE {
//   two-ints-plus ECDSA-Sig-Value,
//   point-int [0] ECDSA-Full-R,
//   ... -- Future representations may be added
// }

// ECDSA-Full-R ::= SEQUENCE {
//   r ECPoint,
//   s INTEGER
// }

// ECPoint ::= OCTET STRING

// ECDSA-Sig-Value ::= SEQUENCE {
//   r INTEGER,
//   s INTEGER,
//   a INTEGER OPTIONAL,
//   y CHOICE { b BOOLEAN, f FieldElement } OPTIONAL
// }

class ECDSASignature extends asn1.Sequence {
  constructor(r, s) {
    super();
    this.r = new asn1.Unsigned(r);
    this.s = new asn1.Unsigned(s);
  }

  getBodySize() {
    let size = 0;
    size += this.r.getSize();
    size += this.s.getSize();
    return size;
  }

  writeBody(bw) {
    this.r.write(bw);
    this.s.write(bw);
    return bw;
  }

  readBody(br) {
    this.r.read(br);
    this.s.read(br);
    return this;
  }

  clean() {
    return this.r.clean() && this.s.clean();
  }

  toPEM() {
    return pem.toPEM(this.encode(), 'EC SIGNATURE');
  }

  fromPEM(str) {
    const data = pem.fromPEM(str, 'EC SIGNATURE');
    return this.decode(data);
  }

  format() {
    return {
      type: this.constructor.name,
      r: this.r,
      s: this.s
    };
  }
}

/*
 * Expose
 */

exports.ECPrivateKey = ECPrivateKey;
exports.ECDSASignature = ECDSASignature;
