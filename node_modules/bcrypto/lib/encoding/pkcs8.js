/*!
 * pkcs8.js - PKCS8 encoding for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on golang/go:
 *   Copyright (c) 2009 The Go Authors. All rights reserved.
 *   https://github.com/golang/go
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/PKCS_8
 *   https://tools.ietf.org/html/rfc5208
 *   https://tools.ietf.org/html/rfc5958
 *   https://github.com/golang/go/blob/master/src/crypto/x509/pkcs8.go
 */

'use strict';

const asn1 = require('./asn1');
const pem = require('./pem');
const x509 = require('./x509');

/**
 * PublicKeyInfo
 */

// PublicKeyInfo ::= SEQUENCE {
//   algorithm       AlgorithmIdentifier,
//   PublicKey       BIT STRING
// }

class PublicKeyInfo extends asn1.Sequence {
  constructor(algorithm, identifier, publicKey) {
    super();
    this.algorithm = new x509.AlgorithmIdentifier(algorithm, identifier);
    this.publicKey = new asn1.BitString(publicKey);
  }

  getBodySize() {
    let size = 0;
    size += this.algorithm.getSize();
    size += this.publicKey.getSize();
    return size;
  }

  writeBody(bw) {
    this.algorithm.write(bw);
    this.publicKey.write(bw);
    return bw;
  }

  readBody(br) {
    this.algorithm.read(br);
    this.publicKey.read(br);
    return this;
  }

  clean() {
    return this.algorithm.clean()
        && this.publicKey.clean();
  }

  toPEM() {
    return pem.toPEM(this.encode(), 'PUBLIC KEY');
  }

  fromPEM(str) {
    const data = pem.fromPEM(str, 'PUBLIC KEY');
    return this.decode(data);
  }

  format() {
    return {
      type: this.constructor.name,
      algorithm: this.algorithm,
      publicKey: this.publicKey
    };
  }
}

/**
 * PrivateKeyInfo
 */

// PrivateKeyInfo ::= SEQUENCE {
//   version         Version,
//   algorithm       AlgorithmIdentifier,
//   PrivateKey      OCTET STRING
// }
//
// PrivateKeyInfo ::= SEQUENCE {
//    version Version,
//    privateKeyAlgorithm AlgorithmIdentifier {{PrivateKeyAlgorithms}},
//    privateKey PrivateKey,
//    attributes [0] Attributes OPTIONAL
// }
//
// Version ::= INTEGER {v1(0)} (v1,...)
//
// PrivateKey ::= OCTET STRING

class PrivateKeyInfo extends asn1.Sequence {
  constructor(version, algorithm, parameters, privateKey) {
    super();
    this.version = new asn1.Unsigned(version);
    this.algorithm = new x509.AlgorithmIdentifier(algorithm, parameters);
    this.privateKey = new asn1.OctString(privateKey);
  }

  get isRaw() {
    return true;
  }

  getBodySize() {
    let size = 0;
    size += this.version.getSize();
    size += this.algorithm.getSize();
    size += this.privateKey.getSize();
    return size;
  }

  writeBody(bw) {
    this.version.write(bw);
    this.algorithm.write(bw);
    this.privateKey.write(bw);
    return bw;
  }

  readBody(br) {
    this.version.read(br);
    this.algorithm.read(br);
    this.privateKey.read(br);
    return this;
  }

  clean() {
    return this.version.clean()
        && this.algorithm.clean()
        && this.privateKey.clean();
  }

  toPEM() {
    return pem.toPEM(this.encode(), 'PRIVATE KEY');
  }

  fromPEM(str) {
    const data = pem.fromPEM(str, 'PRIVATE KEY');
    return this.decode(data);
  }

  format() {
    return {
      type: this.constructor.name,
      version: this.version,
      algorithm: this.algorithm,
      privateKey: this.privateKey
    };
  }
}

/**
 * EncryptedPrivateKeyInfo
 */

// EncryptedPrivateKeyInfo ::= SEQUENCE {
//   encryptionAlgorithm  EncryptionAlgorithmIdentifier,
//   encryptedData        EncryptedData
// }
//
// EncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
//
// EncryptedData ::= OCTET STRING

class EncryptedPrivateKeyInfo extends asn1.Sequence {
  constructor(algorithm, identifier, data) {
    super();
    this.algorithm =
      new x509.AlgorithmIdentifier(algorithm, identifier);
    this.data = new asn1.OctString(data);
  }

  getBodySize() {
    let size = 0;
    size += this.algorithm.getSize();
    size += this.data.getSize();
    return size;
  }

  writeBody(bw) {
    this.algorithm.write(bw);
    this.data.write(bw);
    return bw;
  }

  readBody(br) {
    this.algorithm.read(br);
    this.data.read(br);
    return this;
  }

  clean() {
    return this.algorithm.clean()
        && this.data.clean();
  }

  toPEM() {
    return pem.toPEM(this.encode(), 'ENCRYPTED PRIVATE KEY');
  }

  fromPEM(str) {
    const data = pem.fromPEM(str, 'ENCRYPTED PRIVATE KEY');
    return this.decode(data);
  }

  format() {
    return {
      type: this.constructor.name,
      algorithm: this.algorithm,
      data: this.data
    };
  }
}

/*
 * Expose
 */

exports.PublicKeyInfo = PublicKeyInfo;
exports.PrivateKeyInfo = PrivateKeyInfo;
exports.EncryptedPrivateKeyInfo = EncryptedPrivateKeyInfo;
