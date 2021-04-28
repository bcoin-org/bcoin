/*!
 * openssl.js - openssl-specific encoding for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources:
 *   https://www.openssl.org/docs/man1.1.0/apps/dsa.html
 *   https://superuser.com/questions/478966/dsa-private-key-format
 *   https://github.com/dlitz/pycrypto/blob/master/lib/Crypto/PublicKey/DSA.py
 *   https://github.com/openssl/openssl/blob/master/crypto/dsa/dsa_asn1.c
 */

'use strict';

const asn1 = require('./asn1');
const pem = require('./pem');

/**
 * DSAParams
 */

// DSSParams_OpenSSL ::= SEQUENCE {
//   p INTEGER,
//   q INTEGER,
//   g INTEGER
// }

class DSAParams extends asn1.Sequence {
  constructor(p, q, g) {
    super();
    this.p = new asn1.Unsigned(p);
    this.q = new asn1.Unsigned(q);
    this.g = new asn1.Unsigned(g);
  }

  getBodySize() {
    let size = 0;
    size += this.p.getSize();
    size += this.q.getSize();
    size += this.g.getSize();
    return size;
  }

  writeBody(bw) {
    this.p.write(bw);
    this.q.write(bw);
    this.g.write(bw);
    return bw;
  }

  readBody(br) {
    this.p.read(br);
    this.q.read(br);
    this.g.read(br);
    return this;
  }

  clean() {
    return this.p.clean()
        && this.q.clean()
        && this.g.clean();
  }

  toPEM() {
    return pem.toPEM(this.encode(), 'DSA PARAMETERS');
  }

  fromPEM(str) {
    const data = pem.fromPEM(str, 'DSA PARAMETERS');
    return this.decode(data);
  }

  format() {
    return {
      type: this.constructor.name,
      p: this.p,
      q: this.q,
      g: this.g
    };
  }
}

/**
 * DSAPublicKey
 */

// DSSPublicKey_OpenSSL ::= SEQUENCE {
//   y INTEGER,
//   p INTEGER,
//   q INTEGER,
//   g INTEGER
// }

class DSAPublicKey extends asn1.Sequence {
  constructor(y, p, q, g) {
    super();
    this.y = new asn1.Unsigned(y);
    this.p = new asn1.Unsigned(p);
    this.q = new asn1.Unsigned(q);
    this.g = new asn1.Unsigned(g);
  }

  getBodySize() {
    let size = 0;
    size += this.y.getSize();
    size += this.p.getSize();
    size += this.q.getSize();
    size += this.g.getSize();
    return size;
  }

  writeBody(bw) {
    this.y.write(bw);
    this.p.write(bw);
    this.q.write(bw);
    this.g.write(bw);
    return bw;
  }

  readBody(br) {
    this.y.read(br);
    this.p.read(br);
    this.q.read(br);
    this.g.read(br);
    return this;
  }

  clean() {
    return this.y.clean()
        && this.p.clean()
        && this.q.clean()
        && this.g.clean();
  }

  toPEM() {
    return pem.toPEM(this.encode(), 'DSA PUBLIC KEY');
  }

  fromPEM(str) {
    const data = pem.fromPEM(str, 'DSA PUBLIC KEY');
    return this.decode(data);
  }

  format() {
    return {
      type: this.constructor.name,
      y: this.y,
      p: this.p,
      q: this.q,
      g: this.g
    };
  }
}

/**
 * DSAPrivateKey
 */

// DSSPrivatKey_OpenSSL ::= SEQUENCE {
//   version INTEGER,
//   p INTEGER,
//   q INTEGER,
//   g INTEGER,
//   y INTEGER,
//   x INTEGER
// }

class DSAPrivateKey extends asn1.Sequence {
  constructor(version, p, q, g, y, x) {
    super();
    this.version = new asn1.Unsigned(version);
    this.p = new asn1.Unsigned(p);
    this.q = new asn1.Unsigned(q);
    this.g = new asn1.Unsigned(g);
    this.y = new asn1.Unsigned(y);
    this.x = new asn1.Unsigned(x);
  }

  getBodySize() {
    let size = 0;
    size += this.version.getSize();
    size += this.p.getSize();
    size += this.q.getSize();
    size += this.g.getSize();
    size += this.y.getSize();
    size += this.x.getSize();
    return size;
  }

  writeBody(bw) {
    this.version.write(bw);
    this.p.write(bw);
    this.q.write(bw);
    this.g.write(bw);
    this.y.write(bw);
    this.x.write(bw);
    return bw;
  }

  readBody(br) {
    this.version.read(br);
    this.p.read(br);
    this.q.read(br);
    this.g.read(br);
    this.y.read(br);
    this.x.read(br);
    return this;
  }

  clean() {
    return this.p.clean()
        && this.q.clean()
        && this.g.clean()
        && this.y.clean()
        && this.x.clean();
  }

  toPEM() {
    return pem.toPEM(this.encode(), 'DSA PRIVATE KEY');
  }

  fromPEM(str) {
    const data = pem.fromPEM(str, 'DSA PRIVATE KEY');
    return this.decode(data);
  }

  format() {
    return {
      type: this.constructor.name,
      version: this.version,
      p: this.p,
      q: this.q,
      g: this.g,
      y: this.y,
      x: this.x
    };
  }
}

/*
 * Expose
 */

exports.DSAParams = DSAParams;
exports.DSAPublicKey = DSAPublicKey;
exports.DSAPrivateKey = DSAPrivateKey;
