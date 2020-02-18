/*!
 * rfc3279.js - rfc3279 encoding for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources:
 *   https://tools.ietf.org/html/rfc3279
 *   https://tools.ietf.org/html/rfc5912
 */

'use strict';

const asn1 = require('./asn1');
const pem = require('./pem');

/**
 * DSA Parms
 */

// Dss-Parms  ::=  SEQUENCE  {
//     p             INTEGER,
//     q             INTEGER,
//     g             INTEGER  }

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
    return this.p.clean() && this.q.clean() && this.g.clean();
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
 * DSA Public Key
 */

// DSAPublicKey ::= INTEGER -- public key, Y

class DSAPublicKey extends asn1.Unsigned {
  constructor(y) {
    super(y);
  }

  get y() {
    return this.value;
  }

  set y(value) {
    this.value = value;
  }

  toPEM() {
    return pem.toPEM(this.encode(), 'DSA PUBLIC KEY');
  }

  fromPEM(str) {
    const data = pem.fromPEM(str, 'DSA PUBLIC KEY');
    return this.decode(data);
  }
}

/**
 * DSA Signature
 */

class DSASignature extends asn1.Sequence {
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
    return pem.toPEM(this.encode(), 'DSA SIGNATURE');
  }

  fromPEM(str) {
    const data = pem.fromPEM(str, 'DSA SIGNATURE');
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

exports.DSAParams = DSAParams;
exports.DSAPublicKey = DSAPublicKey;
exports.DSASignature = DSASignature;
