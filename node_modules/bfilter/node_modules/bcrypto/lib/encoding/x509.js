/*!
 * x509.js - X509 for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on indutny/asn1.js:
 *   Copyright Fedor Indutny, 2013.
 *   https://github.com/indutny/asn1.js
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/X.509
 *   https://tools.ietf.org/html/rfc4158
 *   https://www.ietf.org/rfc/rfc2560.txt
 *   https://www.ietf.org/rfc/rfc5280.txt
 *   https://github.com/indutny/asn1.js/blob/master/rfc/2560/index.js
 *   https://github.com/indutny/asn1.js/blob/master/rfc/5280/index.js
 *   https://github.com/indutny/asn1.js/blob/master/lib/asn1/base/node.js
 *   https://github.com/indutny/asn1.js/blob/master/lib/asn1/encoders/der.js
 *   https://github.com/indutny/asn1.js/blob/master/lib/asn1/decoders/der.js
 */

'use strict';

const assert = require('../internal/assert');
const asn1 = require('./asn1');
const pem = require('./pem');
const {types} = asn1;

/**
 * Certificate
 */

// Certificate  ::=  SEQUENCE  {
//      tbsCertificate       TBSCertificate,
//      signatureAlgorithm   AlgorithmIdentifier,
//      signature            BIT STRING  }

class Certificate extends asn1.Sequence {
  constructor() {
    super();
    this.tbsCertificate = new TBSCertificate();
    this.signatureAlgorithm = new AlgorithmIdentifier();
    this.signature = new asn1.BitString();
  }

  get isRaw() {
    return true;
  }

  getBodySize() {
    let size = 0;
    size += this.tbsCertificate.getSize();
    size += this.signatureAlgorithm.getSize();
    size += this.signature.getSize();
    return size;
  }

  writeBody(bw) {
    this.tbsCertificate.write(bw);
    this.signatureAlgorithm.write(bw);
    this.signature.write(bw);
    return bw;
  }

  readBody(br) {
    this.tbsCertificate.read(br);
    this.signatureAlgorithm.read(br);
    this.signature.read(br);
    return this;
  }

  clean() {
    return this.tbsCertificate.clean()
        && this.signatureAlgorithm.clean()
        && this.signature.clean();
  }

  toPEM() {
    return pem.toPEM(this.encode(), 'CERTIFICATE');
  }

  fromPEM(str) {
    const data = pem.fromPEM(str, 'CERTIFICATE');
    return this.decode(data);
  }

  format() {
    return {
      type: this.constructor.name,
      tbsCertificate: this.tbsCertificate,
      signatureAlgorithm: this.signatureAlgorithm,
      signature: this.signature
    };
  }
}

/**
 * TBSCertificate
 */

// TBSCertificate  ::=  SEQUENCE  {
//      version         [0]  Version DEFAULT v1,
//      serialNumber         CertificateSerialNumber,
//      signature            AlgorithmIdentifier,
//      issuer               Name,
//      validity             Validity,
//      subject              Name,
//      subjectPublicKeyInfo SubjectPublicKeyInfo,
//      issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
//      subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
//      extensions      [3]  Extensions OPTIONAL }
//
// Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }

class TBSCertificate extends asn1.Sequence {
  constructor() {
    super();
    this.version = new asn1.Unsigned().explicit(0).optional();
    this.serialNumber = new asn1.Integer();
    this.signature = new AlgorithmIdentifier();
    this.issuer = new RDNSequence();
    this.validity = new Validity();
    this.subject = new RDNSequence();
    this.subjectPublicKeyInfo = new SubjectPublicKeyInfo();
    this.issuerUniqueID = new asn1.BitString().implicit(1).optional();
    this.subjectUniqueID = new asn1.BitString().implicit(2).optional();
    this.extensions = new Extensions().explicit(3).optional();
  }

  get isRaw() {
    return true;
  }

  getBodySize() {
    let size = 0;
    size += this.version.getSize();
    size += this.serialNumber.getSize();
    size += this.signature.getSize();
    size += this.issuer.getSize();
    size += this.validity.getSize();
    size += this.subject.getSize();
    size += this.subjectPublicKeyInfo.getSize();
    size += this.issuerUniqueID.getSize();
    size += this.subjectUniqueID.getSize();
    size += this.extensions.getSize();
    return size;
  }

  writeBody(bw) {
    this.version.write(bw);
    this.serialNumber.write(bw);
    this.signature.write(bw);
    this.issuer.write(bw);
    this.validity.write(bw);
    this.subject.write(bw);
    this.subjectPublicKeyInfo.write(bw);
    this.issuerUniqueID.write(bw);
    this.subjectUniqueID.write(bw);
    this.extensions.write(bw);
    return bw;
  }

  readBody(br) {
    this.version.read(br);
    this.serialNumber.read(br);
    this.signature.read(br);
    this.issuer.read(br);
    this.validity.read(br);
    this.subject.read(br);
    this.subjectPublicKeyInfo.read(br);
    this.issuerUniqueID.read(br);
    this.subjectUniqueID.read(br);
    this.extensions.read(br);
    return this;
  }

  clean() {
    return this.version.clean()
        && this.serialNumber.clean()
        && this.signature.clean()
        && this.issuer.clean()
        && this.validity.clean()
        && this.subject.clean()
        && this.subjectPublicKeyInfo.clean()
        && this.issuerUniqueID.clean()
        && this.subjectUniqueID.clean()
        && this.extensions.clean();
  }

  toPEM() {
    return pem.toPEM(this.encode(), 'TBS CERTIFICATE');
  }

  fromPEM(str) {
    const data = pem.fromPEM(str, 'TBS CERTIFICATE');
    return this.decode(data);
  }

  format() {
    return {
      type: this.constructor.name,
      version: this.version,
      serialNumber: this.serialNumber,
      signature: this.signature,
      issuer: this.issuer,
      validity: this.validity,
      subject: this.subject,
      subjectPublicKeyInfo: this.subjectPublicKeyInfo,
      issuerUniqueID: this.issuerUniqueID,
      subjectUniqueID: this.subjectUniqueID,
      extensions: this.extensions
    };
  }
}

/**
 * AlgorithmIdentifier
 */

// AlgorithmIdentifier  ::=  SEQUENCE  {
//      algorithm               OBJECT IDENTIFIER,
//      parameters              ANY DEFINED BY algorithm OPTIONAL  }

class AlgorithmIdentifier extends asn1.Sequence {
  constructor(algorithm, parameters) {
    super();

    this.algorithm = new asn1.OID(algorithm);
    this.parameters = new asn1.Any(parameters).optional();
  }

  getBodySize() {
    let size = 0;
    size += this.algorithm.getSize();
    size += this.parameters.getSize();
    return size;
  }

  writeBody(bw) {
    this.algorithm.write(bw);
    this.parameters.write(bw);
    return bw;
  }

  readBody(br) {
    this.algorithm.read(br);
    this.parameters.read(br);
    return this;
  }

  clean() {
    return this.algorithm.clean()
        && this.parameters.clean();
  }

  format() {
    return {
      type: this.constructor.name,
      algorithm: this.algorithm,
      parameters: this.parameters
    };
  }
}

/**
 * RDNSequence
 */

// Name ::= CHOICE { -- only one possibility for now --
//      rdnSequence  RDNSequence }
//
// RDNSequence ::= SEQUENCE OF RelativeDistinguishedName

class RDNSequence extends asn1.Sequence {
  constructor() {
    super();
    this.names = [];
  }

  getBodySize() {
    let size = 0;

    for (const rdn of this.names)
      size += rdn.getSize();

    return size;
  }

  writeBody(bw) {
    for (const rdn of this.names)
      rdn.write(bw);
    return bw;
  }

  readBody(br) {
    while (br.left()) {
      const rdn = RDN.read(br);
      this.names.push(rdn);
    }

    return this;
  }

  clean() {
    return this.names.length === 0;
  }

  format() {
    return {
      type: this.constructor.name,
      names: this.names
    };
  }
}

/**
 * RDN
 */

// RelativeDistinguishedName ::=
//      SET SIZE (1..MAX) OF AttributeTypeAndValue
//

class RDN extends asn1.Set {
  constructor(id, value) {
    super();
    this.attributes = [new Attribute(id, value)];
  }

  getBodySize() {
    let size = 0;

    assert(this.attributes.length >= 1);

    for (const attr of this.attributes)
      size += attr.getSize();

    return size;
  }

  writeBody(bw) {
    assert(this.attributes.length >= 1);

    for (const attr of this.attributes)
      attr.write(bw);

    return bw;
  }

  readBody(br) {
    this.attributes[0].read(br);

    while (br.left()) {
      const attr = Attribute.read(br);
      this.attributes.push(attr);
    }

    return this;
  }

  clean() {
    return this.attributes.length === 1 && this.attributes[0].clean();
  }

  format() {
    return {
      type: this.constructor.name,
      attributes: this.attributes
    };
  }
}

/**
 * Attribute
 */

// AttributeTypeAndValue ::= SEQUENCE {
//      type     AttributeType,
//      value    AttributeValue }
//
// AttributeType ::= OBJECT IDENTIFIER
//
// AttributeValue ::= ANY -- DEFINED BY AttributeType

class Attribute extends asn1.Sequence {
  constructor(id, value) {
    super();

    this.id = new asn1.OID(id);
    this.value = new asn1.Any(value);
  }

  getBodySize() {
    let size = 0;
    size += this.id.getSize();
    size += this.value.getSize();
    return size;
  }

  writeBody(bw) {
    this.id.write(bw);
    this.value.write(bw);
    return bw;
  }

  readBody(br) {
    this.id.read(br);
    this.value.read(br);
    return this;
  }

  clean() {
    return this.id.clean()
        && this.value.clean();
  }

  format() {
    return {
      type: this.constructor.name,
      id: this.id,
      value: this.value
    };
  }
}

/**
 * Validity
 */

// Validity ::= SEQUENCE {
//      notBefore      Time,
//      notAfter       Time  }

class Validity extends asn1.Sequence {
  constructor() {
    super();
    this.notBefore = new Time();
    this.notAfter = new Time();
  }

  getBodySize() {
    let size = 0;
    size += this.notBefore.getSize();
    size += this.notAfter.getSize();
    return size;
  }

  writeBody(bw) {
    this.notBefore.write(bw);
    this.notAfter.write(bw);
    return bw;
  }

  readBody(br) {
    this.notBefore.read(br);
    this.notAfter.read(br);
    return this;
  }

  clean() {
    return this.notBefore.clean()
        && this.notAfter.clean();
  }

  format() {
    return {
      type: this.constructor.name,
      notBefore: this.notBefore,
      notAfter: this.notAfter
    };
  }
}

/**
 * Time
 */

// Time ::= CHOICE {
//      utcTime        UTCTime,
//      generalTime    GeneralizedTime }

class Time extends asn1.Choice {
  constructor(options) {
    super(new asn1.UTCTime(), options);
  }

  choices() {
    return [
      types.UTCTIME,
      types.GENTIME
    ];
  }
}

// SubjectPublicKeyInfo  ::=  SEQUENCE  {
//      algorithm            AlgorithmIdentifier,
//      subjectPublicKey     BIT STRING  }

class SubjectPublicKeyInfo extends asn1.Sequence {
  constructor(algorithm, parameters, publicKey) {
    super();
    this.algorithm = new AlgorithmIdentifier(algorithm, parameters);
    this.publicKey = new asn1.BitString(publicKey);
  }

  get isRaw() {
    return true;
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
 * Extensions
 */

class Extensions extends asn1.Sequence {
  constructor() {
    super();
    this.extensions = [];
  }

  getBodySize() {
    let size = 0;

    for (const ext of this.extensions)
      size += ext.getSize();

    return size;
  }

  writeBody(bw) {
    for (const ext of this.extensions)
      ext.write(bw);
    return bw;
  }

  readBody(br) {
    for (const ext of this.extensions)
      ext.read(br);
    return this;
  }

  clean() {
    return this.extensions.length === 0;
  }

  format() {
    return {
      type: this.constructor.name,
      extensions: this.extensions
    };
  }
}

/**
 * Extension
 */

// Extension  ::=  SEQUENCE  {
//      extnID      OBJECT IDENTIFIER,
//      critical    BOOLEAN DEFAULT FALSE,
//      extnValue   OCTET STRING }

class Extension extends asn1.Sequence {
  constructor() {
    super();
    this.extnID = new asn1.OID();
    this.critical = new asn1.Bool().optional();
    this.extnValue = new asn1.OctString();
  }

  getBodySize() {
    let size = 0;
    size += this.extnID.getSize();
    size += this.critical.getSize();
    size += this.extnValue.getSize();
    return size;
  }

  writeBody(bw) {
    this.extnID.write(bw);
    this.critical.write(bw);
    this.extnValue.write(bw);
    return bw;
  }

  readBody(br) {
    this.extnID.read(br);
    this.critical.read(br);
    this.extnValue.read(br);
    return this;
  }

  clean() {
    return this.extnID.clean()
        && this.critical.clean()
        && this.extnValue.clean();
  }

  format() {
    return {
      type: this.constructor.name,
      extnID: this.extnID,
      critical: this.critical,
      extnValue: this.extnValue
    };
  }
}

/**
 * DigestInfo
 */

// See: https://www.ietf.org/rfc/rfc3447.txt
// Section 9.2
//
// DigestInfo ::= SEQUENCE {
//   digestAlgorithm AlgorithmIdentifier,
//   digest OCTET STRING
// }

class DigestInfo extends asn1.Sequence {
  constructor(algorithm, digest) {
    super();
    this.algorithm = new AlgorithmIdentifier(algorithm);
    this.algorithm.parameters.optional(false);
    this.digest = new asn1.OctString(digest);
  }

  getBodySize() {
    let size = 0;
    size += this.algorithm.getSize();
    size += this.digest.getSize();
    return size;
  }

  writeBody(bw) {
    this.algorithm.write(bw);
    this.digest.write(bw);
    return bw;
  }

  readBody(br) {
    this.algorithm.read(br);
    this.digest.read(br);
    return this;
  }

  clean() {
    return this.algorithm.clean()
        && this.digest.clean();
  }

  format() {
    return {
      type: this.constructor.name,
      algorithm: this.algorithm,
      digest: this.digest
    };
  }
}

/*
 * Expose
 */

exports.Certificate = Certificate;
exports.TBSCertificate = TBSCertificate;
exports.AlgorithmIdentifier = AlgorithmIdentifier;
exports.RDNSequence = RDNSequence;
exports.RDN = RDN;
exports.Attribute = Attribute;
exports.Validity = Validity;
exports.Time = Time;
exports.SubjectPublicKeyInfo = SubjectPublicKeyInfo;
exports.Extensions = Extensions;
exports.Extension = Extension;
exports.DigestInfo = DigestInfo;
