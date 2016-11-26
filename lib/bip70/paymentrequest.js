/*!
 * paymentrequest.js - bip70 paymentrequest for bcoin
 * Copyright (c) 2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var util = require('../utils/util');
var co = require('../utils/co');
var crypto = require('../crypto/crypto');
var x509 = require('./x509');
var PEM = require('../utils/pem');
var protobuf = require('../utils/protobuf');
var PaymentDetails = require('./paymentdetails');
var ProtoReader = protobuf.ProtoReader;
var ProtoWriter = protobuf.ProtoWriter;

function PaymentRequest(options) {
  if (!(this instanceof PaymentRequest))
    return new PaymentRequest(options);

  this.version = -1;
  this.pkiType = null;
  this.pkiData = null;
  this.paymentDetails = new PaymentDetails();
  this.signature = null;

  if (options)
    this.fromOptions(options);
}

PaymentRequest.prototype.fromOptions = function fromOptions(options) {
  if (options.version != null) {
    assert(util.isNumber(options.version));
    this.version = options.version;
  }

  if (options.pkiType != null) {
    assert(typeof options.pkiType === 'string');
    this.pkiType = options.pkiType;
  }

  if (options.pkiData) {
    assert(Buffer.isBuffer(options.pkiData));
    this.pkiData = options.pkiData;
  }

  if (options.paymentDetails)
    this.paymentDetails.fromOptions(options.paymentDetails);

  if (options.signature) {
    assert(Buffer.isBuffer(options.signature));
    this.signature = options.signature;
  }

  if (options.chain)
    this.setChain(options.chain);

  return this;
};

PaymentRequest.fromOptions = function fromOptions(options) {
  return new PaymentRequest().fromOptions(options);
};

PaymentRequest.prototype.fromRaw = function fromRaw(data) {
  var br = new ProtoReader(data);

  this.version = br.readFieldU32(1, true);
  this.pkiType = br.readFieldString(2, true);
  this.pkiData = br.readFieldBytes(3, true);
  this.paymentDetails.fromRaw(br.readFieldBytes(4));
  this.signature = br.readFieldBytes(5, true);

  return this;
};

PaymentRequest.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = new Buffer(data, enc);
  return new PaymentRequest().fromRaw(data);
};

PaymentRequest.prototype.toRaw = function toRaw(writer) {
  var bw = new ProtoWriter(writer);

  if (this.version !== -1)
    bw.writeFieldU32(1, this.version);

  if (this.pkiType != null)
    bw.writeFieldString(2, this.pkiType);

  if (this.pkiData)
    bw.writeFieldBytes(3, this.pkiData);

  bw.writeFieldBytes(4, this.paymentDetails.toRaw());

  if (this.signature)
    bw.writeFieldBytes(5, this.signature);

  if (!writer)
    bw = bw.render();

  return bw;
};

PaymentRequest.prototype.getAlgorithm = function getAlgorithm() {
  var parts;

  if (!this.pkiType)
    return;

  parts = this.pkiType.split('+');

  if (parts.length !== 2)
    return;

  if (parts[0] !== 'x509')
    return;

  if (parts[1] !== 'sha1' && parts[1] !== 'sha256')
    return;

  return { key: parts[0], hash: parts[1] };
};

PaymentRequest.prototype.signatureData = function signatureData() {
  var signature = this.signature;
  var data;

  this.signature = new Buffer(0);

  data = this.toRaw();

  this.signature = signature;

  return data;
};

PaymentRequest.prototype.signatureHash = function signatureHash() {
  var alg = this.getAlgorithm();
  assert(alg, 'No hash algorithm available.');
  return crypto.hash(alg.hash, this.signatureData());
};

PaymentRequest.prototype.setChain = function setChain(chain) {
  var bw = new ProtoWriter();
  var i, cert, pem;

  if (!Array.isArray(chain))
    chain = [chain];

  for (i = 0; i < chain.length; i++) {
    cert = chain[i];
    if (typeof cert === 'string') {
      pem = PEM.decode(cert);
      assert(pem.type === 'certificate', 'Bad certificate PEM.');
      cert = pem.data;
    }
    assert(Buffer.isBuffer(cert), 'Certificates must be PEM or DER.');
    bw.writeFieldBytes(1, cert);
  }

  this.pkiData = bw.render();
};

PaymentRequest.prototype.getChain = function getChain() {
  var chain = [];
  var br;

  if (!this.pkiData)
    return chain;

  br = new ProtoReader(this.pkiData);

  while (br.nextTag() === 1)
    chain.push(br.readFieldBytes(1));

  return chain;
};

PaymentRequest.prototype.sign = function sign(key, chain) {
  var alg, msg;

  if (chain)
    this.setChain(chain);

  if (!this.pkiType)
    this.pkiType = 'x509+sha256';

  alg = this.getAlgorithm();
  assert(alg, 'No hash algorithm available.');

  msg = this.signatureData();
  chain = this.getChain();

  this.signature = x509.signSubject(alg.hash, msg, key, chain);
};

PaymentRequest.prototype.verify = function verify() {
  var alg, msg, sig, chain;

  if (!this.pkiType || this.pkiType === 'none')
    return true;

  if (!this.signature)
    return false;

  alg = this.getAlgorithm();

  if (!alg)
    return false;

  msg = this.signatureData();
  sig = this.signature;
  chain = this.getChain();

  return x509.verifySubject(alg.hash, msg, sig, chain);
};

PaymentRequest.prototype.verifyChain = function verifyChain() {
  if (!this.pkiType || this.pkiType === 'none')
    return true;

  return x509.verifyChain(this.getChain());
};

PaymentRequest.prototype.verifyAsync = co(function* verifyAsync() {
  var alg, msg, sig, chain;

  if (!this.pkiType || this.pkiType === 'none')
    return true;

  if (!this.signature)
    return false;

  alg = this.getAlgorithm();

  if (!alg)
    return false;

  msg = this.signatureData();
  sig = this.signature;
  chain = this.getChain();

  return yield x509.verifySubjectAsync(alg.hash, msg, sig, chain);
});

PaymentRequest.prototype.verifyChainAsync = co(function* verifyChain() {
  if (!this.pkiType || this.pkiType === 'none')
    return true;

  return yield x509.verifyChainAsync(this.getChain());
});

PaymentRequest.prototype.getCA = function getCA() {
  var chain, root;

  if (!this.pkiType || this.pkiType === 'none')
    return;

  chain = this.getChain();

  if (chain.length === 0)
    return;

  root = x509.parse(chain[chain.length - 1]);

  if (!root)
    return;

  return {
    name: x509.getCAName(root),
    trusted: x509.isTrusted(root),
    cert: root
  };
};

module.exports = PaymentRequest;
