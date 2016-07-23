/*!
 * bip70.js - bip70 for bcoin
 * Copyright (c) 2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var bcoin = require('../env');
var assert = require('assert');
var utils = bcoin.utils;
var x509 = require('./x509');
var asn1 = require('./asn1');
var protobuf = require('./protobuf');
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
    assert(utils.isNumber(options.version));
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
  var p = new ProtoReader(data);

  this.version = p.readFieldU32(1, true);
  this.pkiType = p.readFieldString(2, true);
  this.pkiData = p.readFieldBytes(3, true);
  this.paymentDetails.fromRaw(p.readFieldBytes(4));
  this.signature = p.readFieldBytes(5, true);

  return this;
};

PaymentRequest.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = new Buffer(data, enc);
  return new PaymentRequest().fromRaw(data);
};

PaymentRequest.prototype.toRaw = function toRaw(writer) {
  var p = new ProtoWriter(writer);

  if (this.version !== -1)
    p.writeFieldU32(1, this.version);

  if (this.pkiType != null)
    p.writeFieldString(2, this.pkiType);

  if (this.pkiData)
    p.writeFieldBytes(3, this.pkiData);

  p.writeFieldBytes(4, this.paymentDetails.toRaw());

  if (this.signature)
    p.writeFieldBytes(5, this.signature);

  if (!writer)
    p = p.render();

  return p;
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
  return utils.hash(alg.hash, this.signatureData());
};

PaymentRequest.prototype.setChain = function setChain(chain) {
  var p = new ProtoWriter();
  var i, cert, pem;

  if (!Array.isArray(chain))
    chain = [chain];

  for (i = 0; i < chain.length; i++) {
    cert = chain[i];
    if (typeof cert === 'string') {
      pem = asn1.fromPEM(cert);
      assert(pem.type === 'certificate', 'Bad certificate PEM.');
      cert = pem.data;
    }
    assert(Buffer.isBuffer(cert), 'Certificates must be PEM or DER.');
    p.writeFieldBytes(1, cert);
  }

  this.pkiData = p.render();
};

PaymentRequest.prototype.getChain = function getChain() {
  var chain = [];
  var p;

  if (!this.pkiData)
    return chain;

  p = new ProtoReader(this.pkiData);

  while (p.nextTag() === 1)
    chain.push(p.readFieldBytes(1));

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

PaymentRequest.prototype.getCA = function getCA() {
  var chain, root, ca;

  if (!this.pkiType || this.pkiType === 'none')
    return;

  chain = this.getChain();

  if (chain.length === 0)
    return;

  root = x509.parse(chain[chain.length - 1]);

  if (!root)
    return;

  ca = x509.getTrusted(root);

  if (!ca)
    return;

  return {
    name: ca.name,
    fingerprint: ca.fingerprint,
    cert: root
  };
};

function PaymentDetails(options) {
  if (!(this instanceof PaymentDetails))
    return new PaymentDetails(options);

  this.network = null;
  this.outputs = [];
  this.time = utils.now();
  this.expires = -1;
  this.memo = null;
  this.paymentUrl = null;
  this.merchantData = null;

  if (options)
    this.fromOptions(options);
}

PaymentDetails.prototype.fromOptions = function fromOptions(options) {
  var i, output;

  if (options.network != null) {
    assert(typeof options.network === 'string');
    this.network = options.network;
  }

  if (options.outputs) {
    assert(Array.isArray(options.outputs));
    for (i = 0; i < options.outputs.length; i++) {
      output = new bcoin.output(options.outputs[i]);
      this.outputs.push(output);
    }
  }

  if (options.time != null) {
    assert(utils.isNumber(options.time));
    this.time = options.time;
  }

  if (options.expires != null) {
    assert(utils.isNumber(options.expires));
    this.expires = options.expires;
  }

  if (options.memo != null) {
    assert(typeof options.memo === 'string');
    this.memo = options.memo;
  }

  if (options.paymentUrl != null) {
    assert(typeof options.paymentUrl === 'string');
    this.paymentUrl = options.paymentUrl;
  }

  if (options.merchantData) {
    assert(Buffer.isBuffer(options.merchantData));
    this.merchantData = options.merchantData;
  }

  return this;
};

PaymentDetails.fromOptions = function fromOptions(options) {
  return new PaymentDetails().fromOptions(options);
};

PaymentDetails.prototype.setData = function setData(data, enc) {
  if (data == null || Buffer.isBuffer(data)) {
    this.merchantData = data;
    return;
  }

  if (enc === 'json') {
    this.merchantData = new Buffer(JSON.stringify(data), 'utf8');
    return;
  }

  assert(typeof data === 'string');
  this.merchantData = new Buffer(data, enc);
};

PaymentDetails.prototype.getData = function getData(enc) {
  var data = this.merchantData;

  if (!data)
    return;

  if (!enc)
    return data;

  if (enc === 'json') {
    data = data.toString('utf8');
    try {
      data = JSON.parse(data);
    } catch (e) {
      return;
    }
    return data;
  }

  return data.toString(enc);
};

PaymentDetails.prototype.fromRaw = function fromRaw(data) {
  var p = new ProtoReader(data);
  var op, output;

  this.network = p.readFieldString(1, true);

  while (p.nextTag() === 2) {
    op = new ProtoReader(p.readFieldBytes(2));
    output = new bcoin.output();
    output.value = op.readFieldU64(1, true);
    output.script.fromRaw(op.readFieldBytes(2, true));
    this.outputs.push(output);
  }

  this.time = p.readFieldU64(3);
  this.expires = p.readFieldU64(4, true);
  this.memo = p.readFieldString(5, true);
  this.paymentUrl = p.readFieldString(6, true);
  this.merchantData = p.readFieldBytes(7, true);

  return this;
};

PaymentDetails.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = new Buffer(data, enc);
  return new PaymentDetails().fromRaw(data);
};

PaymentDetails.prototype.toRaw = function toRaw(writer) {
  var p = new ProtoWriter(writer);
  var i, op, output;

  if (this.network != null)
    p.writeFieldString(1, this.network);

  for (i = 0; i < this.outputs.length; i++) {
    output = this.outputs[i];
    op = new ProtoWriter();
    op.writeFieldU64(1, output.value);
    op.writeFieldBytes(2, output.script.toRaw());
    p.writeFieldBytes(2, op.render());
  }

  p.writeFieldU64(3, this.time);

  if (this.expires !== -1)
    p.writeFieldU64(4, this.expires);

  if (this.memo != null)
    p.writeFieldString(5, this.memo);

  if (this.paymentUrl != null)
    p.writeFieldString(6, this.paymentUrl);

  if (this.merchantData)
    p.writeFieldString(7, this.merchantData);

  if (!writer)
    p = p.render();

  return p;
};

function Payment(options) {
  if (!(this instanceof Payment))
    return new Payment(options);

  this.merchantData = null;
  this.transactions = [];
  this.refundTo = [];
  this.memo = null;

  if (options)
    this.fromOptions(options);
}

Payment.prototype.fromOptions = function fromOptions(options) {
  var i, tx, output;

  if (options.merchantData) {
    assert(Buffer.isBuffer(options.merchantData));
    this.merchantData = options.merchantData;
  }

  if (options.transactions) {
    assert(Array.isArray(options.transactions));
    for (i = 0; i < options.transactions.length; i++) {
      tx = new bcoin.tx(options.transactions[i]);
      this.transactions.push(tx);
    }
  }

  if (options.refundTo) {
    assert(Array.isArray(options.refundTo));
    for (i = 0; i < options.refundTo.length; i++) {
      output = new bcoin.output(options.refundTo[i]);
      this.refundTo.push(output);
    }
  }

  if (options.memo != null) {
    assert(typeof options.memo === 'string');
    this.memo = options.memo;
  }

  return this;
};

Payment.fromOptions = function fromOptions(options) {
  return new Payment().fromOptions(options);
};

Payment.prototype.setData = PaymentDetails.prototype.setData;
Payment.prototype.getData = PaymentDetails.prototype.getData;

Payment.prototype.fromRaw = function fromRaw(data) {
  var p = new ProtoReader(data);
  var tx, op, output;

  this.merchantData = p.readFieldBytes(1, true);

  while (p.nextTag() === 2) {
    tx = bcoin.tx.fromRaw(p.readFieldBytes(2));
    this.transactions.push(tx);
  }

  while (p.nextTag() === 3) {
    op = new ProtoReader(p.readFieldBytes(3));
    output = new bcoin.output();
    output.value = op.readFieldU64(1, true);
    output.script = bcoin.script.fromRaw(op.readFieldBytes(2, true));
    this.refundTo.push(output);
  }

  this.memo = p.readFieldString(4, true);

  return this;
};

Payment.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = new Buffer(data, enc);
  return new Payment().fromRaw(data);
};

Payment.prototype.toRaw = function toRaw(writer) {
  var p = new ProtoWriter(writer);
  var i, tx, op, output;

  if (this.merchantData)
    p.writeFieldBytes(1, this.merchantData);

  for (i = 0; i < this.transactions.length; i++) {
    tx = this.transactions[i];
    this.writeFieldBytes(2, tx.toRaw());
  }

  for (i = 0; i < this.refundTo.length; i++) {
    op = new ProtoWriter();
    output = this.refundTo[i];
    op.writeFieldU64(1, output.value);
    op.writeFieldBytes(2, output.script.toRaw());
    p.writeFieldBytes(3, op.render());
  }

  if (this.memo != null)
    p.writeFieldString(4, this.memo);

  if (!writer)
    p = p.render();

  return p;
};

function PaymentACK(options) {
  if (!(this instanceof PaymentACK))
    return new PaymentACK(options);

  this.payment = new Payment();
  this.memo = null;

  if (options)
    this.fromOptions(options);
}

PaymentACK.prototype.fromOptions = function fromOptions(options) {
  if (options.payment)
    this.payment.fromOptions(options.payment);

  if (options.memo != null) {
    assert(typeof options.memo === 'string');
    this.memo = options.memo;
  }

  return this;
};

PaymentACK.fromOptions = function fromOptions(options) {
  return new PaymentACK().fromOptions(options);
};

PaymentACK.prototype.fromRaw = function fromRaw(data) {
  var p = new ProtoReader(data);

  this.payment.fromRaw(p.readFieldBytes(1));
  this.memo = p.readFieldString(2, true);

  return this;
};

PaymentACK.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = new Buffer(data, enc);
  return new PaymentACK().fromRaw(data);
};

PaymentACK.prototype.toRaw = function toRaw(writer) {
  var p = new ProtoWriter(writer);

  p.writeFieldBytes(1, this.payment.toRaw());

  if (this.memo != null)
    p.writeFieldString(2, this.memo);

  if (!writer)
    p = p.render();

  return p;
};

exports.PaymentRequest = PaymentRequest;
exports.PaymentDetails = PaymentDetails;
exports.Payment = Payment;
exports.PaymentACK = PaymentACK;
