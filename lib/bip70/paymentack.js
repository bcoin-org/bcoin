/*!
 * paymentack.js - bip70 paymentack for bcoin
 * Copyright (c) 2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var protobuf = require('../utils/protobuf');
var Payment = require('./payment');
var ProtoReader = protobuf.ProtoReader;
var ProtoWriter = protobuf.ProtoWriter;

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

module.exports = PaymentACK;
