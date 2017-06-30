/*!
 * paymentack.js - bip70 paymentack for bcoin
 * Copyright (c) 2016-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const ProtoReader = require('../utils/protoreader');
const ProtoWriter = require('../utils/protowriter');
const Payment = require('./payment');

/**
 * Represents a BIP70 payment ack.
 * @alias module:bip70.PaymentACK
 * @constructor
 * @param {Object?} options
 * @property {Payment} payment
 * @property {String|null} memo
 */

function PaymentACK(options) {
  if (!(this instanceof PaymentACK))
    return new PaymentACK(options);

  this.payment = new Payment();
  this.memo = null;

  if (options)
    this.fromOptions(options);
}

/**
 * Inject properties from options.
 * @private
 * @param {Object} options
 * @returns {PaymentACK}
 */

PaymentACK.prototype.fromOptions = function fromOptions(options) {
  if (options.payment)
    this.payment.fromOptions(options.payment);

  if (options.memo != null) {
    assert(typeof options.memo === 'string');
    this.memo = options.memo;
  }

  return this;
};

/**
 * Instantiate payment ack from options.
 * @param {Object} options
 * @returns {PaymentACK}
 */

PaymentACK.fromOptions = function fromOptions(options) {
  return new PaymentACK().fromOptions(options);
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 * @returns {PaymentACK}
 */

PaymentACK.prototype.fromRaw = function fromRaw(data) {
  let br = new ProtoReader(data);

  this.payment.fromRaw(br.readFieldBytes(1));
  this.memo = br.readFieldString(2, true);

  return this;
};

/**
 * Instantiate payment ack from serialized data.
 * @param {Buffer} data
 * @returns {PaymentACK}
 */

PaymentACK.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = Buffer.from(data, enc);
  return new PaymentACK().fromRaw(data);
};

/**
 * Serialize the payment ack (protobuf).
 * @returns {Buffer}
 */

PaymentACK.prototype.toRaw = function toRaw() {
  let bw = new ProtoWriter();

  bw.writeFieldBytes(1, this.payment.toRaw());

  if (this.memo != null)
    bw.writeFieldString(2, this.memo);

  return bw.render();
};

/*
 * Expose
 */

module.exports = PaymentACK;
