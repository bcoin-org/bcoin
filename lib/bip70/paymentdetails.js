/*!
 * paymentdetails.js - bip70 paymentdetails for bcoin
 * Copyright (c) 2016-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const util = require('../utils/util');
const Output = require('../primitives/output');
const ProtoReader = require('../utils/protoreader');
const ProtoWriter = require('../utils/protowriter');

/**
 * Represents BIP70 payment details.
 * @alias module:bip70.PaymentDetails
 * @constructor
 * @param {Object?} options
 * @property {String|null} network
 * @property {Output[]} outputs
 * @property {Number} time
 * @property {Number} expires
 * @property {String|null} memo
 * @property {String|null} paymentUrl
 * @property {Buffer|null} merchantData
 */

function PaymentDetails(options) {
  if (!(this instanceof PaymentDetails))
    return new PaymentDetails(options);

  this.network = null;
  this.outputs = [];
  this.time = util.now();
  this.expires = -1;
  this.memo = null;
  this.paymentUrl = null;
  this.merchantData = null;

  if (options)
    this.fromOptions(options);
}

/**
 * Inject properties from options.
 * @private
 * @param {Object} options
 * @returns {PaymentDetails}
 */

PaymentDetails.prototype.fromOptions = function fromOptions(options) {
  if (options.network != null) {
    assert(typeof options.network === 'string');
    this.network = options.network;
  }

  if (options.outputs) {
    assert(Array.isArray(options.outputs));
    for (let item of options.outputs) {
      let output = new Output(item);
      this.outputs.push(output);
    }
  }

  if (options.time != null) {
    assert(util.isNumber(options.time));
    this.time = options.time;
  }

  if (options.expires != null) {
    assert(util.isNumber(options.expires));
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

  if (options.merchantData)
    this.setData(options.merchantData);

  return this;
};

/**
 * Instantiate payment details from options.
 * @param {Object} options
 * @returns {PaymentDetails}
 */

PaymentDetails.fromOptions = function fromOptions(options) {
  return new PaymentDetails().fromOptions(options);
};

/**
 * Test whether the payment is expired.
 * @returns {Boolean}
 */

PaymentDetails.prototype.isExpired = function isExpired() {
  if (this.expires === -1)
    return false;
  return util.now() > this.expires;
};

/**
 * Set payment details.
 * @param {Object} data
 * @param {String?} enc
 */

PaymentDetails.prototype.setData = function setData(data, enc) {
  if (data == null || Buffer.isBuffer(data)) {
    this.merchantData = data;
    return;
  }

  if (typeof data !== 'string') {
    assert(!enc || enc === 'json');
    this.merchantData = Buffer.from(JSON.stringify(data), 'utf8');
    return;
  }

  this.merchantData = Buffer.from(data, enc);
};

/**
 * Get payment details.
 * @param {String?} enc
 * @returns {String|Object|null}
 */

PaymentDetails.prototype.getData = function getData(enc) {
  let data = this.merchantData;

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

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 * @returns {PaymentDetails}
 */

PaymentDetails.prototype.fromRaw = function fromRaw(data) {
  let br = new ProtoReader(data);

  this.network = br.readFieldString(1, true);

  while (br.nextTag() === 2) {
    let op = new ProtoReader(br.readFieldBytes(2));
    let output = new Output();
    output.value = op.readFieldU64(1, true);
    output.script.fromRaw(op.readFieldBytes(2, true));
    this.outputs.push(output);
  }

  this.time = br.readFieldU64(3);
  this.expires = br.readFieldU64(4, true);
  this.memo = br.readFieldString(5, true);
  this.paymentUrl = br.readFieldString(6, true);
  this.merchantData = br.readFieldBytes(7, true);

  return this;
};

/**
 * Instantiate payment details from serialized data.
 * @param {Buffer} data
 * @returns {PaymentDetails}
 */

PaymentDetails.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = Buffer.from(data, enc);
  return new PaymentDetails().fromRaw(data);
};

/**
 * Serialize the payment details (protobuf).
 * @returns {Buffer}
 */

PaymentDetails.prototype.toRaw = function toRaw() {
  let bw = new ProtoWriter();

  if (this.network != null)
    bw.writeFieldString(1, this.network);

  for (let output of this.outputs) {
    let op = new ProtoWriter();
    op.writeFieldU64(1, output.value);
    op.writeFieldBytes(2, output.script.toRaw());
    bw.writeFieldBytes(2, op.render());
  }

  bw.writeFieldU64(3, this.time);

  if (this.expires !== -1)
    bw.writeFieldU64(4, this.expires);

  if (this.memo != null)
    bw.writeFieldString(5, this.memo);

  if (this.paymentUrl != null)
    bw.writeFieldString(6, this.paymentUrl);

  if (this.merchantData)
    bw.writeFieldString(7, this.merchantData);

  return bw.render();
};

/*
 * Expose
 */

module.exports = PaymentDetails;
