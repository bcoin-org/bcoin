/**
 * uri.js - bitcoin uri parsing for bcoin
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var util = require('../utils/util');
var Address = require('../primitives/address');
var KeyRing = require('../primitives/keyring');
var Amount = require('./amount');
var assert = require('assert');

/**
 * Represents a bitcoin URI.
 * @constructor
 * @param {Object|String} options
 * @property {Address} address
 * @property {Number|-1} version
 * @property {Amount} amount
 * @property {String|null} label
 * @property {String|null} message
 * @property {KeyRing|null} key
 * @property {String|null} request
 */

function URI(options) {
  if (!(this instanceof URI))
    return new URI(options);

  this.address = new Address();
  this.version = -1;
  this.amount = -1;
  this.label = null;
  this.message = null;
  this.key = null;
  this.request = null;

  if (options)
    this.fromOptions(options);
}

/**
 * Inject properties from options object.
 * @private
 * @param {Object|String} options
 * @returns {URI}
 */

URI.prototype.fromOptions = function fromOptions(options) {
  if (typeof options === 'string')
    return this.fromString(options);

  if (options.address)
    this.address.fromOptions(options.address);

  if (options.amount != null) {
    assert(util.isUInt53(options.amount), 'Amount must be a uint53.');
    this.amount = options.amount;
  }

  if (options.version != null) {
    assert(util.isUInt32(options.version), 'Version must be a uint32.');
    this.version = options.version;
  }

  if (options.label) {
    assert(typeof options.label === 'string', 'Label must be a string.');
    this.label = options.label;
  }

  if (options.message) {
    assert(typeof options.message === 'string', 'Message must be a string.');
    this.message = options.message;
  }

  if (options.key) {
    if (typeof options.key === 'string') {
      this.key = KeyRing.fromSecret(options.key);
    } else {
      this.key = KeyRing.fromOptions(options.key);
      assert(this.key.privateKey, 'Key must have a private key.');
    }
  }

  if (options.request) {
    assert(typeof options.request === 'string', 'Request must be a string.');
    this.request = options.request;
  }

  return this;
};

/**
 * Instantiate URI from options.
 * @param {Object|String} options
 * @returns {URI}
 */

URI.fromOptions = function fromOptions(options) {
  return new URI().fromOptions(options);
};

/**
 * Parse and inject properties from string.
 * @private
 * @param {String} str
 * @returns {URI}
 */

URI.prototype.fromString = function fromString(str) {
  var prefix, index, body, query, parts, address, version;

  assert(typeof str === 'string');
  assert(str.length > 8, 'Not a bitcoin URI.');

  prefix = str.substring(0, 8);

  assert(prefix === 'bitcoin:', 'Not a bitcoin URI.');

  str = str.substring(8);

  index = str.indexOf('?');

  if (index === -1) {
    body = str;
  } else {
    body = str.substring(0, index);
    query = str.substring(index + 1);
  }

  parts = body.split(';');
  assert(parts.length <= 2, 'Too many semicolons in body.');

  address = parts[0];

  this.address.fromBase58(address);

  if (parts.length === 2) {
    version = parts[1];
    assert(util.isDecimal(version), 'Version is not decimal.');
    this.version = parseInt(version, 10);
  }

  if (!query)
    return this;

  query = parsePairs(query);

  if (query.amount)
    this.amount = parseAmount(query.amount, query.size);

  if (query.label)
    this.label = query.label;

  if (query.message)
    this.message = query.message;

  if (query.send)
    this.key = KeyRing.fromSecret(query.send);

  if (query.r)
    this.request = query.r;

  return this;
};

/**
 * Instantiate uri from string.
 * @param {String} str
 * @returns {URI}
 */

URI.fromString = function fromString(str) {
  return new URI().fromString(str);
};

/**
 * Serialize uri to a string.
 * @returns {String}
 */

URI.prototype.toString = function toString() {
  var str = 'bitcoin:';
  var query = [];

  str += this.address.toBase58();

  if (this.version !== -1)
    str += ';version=' + this.version;

  if (this.amount !== -1)
    query.push('amount=' + Amount.btc(this.amount));

  if (this.label)
    query.push('label=' + escape(this.label));

  if (this.message)
    query.push('message=' + escape(this.message));

  if (this.key)
    query.push('send=' + this.key.toSecret());

  if (this.request)
    query.push('r=' + escape(this.request));

  if (query.length > 0)
    str += '?' + query.join('&');

  return str;
};

/**
 * Inspect bitcoin uri.
 * @returns {String}
 */

URI.prototype.inspect = function inspect() {
  return '<URI: ' + this.toString() + '>';
};

/*
 * Helpers
 */

function parsePairs(str) {
  var parts = str.split('&');
  var data = {};
  var i, index, pair, key, value;

  for (i = 0; i < parts.length; i++) {
    pair = parts[i];
    index = pair.indexOf('=');

    if (index === -1) {
      key = pair;
      value = '';
    } else {
      key = pair.substring(0, index);
      value = pair.substring(index + 1);
    }

    key = unescape(key);

    if (key.length === 0)
      continue;

    value = unescape(value);

    if (value.length === 0)
      continue;

    data[key] = value;
  }

  return data;
}

function unescape(str) {
  try {
    str = decodeURIComponent(str).replace(/\+/g, ' ');
  } finally {
    return str.replace(/\0/g, '');
  }
}

function escape(str) {
  try {
    str = encodeURIComponent(str).replace(/%20/g, '+');
  } finally {
    return str;
  }
}

function parseAmount(amount, size) {
  var value = amount;
  var exp = 8;
  var parts;

  assert(typeof amount === 'string');
  assert(amount.length > 0);

  if (size) {
    assert(typeof size === 'string');
    assert(size.length > 0);
    exp = size;
    assert(util.isDecimal(exp), 'Exponent is not a decimal.');
    exp = parseInt(exp, 10);
  }

  if (value[0] === 'x') {
    exp = 4;

    assert(value.length > 1);

    value = value.substring(1);
    parts = value.split('X');
    assert(parts.length <= 2, 'Too many bases.');

    value = parts[0];
    assert(value.length > 0, 'Value is empty.');
    assert(util.isHex(value), 'Value is not hex.');
    value = parseInt(value, 16);
    assert(util.isNumber(value), 'Value exceeds 2^53-1 bits.');

    if (parts.length === 2) {
      exp = parts[1];
      assert(util.isHex(exp), 'Exponent is not hex.');
      exp = parseInt(exp, 16);
    }

    assert(exp <= 4, 'Exponent is too large.');

    value *= Math.pow(16, exp);

    assert(util.isNumber(value), 'Value exceeds 2^53-1 bits.');

    return value;
  }

  parts = value.split('X');
  assert(parts.length <= 2, 'Too many bases.');

  value = parts[0];
  assert(value.length > 0, 'Value is empty.');
  assert(value[0] !== '-', 'Value is negative.');
  assert(util.isFloat(value), 'Value is not a float.');

  if (parts.length === 2) {
    exp = parts[1];
    assert(util.isDecimal(exp), 'Exponent is not decimal.');
    exp = parseInt(exp, 10);
  }

  return Amount.parse(value, exp, false);
}

/*
 * Expose
 */

module.exports = URI;
