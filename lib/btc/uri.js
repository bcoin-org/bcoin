/**
 * uri.js - bitcoin uri parsing for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const util = require('../utils/util');
const Address = require('../primitives/address');
const Amount = require('./amount');

/**
 * Represents a bitcoin URI.
 * @alias module:btc.URI
 * @constructor
 * @param {Object|String} options
 * @property {Address} address
 * @property {Amount} amount
 * @property {String|null} label
 * @property {String|null} message
 * @property {String|null} request
 */

function URI(options) {
  if (!(this instanceof URI))
    return new URI(options);

  this.address = new Address();
  this.amount = -1;
  this.label = null;
  this.message = null;
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

  if (options.label) {
    assert(typeof options.label === 'string', 'Label must be a string.');
    this.label = options.label;
  }

  if (options.message) {
    assert(typeof options.message === 'string', 'Message must be a string.');
    this.message = options.message;
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
 * @param {Network?} network
 * @returns {URI}
 */

URI.prototype.fromString = function fromString(str, network) {
  let prefix, index, query, address;

  assert(typeof str === 'string');
  assert(str.length > 8, 'Not a bitcoin URI.');

  prefix = str.substring(0, 8);

  assert(prefix === 'bitcoin:', 'Not a bitcoin URI.');

  str = str.substring(8);

  index = str.indexOf('?');

  if (index === -1) {
    address = str;
  } else {
    address = str.substring(0, index);
    query = str.substring(index + 1);
  }

  this.address.fromString(address, network);

  if (!query)
    return this;

  query = parsePairs(query);

  if (query.amount) {
    assert(query.amount.length > 0, 'Value is empty.');
    assert(query.amount[0] !== '-', 'Value is negative.');
    this.amount = Amount.value(query.amount);
  }

  if (query.label)
    this.label = query.label;

  if (query.message)
    this.message = query.message;

  if (query.r)
    this.request = query.r;

  return this;
};

/**
 * Instantiate uri from string.
 * @param {String} str
 * @param {Network?} network
 * @returns {URI}
 */

URI.fromString = function fromString(str, network) {
  return new URI().fromString(str, network);
};

/**
 * Serialize uri to a string.
 * @returns {String}
 */

URI.prototype.toString = function toString() {
  let str = 'bitcoin:';
  let query = [];

  str += this.address.toString();

  if (this.amount !== -1)
    query.push(`amount=${Amount.btc(this.amount)}`);

  if (this.label)
    query.push(`label=${escape(this.label)}`);

  if (this.message)
    query.push(`message=${escape(this.message)}`);

  if (this.request)
    query.push(`r=${escape(this.request)}`);

  if (query.length > 0)
    str += '?' + query.join('&');

  return str;
};

/**
 * Inspect bitcoin uri.
 * @returns {String}
 */

URI.prototype.inspect = function inspect() {
  return `<URI: ${this.toString()}>`;
};

/*
 * Helpers
 */

function BitcoinQuery() {
  this.amount = null;
  this.label = null;
  this.message = null;
  this.r = null;
}

function parsePairs(str) {
  let parts = str.split('&');
  let data = new BitcoinQuery();
  let size = 0;

  for (let pair of parts) {
    let index = pair.indexOf('=');
    let key, value;

    if (index === -1) {
      key = pair;
      value = '';
    } else {
      key = pair.substring(0, index);
      value = pair.substring(index + 1);
    }

    if (key.length === 0) {
      assert(value.length === 0, 'Empty key in querystring.');
      continue;
    }

    assert(size < 4, 'Too many keys in querystring.');

    switch (key) {
      case 'amount':
        assert(data.amount == null, 'Duplicate key in querystring (amount).');
        data.amount = unescape(value);
        break;
      case 'label':
        assert(data.label == null, 'Duplicate key in querystring (label).');
        data.label = unescape(value);
        break;
      case 'message':
        assert(data.message == null, 'Duplicate key in querystring (message).');
        data.message = unescape(value);
        break;
      case 'r':
        assert(data.r == null, 'Duplicate key in querystring (r).');
        data.r = unescape(value);
        break;
      default:
        assert(false, `Unknown querystring key: ${value}.`);
        break;
    }

    size++;
  }

  return data;
}

function unescape(str) {
  try {
    str = decodeURIComponent(str);
    str = str.replace(/\+/g, ' ');
  } catch (e) {
    throw new Error('Malformed URI.');
  }

  if (str.indexOf('\0') !== -1)
    throw new Error('Malformed URI.');

  return str;
}

function escape(str) {
  str = encodeURIComponent(str);
  str = str.replace(/%20/g, '+');
  return str;
}

/*
 * Expose
 */

module.exports = URI;
