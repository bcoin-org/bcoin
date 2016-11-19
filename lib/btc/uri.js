/**
 * uri.js - bitcoin uri parsing for bcoin
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var util = require('../utils/util');
var Address = require('../primitives/address');
var Amount = require('./amount');
var assert = require('assert');

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

URI.prototype.fromOptions = function fromOptions(options) {
  if (typeof options === 'string')
    return this.fromString(options);

  if (options.address)
    this.address.fromOptions(options.address);

  if (options.amount != null) {
    assert(util.isNumber(options.amount));
    this.amount = options.amount;
  }

  if (options.label) {
    assert(typeof options.label === 'string');
    this.label = options.label;
  }

  if (options.message) {
    assert(typeof options.message === 'string');
    this.message = options.message;
  }

  if (options.request) {
    assert(typeof options.request === 'string');
    this.request = options.request;
  }

  return this;
};

URI.fromOptions = function fromOptions(options) {
  return new URI().fromOptions(options);
};

URI.prototype.fromString = function fromString(str) {
  var prefix, index, address, query;

  assert(typeof str === 'string');
  assert(str.length > 8, 'Not a bitcoin URI.');

  prefix = str.substring(0, 8);

  if (prefix !== 'bitcoin:')
    throw new Error('Not a bitcoin URI.');

  str = str.substring(8);

  index = str.indexOf('?');

  if (index === -1) {
    address = str;
  } else {
    address = str.substring(0, index);
    query = str.substring(index + 1);
  }

  this.address.fromBase58(address);

  if (!query)
    return this;

  query = parsePairs(query);

  if (query.amount)
    this.amount = Amount.value(query.amount);

  if (query.label)
    this.label = query.label;

  if (query.message)
    this.message = query.message;

  if (query.r)
    this.request = query.r;

  return this;
};

URI.fromString = function fromString(str) {
  return new URI().fromString(str);
};

URI.prototype.toString = function toString() {
  var str = 'bitcoin:';
  var query = [];

  str += this.address.toBase58();

  if (this.amount !== -1)
    query.push('amount=' + Amount.btc(this.amount));

  if (this.label)
    query.push('label=' + escape(this.label));

  if (this.message)
    query.push('message=' + escape(this.message));

  if (this.request)
    query.push('r=' + escape(this.request));

  if (query.length > 0)
    str += '?' + query.join('&');

  return str;
};

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

/*
 * Expose
 */

module.exports = URI;
