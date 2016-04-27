/*!
 * uri.js - uri parsing for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

var url = require('url');
var querystring = require('querystring');

exports.parse = function parse(uri) {
  var data = url.parse(uri);
  var query = querystring.parse(data.query || '');

  assert(data.protocol === 'bitcoin:', 'Not a bitcoin URI.');
  assert(data.hostname, 'No address present.');

  return {
    address: data.hostname,
    amount: query.amount ? utils.satoshi(query.amount) : null,
    label: query.label || null,
    message: query.message || null,
    request: query.r || null
  };
};

exports.validate = function validate(uri) {
  try {
    exports.parse(uri);
    return true;
  } catch (e) {
    return false;
  }
};

exports.stringify = function stringify(address, amount) {
  var query = {};
  var data = address;
  var uri;

  if (typeof address === 'string')
    data = { address: address, amount: amount };

  assert(data.address, 'Address is required for a bitcoin URI.');

  uri = 'bitcoin:' + data.address;

  if (data.amount)
    query.amount = utils.btc(data.amount);

  if (data.label)
    query.label = data.label;

  if (data.message)
    query.message = data.message;

  if (data.request)
    query.r = data.request;

  return uri + querystring.stringify(query);
};
