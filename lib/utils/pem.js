/*!
 * pem.js - pem parsing for bcoin
 * Copyright (c) 2016-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');

/**
 * @exports utils/pem
 */

var PEM = exports;

/**
 * Parse PEM into separated chunks.
 * @param {String} pem
 * @returns {Object[]}
 * @throws on parse error
 */

PEM.parse = function parse(pem) {
  var buf = '';
  var chunks = [];
  var s, tag, type;

  while (pem.length) {
    if (s = /^-----BEGIN ([^\-]+)-----/.exec(pem)) {
      pem = pem.substring(s[0].length);
      tag = s[1];
      continue;
    }
    if (s = /^-----END ([^\-]+)-----/.exec(pem)) {
      pem = pem.substring(s[0].length);
      assert(tag === s[1], 'Tag mismatch.');
      buf = new Buffer(buf, 'base64');
      type = tag.split(' ')[0].toLowerCase();
      chunks.push({ tag: tag, type: type, data: buf });
      buf = '';
      tag = null;
      continue;
    }
    if (s = /^[a-zA-Z0-9\+=\/]+/.exec(pem)) {
      pem = pem.substring(s[0].length);
      buf += s[0];
      continue;
    }
    if (s = /^\s+/.exec(pem)) {
      pem = pem.substring(s[0].length);
      continue;
    }
    throw new Error('PEM parse error.');
  }

  assert(chunks.length !== 0, 'PEM parse error.');
  assert(!tag, 'Un-ended tag.');
  assert(buf.length === 0, 'Trailing data.');

  return chunks;
};

/**
 * Decode PEM into a manageable format.
 * @param {String} pem
 * @returns {Object}
 * @throws on parse error
 */

PEM.decode = function decode(pem) {
  var chunks = PEM.parse(pem);
  var body = chunks[0];
  var extra = chunks[1];
  var params, alg;

  if (extra) {
    if (extra.tag.indexOf('PARAMETERS') !== -1)
      params = extra.data;
  }

  switch (body.type) {
    case 'dsa':
      alg = 'dsa';
      break;
    case 'rsa':
      alg = 'rsa';
      break;
    case 'ec':
      alg = 'ecdsa';
      break;
  }

  return {
    type: body.type,
    alg: alg,
    data: body.data,
    params: params
  };
};

/**
 * Encode DER to PEM.
 * @param {Buffer} der
 * @param {String} type - e.g. "ec".
 * @param {String?} suffix - e.g. "public key".
 * @returns {String}
 */

PEM.encode = function encode(der, type, suffix) {
  var pem = '';
  var i;

  if (suffix)
    type += ' ' + suffix;

  type = type.toUpperCase();
  der = der.toString('base64');

  for (i = 0; i < der.length; i += 64)
    pem += der.slice(i, i + 64) + '\n';

  return ''
    + '-----BEGIN ' + type + '-----\n'
    + pem
    + '-----END ' + type + '-----\n';
};
