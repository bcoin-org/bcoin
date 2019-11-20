/*!
 * util.js - utils server for bweb
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bweb
 */

'use strict';

const assert = require('bsert');
const URL = require('url');

exports.parseURL = function parseURL(uri) {
  assert(typeof uri === 'string');

  if (uri.length > 4096)
    throw new Error('URI is too long.');

  if (!/^[a-z]+:\/\//i.test(uri))
    uri = 'http://localhost/' + uri;

  const data = URL.parse(uri);

  let pathname = data.pathname;
  let trailing = false;

  if (pathname) {
    if (pathname.length > 1024)
      throw new Error('Pathname is too long.');

    // Remove double slashes.
    pathname = pathname.replace(/\/{2,}/g, '/');

    // Ensure leading slash.
    if (pathname[0] !== '/')
      pathname = '/' + pathname;

    // Remove trailing slash.
    if (pathname.length > 1) {
      if (pathname[pathname.length - 1] === '/') {
        pathname = pathname.slice(0, -1);
        trailing = true;
      }
    }

    // Unescape.
    pathname = pathname.replace(/%2f/gi, '');
    pathname = unescape(pathname);
  } else {
    // Ensure leading slash.
    pathname = '/';
  }

  // Sanitize.
  pathname = pathname.replace(/\/\.\.?\//g, '');
  pathname = pathname.replace(/[^ -~]+/g, '');
  pathname = pathname.replace(/\\+/, '');

  // Sanity checks.
  assert(pathname.length > 0);
  assert(pathname[0] === '/');

  if (pathname.length > 1)
    assert(pathname[pathname.length - 1] !== '/');

  // Create path array.
  let path = pathname;

  if (path[0] === '/')
    path = path.substring(1);

  path = path.split('/');

  if (path.length === 1) {
    if (path[0].length === 0)
      path = [];
  }

  // URL = Pathname + QS.
  let url = pathname;

  if (data.search && data.search.length > 1) {
    assert(data.search[0] === '?');
    url += data.search;
  }

  // Pre-parsed querystring.
  let query = Object.create(null);

  if (data.query)
    query = exports.parseForm(data.query, 100);

  return {
    url,
    pathname,
    path,
    query,
    trailing
  };
};

exports.parseForm = function parseForm(str, limit) {
  assert((limit >>> 0) === limit);

  const parts = str.split('&');
  const data = Object.create(null);

  if (parts.length > limit)
    throw new Error('Too many keys in querystring.');

  for (const pair of parts) {
    const index = pair.indexOf('=');

    let key, value;
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
};

exports.unescape = function unescape(str) {
  try {
    str = decodeURIComponent(str);
    str = str.replace(/\+/g, ' ');
  } catch (e) {
    ;
  }
  str = str.replace(/\0/g, '');
  return str;
};

exports.isAscii = function isAscii(str) {
  return typeof str === 'string' && /^[\t\n\r -~]*$/.test(str);
};
