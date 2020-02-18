/*!
 * cookie.js - cookie middleware for bweb
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bweb
 */

'use strict';

/**
 * Cookie parsing middleware.
 * @param {String} prefix
 * @returns {Function}
 */

function cookieParser() {
  return async (req, res) => {
    const hdr = req.headers['cookie'];

    if (!hdr)
      return;

    req.cookies = parseCookies(hdr);
  };
}

/*
 * Helpers
 */

function parseCookies(hdr) {
  const parts = hdr.split(/; */);
  const cookies = Object.create(null);

  for (const part of parts) {
    const index = part.indexOf('=');

    let key = part;
    let value = '';

    if (index !== -1) {
      key = part.substring(0, index);
      value = part.substring(index + 1);
      if (value[0] === '"')
        value = value.slice(1, -1);
    }

    if (key.length > 0) {
      try {
        value = decodeURIComponent(value);
      } catch (e) {
        ;
      }
      cookies[key] = value;
    }
  }

  return cookies;
}

/*
 * Expose
 */

module.exports = cookieParser;
