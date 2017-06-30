/*!
 * dns.js - dns backend for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/**
 * @module net/dns
 */

const dns = require('dns');
const socks = require('./socks');

const options = {
  family: 4,
  hints: dns.ADDRCONFIG | dns.V4MAPPED,
  all: true
};

/**
 * Resolve host (no getaddrinfo).
 * @param {String} host
 * @param {String?} proxy - Tor socks proxy.
 * @returns {Promise}
 */

exports.resolve = function resolve(host, proxy) {
  if (proxy)
    return socks.resolve(proxy, host);

  return new Promise((resolve, reject) => {
    dns.resolve(host, 'A', (err, result) => {
      if (err) {
        reject(err);
        return;
      }

      if (result.length === 0) {
        reject(new Error('No DNS results.'));
        return;
      }

      resolve(result);
    });
  });
};

/**
 * Resolve host (getaddrinfo).
 * @param {String} host
 * @param {String?} proxy - Tor socks proxy.
 * @returns {Promise}
 */

exports.lookup = function lookup(host, proxy) {
  if (proxy)
    return socks.resolve(proxy, host);

  return new Promise((resolve, reject) => {
    let addrs = [];

    dns.lookup(host, options, (err, result) => {
      if (err) {
        reject(err);
        return;
      }

      if (result.length === 0) {
        reject(new Error('No DNS results.'));
        return;
      }

      for (let addr of result)
        addrs.push(addr.address);

      resolve(addrs);
    });
  });
};
