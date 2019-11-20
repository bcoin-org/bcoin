/*!
 * dns.js - dns backend for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');
const dns = require('dns');

/*
 * Constants
 */

const DEFAULT_TIMEOUT = 5000;
const OPENDNS_MYIP = 'myip.opendns.com';

const OPENDNS_IPV4 = [
  '208.67.222.222', // resolver1.opendns.com
  '208.67.220.220', // resolver2.opendns.com
  '208.67.222.220', // resolver3.opendns.com
  '208.67.220.222'  // resolver4.opendns.com
];

const OPENDNS_IPV6 = [
  '2620:0:ccc::2',
  '2620:0:ccd::2'
];

/**
 * Supported Flag
 * @const {Boolean}
 * @default
 */

exports.unsupported = false;

/**
 * Resolver
 */

exports.Resolver = class Resolver {
  constructor() {
    if (!dns.Resolver)
      throw new Error('DNS resolver not available.');

    this.dns = new dns.Resolver();
  }
  getServers() {
    return this.dns.getServers();
  }
  setServers(addrs) {
    this.dns.setServers(addrs);
    return this;
  }
  resolve(host, record, timeout) {
    return _resolve(this.dns, host, record, timeout);
  }
  reverse(addr, timeout) {
    return _reverse(this.dns, addr, timeout);
  }
  cancel() {
    this.dns.cancel();
    return this;
  }
};

/**
 * Resolve host (async w/ libcares).
 * @param {String} host
 * @param {String} [record=A]
 * @param {Number} [timeout=5000]
 * @returns {Promise}
 */

exports.resolve = async function resolve(host, record, timeout) {
  if (!dns.Resolver)
    return _resolve(dns, host, record, timeout);

  const res = new exports.Resolver();
  return res.resolve(host, record, timeout);
};

/**
 * Reverse DNS lookup.
 * @param {String} addr
 * @param {Number} [timeout=5000]
 * @returns {Promise}
 */

exports.reverse = async function reverse(addr, timeout) {
  if (!dns.Resolver)
    return _reverse(dns, addr, timeout);

  const res = new exports.Resolver();
  return res.reverse(addr, timeout);
};

/**
 * Resolve host (getaddrinfo).
 * @param {String} host
 * @param {Number} [family=null]
 * @param {Number} [timeout=5000]
 * @returns {Promise}
 */

exports.lookup = async function lookup(host, family, timeout) {
  if (family == null)
    family = null;

  if (timeout == null)
    timeout = DEFAULT_TIMEOUT;

  assert(typeof host === 'string');
  assert(family === null || family === 4 || family === 6);
  assert(timeout === -1 || (timeout >>> 0) === timeout);

  const options = {
    family,
    hints: dns.ADDRCONFIG | dns.V4MAPPED,
    all: true
  };

  return new Promise((resolve, reject) => {
    dns.lookup(host, options, to(dns, timeout, (err, result) => {
      if (err) {
        reject(err);
        return;
      }

      if (result.length === 0) {
        reject(new Error('No DNS results.'));
        return;
      }

      const addrs = [];

      for (const addr of result)
        addrs.push(addr.address);

      resolve(addrs);
    }));
  });
};

/**
 * Lookup name (getnameinfo).
 * @param {String} addr
 * @param {Number} [port=80]
 * @param {Number} [timeout=5000]
 * @returns {Promise}
 */

exports.lookupService = async function lookupService(addr, port, timeout) {
  if (port == null)
    port = 80;

  if (timeout == null)
    timeout = DEFAULT_TIMEOUT;

  assert(typeof addr === 'string');
  assert((port & 0xffff) === port);
  assert(timeout === -1 || (timeout >>> 0) === timeout);

  return new Promise((resolve, reject) => {
    dns.lookupService(addr, port, to(dns, timeout, (err, hostname, service) => {
      if (err) {
        reject(err);
        return;
      }
      resolve({ hostname, service });
    }));
  });
};

/**
 * Resolve IPv4 address from myip.opendns.com.
 * @param {Number} [timeout=5000]
 * @returns {Promise}
 */

exports.getIPv4 = async function getIPv4(timeout) {
  const res = new exports.Resolver();
  res.setServers(OPENDNS_IPV4);
  const addrs = await res.resolve(OPENDNS_MYIP, 'A', timeout);
  return addrs[0];
};

/**
 * Resolve IPv6 address from myip.opendns.com.
 * @param {Number} [timeout=5000]
 * @returns {Promise}
 */

exports.getIPv6 = async function getIPv6(timeout) {
  const res = new exports.Resolver();
  res.setServers(OPENDNS_IPV6);
  const addrs = await res.resolve(OPENDNS_MYIP, 'AAAA', timeout);
  return addrs[0];
};

/*
 * Helpers
 */

async function _resolve(dns, host, record, timeout) {
  if (record == null)
    record = 'A';

  if (timeout == null)
    timeout = DEFAULT_TIMEOUT;

  assert(typeof host === 'string');
  assert(typeof record === 'string');
  assert(timeout === -1 || (timeout >>> 0) === timeout);

  return new Promise((resolve, reject) => {
    dns.resolve(host, record, to(dns, timeout, (err, addrs) => {
      if (err) {
        reject(err);
        return;
      }

      if (addrs.length === 0) {
        reject(new Error('No DNS results.'));
        return;
      }

      resolve(addrs);
    }));
  });
}

async function _reverse(dns, addr, timeout) {
  if (timeout == null)
    timeout = DEFAULT_TIMEOUT;

  assert(typeof addr === 'string');
  assert(timeout === -1 || (timeout >>> 0) === timeout);

  return new Promise((resolve, reject) => {
    dns.reverse(addr, to(dns, timeout, (err, addrs) => {
      if (err) {
        reject(err);
        return;
      }

      if (addrs.length === 0) {
        reject(new Error('No DNS results.'));
        return;
      }

      resolve(addrs);
    }));
  });
}

function to(dns, timeout, callback) {
  let cancelled = false;
  let timer = null;

  if (timeout !== -1) {
    timer = setTimeout(() => {
      timer = null;
      if (dns.cancel) {
        dns.cancel();
      } else {
        cancelled = true;
        callback(new Error('DNS request timed out.'));
      }
    }, timeout);
  }

  return function(err, result) {
    if (!cancelled) {
      if (timer != null)
        clearTimeout(timer);
      callback(err, result);
    }
  };
}
