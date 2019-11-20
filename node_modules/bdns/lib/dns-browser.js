/*!
 * dns.js - dns backend for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/**
 * Supported Flag
 * @const {Boolean}
 * @default
 */

exports.unsupported = true;

/**
 * Resolver
 */

exports.Resolver = class Resolver {
  constructor() {
    throw new Error('DNS resolver not available.');
  }
};

/**
 * Resolve host (no getaddrinfo).
 * @param {String} host
 * @param {String} [record=A]
 * @param {Number} [timeout=5000]
 * @returns {Promise}
 */

exports.resolve = async function resolve(host, record, timeout) {
  throw new Error('DNS not supported.');
};

/**
 * Reverse DNS lookup.
 * @param {String} addr
 * @param {Number} [timeout=5000]
 * @returns {Promise}
 */

exports.reverse = async function reverse(addr, timeout) {
  throw new Error('DNS not supported.');
};

/**
 * Resolve host (getaddrinfo).
 * @param {String} host
 * @param {Number} [family=null]
 * @param {Number} [timeout=5000]
 * @returns {Promise}
 */

exports.lookup = async function lookup(host, family, timeout) {
  throw new Error('DNS not supported.');
};

/**
 * Lookup name (getnameinfo).
 * @param {String} addr
 * @param {Number} [port=80]
 * @param {Number} [timeout=5000]
 * @returns {Promise}
 */

exports.lookupService = async function lookupService(addr, port, timeout) {
  throw new Error('DNS not supported.');
};

/**
 * Resolve IPv4 address from myip.opendns.com.
 * @param {Number} [timeout=5000]
 * @returns {Promise}
 */

exports.getIPv4 = async function getIPv4(timeout) {
  throw new Error('DNS not supported.');
};

/**
 * Resolve IPv6 address from myip.opendns.com.
 * @param {Number} [timeout=5000]
 * @returns {Promise}
 */

exports.getIPv6 = async function getIPv6(timeout) {
  throw new Error('DNS not supported.');
};
