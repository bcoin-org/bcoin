/*!
 * external.js - external ip address discovery for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const request = require('../http/request');
const IP = require('../utils/ip');

/**
 * @exports net/external
 */

const external = exports;

/**
 * Attempt to retrieve external IP from icanhazip.com.
 * @method
 * @returns {Promise}
 */

external.getIPv4 = async function getIPv4() {
  let res, ip;

  try {
    res = await request({
      method: 'GET',
      uri: 'http://ipv4.icanhazip.com',
      expect: 'txt',
      timeout: 2000
    });
  } catch (e) {
    return await external.getIPv42();
  }

  try {
    ip = res.body.trim();
    ip = IP.toBuffer(ip);

    if (!IP.isIPv4(ip))
      throw new Error('Could not find IPv4.');

    ip = IP.toString(ip);
  } catch (e) {
    return await external.getIPv42();
  }

  return ip;
};

/**
 * Attempt to retrieve external IP from dyndns.org.
 * @method
 * @ignore
 * @returns {Promise}
 */

external.getIPv42 = async function getIPv42() {
  let res, match, ip, raw;

  res = await request({
    method: 'GET',
    uri: 'http://checkip.dyndns.org',
    expect: 'html',
    timeout: 2000
  });

  match = /IP Address:\s*([0-9a-f.:]+)/i.exec(res.body);

  if (!match)
    throw new Error('Could not find IPv4.');

  ip = match[1];
  raw = IP.toBuffer(ip);

  if (!IP.isIPv4(raw))
    throw new Error('Could not find IPv4.');

  return IP.toString(raw);
};

/**
 * Attempt to retrieve external IP from icanhazip.com.
 * @method
 * @returns {Promise}
 */

external.getIPv6 = async function getIPv6() {
  let res, ip;

  res = await request({
    method: 'GET',
    uri: 'http://ipv6.icanhazip.com',
    expect: 'txt',
    timeout: 2000
  });

  ip = res.body.trim();
  ip = IP.toBuffer(ip);

  if (!IP.isIPv6(ip))
    throw new Error('Could not find IPv6.');

  return IP.toString(ip);
};
