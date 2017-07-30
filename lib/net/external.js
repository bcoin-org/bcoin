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
  try {
    const res = await request({
      method: 'GET',
      uri: 'http://ipv4.icanhazip.com',
      expect: 'txt',
      timeout: 2000
    });

    const str = res.body.trim();
    const raw = IP.toBuffer(str);

    if (!IP.isIPv4(raw))
      throw new Error('Could not find IPv4.');

    return IP.toString(raw);
  } catch (e) {
    return await external.getIPv42();
  }
};

/**
 * Attempt to retrieve external IP from dyndns.org.
 * @method
 * @ignore
 * @returns {Promise}
 */

external.getIPv42 = async function getIPv42() {
  const res = await request({
    method: 'GET',
    uri: 'http://checkip.dyndns.org',
    expect: 'html',
    timeout: 2000
  });

  const match = /IP Address:\s*([0-9a-f.:]+)/i.exec(res.body);

  if (!match)
    throw new Error('Could not find IPv4.');

  const str = match[1];
  const raw = IP.toBuffer(str);

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
  const res = await request({
    method: 'GET',
    uri: 'http://ipv6.icanhazip.com',
    expect: 'txt',
    timeout: 2000
  });

  const str = res.body.trim();
  const raw = IP.toBuffer(str);

  if (!IP.isIPv6(raw))
    throw new Error('Could not find IPv6.');

  return IP.toString(raw);
};
