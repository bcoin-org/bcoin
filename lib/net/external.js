/*!
 * external.js - external ip address discovery for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var request = require('../http/request');
var IP = require('../utils/ip');
var external = exports;

/**
 * Attempt to retrieve external IP from icanhazip.com.
 * @method
 * @returns {Promise}
 */

external.getIPv4 = async function getIPv4() {
  var res, ip;

  if (request.unsupported)
    throw new Error('Could not find IP.');

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

  ip = res.body.trim();

  try {
    ip = IP.normalize(ip);
  } catch (e) {
    return await external.getIPv42();
  }

  return ip;
};

/**
 * Attempt to retrieve external IP from dyndns.org.
 * @method
 * @returns {Promise}
 */

external.getIPv42 = async function getIPv42() {
  var res, match, ip, raw;

  if (request.unsupported)
    throw new Error('Could not find IP.');

  res = await request({
    method: 'GET',
    uri: 'http://checkip.dyndns.org',
    expect: 'html',
    timeout: 2000
  });

  match = /IP Address:\s*([0-9a-f.:]+)/i.exec(res.body);

  if (!match)
    throw new Error('Could not find IP.');

  ip = match[1];
  raw = IP.toBuffer(ip);

  if (!IP.isMapped(raw))
    throw new Error('Could not find IP.');

  return IP.toString(raw);
};

/**
 * Attempt to retrieve external IP from icanhazip.com.
 * @method
 * @returns {Promise}
 */

external.getIPv6 = async function getIPv6() {
  var res, ip;

  if (request.unsupported)
    throw new Error('Could not find IP.');

  res = await request({
    method: 'GET',
    uri: 'http://ipv6.icanhazip.com',
    expect: 'txt',
    timeout: 2000
  });

  ip = res.body.trim();

  return IP.normalize(ip);
};
