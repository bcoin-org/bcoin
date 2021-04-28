/*!
 * socks.js - socks proxy for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

exports.unsupported = true;

exports.connect = function connect(proxy, destPort, destHost) {
  throw new Error('SOCKS unsupported.');
};

exports.resolve = async function resolve(proxy, name) {
  throw new Error('SOCKS unsupported.');
};
