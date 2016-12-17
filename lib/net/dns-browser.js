/*!
 * dns.js - dns backend for bcoin
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

exports.resolve = function resolve(host) {
  return Promise.reject(new Error('No DNS results.'));
};
