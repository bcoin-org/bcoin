/*!
 * dns.js - dns backend for bcoin
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var dns = require('dns');

exports.resolve = function resolve(host) {
  return new Promise(function(resolve, reject) {
    dns.resolve(host, 'A', function(err, result) {
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
