/*!
 * dns.js - dns backend for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var ProxySocket = require('./proxysocket');
var socket;

/**
 * Resolve host (no getaddrinfo).
 * @ignore
 * @param {String} host
 * @param {String?} proxy
 * @param {Boolean?} onion
 * @returns {Promise}
 */

exports.resolve = function resolve(host, proxy, onion) {
  return new Promise(function(resolve, reject) {
    if (!socket)
      socket = new ProxySocket(proxy);

    socket.resolve(host, 'A', function(err, result) {
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
 * @ignore
 * @param {String} host
 * @param {String?} proxy
 * @param {Boolean?} onion
 * @returns {Promise}
 */

exports.lookup = function lookup(host, proxy, onion) {
  return exports.resolve(host, proxy, onion);
};
