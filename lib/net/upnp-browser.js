/*!
 * upnp-browser.js - upnp for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/**
 * UPNP
 * @constructor
 * @ignore
 * @param {String?} host - Multicast IP.
 * @param {Number?} port - Multicast port.
 * @param {String?} gateway - Gateway name.
 */

function UPNP(host, port, gateway) {
  throw new Error('UPNP not supported.');
}

/**
 * Discover gateway and resolve service.
 * @param {String?} host - Multicast IP.
 * @param {Number?} port - Multicast port.
 * @param {String?} gateway - Gateway type.
 * @param {String[]?} targets - Target service types.
 * @returns {Promise} Service.
 */

UPNP.discover = function discover(host, port, gateway, targets) {
  return new Promise((resolve, reject) => {
    reject(new Error('UPNP not supported.'));
  });
};

/*
 * Expose
 */

module.exports = UPNP;
